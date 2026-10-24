/*
 * tests/test_bpf.c — Unit tests for the classic BPF frame filter (§3.4/§3.5.2)
 *                    and SHA-256 / HMAC-SHA256 authentication (§4.1).
 *
 * Uses a self-contained classic BPF bytecode interpreter so tests run
 * deterministically on every host OS, container, and CI environment without
 * requiring CAP_NET_RAW or AF_PACKET kernel sockets.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_passed;
static int g_failed;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

/* ── Deterministic Classic BPF Interpreter (RFC / Linux filter.h) ─────────── */
static uint32_t eval_cbpf(const struct sock_filter *insns, unsigned short len,
                          const uint8_t *pkt, size_t pkt_len)
{
    uint32_t A = 0;
    uint32_t X = 0;
    unsigned short pc = 0;

    while (pc < len) {
        const struct sock_filter *f = &insns[pc++];
        uint16_t code = f->code;
        uint32_t k = f->k;
        size_t off;

        switch (code) {
        case (BPF_LD | BPF_B | BPF_ABS):
            if (k >= pkt_len) { return 0; }
            A = pkt[k];
            break;
        case (BPF_LD | BPF_B | BPF_IND):
            off = (size_t)X + (size_t)k;
            if (off >= pkt_len) { return 0; }
            A = pkt[off];
            break;
        case (BPF_LD | BPF_H | BPF_IND):
            off = (size_t)X + (size_t)k;
            if (off + 2u > pkt_len) { return 0; }
            A = ((uint32_t)pkt[off] << 8) | (uint32_t)pkt[off + 1u];
            break;
        case (BPF_LD | BPF_W | BPF_IND):
            off = (size_t)X + (size_t)k;
            if (off + 4u > pkt_len) { return 0; }
            A = ((uint32_t)pkt[off + 0u] << 24)
              | ((uint32_t)pkt[off + 1u] << 16)
              | ((uint32_t)pkt[off + 2u] << 8)
              |  (uint32_t)pkt[off + 3u];
            break;
        case (BPF_ALU | BPF_LSH | BPF_K):
            A <<= k;
            break;
        case (BPF_ALU | BPF_OR | BPF_X):
            A |= X;
            break;
        case (BPF_ALU | BPF_AND | BPF_K):
            A &= k;
            break;
        case (BPF_MISC | BPF_TAX):
            X = A;
            break;
        case (BPF_JMP | BPF_JEQ | BPF_K):
            pc = (unsigned short)(pc + ((A == k) ? f->jt : f->jf));
            break;
        case (BPF_RET | BPF_K):
            return k;
        default:
            return 0;
        }
    }
    return 0;
}

/* Build RadioTap + 802.11 header. it_len is the RadioTap length in bytes. */
static void build_frame(uint8_t *buf, size_t it_len, uint8_t fc0, uint8_t fc1,
                        const uint8_t a1[6], const uint8_t a2[6],
                        const uint8_t a3[6], size_t *out_len)
{
    memset(buf, 0, it_len + 24);
    buf[2] = (uint8_t)(it_len & 0xffu);         /* it_len little-endian */
    buf[3] = (uint8_t)((it_len >> 8) & 0xffu);
    buf[it_len + 0] = fc0;                      /* Frame Control */
    buf[it_len + 1] = fc1;
    memcpy(buf + it_len + 4,  a1, 6);           /* Addr1 */
    memcpy(buf + it_len + 10, a2, 6);           /* Addr2 */
    memcpy(buf + it_len + 16, a3, 6);           /* Addr3 */
    *out_len = it_len + 24;
}

static void test_bssid_filter(void)
{
    const uint8_t bssid[6]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    struct sock_filter insns[32];
    unsigned short prog_len = 0;
    uint8_t buf[512];
    size_t  flen;

    if (capture_build_bpf(false, bssid, insns, 32, &prog_len) < 0 || prog_len == 0) {
        FAIL("build bssid filter", "capture_build_bpf failed");
        return;
    }

    build_frame(buf, 24, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("bssid addr1 (ToDS)", eval_cbpf(insns, prog_len, buf, flen) > 0);

    build_frame(buf, 24, 0x08, 0x02, client, bssid, other, &flen);
    CHECK("bssid addr2 (FromDS)", eval_cbpf(insns, prog_len, buf, flen) > 0);

    build_frame(buf, 24, 0x80, 0x00, other, client, bssid, &flen);
    CHECK("bssid addr3 (mgmt)", eval_cbpf(insns, prog_len, buf, flen) > 0);

    build_frame(buf, 24, 0x08, 0x01, other, client, other, &flen);
    CHECK("bssid mismatch dropped", eval_cbpf(insns, prog_len, buf, flen) == 0);

    /* Extended RadioTap header: it_len = 280 (> 255) */
    build_frame(buf, 280, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("extended radiotap it_len", eval_cbpf(insns, prog_len, buf, flen) > 0);
}

static void test_mgmt_and_bssid_filter(void)
{
    const uint8_t bssid[6]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    struct sock_filter insns[32];
    unsigned short prog_len = 0;
    uint8_t buf[512];
    size_t  flen;

    if (capture_build_bpf(true, bssid, insns, 32, &prog_len) < 0 || prog_len == 0) {
        FAIL("build mgmt+bssid filter", "capture_build_bpf failed");
        return;
    }

    build_frame(buf, 24, 0x80, 0x00, other, client, bssid, &flen);
    CHECK("mgmt+bssid keeps mgmt", eval_cbpf(insns, prog_len, buf, flen) > 0);

    build_frame(buf, 24, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("mgmt+bssid drops data", eval_cbpf(insns, prog_len, buf, flen) == 0);

    build_frame(buf, 24, 0x80, 0x00, other, client, other, &flen);
    CHECK("mgmt+bssid wrong BSSID", eval_cbpf(insns, prog_len, buf, flen) == 0);
}

static void test_mgmt_only_filter(void)
{
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    struct sock_filter insns[32];
    unsigned short prog_len = 0;
    uint8_t buf[512];
    size_t  flen;

    if (capture_build_bpf(true, NULL, insns, 32, &prog_len) < 0 || prog_len == 0) {
        FAIL("build mgmt-only filter", "capture_build_bpf failed");
        return;
    }

    build_frame(buf, 24, 0x80, 0x00, other, client, other, &flen);
    CHECK("mgmt-only keeps mgmt", eval_cbpf(insns, prog_len, buf, flen) > 0);

    build_frame(buf, 24, 0x08, 0x01, other, client, other, &flen);
    CHECK("mgmt-only drops data", eval_cbpf(insns, prog_len, buf, flen) == 0);
}

static void test_sha256_and_hmac(void)
{
    uint8_t digest[32];
    char hex_out[65];

    /* FIPS 180-4 test vector: SHA256("abc") */
    static const uint8_t expected_abc[32] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    util_sha256((const uint8_t *)"abc", 3, digest);
    CHECK("sha256('abc') FIPS vector", memcmp(digest, expected_abc, 32) == 0);

    /* RFC 4231 Test Case 2: HMAC-SHA256("Jefe", "what do ya want for nothing?") */
    util_hmac_sha256_hex("Jefe", "what do ya want for nothing?", hex_out);
    CHECK("hmac_sha256 RFC 4231 vector",
          strcmp(hex_out, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") == 0);
}

int run_bpf_tests(void)
{
    printf("=== Classic BPF Filter & Crypto Tests ===\n");
    test_bssid_filter();
    test_mgmt_and_bssid_filter();
    test_mgmt_only_filter();
    test_sha256_and_hmac();
    return g_failed;
}

#ifndef TEST_COMBINED
int main(void)
{
    run_bpf_tests();
    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
#endif
