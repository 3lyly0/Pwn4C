/*
 * tests/test_bpf.c — Unit tests for the classic BPF frame filter (§3.4/§3.5.2).
 *
 * The generated program is attached to one end of an AF_UNIX SOCK_DGRAM
 * socketpair (the filter sees the payload at offset 0, exactly like the
 * RadioTap frame seen on an AF_PACKET socket) and synthetic RadioTap +
 * 802.11 frames are pushed through it.
 *
 * Verifies:
 *   1. BSSID matching on Addr1 (ToDS), Addr2 (FromDS) and Addr3 (Management).
 *   2. Non-matching BSSID frames are rejected.
 *   3. 16-bit little-endian RadioTap it_len is honoured past byte 255.
 *   4. mgmt_only rejects Data frames and keeps Management frames.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>

static int g_passed;
static int g_failed;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

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

/* Returns 1 if the frame passed the filter, 0 if rejected. */
static int deliver(int tx, int rx, const uint8_t *frame, size_t len)
{
    uint8_t tmp[512];
    ssize_t n;

    if (send(tx, frame, len, 0) < 0) {
        return -1;
    }
    n = recv(rx, tmp, sizeof(tmp), MSG_DONTWAIT);
    if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
        return 0;
    }
    return n >= 0 ? 1 : -1;
}

static int open_pair(daemon_t *d, int *tx)
{
    int sv[2];

    memset(d, 0, sizeof(*d));
    d->mock_mode = false;
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, sv) < 0) {
        return -1;
    }
    d->pkt_fd = sv[0];
    *tx = sv[1];
    return 0;
}

static void test_bssid_filter(void)
{
    const uint8_t bssid[6]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    uint8_t buf[512];
    size_t  flen;
    daemon_t d;
    int tx;

    if (open_pair(&d, &tx) < 0) {
        FAIL("open socketpair", "errno=%s", strerror(errno));
        return;
    }
    if (capture_set_filter(&d, false, bssid) < 0) {
        FAIL("attach bssid filter", "capture_set_filter failed");
        close(tx); close(d.pkt_fd);
        return;
    }

    build_frame(buf, 24, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("bssid addr1 (ToDS)", deliver(tx, d.pkt_fd, buf, flen) == 1);

    build_frame(buf, 24, 0x08, 0x02, client, bssid, other, &flen);
    CHECK("bssid addr2 (FromDS)", deliver(tx, d.pkt_fd, buf, flen) == 1);

    build_frame(buf, 24, 0x80, 0x00, other, client, bssid, &flen);
    CHECK("bssid addr3 (mgmt)", deliver(tx, d.pkt_fd, buf, flen) == 1);

    build_frame(buf, 24, 0x08, 0x01, other, client, other, &flen);
    CHECK("bssid mismatch dropped", deliver(tx, d.pkt_fd, buf, flen) == 0);

    /* Extended RadioTap header: it_len = 280 (> 255) */
    build_frame(buf, 280, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("extended radiotap it_len", deliver(tx, d.pkt_fd, buf, flen) == 1);

    close(tx);
    close(d.pkt_fd);
}

static void test_mgmt_and_bssid_filter(void)
{
    const uint8_t bssid[6]  = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    uint8_t buf[512];
    size_t  flen;
    daemon_t d;
    int tx;

    if (open_pair(&d, &tx) < 0) {
        FAIL("open socketpair", "errno=%s", strerror(errno));
        return;
    }
    if (capture_set_filter(&d, true, bssid) < 0) {
        FAIL("attach mgmt+bssid filter", "capture_set_filter failed");
        close(tx); close(d.pkt_fd);
        return;
    }

    build_frame(buf, 24, 0x80, 0x00, other, client, bssid, &flen);
    CHECK("mgmt+bssid keeps mgmt", deliver(tx, d.pkt_fd, buf, flen) == 1);

    build_frame(buf, 24, 0x08, 0x01, bssid, client, other, &flen);
    CHECK("mgmt+bssid drops data", deliver(tx, d.pkt_fd, buf, flen) == 0);

    build_frame(buf, 24, 0x80, 0x00, other, client, other, &flen);
    CHECK("mgmt+bssid wrong BSSID", deliver(tx, d.pkt_fd, buf, flen) == 0);

    close(tx);
    close(d.pkt_fd);
}

static void test_mgmt_only_filter(void)
{
    const uint8_t client[6] = {0x02, 0x11, 0x22, 0x33, 0x44, 0x55};
    const uint8_t other[6]  = {0x66, 0x66, 0x66, 0x66, 0x66, 0x66};
    uint8_t buf[512];
    size_t  flen;
    daemon_t d;
    int tx;

    if (open_pair(&d, &tx) < 0) {
        FAIL("open socketpair", "errno=%s", strerror(errno));
        return;
    }
    if (capture_set_filter(&d, true, NULL) < 0) {
        FAIL("attach mgmt-only filter", "capture_set_filter failed");
        close(tx); close(d.pkt_fd);
        return;
    }

    build_frame(buf, 24, 0x80, 0x00, other, client, other, &flen);
    CHECK("mgmt-only keeps mgmt", deliver(tx, d.pkt_fd, buf, flen) == 1);

    build_frame(buf, 24, 0x08, 0x01, other, client, other, &flen);
    CHECK("mgmt-only drops data", deliver(tx, d.pkt_fd, buf, flen) == 0);

    close(tx);
    close(d.pkt_fd);
}

int run_bpf_tests(void)
{
    printf("=== Classic BPF Filter Tests ===\n");
    test_bssid_filter();
    test_mgmt_and_bssid_filter();
    test_mgmt_only_filter();
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
