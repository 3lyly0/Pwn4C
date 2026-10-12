/*
 * tests/test_stream_hdr.c — Unit tests for stream header byte layout.
 *
 * Verifies:
 *   1. put_u32_be writes correct big-endian bytes.
 *   2. put_u16_be writes correct big-endian bytes.
 *   3. Full 16-byte stream header encodes correctly.
 *   4. Sequence number wrap (0xFFFFFFFF -> 0x00000000 next).
 *   5. fragment_count ceiling division (integer, no float).
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static int g_passed = 0;
static int g_failed = 0;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

/* Replicate the helpers from stream.c (they're static there) */
static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

static void put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v     );
}

static void test_put_u32_be(void)
{
    uint8_t buf[4];

    put_u32_be(buf, 0x01020304u);
    CHECK("u32be bytes", buf[0]==0x01 && buf[1]==0x02
          && buf[2]==0x03 && buf[3]==0x04);

    put_u32_be(buf, 0x00000000u);
    CHECK("u32be zero", buf[0]==0 && buf[1]==0 && buf[2]==0 && buf[3]==0);

    put_u32_be(buf, 0xFFFFFFFFu);
    CHECK("u32be all-ff", buf[0]==0xFF && buf[1]==0xFF
          && buf[2]==0xFF && buf[3]==0xFF);

    put_u32_be(buf, 0xDEADBEEFu);
    CHECK("u32be deadbeef", buf[0]==0xDE && buf[1]==0xAD
          && buf[2]==0xBE && buf[3]==0xEF);
}

static void test_put_u16_be(void)
{
    uint8_t buf[2];

    put_u16_be(buf, 0x0102u);
    CHECK("u16be bytes", buf[0]==0x01 && buf[1]==0x02);

    put_u16_be(buf, 0x0000u);
    CHECK("u16be zero", buf[0]==0 && buf[1]==0);

    put_u16_be(buf, 0xFFFFu);
    CHECK("u16be all-ff", buf[0]==0xFF && buf[1]==0xFF);
}

static void test_stream_header(void)
{
    /* Build a complete 16-byte header and verify every byte */
    uint8_t hdr[16];
    uint32_t seq    = 0xCAFEBABEu;
    uint32_t ts_us  = 0x00001234u;
    uint16_t fidx   = 0;
    uint16_t fcnt   = 1;
    uint16_t flen   = 1400;
    uint16_t rsv    = 0;

    memset(hdr, 0xAA, sizeof(hdr));

    put_u32_be(hdr + 0,  seq);
    put_u32_be(hdr + 4,  ts_us);
    put_u16_be(hdr + 8,  fidx);
    put_u16_be(hdr + 10, fcnt);
    put_u16_be(hdr + 12, flen);
    put_u16_be(hdr + 14, rsv);

    /* Verify seq */
    CHECK("hdr seq[0]", hdr[0] == 0xCA);
    CHECK("hdr seq[1]", hdr[1] == 0xFE);
    CHECK("hdr seq[2]", hdr[2] == 0xBA);
    CHECK("hdr seq[3]", hdr[3] == 0xBE);

    /* Verify timestamp */
    CHECK("hdr ts[0]",  hdr[4] == 0x00);
    CHECK("hdr ts[1]",  hdr[5] == 0x00);
    CHECK("hdr ts[2]",  hdr[6] == 0x12);
    CHECK("hdr ts[3]",  hdr[7] == 0x34);

    /* frag_index = 0 */
    CHECK("hdr fidx[0]", hdr[8]  == 0x00);
    CHECK("hdr fidx[1]", hdr[9]  == 0x00);

    /* frag_count = 1 */
    CHECK("hdr fcnt[0]", hdr[10] == 0x00);
    CHECK("hdr fcnt[1]", hdr[11] == 0x01);

    /* frame_len = 1400 = 0x0578 */
    CHECK("hdr flen[0]", hdr[12] == 0x05);
    CHECK("hdr flen[1]", hdr[13] == 0x78);

    /* reserved = 0 */
    CHECK("hdr rsv[0]",  hdr[14] == 0x00);
    CHECK("hdr rsv[1]",  hdr[15] == 0x00);
}

static void test_frag_count(void)
{
    /* Replicate frag_count computation from stream.c (no float) */
    #define STREAM_FRAG_MAX 1472u

    uint16_t frag_count;
    uint16_t frame_len;

    /* Unfragmented */
    frame_len  = 100;
    frag_count = (frame_len <= STREAM_FRAG_MAX)
               ? 1u
               : (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u) / STREAM_FRAG_MAX);
    CHECK("frag_count 100B", frag_count == 1);

    /* Exactly 1472: still 1 fragment */
    frame_len  = 1472;
    frag_count = (frame_len <= STREAM_FRAG_MAX)
               ? 1u
               : (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u) / STREAM_FRAG_MAX);
    CHECK("frag_count 1472B", frag_count == 1);

    /* 1473: needs 2 fragments */
    frame_len  = 1473;
    frag_count = (frame_len <= STREAM_FRAG_MAX)
               ? 1u
               : (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u) / STREAM_FRAG_MAX);
    CHECK("frag_count 1473B", frag_count == 2);

    /* 2944 = 2*1472: exactly 2 fragments */
    frame_len  = 2944;
    frag_count = (frame_len <= STREAM_FRAG_MAX)
               ? 1u
               : (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u) / STREAM_FRAG_MAX);
    CHECK("frag_count 2944B", frag_count == 2);

    /* 2945: 3 fragments */
    frame_len  = 2945;
    frag_count = (frame_len <= STREAM_FRAG_MAX)
               ? 1u
               : (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u) / STREAM_FRAG_MAX);
    CHECK("frag_count 2945B", frag_count == 3);

    #undef STREAM_FRAG_MAX
}

static void test_seq_wrap(void)
{
    /* Simulate wrapping of 32-bit sequence counter */
    uint32_t seq = 0xFFFFFFFEu;
    seq++;
    CHECK("seq wrap 0xFFFFFFFE+1", seq == 0xFFFFFFFFu);
    seq++;
    CHECK("seq wrap 0xFFFFFFFF+1", seq == 0x00000000u);
}

void run_stream_tests(void)
{
    printf("=== Stream Header Tests ===\n");
    test_put_u32_be();
    test_put_u16_be();
    test_stream_header();
    test_frag_count();
    test_seq_wrap();
}

#ifndef TEST_COMBINED
int main(void)
{
    run_stream_tests();
    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
#endif
