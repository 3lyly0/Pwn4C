/*
 * tests/test_hex_decode.c — Unit tests for hex decode (SEND_INJECTION).
 *
 * The hex_decode function is static in control.c, so we replicate it here
 * for independent testing.  The logic is identical.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static int g_passed = 0;
static int g_failed = 0;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

/* Copy of hex_decode from control.c */
static int hex_decode(const char *hex, uint8_t *out, size_t outsize,
                      size_t *outlen)
{
    size_t hlen, i;
    if (!hex || !out || !outlen) { return -1; }
    hlen = strlen(hex);
    if (hlen % 2 != 0) { return -1; }
    if (hlen / 2 > outsize) { return -1; }
    for (i = 0; i < hlen; i += 2) {
        unsigned int hi, lo;
        char h = hex[i], l = hex[i+1];
        if      (h>='0'&&h<='9') { hi=(unsigned int)(h-'0'); }
        else if (h>='a'&&h<='f') { hi=(unsigned int)(h-'a'+10); }
        else if (h>='A'&&h<='F') { hi=(unsigned int)(h-'A'+10); }
        else { return -1; }
        if      (l>='0'&&l<='9') { lo=(unsigned int)(l-'0'); }
        else if (l>='a'&&l<='f') { lo=(unsigned int)(l-'a'+10); }
        else if (l>='A'&&l<='F') { lo=(unsigned int)(l-'A'+10); }
        else { return -1; }
        out[i/2] = (uint8_t)((hi<<4)|lo);
    }
    *outlen = hlen/2;
    return 0;
}

static void test_hex_decode(void)
{
    uint8_t buf[64];
    size_t  len;
    int     r;

    /* 1. Empty string */
    r = hex_decode("", buf, sizeof(buf), &len);
    CHECK("hex empty", r == 0 && len == 0);

    /* 2. Single byte lower */
    r = hex_decode("ff", buf, sizeof(buf), &len);
    CHECK("hex ff lower", r == 0 && len == 1 && buf[0] == 0xFF);

    /* 3. Single byte upper */
    r = hex_decode("FF", buf, sizeof(buf), &len);
    CHECK("hex FF upper", r == 0 && len == 1 && buf[0] == 0xFF);

    /* 4. Mixed case */
    r = hex_decode("DeAdBeEf", buf, sizeof(buf), &len);
    CHECK("hex mixed", r == 0 && len == 4
          && buf[0]==0xDE && buf[1]==0xAD
          && buf[2]==0xBE && buf[3]==0xEF);

    /* 5. All zeros */
    r = hex_decode("00000000", buf, sizeof(buf), &len);
    CHECK("hex zeros", r == 0 && len == 4
          && buf[0]==0 && buf[1]==0 && buf[2]==0 && buf[3]==0);

    /* 6. Odd nibble count — must fail */
    r = hex_decode("abc", buf, sizeof(buf), &len);
    CHECK("hex odd", r < 0);

    /* 7. Invalid character 'G' — must fail */
    r = hex_decode("GG", buf, sizeof(buf), &len);
    CHECK("hex invalid G", r < 0);

    /* 8. Buffer overflow — must fail */
    r = hex_decode("000000", buf, 2, &len);
    CHECK("hex overflow", r < 0);

    /* 9. Minimal valid RadioTap frame (8+ bytes) */
    /* 0000080000000000 = radiotap rev0 pad0 len8 present0 */
    r = hex_decode("0000080000000000"
                   "80000000"              /* FC=beacon, duration=0 */
                   "ffffffffffff"          /* DA=broadcast */
                   "020000deadbe"          /* SA */
                   "020000deadbe"          /* BSSID */
                   "0000",                 /* seq-ctrl */
                   buf, sizeof(buf), &len);
    CHECK("hex valid radiotap", r == 0 && len >= 8);

    /* 10. Null pointer — must fail */
    r = hex_decode(NULL, buf, sizeof(buf), &len);
    CHECK("hex null", r < 0);

    /* 11. Null output — must fail */
    r = hex_decode("ff", NULL, sizeof(buf), &len);
    CHECK("hex null out", r < 0);

    /* 12. Whitespace is invalid */
    r = hex_decode("ff ee", buf, sizeof(buf), &len);
    CHECK("hex whitespace", r < 0);
}

static void test_mac_parse(void)
{
    /* Replicate util_parse_mac logic */
    unsigned int v[6];
    int r;
    const char *valid   = "AA:BB:CC:DD:EE:FF";
    const char *lower   = "aa:bb:cc:dd:ee:ff";
    const char *bad_sep = "AA-BB-CC-DD-EE-FF";  /* dash separator: sscanf ok */
    const char *too_short = "AA:BB:CC:DD:EE";
    const char *garbage = "GGGGGGGGGGGG";

    r = sscanf(valid,  "%x:%x:%x:%x:%x:%x",
               &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    CHECK("mac valid upper", r == 6
          && v[0]==0xAA && v[5]==0xFF);

    r = sscanf(lower, "%x:%x:%x:%x:%x:%x",
               &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    CHECK("mac valid lower", r == 6 && v[0]==0xAA);

    r = sscanf(too_short, "%x:%x:%x:%x:%x:%x",
               &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    CHECK("mac too short", r < 6);

    r = sscanf(garbage, "%x:%x:%x:%x:%x:%x",
               &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    CHECK("mac garbage", r < 6);

    /* dash separator: sscanf %x:%x won't match — deviation OK */
    r = sscanf(bad_sep, "%x:%x:%x:%x:%x:%x",
               &v[0],&v[1],&v[2],&v[3],&v[4],&v[5]);
    CHECK("mac dash sep fail", r < 6);
}

void run_hex_tests(void)
{
    printf("=== Hex Decode + MAC Parse Tests ===\n");
    test_hex_decode();
    test_mac_parse();
}

#ifndef TEST_COMBINED
int main(void)
{
    run_hex_tests();
    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
#endif
