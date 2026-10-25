/*
 * tests/test_beacon.c — Unit tests for the WIFI_SCAN beacon parser.
 *
 * Builds synthetic RadioTap + 802.11 beacon frames the way kmod-mt76 emits
 * them (flags, rate, channel, dBm antenna signal) and checks that
 * scan_parse_beacon extracts BSSID, channel, signal, SSID and the hidden
 * SSID heuristics (blanked IE with real length, and zero-length IE).
 */

#include <stdio.h>
#include <string.h>

#include "../pwn4cd.h"

static int g_passed;
static int g_failed;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

/* ── Frame builder helpers ────────────────────────────────────────────────── */

static uint8_t frame_buf[512];

static size_t build_beacon(const uint8_t *bssid, int channel,
                           const char *ssid, const uint8_t *raw_ssid,
                           uint8_t ssid_len)
{
    size_t off = 0;
    size_t i;

    /* RadioTap: rev 0, pad 0, len 16, present = FLAGS|RATE|CHANNEL|SIGNAL */
    frame_buf[off++] = 0x00;                       /* revision          */
    frame_buf[off++] = 0x00;                       /* pad               */
    frame_buf[off++] = 16;                         /* it_len lo         */
    frame_buf[off++] = 0x00;                       /* it_len hi         */
    frame_buf[off++] = 0x2e;                       /* present lo: 0b101110 */
    frame_buf[off++] = 0x00;
    frame_buf[off++] = 0x00;
    frame_buf[off++] = 0x00;
    frame_buf[off++] = 0x10;                       /* flags: FCS at end */
    frame_buf[off++] = 0x02;                       /* rate: 1 Mbps      */
    frame_buf[off++] = (uint8_t)(2437 & 0xff);     /* channel freq lo   */
    frame_buf[off++] = (uint8_t)(2437 >> 8);       /* channel freq hi   */
    frame_buf[off++] = 0x40;                       /* flags: 2.4 GHz    */
    frame_buf[off++] = 0x00;
    frame_buf[off++] = (uint8_t)(0x100 - 60);      /* signal: -60 dBm   */
    frame_buf[off++] = 0x00;                       /* padding to even   */

    /* 802.11 management header: beacon */
    frame_buf[off++] = 0x80; frame_buf[off++] = 0x00;   /* FC: beacon   */
    frame_buf[off++] = 0x00; frame_buf[off++] = 0x00;   /* duration     */
    for (i = 0; i < 6; i++) frame_buf[off++] = 0xff;    /* DA broadcast */
    for (i = 0; i < 6; i++) frame_buf[off++] = bssid[i];/* SA = BSSID   */
    for (i = 0; i < 6; i++) frame_buf[off++] = bssid[i];/* BSSID        */
    frame_buf[off++] = 0x00; frame_buf[off++] = 0x00;   /* seq ctrl     */

    /* Fixed parameters: timestamp (8) + beacon interval (2) + capab (2) */
    memset(frame_buf + off, 0, 8);              off += 8;
    frame_buf[off++] = 0x64; frame_buf[off++] = 0x00;   /* 100 TU       */
    frame_buf[off++] = 0x01; frame_buf[off++] = 0x04;   /* ESS          */

    /* Information elements */
    if (raw_ssid != NULL) {
        frame_buf[off++] = 0x00;                    /* SSID IE          */
        frame_buf[off++] = ssid_len;
        memcpy(frame_buf + off, raw_ssid, ssid_len);
        off += ssid_len;
    } else if (ssid != NULL) {
        size_t len = strlen(ssid);
        frame_buf[off++] = 0x00;
        frame_buf[off++] = (uint8_t)len;
        memcpy(frame_buf + off, ssid, len);
        off += len;
    }
    /* DS parameter set */
    frame_buf[off++] = 0x03;
    frame_buf[off++] = 0x01;
    frame_buf[off++] = (uint8_t)channel;

    return off;
}

/* ── Suites ───────────────────────────────────────────────────────────────── */

static void test_beacon_visible_ssid(void)
{
    static const uint8_t bssid[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    scan_net_t net;
    size_t len = build_beacon(bssid, 6, "Test Network 123", NULL, 0);

    CHECK("visible: parse succeeds",
          scan_parse_beacon(frame_buf, len, 1, &net) == 0);
    CHECK("visible: ssid extracted",
          strcmp(net.ssid, "Test Network 123") == 0);
    CHECK("visible: not hidden", net.hidden == false);
    CHECK("visible: ssid_len matches", net.ssid_len == 16);
    CHECK("visible: bssid extracted",
          memcmp(net.bssid, bssid, 6) == 0);
    CHECK("visible: channel from DS IE", net.channel == 6);
    CHECK("visible: signal from radiotap", net.signal_dbm == -60);
}

static void test_beacon_hidden_blank_ssid(void)
{
    static const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x02};
    uint8_t blank[8];
    scan_net_t net;
    size_t len;

    memset(blank, 0, sizeof(blank));
    len = build_beacon(bssid, 11, NULL, blank, 8);

    CHECK("hidden-blank: parse succeeds",
          scan_parse_beacon(frame_buf, len, 1, &net) == 0);
    CHECK("hidden-blank: flagged hidden", net.hidden == true);
    CHECK("hidden-blank: length preserved", net.ssid_len == 8);
    CHECK("hidden-blank: ssid empty", net.ssid[0] == '\0');
    CHECK("hidden-blank: channel from DS IE", net.channel == 11);
}

static void test_beacon_hidden_zero_len(void)
{
    static const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x03};
    scan_net_t net;
    size_t len = build_beacon(bssid, 1, NULL, NULL, 0);

    CHECK("hidden-zero: parse succeeds",
          scan_parse_beacon(frame_buf, len, 1, &net) == 0);
    CHECK("hidden-zero: flagged hidden", net.hidden == true);
    CHECK("hidden-zero: length unknown", net.ssid_len == 0);
}

static void test_beacon_rejects(void)
{
    static const uint8_t bssid[6] = {0x02, 0x00, 0x00, 0xde, 0xad, 0x01};
    scan_net_t net;
    size_t len;

    /* Non-management frame: FC = data (type 2) */
    len = build_beacon(bssid, 6, "x", NULL, 0);
    frame_buf[16] = 0x08;   /* was 0x80 (beacon) — now data frame */
    frame_buf[17] = 0x41;
    CHECK("reject: data frame",
          scan_parse_beacon(frame_buf, len, 1, &net) != 0);

    /* Broadcast BSSID (malformed) */
    {
        static const uint8_t bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        len = build_beacon(bcast, 6, "x", NULL, 0);
        CHECK("reject: broadcast BSSID",
              scan_parse_beacon(frame_buf, len, 1, &net) != 0);
    }

    /* Truncated frame */
    len = build_beacon(bssid, 6, "visible", NULL, 0);
    CHECK("reject: truncated frame",
          scan_parse_beacon(frame_buf, 20, 1, &net) != 0);
}

int run_beacon_tests(void)
{
    printf("── beacon parser (beacon_parse.c)──────────────\n");
    g_passed = 0;
    g_failed = 0;

    test_beacon_visible_ssid();
    test_beacon_hidden_blank_ssid();
    test_beacon_hidden_zero_len();
    test_beacon_rejects();

    printf("  (%d passed, %d failed)\n", g_passed, g_failed);
    return g_failed;
}
