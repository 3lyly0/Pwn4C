/*
 * tests/test_eapol.c — Unit tests for the EAPOL-Key parser and harvest table.
 *
 * Builds synthetic RadioTap + 802.11 frames the way a monitor-mode capture
 * delivers them, then checks:
 *   - M1/M2/M3/M4 classification and field extraction
 *   - PMKID KDE extraction from M1 key data
 *   - rejection of beacons, group-key messages and truncated frames
 *   - the bounded (BSSID, STA) table: completion, SSID learning, paging
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

/* ── Frame builders ───────────────────────────────────────────────────────── */

static uint8_t frame_buf[512];

static size_t put_radiotap(uint8_t *out)
{
    /* rev 0, pad 0, len 8, present bitmap 0 (no fields) */
    out[0] = 0x00; out[1] = 0x00; out[2] = 0x08; out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x00; out[6] = 0x00; out[7] = 0x00;
    return 8;
}

static size_t build_beacon(uint8_t *out, const uint8_t *bssid,
                           const char *ssid)
{
    size_t n = put_radiotap(out);
    size_t len = strlen(ssid);
    size_t i;

    out[n++] = 0x80; out[n++] = 0x00;              /* beacon            */
    out[n++] = 0x00; out[n++] = 0x00;              /* duration          */
    for (i = 0; i < 6; i++) { out[n++] = 0xff; }   /* DA broadcast      */
    for (i = 0; i < 6; i++) { out[n++] = bssid[i]; }
    for (i = 0; i < 6; i++) { out[n++] = bssid[i]; }
    out[n++] = 0x00; out[n++] = 0x00;              /* sequence control  */

    memset(out + n, 0, 8); n += 8;                 /* timestamp         */
    out[n++] = 0x64; out[n++] = 0x00;              /* interval          */
    out[n++] = 0x01; out[n++] = 0x04;              /* capability        */

    out[n++] = 0x00; out[n++] = (uint8_t)len;      /* SSID IE           */
    memcpy(out + n, ssid, len); n += len;

    out[n++] = 0x03; out[n++] = 0x01; out[n++] = 0x06;  /* DS: ch 6     */
    return n;
}

static size_t build_eapol(uint8_t *out, const uint8_t *bssid,
                          const uint8_t *sta, bool from_ap,
                          uint16_t key_info, uint8_t nonce_byte,
                          bool with_pmkid)
{
    const size_t kd_len   = with_pmkid ? 22u : 0u;
    const size_t body_len = 95u + kd_len;
    size_t n = put_radiotap(out);
    size_t i;

    out[n++] = 0x08;                               /* data              */
    out[n++] = from_ap ? 0x02 : 0x01;              /* FromDS / ToDS     */
    out[n++] = 0x00; out[n++] = 0x00;

    if (from_ap) {
        memcpy(out + n, sta, 6);   n += 6;
        memcpy(out + n, bssid, 6); n += 6;
    } else {
        memcpy(out + n, bssid, 6); n += 6;
        memcpy(out + n, sta, 6);   n += 6;
    }
    memcpy(out + n, bssid, 6); n += 6;
    out[n++] = 0x20; out[n++] = 0x00;

    out[n++] = 0xaa; out[n++] = 0xaa; out[n++] = 0x03;
    out[n++] = 0x00; out[n++] = 0x00; out[n++] = 0x00;
    out[n++] = 0x88; out[n++] = 0x8e;

    out[n++] = 0x02;
    out[n++] = 0x03;
    out[n++] = (uint8_t)(body_len >> 8);
    out[n++] = (uint8_t)(body_len & 0xffu);

    out[n++] = 0x02;
    out[n++] = (uint8_t)(key_info >> 8);
    out[n++] = (uint8_t)(key_info & 0xffu);
    out[n++] = 0x00; out[n++] = 0x10;

    for (i = 0; i < 7; i++) { out[n++] = 0x00; }
    out[n++] = 0x01;                               /* replay counter    */

    for (i = 0; i < 32; i++) { out[n++] = nonce_byte; }
    for (i = 0; i < 16; i++) { out[n++] = 0x00; }  /* IV                */
    for (i = 0; i < 8; i++)  { out[n++] = 0x00; }  /* RSC               */
    for (i = 0; i < 8; i++)  { out[n++] = 0x00; }  /* key id            */
    for (i = 0; i < 16; i++) {                     /* MIC               */
        out[n++] = from_ap ? 0x00 : 0x11;
    }

    out[n++] = (uint8_t)(kd_len >> 8);
    out[n++] = (uint8_t)(kd_len & 0xffu);

    if (with_pmkid) {
        out[n++] = 0xdd; out[n++] = 0x14;
        out[n++] = 0x00; out[n++] = 0x0f;
        out[n++] = 0xac; out[n++] = 0x04;
        for (i = 0; i < 16; i++) { out[n++] = 0x5a; }
    }

    return n;
}

/* ── Fixtures ─────────────────────────────────────────────────────────────── */

static const uint8_t BSSID[6] = { 0x02, 0x11, 0x22, 0x33, 0x44, 0x55 };
static const uint8_t STA[6]   = { 0x02, 0xaa, 0xbb, 0xcc, 0xdd, 0xee };

/* ── Parser tests ─────────────────────────────────────────────────────────── */

static void test_message_classification(void)
{
    eapol_msg_t m;
    size_t      n;

    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, false);
    CHECK("M1 parsed", eapol_parse_frame(frame_buf, n, &m) == 0);
    CHECK("M1 number", m.msg == 1u);
    CHECK("M1 key_info", m.key_info == 0x008a);
    CHECK("M1 anonce", m.nonce[0] == 0xa1 && m.nonce[31] == 0xa1);
    CHECK("M1 eapol_len", m.eapol_len == 99u);
    CHECK("M1 bssid", memcmp(m.bssid, BSSID, 6) == 0);
    CHECK("M1 sta", memcmp(m.sta, STA, 6) == 0);
    CHECK("M1 has no pmkid", !m.has_pmkid);

    n = build_eapol(frame_buf, BSSID, STA, false, 0x010a, 0xb2, false);
    CHECK("M2 parsed", eapol_parse_frame(frame_buf, n, &m) == 0);
    CHECK("M2 number", m.msg == 2u);
    CHECK("M2 snonce", m.nonce[0] == 0xb2 && m.nonce[31] == 0xb2);
    CHECK("M2 mic", m.mic[0] == 0x11 && m.mic[15] == 0x11);

    n = build_eapol(frame_buf, BSSID, STA, true, 0x13ca, 0xc3, false);
    CHECK("M3 parsed", eapol_parse_frame(frame_buf, n, &m) == 0 && m.msg == 3u);

    n = build_eapol(frame_buf, BSSID, STA, false, 0x030a, 0xd4, false);
    CHECK("M4 parsed", eapol_parse_frame(frame_buf, n, &m) == 0 && m.msg == 4u);
}

static void test_pmkid_kde(void)
{
    eapol_msg_t m;
    size_t      n;

    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, true);
    CHECK("M1 with PMKID parsed", eapol_parse_frame(frame_buf, n, &m) == 0);
    CHECK("M1 pmkid flag", m.has_pmkid);
    CHECK("M1 pmkid bytes", m.pmkid[0] == 0x5a && m.pmkid[15] == 0x5a);
    CHECK("M1 pmkid eapol_len", m.eapol_len == 99u + 22u);
}

static void test_rejections(void)
{
    eapol_msg_t m;
    size_t      n;

    n = build_beacon(frame_buf, BSSID, "reject-me");
    CHECK("beacon rejected", eapol_parse_frame(frame_buf, n, &m) < 0);

    /* Group-key message: pairwise bit clear. */
    n = build_eapol(frame_buf, BSSID, STA, true, 0x0182, 0xa1, false);
    CHECK("group-key rejected", eapol_parse_frame(frame_buf, n, &m) < 0);

    /* Truncated EAPOL body: header claims more than the capture holds. */
    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, false);
    frame_buf[8 + 24 + 8 + 2] = 0x40;   /* body length 0x4000 */
    frame_buf[8 + 24 + 8 + 3] = 0x00;
    CHECK("truncated rejected", eapol_parse_frame(frame_buf, n, &m) < 0);

    CHECK("null frame rejected", eapol_parse_frame(NULL, 0, &m) < 0);
}

/* ── Table tests ──────────────────────────────────────────────────────────── */

static void test_pair_completion(void)
{
    const char *json;
    int         total = -1;
    size_t      n;

    hs_reset();

    n = build_beacon(frame_buf, BSSID, "test-ssid");
    hs_observe(NULL, frame_buf, n);
    CHECK("beacon alone is not ready", hs_ready_count() == 0);

    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, false);
    hs_observe(NULL, frame_buf, n);
    CHECK("M1 alone is not ready", hs_ready_count() == 0);

    n = build_eapol(frame_buf, BSSID, STA, false, 0x010a, 0xb2, false);
    hs_observe(NULL, frame_buf, n);
    CHECK("M1+M2 completes a pair", hs_ready_count() == 1);

    json = hs_report(0, false, &total);
    CHECK("report count", total == 1);
    CHECK("report is JSON", json != NULL && json[0] == '{');
    CHECK("report has bssid", strstr(json, "\"bssid\":\"02:11:22:33:44:55\"") != NULL);
    CHECK("report has sta", strstr(json, "\"sta\":\"02:AA:BB:CC:DD:EE\"") != NULL);
    CHECK("report has learned ssid", strstr(json, "\"ssid\":\"test-ssid\"") != NULL);
    CHECK("report has ssid hex",
          strstr(json, "\"ssid_hex\":\"746573742d73736964\"") != NULL);
    CHECK("report message_pair 0", strstr(json, "\"message_pair\":0") != NULL);
    CHECK("report has anonce", strstr(json, "\"anonce\":\"a1a1") != NULL);
    CHECK("report has eapol", strstr(json, "\"eapol_len\":99") != NULL);
    CHECK("report not truncated", strstr(json, "\"truncated\":false") != NULL);
}

static void test_pmkid_only(void)
{
    const char *json;
    int         total = -1;
    size_t      n;

    hs_reset();

    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, true);
    hs_observe(NULL, frame_buf, n);
    CHECK("PMKID alone is ready", hs_ready_count() == 1);

    json = hs_report(0, false, &total);
    CHECK("PMKID report count", total == 1);
    CHECK("PMKID report has pmkid", strstr(json, "\"pmkid\":\"5a5a") != NULL);
    CHECK("PMKID-only message_pair is -1",
          strstr(json, "\"message_pair\":-1") != NULL);
}

static void test_paging(void)
{
    const char *json;
    int         total = -1;
    size_t      i;
    uint8_t     sta[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t      n;

    hs_reset();

    for (i = 0; i < 7u; i++) {
        sta[5] = (uint8_t)(i + 1u);
        n = build_eapol(frame_buf, BSSID, sta, true, 0x008a, 0xa1, false);
        hs_observe(NULL, frame_buf, n);
        n = build_eapol(frame_buf, BSSID, sta, false, 0x010a, 0xb2, false);
        hs_observe(NULL, frame_buf, n);
    }

    CHECK("seven pairs tracked", hs_ready_count() == 7);

    json = hs_report(0, false, &total);
    CHECK("page 1 count", total == 7);
    CHECK("page 1 returned 6", strstr(json, "\"returned\":6") != NULL);
    CHECK("page 1 truncated", strstr(json, "\"truncated\":true") != NULL);

    json = hs_report(6, false, &total);
    CHECK("page 2 count", total == 7);
    CHECK("page 2 returned 1", strstr(json, "\"returned\":1") != NULL);
    CHECK("page 2 not truncated", strstr(json, "\"truncated\":false") != NULL);

    json = hs_report(0, true, &total);
    CHECK("reset clears the table", total == 0 && hs_ready_count() == 0);
}

static void test_prefer_m1_and_m2(void)
{
    const char *json;
    size_t      n;

    hs_reset();

    /* M3 first, then M1: the table must keep M1's ANonce. */
    n = build_eapol(frame_buf, BSSID, STA, true, 0x13ca, 0xc3, false);
    hs_observe(NULL, frame_buf, n);
    n = build_eapol(frame_buf, BSSID, STA, true, 0x008a, 0xa1, false);
    hs_observe(NULL, frame_buf, n);

    /* M4 first, then M2: the table must keep M2's SNonce. */
    n = build_eapol(frame_buf, BSSID, STA, false, 0x030a, 0xd4, false);
    hs_observe(NULL, frame_buf, n);
    n = build_eapol(frame_buf, BSSID, STA, false, 0x010a, 0xb2, false);
    hs_observe(NULL, frame_buf, n);

    json = hs_report(0, false, NULL);
    CHECK("M1 preferred over M3", strstr(json, "\"anonce\":\"a1a1") != NULL);
    CHECK("M2 preferred over M4", strstr(json, "\"message_pair\":0") != NULL);
}

/* ── Suite entry point ────────────────────────────────────────────────────── */

int run_eapol_tests(void)
{
    g_passed = 0;
    g_failed = 0;

    printf("── EAPOL-Key parser ──────────────────────────\n");
    test_message_classification();
    test_pmkid_kde();
    test_rejections();

    printf("── Harvest table ─────────────────────────────\n");
    test_pair_completion();
    test_pmkid_only();
    test_paging();
    test_prefer_m1_and_m2();

    hs_reset();

    printf("  %d passed, %d failed\n", g_passed, g_failed);
    return g_failed;
}
