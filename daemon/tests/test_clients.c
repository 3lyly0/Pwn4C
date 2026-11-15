/*
 * tests/test_clients.c — Unit tests for the station parser and inventory.
 *
 * Builds synthetic RadioTap + 802.11 frames the way a monitor-mode capture
 * delivers them, then checks:
 *   - probe/assoc/data/deauth classification and address extraction
 *   - SSID (PNL) extraction, including wildcard probes
 *   - rejection of beacons, control frames and group source addresses
 *   - the bounded inventory: association state, paging, eviction, reset
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

static const uint8_t BSSID[6] = { 0x02, 0x00, 0x00, 0xde, 0xad, 0x01 };
static const uint8_t STA[6]   = { 0x02, 0x00, 0x00, 0xbe, 0xef, 0x02 };
static const uint8_t BC[6]    = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

static uint8_t frame_buf[512];

/* ── Frame builders ───────────────────────────────────────────────────────── */

static size_t put_radiotap(uint8_t *out)
{
    /* rev 0, pad 0, len 8, present bitmap 0 (no fields) */
    out[0] = 0x00; out[1] = 0x00; out[2] = 0x08; out[3] = 0x00;
    out[4] = 0x00; out[5] = 0x00; out[6] = 0x00; out[7] = 0x00;
    return 8;
}

static size_t put_radiotap_signal(uint8_t *out, int8_t dbm)
{
    /* rev 0, pad 0, len 9, present bit 5 (antenna signal), signal byte */
    out[0] = 0x00; out[1] = 0x00; out[2] = 0x09; out[3] = 0x00;
    out[4] = 0x20; out[5] = 0x00; out[6] = 0x00; out[7] = 0x00;
    out[8] = (uint8_t)dbm;
    return 9;
}

static size_t put_hdr(uint8_t *out, uint8_t fc0, uint8_t fc1,
                      const uint8_t *a1, const uint8_t *a2, const uint8_t *a3)
{
    size_t n = 0;

    out[n++] = fc0; out[n++] = fc1;
    out[n++] = 0x00; out[n++] = 0x00;      /* duration */
    memcpy(out + n, a1, 6); n += 6;
    memcpy(out + n, a2, 6); n += 6;
    memcpy(out + n, a3, 6); n += 6;
    out[n++] = 0x00; out[n++] = 0x00;      /* sequence control */
    return n;
}

static size_t build_probe(uint8_t *out, const uint8_t *sta, const char *ssid)
{
    size_t n = put_radiotap(out);
    size_t len = strlen(ssid);

    n += put_hdr(out + n, 0x40, 0x00, BC, sta, BC);
    out[n++] = 0x00; out[n++] = (uint8_t)len;
    memcpy(out + n, ssid, len);
    return n + len;
}

static size_t build_assoc(uint8_t *out, const uint8_t *bssid,
                          const uint8_t *sta, const char *ssid, bool reassoc)
{
    size_t n = put_radiotap(out);
    size_t len = strlen(ssid);
    size_t i;

    n += put_hdr(out + n, reassoc ? 0x20 : 0x00, 0x00, bssid, sta, bssid);
    out[n++] = 0x31; out[n++] = 0x04;      /* capability     */
    out[n++] = 0x0a; out[n++] = 0x00;      /* listen interval */
    if (reassoc) {
        for (i = 0; i < 6; i++) { out[n++] = BSSID[i]; }  /* current AP */
    }
    out[n++] = 0x00; out[n++] = (uint8_t)len;
    memcpy(out + n, ssid, len);
    return n + len;
}

static size_t build_data(uint8_t *out, const uint8_t *bssid,
                         const uint8_t *sta, bool from_ap)
{
    size_t n = put_radiotap(out);

    if (from_ap) {
        n += put_hdr(out + n, 0x08, 0x02, sta, bssid, bssid);
    } else {
        n += put_hdr(out + n, 0x08, 0x01, bssid, sta, bssid);
    }
    return n;
}

static size_t build_deauth(uint8_t *out, const uint8_t *bssid,
                           const uint8_t *sta)
{
    size_t n = put_radiotap(out);

    n += put_hdr(out + n, 0xc0, 0x00, sta, bssid, bssid);
    out[n++] = 0x07; out[n++] = 0x00;      /* reason */
    return n;
}

/* ── Parser tests ─────────────────────────────────────────────────────────── */

static void test_probe_request(void)
{
    client_frame_t cf;
    size_t n = build_probe(frame_buf, STA, "mock-lab");

    CHECK("probe parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("probe is flagged", cf.probe);
    CHECK("probe STA", memcmp(cf.sta, STA, 6) == 0);
    CHECK("probe has no BSSID", !cf.has_bssid);
    CHECK("probe SSID", cf.has_ssid && cf.ssid_len == 8 &&
          memcmp(cf.ssid, "mock-lab", 8) == 0);
}

static void test_wildcard_probe(void)
{
    client_frame_t cf;
    size_t n = build_probe(frame_buf, STA, "");

    CHECK("wildcard probe parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("wildcard probe flagged", cf.probe);
    CHECK("wildcard probe SSID is empty", cf.has_ssid && cf.ssid_len == 0);
}

static void test_assoc_and_reassoc(void)
{
    client_frame_t cf;
    size_t n = build_assoc(frame_buf, BSSID, STA, "mock-lab", false);

    CHECK("assoc parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("assoc flagged", cf.assoc && !cf.probe && !cf.data);
    CHECK("assoc STA", memcmp(cf.sta, STA, 6) == 0);
    CHECK("assoc BSSID", cf.has_bssid && memcmp(cf.bssid, BSSID, 6) == 0);
    CHECK("assoc SSID", cf.has_ssid && cf.ssid_len == 8 &&
          memcmp(cf.ssid, "mock-lab", 8) == 0);

    n = build_assoc(frame_buf, BSSID, STA, "mock-lab", true);
    CHECK("reassoc parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("reassoc SSID skips the current-AP field",
          cf.has_ssid && cf.ssid_len == 8);
}

static void test_data_frames(void)
{
    client_frame_t cf;
    size_t n = build_data(frame_buf, BSSID, STA, false);

    CHECK("ToDS data parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("ToDS data flagged", cf.data);
    CHECK("ToDS STA", memcmp(cf.sta, STA, 6) == 0);
    CHECK("ToDS BSSID", memcmp(cf.bssid, BSSID, 6) == 0);

    n = build_data(frame_buf, BSSID, STA, true);
    CHECK("FromDS data parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("FromDS STA", memcmp(cf.sta, STA, 6) == 0);
    CHECK("FromDS BSSID", memcmp(cf.bssid, BSSID, 6) == 0);
}

static void test_deauth(void)
{
    client_frame_t cf;
    size_t n = build_deauth(frame_buf, BSSID, STA);

    CHECK("deauth parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("deauth flagged as leaving", cf.left && !cf.data);
    CHECK("deauth STA is Addr1", memcmp(cf.sta, STA, 6) == 0);
    CHECK("deauth BSSID", memcmp(cf.bssid, BSSID, 6) == 0);
}

static void test_signal(void)
{
    client_frame_t cf;
    size_t n;

    n = put_radiotap_signal(frame_buf, -42);
    n += put_hdr(frame_buf + n, 0x40, 0x00, BC, STA, BC);

    CHECK("signal parses", client_parse_frame(frame_buf, n, &cf) == 0);
    CHECK("signal present", cf.has_signal);
    CHECK("signal value", cf.signal_dbm == -42);
}

static void test_rejections(void)
{
    client_frame_t cf;
    size_t n;
    uint8_t zero[6] = { 0 };
    uint8_t group[6] = { 0x01, 0x00, 0x5e, 0x00, 0x00, 0x01 };

    /* Beacon: not a station observation. */
    n = put_radiotap(frame_buf);
    n += put_hdr(frame_buf + n, 0x80, 0x00, BC, BSSID, BSSID);
    CHECK("beacon rejected", client_parse_frame(frame_buf, n, &cf) < 0);

    /* ACK: control frame. */
    n = put_radiotap(frame_buf);
    frame_buf[n++] = 0xd4; frame_buf[n++] = 0x00;
    CHECK("ACK rejected", client_parse_frame(frame_buf, n, &cf) < 0);

    /* Probe from a group address. */
    n = build_probe(frame_buf, group, "x");
    CHECK("group STA rejected", client_parse_frame(frame_buf, n, &cf) < 0);

    /* Probe from the zero address. */
    n = build_probe(frame_buf, zero, "x");
    CHECK("zero STA rejected", client_parse_frame(frame_buf, n, &cf) < 0);

    /* Truncated header. */
    CHECK("short frame rejected", client_parse_frame(frame_buf, 10, &cf) < 0);
    CHECK("null frame rejected", client_parse_frame(NULL, 0, &cf) < 0);
}

/* ── Inventory tests ──────────────────────────────────────────────────────── */

static void test_inventory(void)
{
    const char *json;
    int         total = -1;
    size_t      n;

    cl_reset();

    n = build_probe(frame_buf, STA, "mock-lab");
    cl_observe(NULL, frame_buf, n);
    n = build_assoc(frame_buf, BSSID, STA, "mock-lab", false);
    cl_observe(NULL, frame_buf, n);
    n = build_data(frame_buf, BSSID, STA, false);
    cl_observe(NULL, frame_buf, n);

    CHECK("one station tracked", cl_tracked_count() == 1);

    json = cl_report(0, false, &total);
    CHECK("report count", total == 1);
    CHECK("report has STA", strstr(json, "\"sta\":\"02:00:00:BE:EF:02\"") != NULL);
    CHECK("report has BSSID", strstr(json, "\"bssid\":\"02:00:00:DE:AD:01\"") != NULL);
    CHECK("report is associated", strstr(json, "\"associated\":true") != NULL);
    CHECK("report probed", strstr(json, "\"probed\":true") != NULL);
    CHECK("report SSID", strstr(json, "\"ssid\":\"mock-lab\"") != NULL);
    CHECK("report SSID hex", strstr(json, "\"ssid_hex\":\"6d6f636b2d6c6162\"") != NULL);
    CHECK("report counts three frames", strstr(json, "\"frames\":3") != NULL);
    CHECK("report has no RSSI", strstr(json, "\"has_rssi\":false") != NULL);

    /* A deauth clears the association but keeps the station. */
    n = build_deauth(frame_buf, BSSID, STA);
    cl_observe(NULL, frame_buf, n);
    json = cl_report(0, false, &total);
    CHECK("deauth clears association", strstr(json, "\"associated\":false") != NULL);
    CHECK("deauth keeps the station", total == 1);
}

static void test_paging_and_reset(void)
{
    const char *json;
    int         total = -1;
    uint8_t     sta[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t      i;
    size_t      n;

    cl_reset();

    for (i = 0; i < 7u; i++) {
        sta[5] = (uint8_t)(i + 1u);
        n = build_probe(frame_buf, sta, "paged");
        cl_observe(NULL, frame_buf, n);
    }

    CHECK("seven stations tracked", cl_tracked_count() == 7);

    json = cl_report(0, false, &total);
    CHECK("page 1 count", total == 7);
    CHECK("page 1 returned 6", strstr(json, "\"returned\":6") != NULL);
    CHECK("page 1 truncated", strstr(json, "\"truncated\":true") != NULL);

    json = cl_report(6, false, &total);
    CHECK("page 2 returned 1", strstr(json, "\"returned\":1") != NULL);
    CHECK("page 2 not truncated", strstr(json, "\"truncated\":false") != NULL);

    json = cl_report(0, true, &total);
    CHECK("reset clears the table", total == 0 && cl_tracked_count() == 0);
}

static void test_eviction(void)
{
    uint8_t sta[6] = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00 };
    size_t  i;
    size_t  n;

    cl_reset();

    /* One more station than the table holds: the oldest must be evicted. */
    for (i = 0; i < CL_MAX_CLIENTS + 1u; i++) {
        sta[5] = (uint8_t)(i + 1u);
        n = build_probe(frame_buf, sta, "flood");
        cl_observe(NULL, frame_buf, n);
    }

    CHECK("table stays bounded", cl_tracked_count() == (int)CL_MAX_CLIENTS);

    sta[5] = 1;   /* the first station we fed */
    n = build_data(frame_buf, BSSID, sta, false);
    cl_observe(NULL, frame_buf, n);
    CHECK("evicted station is re-added", cl_tracked_count() == (int)CL_MAX_CLIENTS);
}

/* ── Suite entry point ────────────────────────────────────────────────────── */

int run_clients_tests(void)
{
    g_passed = 0;
    g_failed = 0;

    printf("── Station parser ────────────────────────────\n");
    test_probe_request();
    test_wildcard_probe();
    test_assoc_and_reassoc();
    test_data_frames();
    test_deauth();
    test_signal();
    test_rejections();

    printf("── Client inventory ──────────────────────────\n");
    test_inventory();
    test_paging_and_reset();
    test_eviction();

    cl_reset();

    printf("  %d passed, %d failed\n", g_passed, g_failed);
    return g_failed;
}
