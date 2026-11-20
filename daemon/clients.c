/*
 * clients.c — Bounded station inventory feeding `pwn4c clients`.
 *
 * Fed by capture_read_frame() with every captured frame. Keeps at most
 * CL_MAX_CLIENTS station slots: the BSSID each station is talking to, the
 * last RSSI the radio reported, the SSID it probed for (its PNL entry), and
 * first/last-seen timestamps. Reports facts only; the host decides what to do
 * with them (target a kick, list a PNL, aim CSA at one client).
 *
 * Zero allocation. All state is static and bounded, so the daemon's RSS does
 * not depend on how long a capture runs or how many stations fly past.
 */

#include "pwn4cd.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define CL_REPORT_BUF  8192u
#define CL_ENTRY_MAX   384u    /* worst-case serialised entry, with slack */

typedef struct {
    bool     used;
    uint8_t  sta[6];

    uint8_t  bssid[6];
    bool     has_bssid;
    bool     associated;

    bool     probed;
    bool     has_ssid;
    uint8_t  ssid[CL_SSID_MAX];
    uint8_t  ssid_len;

    int      signal_dbm;
    bool     has_signal;

    uint32_t frames;
    int64_t  first_ms;
    int64_t  last_ms;
} cl_slot_t;

static cl_slot_t s_slots[CL_MAX_CLIENTS];
static char      s_report[CL_REPORT_BUF];
static bool      s_mock_done;

/* ── Table management ─────────────────────────────────────────────────────── */

void cl_reset(void)
{
    memset(s_slots, 0, sizeof(s_slots));
    s_mock_done = false;
}

int cl_tracked_count(void)
{
    size_t i;
    int    n = 0;

    for (i = 0; i < CL_MAX_CLIENTS; i++) {
        if (s_slots[i].used) { n++; }
    }
    return n;
}

/*
 * cl_slot_for — Return the slot for a station, allocating one when needed.
 * A full table evicts the station that has been quiet the longest: a busy
 * capture should not forget the client it just saw.
 */
static cl_slot_t *cl_slot_for(const uint8_t sta[6])
{
    size_t i;
    size_t free_slot = CL_MAX_CLIENTS;
    size_t victim    = 0;

    for (i = 0; i < CL_MAX_CLIENTS; i++) {
        if (s_slots[i].used && memcmp(s_slots[i].sta, sta, 6) == 0) {
            return &s_slots[i];
        }
        if (!s_slots[i].used && free_slot == CL_MAX_CLIENTS) {
            free_slot = i;
        }
    }

    if (free_slot == CL_MAX_CLIENTS) {
        for (i = 1; i < CL_MAX_CLIENTS; i++) {
            if (s_slots[i].last_ms < s_slots[victim].last_ms) { victim = i; }
        }
        free_slot = victim;
        memset(&s_slots[free_slot], 0, sizeof(s_slots[free_slot]));
    }

    s_slots[free_slot].used     = true;
    s_slots[free_slot].first_ms = util_monotonic_ms();
    s_slots[free_slot].last_ms  = s_slots[free_slot].first_ms;
    memcpy(s_slots[free_slot].sta, sta, 6);
    return &s_slots[free_slot];
}

/* ── Frame intake ─────────────────────────────────────────────────────────── */

void cl_observe(daemon_t *d, const uint8_t *frame, size_t len)
{
    client_frame_t cf;
    cl_slot_t     *slot;

    (void)d;

    if (client_parse_frame(frame, len, &cf) < 0) { return; }

    slot = cl_slot_for(cf.sta);
    slot->last_ms = util_monotonic_ms();
    if (slot->frames < UINT32_MAX) { slot->frames++; }

    if (cf.has_signal) {
        slot->signal_dbm = cf.signal_dbm;
        slot->has_signal = true;
    }

    if (cf.has_bssid) {
        memcpy(slot->bssid, cf.bssid, 6);
        slot->has_bssid = true;
    }

    /* Association is sticky: a probe request does not clear it, only an
     * explicit deauth/disassoc (or a different AP) changes the picture. */
    if (cf.assoc || cf.data) { slot->associated = true; }
    if (cf.left)             { slot->associated = false; }

    if (cf.probe) {
        slot->probed = true;
        if (cf.has_ssid && cf.ssid_len > 0) {
            memcpy(slot->ssid, cf.ssid, cf.ssid_len);
            slot->ssid_len = cf.ssid_len;
            slot->has_ssid = true;
        }
    }
}

/* ── JSON serialisation ───────────────────────────────────────────────────── */

static void cl_hex(const uint8_t *data, size_t len, char *out)
{
    static const char HEX[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2]     = HEX[(data[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = HEX[data[i] & 0x0fu];
    }
    out[len * 2] = '\0';
}

static bool cl_append(char *out, size_t out_sz, size_t *used,
                      const char *fmt, ...)
{
    va_list ap;
    int     n;

    if (*used >= out_sz) { return false; }

    va_start(ap, fmt);
    n = vsnprintf(out + *used, out_sz - *used, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= out_sz - *used) {
        *used = out_sz;
        return false;
    }
    *used += (size_t)n;
    return true;
}

const char *cl_report(int offset, bool reset, int *total_out)
{
    size_t order[CL_MAX_CLIENTS];
    size_t n = 0;
    size_t tracked = 0;
    size_t start;
    size_t end;
    size_t i;
    size_t j;
    size_t used = 0;
    int64_t now;

    if (reset) { cl_reset(); }

    /* Oldest first, so paging from the end yields the freshest station. */
    for (i = 0; i < CL_MAX_CLIENTS; i++) {
        if (!s_slots[i].used) { continue; }
        tracked++;

        j = n;
        while (j > 0 && s_slots[order[j - 1]].last_ms > s_slots[i].last_ms) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = i;
        n++;
    }

    if (total_out) { *total_out = (int)n; }

    start = (offset > 0) ? (size_t)offset : 0;
    if (start > n) { start = n; }
    end = start + CL_JSON_PAGE;
    if (end > n) { end = n; }

    (void)cl_append(s_report, sizeof(s_report), &used,
        "{\"count\":%lu,\"tracked\":%lu,\"offset\":%lu,\"returned\":%lu,"
        "\"truncated\":%s,\"clients\":[",
        (unsigned long)n, (unsigned long)tracked, (unsigned long)start,
        (unsigned long)(end - start), (end < n) ? "true" : "false");

    now = util_monotonic_ms();

    for (i = start; i < end; i++) {
        const cl_slot_t *c = &s_slots[order[n - 1 - i]];
        char sta_s[18];
        char bssid_s[18];
        char ssid_esc[CL_SSID_MAX * 2 + 1];
        char ssid_hex[CL_SSID_MAX * 2 + 1];
        int64_t age = now - c->last_ms;

        if (used + CL_ENTRY_MAX > sizeof(s_report)) { break; }
        if (age < 0) { age = 0; }

        util_mac_to_str(c->sta, sta_s, sizeof(sta_s));
        bssid_s[0] = '\0';
        if (c->has_bssid) {
            util_mac_to_str(c->bssid, bssid_s, sizeof(bssid_s));
        }

        /* SSIDs are arbitrary bytes: send the printable and hex forms, the
         * same way the handshake report does. */
        ssid_esc[0] = '\0';
        ssid_hex[0] = '\0';
        if (c->has_ssid) {
            char raw[CL_SSID_MAX + 1];

            memcpy(raw, c->ssid, c->ssid_len);
            raw[c->ssid_len] = '\0';
            util_json_escape(raw, ssid_esc, sizeof(ssid_esc));
            cl_hex(c->ssid, c->ssid_len, ssid_hex);
        }

        (void)cl_append(s_report, sizeof(s_report), &used,
            "%s{\"sta\":\"%s\",\"bssid\":\"%s\",\"associated\":%s,"
            "\"probed\":%s,\"ssid\":\"%s\",\"ssid_len\":%u,\"ssid_hex\":\"%s\","
            "\"rssi\":%d,\"has_rssi\":%s,\"frames\":%lu,\"age_ms\":%ld}",
            (i == start) ? "" : ",",
            sta_s, bssid_s,
            c->associated ? "true" : "false",
            c->probed ? "true" : "false",
            ssid_esc, (unsigned)c->ssid_len, ssid_hex,
            c->signal_dbm, c->has_signal ? "true" : "false",
            (unsigned long)c->frames, (long)age);
    }

    (void)cl_append(s_report, sizeof(s_report), &used, "]}");

    return s_report;
}

/* ── Mock mode ────────────────────────────────────────────────────────────── */

/* Minimal radiotap header: no present fields, 8-byte length. */
static const uint8_t CL_RT[8] = { 0x00, 0x00, 0x08, 0x00,
                                  0x00, 0x00, 0x00, 0x00 };

static size_t cl_put_radiotap(uint8_t *out)
{
    memcpy(out, CL_RT, sizeof(CL_RT));
    return sizeof(CL_RT);
}

static size_t cl_build_probe(uint8_t *out, size_t cap,
                             const uint8_t sta[6], const char *ssid)
{
    size_t ssid_len = strlen(ssid);
    size_t n;
    size_t i;

    if (cap < 8u + 24u + 2u + ssid_len) { return 0; }

    n = cl_put_radiotap(out);
    out[n++] = 0x40; out[n++] = 0x00;              /* probe request      */
    out[n++] = 0x00; out[n++] = 0x00;              /* duration           */
    for (i = 0; i < 6; i++) { out[n++] = 0xff; }   /* DA broadcast       */
    memcpy(out + n, sta, 6); n += 6;               /* SA                 */
    for (i = 0; i < 6; i++) { out[n++] = 0xff; }   /* BSSID: wildcard    */
    out[n++] = 0x10; out[n++] = 0x00;              /* sequence control   */

    out[n++] = 0x00; out[n++] = (uint8_t)ssid_len; /* SSID IE            */
    memcpy(out + n, ssid, ssid_len);
    n += ssid_len;

    return n;
}

static size_t cl_build_assoc(uint8_t *out, size_t cap,
                             const uint8_t bssid[6], const uint8_t sta[6],
                             const char *ssid)
{
    size_t ssid_len = strlen(ssid);
    size_t n;

    if (cap < 8u + 24u + 4u + 2u + ssid_len) { return 0; }

    n = cl_put_radiotap(out);
    out[n++] = 0x00; out[n++] = 0x00;              /* association request */
    out[n++] = 0x00; out[n++] = 0x00;
    memcpy(out + n, bssid, 6); n += 6;             /* Addr1 = AP          */
    memcpy(out + n, sta, 6);   n += 6;             /* Addr2 = STA         */
    memcpy(out + n, bssid, 6); n += 6;             /* Addr3 = BSSID       */
    out[n++] = 0x20; out[n++] = 0x00;              /* sequence control    */

    out[n++] = 0x31; out[n++] = 0x04;              /* capability          */
    out[n++] = 0x0a; out[n++] = 0x00;              /* listen interval     */

    out[n++] = 0x00; out[n++] = (uint8_t)ssid_len; /* SSID IE             */
    memcpy(out + n, ssid, ssid_len);
    n += ssid_len;

    return n;
}

static size_t cl_build_data(uint8_t *out, size_t cap,
                            const uint8_t bssid[6], const uint8_t sta[6])
{
    size_t n;

    if (cap < 8u + 24u) { return 0; }

    n = cl_put_radiotap(out);
    out[n++] = 0x08; out[n++] = 0x01;              /* data, ToDS          */
    out[n++] = 0x00; out[n++] = 0x00;
    memcpy(out + n, bssid, 6); n += 6;             /* Addr1 = BSSID       */
    memcpy(out + n, sta, 6);   n += 6;             /* Addr2 = SA          */
    memcpy(out + n, bssid, 6); n += 6;             /* Addr3 = DA          */
    out[n++] = 0x30; out[n++] = 0x00;              /* sequence control    */

    return n;
}

/*
 * cl_mock_inject — Feed synthetic observations through the real parser so
 * `mock_transcript.sh` can assert the inventory without a radio: one client
 * that probes for "mock-lab" and associates, and one that only probes for
 * "other-net" (the PNL case). Runs once per monitor session.
 */
void cl_mock_inject(daemon_t *d)
{
    static uint8_t frame[256];
    static const uint8_t bssid[6] = { 0x02, 0x00, 0x00, 0xde, 0xad, 0x01 };
    static const uint8_t sta1[6]  = { 0x02, 0x00, 0x00, 0xbe, 0xef, 0x02 };
    static const uint8_t sta2[6]  = { 0x02, 0x00, 0x00, 0xbe, 0xef, 0x03 };
    size_t n;

    if (s_mock_done) { return; }
    s_mock_done = true;

    n = cl_build_probe(frame, sizeof(frame), sta1, "mock-lab");
    if (n > 0) { cl_observe(d, frame, n); }

    n = cl_build_assoc(frame, sizeof(frame), bssid, sta1, "mock-lab");
    if (n > 0) { cl_observe(d, frame, n); }

    n = cl_build_data(frame, sizeof(frame), bssid, sta1);
    if (n > 0) { cl_observe(d, frame, n); }

    n = cl_build_probe(frame, sizeof(frame), sta2, "other-net");
    if (n > 0) { cl_observe(d, frame, n); }
}
