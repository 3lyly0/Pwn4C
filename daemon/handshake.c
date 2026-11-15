/*
 * handshake.c — Bounded 4-way/PMKID table feeding `pwn4c harvest`.
 *
 * Fed by capture_read_frame() with every captured frame. Keeps at most
 * HS_MAX_PAIRS (BSSID, STA) slots plus a small BSSID -> SSID cache learned
 * from beacons and probe responses, because a hashcat 22000 line needs the
 * ESSID. Reports facts only: the host formats the hash and decides when the
 * capture is done.
 *
 * Zero allocation. All state is static and bounded, so the daemon's RSS does
 * not depend on how long a capture runs or how many frames fly past.
 */

#include "pwn4cd.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#define HS_REPORT_BUF  8192u
#define HS_ENTRY_MAX   1024u   /* worst-case serialised entry, with slack */
#define HS_PMKID_LEN   16u

typedef struct {
    bool     used;
    uint8_t  bssid[6];
    uint8_t  sta[6];

    /* AP side: M1 or M3 (carries ANonce, and the PMKID when present). */
    bool     has_ap;
    uint8_t  ap_msg;
    uint8_t  anonce[32];
    uint8_t  ap_eapol[HS_EAPOL_MAX];
    uint16_t ap_eapol_len;

    /* Client side: M2 or M4 (carries the MIC and the client's EAPOL frame). */
    bool     has_sta;
    uint8_t  sta_msg;
    uint8_t  mic[16];
    uint8_t  sta_eapol[HS_EAPOL_MAX];
    uint16_t sta_eapol_len;

    bool     has_pmkid;
    uint8_t  pmkid[16];

    int64_t  first_ms;
    int64_t  last_ms;
    uint16_t frames;
} hs_pair_t;

typedef struct {
    bool     used;
    uint8_t  bssid[6];
    char     ssid[SCAN_SSID_MAX + 1];
    uint8_t  ssid_len;
} hs_ssid_t;

static hs_pair_t s_pairs[HS_MAX_PAIRS];
static hs_ssid_t s_ssids[HS_MAX_BSSIDS];
static char      s_report[HS_REPORT_BUF];
static bool      s_mock_done;

/* ── Table management ─────────────────────────────────────────────────────── */

void hs_reset(void)
{
    memset(s_pairs, 0, sizeof(s_pairs));
    memset(s_ssids, 0, sizeof(s_ssids));
    s_mock_done = false;
}

static bool hs_pair_ready(const hs_pair_t *p)
{
    return (p->has_ap && p->has_sta) || p->has_pmkid;
}

int hs_ready_count(void)
{
    size_t i;
    int    n = 0;

    for (i = 0; i < HS_MAX_PAIRS; i++) {
        if (s_pairs[i].used && hs_pair_ready(&s_pairs[i])) { n++; }
    }
    return n;
}

/* ── BSSID -> SSID cache ──────────────────────────────────────────────────── */

static void hs_ssid_learn(const uint8_t bssid[6], const char *ssid,
                          size_t ssid_len)
{
    size_t i;
    size_t slot = HS_MAX_BSSIDS;

    if (!ssid || ssid_len == 0) { return; }

    for (i = 0; i < HS_MAX_BSSIDS; i++) {
        if (s_ssids[i].used && memcmp(s_ssids[i].bssid, bssid, 6) == 0) {
            slot = i;
            break;
        }
    }
    if (slot == HS_MAX_BSSIDS) {
        for (i = 0; i < HS_MAX_BSSIDS; i++) {
            if (!s_ssids[i].used) { slot = i; break; }
        }
    }
    if (slot == HS_MAX_BSSIDS) { return; }   /* cache full: keep what we have */

    if (ssid_len > SCAN_SSID_MAX) { ssid_len = SCAN_SSID_MAX; }
    s_ssids[slot].used = true;
    memcpy(s_ssids[slot].bssid, bssid, 6);
    memcpy(s_ssids[slot].ssid, ssid, ssid_len);
    s_ssids[slot].ssid[ssid_len] = '\0';
    s_ssids[slot].ssid_len = (uint8_t)ssid_len;
}

static const char *hs_ssid_for(const uint8_t bssid[6], size_t *len_out)
{
    size_t i;

    for (i = 0; i < HS_MAX_BSSIDS; i++) {
        if (s_ssids[i].used && memcmp(s_ssids[i].bssid, bssid, 6) == 0) {
            if (len_out) { *len_out = s_ssids[i].ssid_len; }
            return s_ssids[i].ssid;
        }
    }
    if (len_out) { *len_out = 0; }
    return "";
}

/* ── Pair slots ───────────────────────────────────────────────────────────── */

static hs_pair_t *hs_pair_get(const uint8_t bssid[6], const uint8_t sta[6])
{
    size_t i;
    size_t victim = HS_MAX_PAIRS;

    for (i = 0; i < HS_MAX_PAIRS; i++) {
        if (s_pairs[i].used
            && memcmp(s_pairs[i].bssid, bssid, 6) == 0
            && memcmp(s_pairs[i].sta, sta, 6) == 0) {
            return &s_pairs[i];
        }
    }

    for (i = 0; i < HS_MAX_PAIRS; i++) {
        if (!s_pairs[i].used) { victim = i; break; }
    }
    if (victim == HS_MAX_PAIRS) {
        /* Recycle an incomplete slot first: a captured hash is worth more
         * than a half-seen pair. */
        for (i = 0; i < HS_MAX_PAIRS; i++) {
            if (!hs_pair_ready(&s_pairs[i])
                && (victim == HS_MAX_PAIRS
                    || s_pairs[i].last_ms < s_pairs[victim].last_ms)) {
                victim = i;
            }
        }
    }
    if (victim == HS_MAX_PAIRS) {
        /* Everything is ready: drop the least recently active pair so a long
         * capture keeps learning instead of stopping. */
        victim = 0;
        for (i = 1; i < HS_MAX_PAIRS; i++) {
            if (s_pairs[i].last_ms < s_pairs[victim].last_ms) { victim = i; }
        }
    }

    memset(&s_pairs[victim], 0, sizeof(s_pairs[victim]));
    s_pairs[victim].used     = true;
    s_pairs[victim].first_ms = util_monotonic_ms();
    s_pairs[victim].last_ms  = s_pairs[victim].first_ms;
    memcpy(s_pairs[victim].bssid, bssid, 6);
    memcpy(s_pairs[victim].sta, sta, 6);
    return &s_pairs[victim];
}

/* ── Frame ingestion ──────────────────────────────────────────────────────── */

static bool hs_store_eapol(uint8_t *dst, uint16_t *dst_len,
                           const eapol_msg_t *m)
{
    if (m->eapol_len == 0 || m->eapol_len > HS_EAPOL_MAX || !m->eapol) {
        return false;
    }
    memcpy(dst, m->eapol, m->eapol_len);
    *dst_len = m->eapol_len;
    return true;
}

void hs_observe(daemon_t *d, const uint8_t *frame, size_t len)
{
    eapol_msg_t msg;
    scan_net_t  net;
    hs_pair_t  *p;

    if (!frame || len < 24u) { return; }

    /*
     * Learn BSSID -> SSID from any AP announcement we happen to capture.
     * Beacons dominate a monitor capture, so this is the cheapest place to
     * pick up the ESSID hashcat 22000 needs.
     */
    if (scan_parse_beacon(frame, len, d ? d->channel : 0, &net) == 0) {
        if (!net.hidden && net.ssid_len > 0) {
            hs_ssid_learn(net.bssid, net.ssid, net.ssid_len);
        }
    }

    if (eapol_parse_frame(frame, len, &msg) < 0) { return; }

    p = hs_pair_get(msg.bssid, msg.sta);
    p->frames++;
    p->last_ms = util_monotonic_ms();

    if (msg.has_pmkid && !p->has_pmkid) {
        memcpy(p->pmkid, msg.pmkid, HS_PMKID_LEN);
        p->has_pmkid = true;
    }

    if (msg.msg == 1u || msg.msg == 3u) {
        /*
         * Prefer M1 over M3: M1 is the message hashcat pairs with a client
         * MIC, and it is the one that carries the PMKID KDE.
         */
        if (!p->has_ap || (msg.msg == 1u && p->ap_msg == 3u)) {
            if (hs_store_eapol(p->ap_eapol, &p->ap_eapol_len, &msg)) {
                p->has_ap = true;
                p->ap_msg = msg.msg;
                memcpy(p->anonce, msg.nonce, 32);
            }
        }
    } else {
        /* Prefer M2 over M4 for the same reason. */
        if (!p->has_sta || (msg.msg == 2u && p->sta_msg == 4u)) {
            if (hs_store_eapol(p->sta_eapol, &p->sta_eapol_len, &msg)) {
                p->has_sta = true;
                p->sta_msg = msg.msg;
                memcpy(p->mic, msg.mic, 16);
            }
        }
    }
}

/* ── JSON serialisation ───────────────────────────────────────────────────── */

static void hs_hex(const uint8_t *data, size_t len, char *out)
{
    static const char HEX[] = "0123456789abcdef";
    size_t i;

    for (i = 0; i < len; i++) {
        out[i * 2]     = HEX[(data[i] >> 4) & 0x0fu];
        out[i * 2 + 1] = HEX[data[i] & 0x0fu];
    }
    out[len * 2] = '\0';
}

static bool hs_append(char *out, size_t out_sz, size_t *used,
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

/*
 * hs_message_pair — hashcat 22000 message-pair id for the stored combination.
 * 0 = M1+M2, 1 = M1+M4, 2 = M3+M2, 3 = M3+M4.
 */
static int hs_message_pair(const hs_pair_t *p)
{
    if (p->ap_msg == 1u) { return (p->sta_msg == 2u) ? 0 : 1; }
    return (p->sta_msg == 2u) ? 2 : 3;
}

const char *hs_report(int offset, bool reset, int *total_out)
{
    size_t order[HS_MAX_PAIRS];
    size_t n_ready = 0;
    size_t tracked = 0;
    size_t start;
    size_t end;
    size_t i;
    size_t j;
    size_t used = 0;

    if (reset) { hs_reset(); }

    for (i = 0; i < HS_MAX_PAIRS; i++) {
        if (!s_pairs[i].used) { continue; }
        tracked++;
        if (!hs_pair_ready(&s_pairs[i])) { continue; }

        /* Insertion sort by first_ms: the table holds 16 entries at most, and
         * a stable order is what makes offset-based paging correct. */
        j = n_ready;
        while (j > 0 && s_pairs[order[j - 1]].first_ms > s_pairs[i].first_ms) {
            order[j] = order[j - 1];
            j--;
        }
        order[j] = i;
        n_ready++;
    }

    if (total_out) { *total_out = (int)n_ready; }

    start = (offset > 0) ? (size_t)offset : 0;
    if (start > n_ready) { start = n_ready; }
    end = start + HS_JSON_PAIRS;
    if (end > n_ready) { end = n_ready; }

    (void)hs_append(s_report, sizeof(s_report), &used,
        "{\"count\":%lu,\"tracked\":%lu,\"offset\":%lu,\"returned\":%lu,"
        "\"truncated\":%s,\"handshakes\":[",
        (unsigned long)n_ready, (unsigned long)tracked, (unsigned long)start,
        (unsigned long)(end - start), (end < n_ready) ? "true" : "false");

    for (i = start; i < end; i++) {
        const hs_pair_t *p = &s_pairs[order[i]];
        char bssid_s[18];
        char sta_s[18];
        char ssid_esc[SCAN_SSID_MAX * 2 + 1];
        char ssid_hex[SCAN_SSID_MAX * 2 + 1];
        char anonce_hex[65];
        char mic_hex[33];
        char pmkid_hex[33];
        char eapol_hex[HS_EAPOL_MAX * 2 + 1];
        const char *ssid;
        size_t ssid_len = 0;
        int    mp = -1;

        if (used + HS_ENTRY_MAX > sizeof(s_report)) { break; }

        util_mac_to_str(p->bssid, bssid_s, sizeof(bssid_s));
        util_mac_to_str(p->sta, sta_s, sizeof(sta_s));

        ssid = hs_ssid_for(p->bssid, &ssid_len);
        util_json_escape(ssid, ssid_esc, sizeof(ssid_esc));

        /*
         * hashcat 22000 needs the exact ESSID bytes, and an SSID is an
         * arbitrary byte string: send the hex form alongside the printable
         * one so a binary SSID still produces a correct hash.
         */
        hs_hex((const uint8_t *)ssid, ssid_len, ssid_hex);

        anonce_hex[0] = '\0';
        mic_hex[0]    = '\0';
        pmkid_hex[0]  = '\0';
        eapol_hex[0]  = '\0';

        if (p->has_ap) { hs_hex(p->anonce, 32, anonce_hex); }
        if (p->has_sta) {
            hs_hex(p->mic, 16, mic_hex);
            hs_hex(p->sta_eapol, p->sta_eapol_len, eapol_hex);
            if (p->has_ap) { mp = hs_message_pair(p); }
        }
        if (p->has_pmkid) { hs_hex(p->pmkid, 16, pmkid_hex); }

        (void)hs_append(s_report, sizeof(s_report), &used,
            "%s{\"bssid\":\"%s\",\"sta\":\"%s\",\"ssid\":\"%s\","
            "\"ssid_len\":%lu,\"ssid_hex\":\"%s\",\"message_pair\":%d,"
            "\"frames\":%u,"
            "\"anonce\":\"%s\",\"mic\":\"%s\",\"pmkid\":\"%s\","
            "\"eapol\":\"%s\",\"eapol_len\":%u}",
            (i == start) ? "" : ",",
            bssid_s, sta_s, ssid_esc,
            (unsigned long)ssid_len, ssid_hex, mp, (unsigned)p->frames,
            anonce_hex, mic_hex, pmkid_hex,
            eapol_hex, (unsigned)p->sta_eapol_len);
    }

    (void)hs_append(s_report, sizeof(s_report), &used, "]}");

    return s_report;
}

/* ── Mock mode ────────────────────────────────────────────────────────────── */

/* Minimal radiotap header: no present fields, 8-byte length. */
static const uint8_t HS_RT[8] = { 0x00, 0x00, 0x08, 0x00,
                                  0x00, 0x00, 0x00, 0x00 };

static size_t hs_build_beacon(uint8_t *out, size_t cap,
                              const uint8_t bssid[6], const char *ssid)
{
    size_t ssid_len = strlen(ssid);
    size_t n = 0;
    size_t i;

    if (cap < 8u + 24u + 12u + 2u + ssid_len + 3u) { return 0; }

    memcpy(out, HS_RT, 8);
    n = 8;

    out[n++] = 0x80; out[n++] = 0x00;          /* beacon                 */
    out[n++] = 0x00; out[n++] = 0x00;          /* duration               */
    for (i = 0; i < 6; i++) { out[n++] = 0xff; }   /* DA broadcast       */
    memcpy(out + n, bssid, 6); n += 6;         /* SA                     */
    memcpy(out + n, bssid, 6); n += 6;         /* BSSID                  */
    out[n++] = 0x10; out[n++] = 0x00;          /* sequence control       */

    for (i = 0; i < 8; i++) { out[n++] = 0x00; }   /* timestamp          */
    out[n++] = 0x64; out[n++] = 0x00;          /* beacon interval 100 TU */
    out[n++] = 0x01; out[n++] = 0x00;          /* capability: ESS        */

    out[n++] = 0x00; out[n++] = (uint8_t)ssid_len;  /* SSID IE            */
    memcpy(out + n, ssid, ssid_len);
    n += ssid_len;

    out[n++] = 0x03; out[n++] = 0x01; out[n++] = 0x06;  /* DS: channel 6  */

    return n;
}

static size_t hs_build_eapol(uint8_t *out, size_t cap,
                             const uint8_t bssid[6], const uint8_t sta[6],
                             bool from_ap, uint16_t key_info,
                             uint8_t nonce_byte, bool with_pmkid)
{
    const size_t kd_len    = with_pmkid ? 22u : 0u;
    const size_t body_len  = 95u + kd_len;
    size_t       n = 0;
    size_t       i;

    if (cap < 8u + 24u + 8u + 4u + body_len) { return 0; }

    memcpy(out, HS_RT, 8);
    n = 8;

    out[n++] = 0x08;                           /* data frame             */
    out[n++] = from_ap ? 0x02 : 0x01;          /* FromDS / ToDS          */
    out[n++] = 0x00; out[n++] = 0x00;          /* duration               */

    if (from_ap) {
        memcpy(out + n, sta, 6);   n += 6;     /* Addr1 = DA             */
        memcpy(out + n, bssid, 6); n += 6;     /* Addr2 = SA (BSSID)     */
    } else {
        memcpy(out + n, bssid, 6); n += 6;     /* Addr1 = BSSID          */
        memcpy(out + n, sta, 6);   n += 6;     /* Addr2 = SA (client)    */
    }
    memcpy(out + n, bssid, 6);     n += 6;     /* Addr3 = BSSID          */
    out[n++] = 0x20; out[n++] = 0x00;          /* sequence control       */

    /* LLC/SNAP for EtherType 0x888E */
    out[n++] = 0xaa; out[n++] = 0xaa; out[n++] = 0x03;
    out[n++] = 0x00; out[n++] = 0x00; out[n++] = 0x00;
    out[n++] = 0x88; out[n++] = 0x8e;

    /* EAPOL header */
    out[n++] = 0x02;                           /* version 2004           */
    out[n++] = 0x03;                           /* type: EAPOL-Key        */
    out[n++] = (uint8_t)(body_len >> 8);
    out[n++] = (uint8_t)(body_len & 0xffu);

    /* EAPOL-Key body */
    out[n++] = 0x02;                           /* RSN descriptor         */
    out[n++] = (uint8_t)(key_info >> 8);
    out[n++] = (uint8_t)(key_info & 0xffu);
    out[n++] = 0x00; out[n++] = 0x10;          /* key length 16          */

    for (i = 0; i < 7; i++) { out[n++] = 0x00; }   /* replay counter     */
    out[n++] = 0x01;

    for (i = 0; i < 32; i++) { out[n++] = nonce_byte; }   /* nonce        */
    for (i = 0; i < 16; i++) { out[n++] = 0x00; }         /* IV           */
    for (i = 0; i < 8; i++)  { out[n++] = 0x00; }         /* RSC          */
    for (i = 0; i < 8; i++)  { out[n++] = 0x00; }         /* key id       */

    for (i = 0; i < 16; i++) {                 /* MIC                    */
        out[n++] = from_ap ? 0x00 : 0x11;
    }

    out[n++] = (uint8_t)(kd_len >> 8);
    out[n++] = (uint8_t)(kd_len & 0xffu);

    if (with_pmkid) {
        out[n++] = 0xdd; out[n++] = 0x14;      /* vendor-specific, 20    */
        out[n++] = 0x00; out[n++] = 0x0f;
        out[n++] = 0xac; out[n++] = 0x04;      /* RSN PMKID KDE          */
        for (i = 0; i < 16; i++) { out[n++] = 0x5a; }
    }

    return n;
}

/*
 * hs_mock_inject — Feed one synthetic beacon + M1/M2 pair through the real
 * parser so `mock_transcript.sh` can assert the whole harvest path without a
 * radio. Runs once per monitor session (hs_reset() clears the latch).
 */
void hs_mock_inject(daemon_t *d)
{
    static uint8_t frame[512];
    static const uint8_t bssid[6] = { 0x02, 0x00, 0x00, 0xde, 0xad, 0x01 };
    static const uint8_t sta[6]   = { 0x02, 0x00, 0x00, 0xbe, 0xef, 0x02 };
    static const uint8_t sta2[6]  = { 0x02, 0x00, 0x00, 0xbe, 0xef, 0x03 };
    size_t n;

    if (s_mock_done) { return; }
    s_mock_done = true;

    n = hs_build_beacon(frame, sizeof(frame), bssid, "mock-lab");
    if (n > 0) { hs_observe(d, frame, n); }

    n = hs_build_eapol(frame, sizeof(frame), bssid, sta,
                       true, 0x008a, 0xa1, true);
    if (n > 0) { hs_observe(d, frame, n); }

    n = hs_build_eapol(frame, sizeof(frame), bssid, sta,
                       false, 0x010a, 0xb2, false);
    if (n > 0) { hs_observe(d, frame, n); }

    /*
     * A second client on the same AP, this time without a PMKID: it exercises
     * the classic M1+M2 path (hashcat WPA*02) that the host formatter builds.
     */
    n = hs_build_eapol(frame, sizeof(frame), bssid, sta2,
                       true, 0x008a, 0xc5, false);
    if (n > 0) { hs_observe(d, frame, n); }

    n = hs_build_eapol(frame, sizeof(frame), bssid, sta2,
                       false, 0x010a, 0xd6, false);
    if (n > 0) { hs_observe(d, frame, n); }
}
