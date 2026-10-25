/*
 * beacon_parse.c — Standalone 802.11 beacon/probe-response parser.
 *
 * Pure parser: no daemon state, no sockets, no allocation — deliberately
 * separated from wifi_scan.c so the unit tests can link it without the
 * radio/capture stack. Extracts the BSSID, channel (DS parameter IE with
 * radiotap frequency fallback), antenna signal and SSID (including the
 * hidden-SSID heuristics) from one RadioTap+802.11 frame.
 */

#include "pwn4cd.h"

#include <string.h>

static const uint8_t SCAN_BROADCAST_MAC[6] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff
};

/* ── Radiotap walker ──────────────────────────────────────────────────────── */

/* Size/alignment of the radiotap v1 fields we walk past (bits 0-15). */
static const uint8_t RT_FIELD_SIZE[16]  = {
    8, 1, 1, 4, 2, 1, 1, 2,   /* TSFT..LOCK_QUALITY                            */
    2, 2, 1, 1, 2, 2, 2, 2    /* TX_ATTENUATION..bit15                         */
};
static const uint8_t RT_FIELD_ALIGN[16] = {
    8, 1, 1, 2, 2, 1, 1, 2,
    2, 2, 1, 1, 2, 2, 2, 2
};

/*
 * rt_walk — Walk the radiotap header (already length-validated) and extract
 * the antenna signal (dBm) and channel frequency (MHz) when present.
 * Handles extended present bitmaps (bit 31 of each word continues the list).
 */
static void rt_walk(const uint8_t *rt, size_t rt_len,
                    int *signal_dbm, int *freq_mhz)
{
    uint32_t words[8];
    size_t   num_words = 0;
    size_t   data_off = 4;
    size_t   i;

    *signal_dbm = 0;
    *freq_mhz   = 0;

    /* 1. Walk all present bitmaps. In radiotap, every present word has
     * bit 31 set if another present word follows immediately. */
    while (data_off + 4 <= rt_len && num_words < 8) {
        uint32_t w = (uint32_t)rt[data_off]
                   | ((uint32_t)rt[data_off + 1] << 8)
                   | ((uint32_t)rt[data_off + 2] << 16)
                   | ((uint32_t)rt[data_off + 3] << 24);
        words[num_words++] = w;
        data_off += 4;
        if (!(w & (1u << 31))) {
            break;
        }
    }

    if (num_words == 0) { return; }

    /* 2. Walk fields in word 0. We only care about frequency (bit 3)
     * and antenna signal (bit 5). Bits 0..15 have fixed sizes. */
    uint32_t word0 = words[0];
    for (i = 0; i < 16; i++) {
        if (!(word0 & (1u << i))) { continue; }

        size_t size  = RT_FIELD_SIZE[i];
        size_t align = RT_FIELD_ALIGN[i];

        /* Align to field requirement */
        data_off = (data_off + align - 1) & ~(align - 1);
        if (data_off + size > rt_len) { return; }

        if (i == 3 && size == 4) {
            *freq_mhz = (int)rt[data_off] | ((int)rt[data_off + 1] << 8);
        } else if (i == 5 && size == 1) {
            *signal_dbm = (int8_t)rt[data_off];
        }

        data_off += size;
    }
}

/* ── Beacon parsing ───────────────────────────────────────────────────────── */

/*
 * scan_parse_beacon — Parse one RadioTap+802.11 frame into a survey entry.
 * Accepts beacons (subtype 8) and probe responses (subtype 5). Returns 0 on
 * success, -1 when the frame is not a usable AP announcement.
 */
int scan_parse_beacon(const uint8_t *frame, size_t len,
                      int fallback_channel, scan_net_t *out)
{
    size_t   rt;
    size_t   body;
    size_t   ies_len;
    size_t   p;
    int      signal_dbm = 0;
    int      freq_mhz   = 0;
    uint8_t  fc0;
    uint8_t  subtype;
    bool     ssid_blank = true;
    bool     seen_ssid  = false;
    size_t   i;

    if (!frame || !out || len < 24) { return -1; }
    memset(out, 0, sizeof(*out));

    rt = (size_t)frame[2] | ((size_t)frame[3] << 8);
    if (rt < 8 || rt + 24 > len) { return -1; }

    rt_walk(frame, rt, &signal_dbm, &freq_mhz);

    fc0 = frame[rt];
    if ((fc0 & 0x0cu) != 0x00u) { return -1; }          /* management frames only */
    subtype = (uint8_t)((fc0 >> 4) & 0x0fu);
    if (subtype != 0x08u && subtype != 0x05u) { return -1; }  /* beacon / probe resp */

    /* BSSID = Address 3 for beacons and probe responses */
    memcpy(out->bssid, frame + rt + 16, 6);
    if (memcmp(out->bssid, SCAN_BROADCAST_MAC, 6) == 0) { return -1; }

    body    = rt + 24;
    ies_len = len - body - 12;   /* fixed parameters: timestamp 8 + beacon itv 2 + capab 2 */
    if (body + 12 > len || ies_len < 2) {
        ies_len = 0;
    }

    /* Channel: DS parameter IE first, radiotap frequency second, fallback last */
    out->channel = fallback_channel;
    if (freq_mhz >= 2412 && freq_mhz <= 2472) {
        out->channel = (freq_mhz - 2407) / 5;
    } else if (freq_mhz == 2484) {
        out->channel = 14;
    }

    out->signal_dbm = signal_dbm;

    p = 0;
    while (p + 2 <= ies_len) {
        uint8_t tag  = frame[body + 12 + p];
        uint8_t tlen = frame[body + 12 + p + 1];

        if (p + 2 + tlen > ies_len) { break; }
        const uint8_t *data = frame + body + 12 + p + 2;

        if (tag == 0x00u) {
            /* SSID IE */
            seen_ssid = true;
            if (tlen == 0) {
                out->hidden   = true;
                out->ssid_len = 0;
            } else {
                for (i = 0; i < tlen; i++) {
                    if (data[i] != 0x00u) { ssid_blank = false; }
                }
                if (ssid_blank) {
                    out->hidden   = true;
                    out->ssid_len = tlen;
                } else {
                    size_t copy = tlen;
                    if (copy > SCAN_SSID_MAX) { copy = SCAN_SSID_MAX; }
                    memcpy(out->ssid, data, copy);
                    out->ssid[copy] = '\0';
                    out->ssid_len   = tlen;
                    out->hidden     = false;
                }
            }
        } else if (tag == 0x03u && tlen >= 1) {
            /* DS parameter set: direct channel */
            int ch = data[0];
            if (ch >= CHAN_MIN && ch <= 14) { out->channel = ch; }
        }

        p += (size_t)2 + tlen;
    }

    /* Beacons with no SSID information element at all: report as hidden
     * with an unknown advertised length (some vendors blank the whole IE). */
    if (!seen_ssid) {
        out->hidden   = true;
        out->ssid_len = 0;
    }

    return 0;
}

