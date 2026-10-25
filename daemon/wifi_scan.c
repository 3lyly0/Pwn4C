/*
 * wifi_scan.c — Monitor-mode Wi-Fi survey (WIFI_SCAN).
 *
 * Answers "which networks are around the drone?" without ever touching the
 * managed wireless stack: the radio stays in monitor mode, a management-only
 * BPF filter keeps beacons and probe responses, and the raw frames are parsed
 * in place — no host round-trips, no PCAP streaming.
 *
 * Hidden SSID handling (§scan):
 *   - SSID IE length 0            -> hidden, length unknown
 *   - SSID IE all-zero bytes      -> hidden, length known (many APs broadcast
 *                                    the real length with blanked bytes)
 *   - printable SSID              -> reported verbatim
 *
 * Constraints honoured: no float, no dynamic allocation, bounded buffers.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <time.h>

#define SCAN_DWELL_DEFAULT_MS  4000
#define SCAN_DWELL_MIN_MS      1000
#define SCAN_DWELL_MAX_MS      15000
#define SCAN_CHAN_DWELL_MS     120      /* per-channel sweep dwell          */

static uint8_t scan_frame_buf[FRAME_SLOT_MAX];

typedef struct {
    scan_net_t nets[SCAN_MAX_NETS];
    size_t     count;
} scan_table_t;

/* ── Table management ─────────────────────────────────────────────────────── */

/*
 * scan_table_add — Deduplicate by BSSID, keep the strongest signal per AP and
 * evict the weakest entry once the table is full.
 */
static void scan_table_add(scan_table_t *t, const scan_net_t *net)
{
    size_t   i;
    size_t   weakest = 0;
    int      weakest_signal = 0;

    for (i = 0; i < t->count; i++) {
        if (memcmp(t->nets[i].bssid, net->bssid, 6) == 0) {
            t->nets[i].beacons++;
            if (net->signal_dbm != 0
                && (t->nets[i].signal_dbm == 0
                    || net->signal_dbm > t->nets[i].signal_dbm)) {
                t->nets[i].signal_dbm = net->signal_dbm;
                t->nets[i].channel    = net->channel;
            }
            return;
        }
    }

    if (t->count < SCAN_MAX_NETS) {
        t->nets[t->count] = *net;
        t->nets[t->count].beacons = 1;
        t->count++;
        return;
    }

    /* Table full: replace the weakest entry if the newcomer is stronger */
    weakest_signal = t->nets[0].signal_dbm;
    for (i = 1; i < t->count; i++) {
        if (t->nets[i].signal_dbm < weakest_signal) {
            weakest_signal = t->nets[i].signal_dbm;
            weakest        = i;
        }
    }
    if (net->signal_dbm != 0 && net->signal_dbm > weakest_signal) {
        t->nets[weakest] = *net;
        t->nets[weakest].beacons = 1;
    }
}

/* Strongest first so the CLI table reads like a proper survey */
static void scan_table_sort(scan_table_t *t)
{
    size_t i;
    size_t j;

    for (i = 0; i + 1 < t->count; i++) {
        size_t best = i;
        for (j = i + 1; j < t->count; j++) {
            if (t->nets[j].signal_dbm > t->nets[best].signal_dbm) {
                best = j;
            }
        }
        if (best != i) {
            scan_net_t tmp = t->nets[i];
            t->nets[i] = t->nets[best];
            t->nets[best] = tmp;
        }
    }
}

/* ── JSON rendering ───────────────────────────────────────────────────────── */

static void scan_json_append_net(char *out, size_t outsz, size_t *off,
                                 const scan_net_t *net)
{
    char escaped[SCAN_SSID_MAX * 2 + 2];
    char bssid_str[18];
    int  n;

    util_json_escape(net->ssid, escaped, sizeof(escaped));
    util_mac_to_str(net->bssid, bssid_str, sizeof(bssid_str));

    n = snprintf(out + *off, outsz - *off,
                 "%s{\"ssid\":\"%s\",\"bssid\":\"%s\",\"channel\":%d,"
                 "\"signal_dbm\":%d,\"hidden\":%s",
                 (*off == 0) ? "" : ",",
                 escaped,
                 bssid_str,
                 net->channel,
                 net->signal_dbm,
                 net->hidden ? "true" : "false");
    if (n < 0 || (size_t)n >= outsz - *off) { return; }
    *off += (size_t)n;

    if (net->hidden) {
        n = snprintf(out + *off, outsz - *off, ",\"ssid_len\":%u",
                     (unsigned)net->ssid_len);
        if (n < 0 || (size_t)n >= outsz - *off) { return; }
        *off += (size_t)n;
    }

    n = snprintf(out + *off, outsz - *off, "}");
    if (n < 0 || (size_t)n >= outsz - *off) { return; }
    *off += (size_t)n;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

/*
 * scan_run — Run one survey sweep and render the result as the WIFI_SCAN
 * response data object. Blocking for up to dwell_ms (event loop pauses, the
 * control client is already waiting for this exact response).
 *
 * Radio discipline:
 *   - monitoring already  -> reuse the session, sweep channels only when the
 *                            autonomous hopper is idle, restore afterwards
 *   - idle                -> enter monitor, sweep, exit monitor (pre-state is
 *                            restored by radio_exit_monitor)
 */
int scan_run(daemon_t *d, int dwell_ms, char *out_json, size_t out_sz)
{
    scan_table_t table;
    int64_t      deadline;
    int64_t      next_chan_ms;
    int          sweep_channel = 1;
    bool         we_entered_monitor = false;
    bool         filter_changed     = false;
    bool         restore_channel    = false;
    int          saved_channel      = d->channel;
    bool         saved_mgmt         = d->filter_mgmt_only;
    bool         saved_bssid_set    = d->filter_bssid_set;
    uint8_t      saved_bssid[6];
    size_t       off = 0;
    size_t       i;
    int          n;

    memset(&table, 0, sizeof(table));
    memcpy(saved_bssid, d->filter_bssid, sizeof(saved_bssid));

    if (dwell_ms <= 0) { dwell_ms = SCAN_DWELL_DEFAULT_MS; }
    if (dwell_ms < SCAN_DWELL_MIN_MS)   { dwell_ms = SCAN_DWELL_MIN_MS; }
    if (dwell_ms > SCAN_DWELL_MAX_MS)   { dwell_ms = SCAN_DWELL_MAX_MS; }

    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) {
        if (radio_enter_monitor(d, 1) < 0) { return -1; }
        d->radio_mode = RADIO_MONITOR;
        if (capture_open(d) < 0) {
            (void)radio_exit_monitor(d);
            return -1;
        }
        we_entered_monitor = true;
    } else if (!d->mock_mode && d->pkt_fd < 0) {
        return -1;   /* inconsistent state: monitoring without capture socket */
    } else if (!d->hop_enabled) {
        restore_channel = true;
    }

    if (!d->filter_mgmt_only) {
        (void)capture_set_filter(d, true, NULL);
        filter_changed = true;
    }

    deadline     = util_monotonic_ms() + dwell_ms;
    next_chan_ms = util_monotonic_ms() + SCAN_CHAN_DWELL_MS;

    while (util_monotonic_ms() < deadline) {
        if (!d->hop_enabled && util_monotonic_ms() >= next_chan_ms) {
            (void)radio_set_channel(d, sweep_channel);
            sweep_channel = (sweep_channel % CHAN_MAX) + 1;
            next_chan_ms  = util_monotonic_ms() + SCAN_CHAN_DWELL_MS;
        }

        /* Drain everything currently queued on the packet socket */
        for (;;) {
            scan_net_t net;
            ssize_t    nb = recv(d->pkt_fd, scan_frame_buf,
                                 sizeof(scan_frame_buf), MSG_DONTWAIT);
            if (nb <= 0) { break; }
            if (scan_parse_beacon(scan_frame_buf, (size_t)nb,
                                  d->channel, &net) == 0) {
                scan_table_add(&table, &net);
            }
        }

        util_sleep_ms(5);
    }

    /* ── Restore the radio exactly as we found it ─────────────────────────── */
    if (filter_changed) {
        if (saved_mgmt || saved_bssid_set) {
            (void)capture_set_filter(d, saved_mgmt,
                                     saved_bssid_set ? saved_bssid : NULL);
        } else {
            (void)capture_set_filter(d, false, NULL);
        }
    }
    if (we_entered_monitor) {
        capture_close(d);
        (void)radio_exit_monitor(d);
    } else {
        if (restore_channel && saved_channel >= CHAN_MIN && saved_channel <= CHAN_MAX) {
            (void)radio_set_channel(d, saved_channel);
        }
    }

    scan_table_sort(&table);

    n = snprintf(out_json, out_sz,
                 "{\"count\":%u,\"dwell_ms\":%d,\"networks\":[",
                 (unsigned)table.count, dwell_ms);
    if (n < 0 || (size_t)n >= out_sz) { return -1; }
    off = (size_t)n;

    for (i = 0; i < table.count; i++) {
        scan_json_append_net(out_json, out_sz, &off, &table.nets[i]);
    }

    n = snprintf(out_json + off, out_sz - off, "]}");
    if (n < 0 || (size_t)n >= out_sz - off) { return -1; }
    off += (size_t)n;
    out_json[off] = '\0';

    util_log("scan", "WIFI_SCAN done: %u networks in %d ms",
             (unsigned)table.count, dwell_ms);
    return 0;
}
