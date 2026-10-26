/*
 * mock.c — Mock mode: replays canned frames and simulates hardware.
 *
 * In --mock mode, the daemon runs on x86_64 Linux (no hardware).
 * All radio operations are bypassed (MOCK_RETURN in radio.c).
 * capture_read_frame() generates synthetic 802.11 beacon frames.
 * The main loop drives everything exactly as on hardware.
 *
 * This file contains the mock-specific frame injection rate limiter
 * and any mock-only diagnostics.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <time.h>

/* Mock frame rate: 10 frames per second = 100ms between frames */
#define MOCK_FRAME_INTERVAL_MS  100

/* Last mock frame time (monotonic ms) */
static int64_t s_last_mock_us;

/*
 * mock_tick — Called each main loop iteration when mock_mode is true
 * and monitor is active.  Generates frames at MOCK_FRAME_INTERVAL_MS rate.
 */
void mock_tick(daemon_t *d)
{
    int64_t now_us;
    int64_t delta_us;

    if (!d->mock_mode) { return; }
    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) { return; }

    now_us   = util_monotonic_us();
    delta_us = now_us - s_last_mock_us;

    if (delta_us >= (int64_t)MOCK_FRAME_INTERVAL_MS * 1000LL) {
        s_last_mock_us = now_us;
        (void)capture_read_frame(d);   /* enqueues one synthetic frame */
    }
}

/*
 * mock_run — Initialize mock state.
 */
void mock_run(daemon_t *d)
{
    s_last_mock_us = util_monotonic_us();

    /* Synthesise a base MAC if we can't read one from sysfs */
    if (d->base_mac[0] == 0 && d->base_mac[1] == 0
        && d->base_mac[2] == 0 && d->base_mac[3] == 0
        && d->base_mac[4] == 0 && d->base_mac[5] == 0) {
        d->base_mac[0] = 0x02;   /* locally administered */
        d->base_mac[1] = 0x00;
        d->base_mac[2] = 0x00;
        d->base_mac[3] = 0xca;
        d->base_mac[4] = 0xfe;
        d->base_mac[5] = 0x01;
    }

    util_log("mock", "mock mode active — no hardware ops");
}

/*
 * mock_scan_json — Canned WIFI_SCAN result used by the e2e tests and by the
 * host CLI smoke tests. Includes one hidden network with a known advertised
 * SSID length so the host-side rendering path is exercised too.
 */
void mock_scan_json(char *out, size_t n)
{
    (void)snprintf(out, n,
        "{\"count\":4,\"dwell_ms\":4000,\"networks\":["
        "{\"ssid\":\"mock-drone\",\"bssid\":\"02:00:00:de:ad:01\","
            "\"channel\":6,\"signal_dbm\":-42,\"hidden\":false},"
        "{\"ssid\":\"mock-lab-5\",\"bssid\":\"02:00:00:de:ad:02\","
            "\"channel\":11,\"signal_dbm\":-58,\"hidden\":false},"
        "{\"ssid\":\"\",\"bssid\":\"02:00:00:de:ad:03\","
            "\"channel\":1,\"signal_dbm\":-64,\"hidden\":true,\"ssid_len\":8},"
        "{\"ssid\":\"mock-open\",\"bssid\":\"02:00:00:de:ad:04\","
            "\"channel\":3,\"signal_dbm\":-71,\"hidden\":false}"
        "]}");
}

/*
 * mock_sta_status_json — Canned WIFI_STATUS result: associated with an
 * upstream AP holding a DHCP lease.
 */
void mock_sta_status_json(char *out, size_t n)
{
    (void)snprintf(out, n,
        "{\"connected\":true,\"ssid\":\"mock-uplink\","
        "\"bssid\":\"02:00:00:de:ad:09\",\"ip\":\"192.168.1.44\","
        "\"channel\":11,\"mode\":\"sta\",\"sharing\":true}");
}
