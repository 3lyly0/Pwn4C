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
