/*
 * stream.c — UDP frame streamer (Drone -> Host, port 5555).
 *
 * Drains one slot from the capture ring per call to stream_send_next().
 * Fragments frames > STREAM_FRAG_MAX bytes per api_reference.md.
 * Header fields are all big-endian (network byte order).
 *
 * No float.  Timestamp computed as integer µs delta from monitor start.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

/* Declare capture_ring_pop (defined in capture.c) */
int capture_ring_pop(daemon_t *d, uint8_t *buf, size_t bufsize,
                     uint16_t *frame_len_out);

/* Datagram send buffer: stream header (16) + max fragment payload (1472) */
static uint8_t sg_send_buf[STREAM_HDR_LEN + STREAM_FRAG_MAX];

/* ── Byte-order helpers (no htons/htonl calls on struct fields) ──────────── */

static void put_u32_be(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >>  8);
    p[3] = (uint8_t)(v      );
}

static void put_u16_be(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v     );
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int stream_open(daemon_t *d)
{
    int fd;
    int val;

    if (d->stream_fd >= 0) { return 0; }  /* already open */

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        util_log("stream", "socket: %s", strerror(errno));
        return -1;
    }

    /* Non-blocking so we never block the main loop */
    val = fcntl(fd, F_GETFL, 0);
    if (val < 0 || fcntl(fd, F_SETFL, val | O_NONBLOCK) < 0) {
        util_log("stream", "fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Allow send even without explicit bind (OS chooses ephemeral port) */
    d->stream_fd = fd;
    util_log("stream", "UDP stream socket ready (fd=%d)", fd);
    return 0;
}

void stream_close(daemon_t *d)
{
    if (d->stream_fd >= 0) {
        close(d->stream_fd);
        d->stream_fd = -1;
    }
}

/*
 * stream_send_next — Pop one frame from the ring and send it via UDP.
 *
 * Returns:
 *   1  — frame sent (may be fragmented into multiple datagrams)
 *   0  — ring empty, nothing sent
 *  -1  — error
 */
int stream_send_next(daemon_t *d)
{
    static uint8_t    frame_buf[FRAME_SLOT_MAX];
    uint16_t          frame_len;
    int               r;
    uint32_t          ts_us;
    int64_t           now_us;
    int64_t           start_us;
    uint32_t          seq;
    uint16_t          frag_count;
    uint16_t          frag_idx;
    uint16_t          offset;
    struct sockaddr_in dest;

    if (d->stream_fd < 0) { return -1; }
    if (d->host_ip == 0)  { return 0; }

    r = capture_ring_pop(d, frame_buf, sizeof(frame_buf), &frame_len);
    if (r <= 0) { return r; }

    /* Compute timestamp_us: integer µs since monitor start, wraps at 2^32 */
    now_us   = util_monotonic_us();
    start_us = d->monitor_start_sec * 1000000LL
             + (int64_t)(d->monitor_start_nsec / 1000);
    ts_us    = (uint32_t)((now_us - start_us) & 0xFFFFFFFFu);

    seq = d->stream_seq++;

    /* Calculate fragment count (ceil division, no float) */
    if (frame_len <= STREAM_FRAG_MAX) {
        frag_count = 1;
    } else {
        frag_count = (uint16_t)((frame_len + STREAM_FRAG_MAX - 1u)
                                / STREAM_FRAG_MAX);
    }

    memset(&dest, 0, sizeof(dest));
    dest.sin_family      = AF_INET;
    dest.sin_port        = htons(STREAM_PORT);
    dest.sin_addr.s_addr = d->host_ip;

    for (frag_idx = 0, offset = 0; frag_idx < frag_count; frag_idx++) {
        uint16_t  payload_len;
        ssize_t   sent;
        uint8_t  *hdrp = sg_send_buf;

        payload_len = frame_len - offset;
        if (payload_len > STREAM_FRAG_MAX) {
            payload_len = STREAM_FRAG_MAX;
        }

        /* Build 16-byte stream header in network byte order */
        put_u32_be(hdrp + 0,  seq);
        put_u32_be(hdrp + 4,  ts_us);
        put_u16_be(hdrp + 8,  frag_idx);
        put_u16_be(hdrp + 10, frag_count);
        put_u16_be(hdrp + 12, frame_len);
        put_u16_be(hdrp + 14, 0);  /* reserved = 0 */

        memcpy(sg_send_buf + STREAM_HDR_LEN, frame_buf + offset, payload_len);

        do {
            sent = sendto(d->stream_fd, sg_send_buf,
                          (size_t)(STREAM_HDR_LEN + payload_len), 0,
                          (struct sockaddr *)&dest, sizeof(dest));
        } while (sent < 0 && errno == EINTR);

        if (sent < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                util_log("stream", "sendto: %s", strerror(errno));
            }
            /* Don't abort the whole session for a dropped datagram */
        }

        offset = (uint16_t)(offset + payload_len);
    }

    return 1;
}
