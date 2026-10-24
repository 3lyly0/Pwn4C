/*
 * capture.c — Raw 802.11 frame capture via AF_PACKET socket.
 *
 * Opens an ETH_P_ALL packet socket bound to the monitor interface.
 * Reads frames into the ring buffer; drops oldest on overflow.
 * No dynamic allocation in the hot path.
 *
 * Ring buffer layout:
 *   Each slot: [slot_hdr_t (4 bytes)] [frame bytes (frame_bytes)]
 *   Slots are contiguous; if a frame would wrap around the ring end,
 *   it is split into two memcpy calls (ring is a circular byte array).
 *
 *   We use a simpler approach: individual frames are never larger than
 *   FRAME_SLOT_MAX bytes (2332).  Since RING_BYTES = 524288 >> FRAME_SLOT_MAX
 *   we never need wrap-splitting: if (ring_head + slot_size) wraps, we
 *   drop the oldest frames until there is room, or skip this frame.
 *
 * In mock mode: a timer-driven synthetic frame generator fills the ring.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <time.h>

/* Synthetic mock frame: minimal RadioTap + 802.11 beacon stub.              */
/* 0x0000 = radiotap revision/pad; 0x0008 = len 8 (minimal); no fields.     */
static const uint8_t MOCK_FRAME[] = {
    /* RadioTap header: revision=0, pad=0, len=8, present=0x0000 */
    0x00, 0x00, 0x08, 0x00,   0x00, 0x00, 0x00, 0x00,
    /* 802.11 frame: FC=0x8000 (beacon), Duration=0x0000 */
    0x80, 0x00, 0x00, 0x00,
    /* DA: ff:ff:ff:ff:ff:ff (broadcast) */
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    /* SA: 02:00:00:de:ad:01 (locally-administered stub) */
    0x02, 0x00, 0x00, 0xde, 0xad, 0x01,
    /* BSSID: same as SA */
    0x02, 0x00, 0x00, 0xde, 0xad, 0x01,
    /* Seq-ctrl */
    0x00, 0x00,
    /* Beacon fixed params: timestamp=0 */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    /* Beacon interval: 100 TU */
    0x64, 0x00,
    /* Capability: ESS */
    0x01, 0x04,
    /* SSID IE: "mock-drone" */
    0x00, 0x0a,
    0x6d, 0x6f, 0x63, 0x6b, 0x2d, 0x64, 0x72, 0x6f, 0x6e, 0x65,
};
static const size_t MOCK_FRAME_LEN = sizeof(MOCK_FRAME);

/* ── Ring buffer helpers ──────────────────────────────────────────────────── */

/* Number of bytes currently used in the ring */
static uint32_t ring_used(const daemon_t *d)
{
    return (d->ring_head - d->ring_tail) & RING_MASK;
}

/* Number of bytes free */
static uint32_t ring_free(const daemon_t *d)
{
    return RING_BYTES - ring_used(d) - 1u;
}

/*
 * ring_drop_one_slot — Advance ring_tail past one slot.
 * Called when the ring is full and we must make room.
 */
static void ring_drop_one_slot(daemon_t *d)
{
    slot_hdr_t hdr;
    uint32_t   tail = d->ring_tail;
    uint32_t   i;

    /* Read slot header from ring (may wrap) */
    for (i = 0; i < sizeof(hdr); i++) {
        ((uint8_t *)&hdr)[i] = d->ring_buf[(tail + i) & RING_MASK];
    }
    /* Advance past slot: header + frame bytes + alignment padding */
    {
        uint32_t slot_sz = (uint32_t)sizeof(slot_hdr_t) + hdr.frame_bytes;
        /* align to 4 bytes */
        slot_sz = (slot_sz + 3u) & ~3u;
        d->ring_tail = (tail + slot_sz) & RING_MASK;
    }
    d->frames_dropped++;
    d->ring_overruns++;
}

/*
 * ring_push_frame — Write a frame into the ring buffer.
 * Returns 0 on success, -1 if dropped after drop-oldest policy.
 */
static int ring_push_frame(daemon_t *d, const uint8_t *frame, uint16_t flen)
{
    slot_hdr_t hdr;
    uint32_t   slot_sz;
    uint32_t   i;
    uint32_t   head;

    if (flen == 0 || flen > FRAME_SLOT_MAX - sizeof(slot_hdr_t)) {
        d->frames_dropped++;
        return -1;
    }

    hdr.frame_bytes = flen;
    hdr._pad        = 0;

    slot_sz = (uint32_t)sizeof(slot_hdr_t) + flen;
    slot_sz = (slot_sz + 3u) & ~3u;  /* 4-byte align */

    /* Drop oldest slots until we have room (max loop: ring is finite) */
    while (ring_free(d) < slot_sz) {
        ring_drop_one_slot(d);
    }

    head = d->ring_head;

    /* Write slot header (byte-by-byte for wrap safety) */
    for (i = 0; i < sizeof(hdr); i++) {
        d->ring_buf[(head + i) & RING_MASK] = ((uint8_t *)&hdr)[i];
    }
    head = (head + sizeof(hdr)) & RING_MASK;

    /* Write frame bytes */
    for (i = 0; i < flen; i++) {
        d->ring_buf[(head + i) & RING_MASK] = frame[i];
    }
    head = (head + flen) & RING_MASK;

    /* Padding */
    {
        uint32_t pad = (slot_sz - sizeof(slot_hdr_t) - flen);
        for (i = 0; i < pad; i++) {
            d->ring_buf[(head + i) & RING_MASK] = 0;
        }
        head = (head + pad) & RING_MASK;
    }

    d->ring_head = head;
    d->frames_captured++;
    return 0;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int capture_open(daemon_t *d)
{
    struct sockaddr_ll sll;
    struct ifreq       ifr;
    int                fd;
    int                val;

    if (d->mock_mode) { return 0; }

    fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        util_log("capture", "socket(AF_PACKET) failed: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking */
    val = fcntl(fd, F_GETFL, 0);
    if (val < 0 || fcntl(fd, F_SETFL, val | O_NONBLOCK) < 0) {
        util_log("capture", "fcntl non-block failed: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Resolve interface index */
    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", d->wlan_iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        util_log("capture", "SIOCGIFINDEX %s: %s",
                 d->wlan_iface, strerror(errno));
        close(fd);
        return -1;
    }

    /* Bind to interface */
    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        util_log("capture", "bind AF_PACKET: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* §2.1: Expand kernel receive buffer to 256 KiB to absorb bursts */
    {
        int rcvbuf = 262144;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
            util_log("capture", "SO_RCVBUF: %s (non-fatal)", strerror(errno));
        }
    }

    d->pkt_fd = fd;
    util_log("capture", "AF_PACKET socket bound to %s (fd=%d)",
             d->wlan_iface, fd);
    return 0;
}

void capture_close(daemon_t *d)
{
    if (d->pkt_fd >= 0) {
        close(d->pkt_fd);
        d->pkt_fd = -1;
    }
}

/*
 * capture_read_frame — Attempt to read one frame from the packet socket
 * and push it into the ring buffer.
 *
 * Returns:
 *   1  — frame read and pushed (or mock frame generated)
 *   0  — no frame available (EAGAIN/EWOULDBLOCK)
 *  -1  — error
 */
int capture_read_frame(daemon_t *d)
{
    static uint8_t frame_buf[FRAME_SLOT_MAX];
    ssize_t        n;

    if (d->mock_mode) {
        /* Generate one synthetic frame (caller throttles rate) */
        if (MOCK_FRAME_LEN > FRAME_SLOT_MAX - sizeof(slot_hdr_t)) {
            return -1;
        }
        ring_push_frame(d, MOCK_FRAME, (uint16_t)MOCK_FRAME_LEN);
        return 1;
    }

    for (;;) {
        n = recv(d->pkt_fd, frame_buf, sizeof(frame_buf), MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR)              { continue; }
            if (errno == EAGAIN || errno == EWOULDBLOCK) { return 0; }
            util_log("capture", "recv: %s", strerror(errno));
            return -1;
        }
        break;
    }

    if (n < 8) {
        /* Too short to be a valid RadioTap + 802.11 frame; discard */
        return 0;
    }

    ring_push_frame(d, frame_buf, (uint16_t)n);
    return 1;
}

/*
 * capture_ring_pop — Pop one frame from the ring into buf (for stream.c).
 * Returns frame length, 0 if ring empty, -1 on error.
 * (Called from stream.c via inline access — exposed via this translation unit
 *  to keep the ring buffer private.)
 */
int capture_ring_pop(daemon_t *d, uint8_t *buf, size_t bufsize,
                     uint16_t *frame_len_out)
{
    slot_hdr_t hdr;
    uint32_t   tail;
    uint32_t   i;
    uint32_t   slot_sz;

    if (!buf || !frame_len_out) { return -1; }
    *frame_len_out = 0;

    if (ring_used(d) == 0) { return 0; }  /* empty */

    tail = d->ring_tail;

    /* Read header */
    for (i = 0; i < sizeof(hdr); i++) {
        ((uint8_t *)&hdr)[i] = d->ring_buf[(tail + i) & RING_MASK];
    }
    tail = (tail + sizeof(hdr)) & RING_MASK;

    if (hdr.frame_bytes == 0 || hdr.frame_bytes > bufsize) {
        /* Corrupt slot — reset ring */
        util_log("capture", "corrupt ring slot %u bytes; resetting ring",
                 hdr.frame_bytes);
        d->ring_tail = d->ring_head;
        return -1;
    }

    /* Read frame bytes */
    for (i = 0; i < hdr.frame_bytes; i++) {
        buf[i] = d->ring_buf[(tail + i) & RING_MASK];
    }
    tail = (tail + hdr.frame_bytes) & RING_MASK;

    /* Skip alignment padding */
    slot_sz = ((uint32_t)sizeof(slot_hdr_t) + hdr.frame_bytes + 3u) & ~3u;
    {
        uint32_t pad = slot_sz - sizeof(slot_hdr_t) - hdr.frame_bytes;
        tail = (tail + pad) & RING_MASK;
    }

    d->ring_tail   = tail;
    *frame_len_out = hdr.frame_bytes;
    return (int)hdr.frame_bytes;
}

/* §2.4: Query kernel PACKET_STATISTICS for hardware-level drop counter.
 * Returns kernel drop count, or -1 if unavailable. */
int capture_get_kernel_drops(daemon_t *d, uint32_t *tp_drops_out)
{
    struct tpacket_stats stats;
    socklen_t            slen = sizeof(stats);

    if (!tp_drops_out) { return -1; }
    *tp_drops_out = 0;

    if (d->mock_mode || d->pkt_fd < 0) { return 0; }

    if (getsockopt(d->pkt_fd, SOL_PACKET, PACKET_STATISTICS,
                   &stats, &slen) < 0) {
        return -1;
    }
    *tp_drops_out = stats.tp_drops;
    return 0;
}
