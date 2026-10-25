/*
 * control.c — TCP control channel (port 4444): JSON command dispatcher.
 *
 * Single-client accept; newline-delimited JSON.
 * Supports challenge-response HMAC-SHA256 authentication (§4.1):
 *   - GET_CHALLENGE -> returns per-session 32-hex-char nonce
 *   - AUTH          -> verifies HMAC-SHA256(psk, nonce)
 * All commands per api_reference.md implemented.
 * Unknown command -> INVALID_COMMAND, never crash.
 * Partial read handling: accumulate into line buffer until '\n'.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <time.h>

/* ── Partial-read accumulation buffer (per control client) ────────────────── */
static char s_linebuf[JSON_BUF_LEN];
static int  s_linelen;

/* ── Non-blocking Injection TX socket (AF_PACKET) (§3.3) ────────────────── */

static int tx_open(daemon_t *d)
{
    struct sockaddr_ll sll;
    struct ifreq       ifr;
    int                fd;
    int                flags;

    if (d->tx_fd >= 0) { return 0; }
    if (d->mock_mode) { return 0; }

    fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        util_log("inject", "socket(AF_PACKET): %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking mode on injection socket */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }

    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", d->wlan_iface);
    if (ioctl(fd, SIOCGIFINDEX, &ifr) < 0) {
        util_log("inject", "SIOCGIFINDEX: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&sll, 0, sizeof(sll));
    sll.sll_family   = AF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex  = ifr.ifr_ifindex;

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        util_log("inject", "bind: %s", strerror(errno));
        close(fd);
        return -1;
    }

    d->tx_fd = fd;
    return 0;
}

static void tx_close(daemon_t *d)
{
    if (d->tx_fd >= 0) {
        close(d->tx_fd);
        d->tx_fd = -1;
    }
    memset(&d->tx_q, 0, sizeof(d->tx_q));
}

/*
 * tx_queue_drain_step — Drain one frame from the TX queue non-blockingly.
 * Returns 1 on frame transmitted, 0 if queue empty or socket full, -1 on drop.
 */
int tx_queue_drain_step(daemon_t *d)
{
    tx_slot_t *slot;
    ssize_t    n;

    if (d->tx_q.count == 0) { return 0; }

    slot = &d->tx_q.slots[d->tx_q.tail];

    if (d->mock_mode) {
        d->tx_q.tail = (d->tx_q.tail + 1u) % TX_QUEUE_MAX;
        d->tx_q.count--;
        return 1;
    }

    if (d->tx_fd < 0) { return -1; }

    do {
        n = send(d->tx_fd, slot->frame, slot->len, MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);

    if (n >= 0) {
        d->tx_q.tail = (d->tx_q.tail + 1u) % TX_QUEUE_MAX;
        d->tx_q.count--;
        return 1;
    }

    if (errno == ENOBUFS || errno == EAGAIN || errno == EWOULDBLOCK) {
        slot->retries++;
        if (slot->retries > TX_RETRY_COUNT) {
            d->inject_failures++;
            d->tx_q.tail = (d->tx_q.tail + 1u) % TX_QUEUE_MAX;
            d->tx_q.count--;
            return -1;
        }
        return 0;
    }

    /* Self-heal TX socket if interface bounced (§4.2) */
    if (errno == ENETDOWN || errno == ENODEV || errno == ENXIO) {
        close(d->tx_fd);
        d->tx_fd = -1;
        (void)tx_open(d);
    }

    /* Unrecoverable error for this slot */
    d->inject_failures++;
    d->tx_q.tail = (d->tx_q.tail + 1u) % TX_QUEUE_MAX;
    d->tx_q.count--;
    return -1;
}

/* ── Hex decode helper ────────────────────────────────────────────────────── */

static int hex_decode(const char *hex, uint8_t *out, size_t outsize,
                      size_t *outlen)
{
    size_t hlen;
    size_t i;

    if (!hex || !out || !outlen) { return -1; }
    hlen = strlen(hex);
    if (hlen % 2 != 0) { return -1; }          /* odd nibble count */
    if (hlen / 2 > outsize) { return -1; }     /* would overflow   */

    for (i = 0; i < hlen; i += 2) {
        unsigned int hi, lo;
        char h = hex[i], l = hex[i + 1];

        if (h >= '0' && h <= '9') { hi = (unsigned int)(h - '0'); }
        else if (h >= 'a' && h <= 'f') { hi = (unsigned int)(h - 'a' + 10); }
        else if (h >= 'A' && h <= 'F') { hi = (unsigned int)(h - 'A' + 10); }
        else { return -1; }

        if (l >= '0' && l <= '9') { lo = (unsigned int)(l - '0'); }
        else if (l >= 'a' && l <= 'f') { lo = (unsigned int)(l - 'a' + 10); }
        else if (l >= 'A' && l <= 'F') { lo = (unsigned int)(l - 'A' + 10); }
        else { return -1; }

        out[i / 2] = (uint8_t)((hi << 4) | lo);
    }
    *outlen = hlen / 2;
    return 0;
}

/* ── Response builders ────────────────────────────────────────────────────── */

static void send_ok(daemon_t *d, const char *id, const char *data_json)
{
    char buf[JSON_BUF_LEN];
    (void)snprintf(buf, sizeof(buf),
        "{\"id\":\"%s\",\"status\":\"ok\",\"data\":%s}\n",
        id, data_json);
    ctrl_send(d, buf);
}

static void send_error(daemon_t *d, const char *id,
                       const char *code, const char *msg)
{
    char buf[JSON_BUF_LEN];
    (void)snprintf(buf, sizeof(buf),
        "{\"id\":\"%s\",\"status\":\"error\","
        "\"error\":{\"code\":\"%s\",\"message\":\"%s\"}}\n",
        id, code, msg);
    ctrl_send(d, buf);
}

/* ── Monitor teardown ─────────────────────────────────────────────────────── */

/* Bounded window given to queued injection frames before teardown (§deauth) */
#define TX_FLUSH_MAX_MS   2000
/* Driver settle time after the queue is empty, before the radio is touched   */
#define TX_SETTLE_MS      100

/*
 * tx_queue_flush_wait — Give pending injection frames a bounded window to
 * leave the air, then drop whatever is left. Tearing the interface down while
 * frames are still queued for paced transmission is the one sequence mt76x8
 * does not tolerate: the drone ends up restarting right after a deauth burst
 * that is followed by an immediate client disconnect.
 */
static void tx_queue_flush_wait(daemon_t *d, int max_wait_ms)
{
    int64_t deadline = util_monotonic_ms() + max_wait_ms;

    while (d->tx_q.count > 0) {
        if (!d->mock_mode && d->tx_fd < 0) { break; }  /* no socket: drop */
        if (util_monotonic_ms() >= deadline) { break; }
        (void)tx_queue_drain_step(d);
        util_sleep_ms(2);
    }
    memset(&d->tx_q, 0, sizeof(d->tx_q));
}

/*
 * ctrl_teardown_monitor — Shared teardown path for STOP_MONITOR,
 * RESTORE_NORMAL, REBOOT, control-client disconnect and SIGTERM. Drains
 * pending injection frames, gives the driver a short settle window, then
 * closes the capture/stream/injection sockets and restores the radio mode.
 */
void ctrl_teardown_monitor(daemon_t *d)
{
    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING
        && d->radio_mode != RADIO_MONITOR) { return; }

    d->hop_enabled = false;
    tx_queue_flush_wait(d, TX_FLUSH_MAX_MS);
    util_sleep_ms(TX_SETTLE_MS);
    capture_close(d);
    stream_close(d);
    tx_close(d);
    util_sleep_ms(150);
    if (radio_exit_monitor(d) < 0) {
        util_log("ctrl", "monitor teardown: radio_exit_monitor partial failure");
    }
}

/* ── Challenge-Response Authentication (§4.1) ─────────────────────────────── */

static void cmd_get_challenge(daemon_t *d, const char *id)
{
    char data[128];

    /* Regenerate fresh nonce on every challenge request */
    if (util_random_hex(d->auth_nonce, 32) < 0) {
        (void)snprintf(d->auth_nonce, sizeof(d->auth_nonce),
                       "%016llx%016llx",
                       (unsigned long long)util_monotonic_us(),
                       (unsigned long long)d->frames_captured);
    }

    (void)snprintf(data, sizeof(data),
        "{\"nonce\":\"%s\",\"auth_required\":%s}",
        d->auth_nonce,
        d->psk_required ? "true" : "false");
    send_ok(d, id, data);
}

static void cmd_auth(daemon_t *d, const char *id, const char *params)
{
    char hmac_in[128];
    char expected[65];
    size_t i;
    uint8_t diff = 0;

    if (!d->psk_required) {
        d->client_authed = true;
        send_ok(d, id, "{\"authenticated\":true}");
        return;
    }

    if (json_get_str(params, "hmac", hmac_in, sizeof(hmac_in)) < 0
        || strlen(hmac_in) != 64u) {
        send_error(d, id, "AUTH_FAILED", "Missing or invalid 64-char hex HMAC");
        return;
    }

    util_hmac_sha256_hex(d->psk, d->auth_nonce, expected);

    /* Constant-time case-insensitive hex comparison */
    for (i = 0; i < 64u; i++) {
        unsigned char a = (unsigned char)tolower((unsigned char)hmac_in[i]);
        unsigned char b = (unsigned char)expected[i];
        diff |= (uint8_t)(a ^ b);
    }

    /* Rotate nonce immediately to prevent replay */
    (void)util_random_hex(d->auth_nonce, 32);

    if (diff != 0) {
        d->client_authed = false;
        send_error(d, id, "AUTH_FAILED", "HMAC verification failed");
        return;
    }

    d->client_authed = true;
    send_ok(d, id, "{\"authenticated\":true}");
}

/* ── Command handlers ─────────────────────────────────────────────────────── */

static void cmd_get_status(daemon_t *d, const char *id)
{
    char     data[896];
    char     drone_id[32];
    int      cpu_temp = 0;
    int64_t  free_ram = 0;
    int      uptime;
    uint32_t kernel_drops = 0;

    (void)snprintf(drone_id, sizeof(drone_id), "pwn4c-%02x%02x",
                   d->base_mac[4], d->base_mac[5]);

    util_cpu_temp(&cpu_temp);
    util_free_ram_bytes(&free_ram);
    uptime = (int)(util_monotonic_sec() - d->start_sec);
    (void)capture_get_kernel_drops(d, &kernel_drops);

    (void)snprintf(data, sizeof(data),
        "{"
        "\"state\":\"%s\","
        "\"channel\":%d,"
        "\"monitor_active\":%s,"
        "\"tx_queue_depth\":%d,"
        "\"tx_queue_max\":%u,"
        "\"uptime_seconds\":%d,"
        "\"cpu_temp_celsius\":%d,"
        "\"free_ram_bytes\":%lld,"
        "\"firmware_version\":\"%s\","
        "\"drone_id\":\"%s\","
        "\"rx_frames\":%llu,"
        "\"tx_frames\":%llu,"
        "\"ring_overruns\":%llu,"
        "\"inject_failures\":%llu,"
        "\"kernel_drops\":%lu,"
        "\"iface_recoveries\":%llu"
        "}",
        d->state == STATE_MONITORING || d->state == STATE_INJECTING
            ? "monitor" : "idle",
        d->channel,
        (d->state == STATE_MONITORING || d->state == STATE_INJECTING)
            ? "true" : "false",
        (int)d->tx_q.count,
        TX_QUEUE_MAX,
        uptime,
        cpu_temp,
        (long long)free_ram,
        DAEMON_VERSION,
        drone_id,
        (unsigned long long)d->frames_captured,
        (unsigned long long)d->stream_seq,
        (unsigned long long)d->ring_overruns,
        (unsigned long long)d->inject_failures,
        (unsigned long)kernel_drops,
        (unsigned long long)d->iface_recoveries
    );
    send_ok(d, id, data);
}

static void cmd_start_monitor(daemon_t *d, const char *id, const char *params)
{
    int  channel = 1;
    char ht_mode[16];
    char data[128];
    char stream_target[48];

    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        send_error(d, id, "ALREADY_MONITORING",
                   "Monitor mode is already active");
        return;
    }

    /* Optional channel param */
    if (json_get_int(params, "channel", &channel) < 0) { channel = 1; }
    if (channel < CHAN_MIN || channel > CHAN_MAX) {
        send_error(d, id, "INVALID_CHANNEL",
                   "Channel outside allowed range (1-13)");
        return;
    }

    /* ht_mode: only HT20 supported; warn if other requested but continue */
    if (json_get_str(params, "ht_mode", ht_mode, sizeof(ht_mode)) == 0) {
        if (strcmp(ht_mode, "HT20") != 0) {
            util_log("ctrl", "ht_mode %s unsupported; forcing HT20", ht_mode);
        }
    }

    /* Enter monitor mode */
    if (radio_enter_monitor(d, channel) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to configure monitor mode");
        return;
    }

    /* Open capture socket */
    if (capture_open(d) < 0) {
        (void)radio_exit_monitor(d);
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to open capture socket");
        return;
    }

    /* Open stream socket */
    if (stream_open(d) < 0) {
        d->hop_enabled = false;
        capture_close(d);
        (void)radio_exit_monitor(d);
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to open stream socket");
        return;
    }

    /* Record monitor start time for timestamp_us */
    util_clock_gettime_sec(&d->monitor_start_sec, &d->monitor_start_nsec);
    d->state          = STATE_MONITORING;
    d->channel        = channel;
    d->frames_captured = 0;
    d->frames_dropped  = 0;
    d->stream_seq      = 0;

    /* Apply BPF frame filter if requested in start params (§3.4) */
    {
        int mgmt_only = 0;
        char bssid_str[32];
        uint8_t bssid[6];
        bool has_bssid = false;

        (void)json_get_int(params, "mgmt_only", &mgmt_only);
        if (json_get_str(params, "bssid", bssid_str, sizeof(bssid_str)) == 0) {
            if (util_parse_mac(bssid_str, bssid) == 0) {
                has_bssid = true;
            }
        }
        if (mgmt_only || has_bssid) {
            (void)capture_set_filter(d, mgmt_only != 0, has_bssid ? bssid : NULL);
        }
    }

    /* Build stream target string for response */
    {
        struct in_addr ia;
        ia.s_addr = d->host_ip;
        (void)snprintf(stream_target, sizeof(stream_target), "%s:%d",
                       inet_ntoa(ia), STREAM_PORT);
    }

    (void)snprintf(data, sizeof(data),
        "{\"monitor_active\":true,\"channel\":%d,\"stream_target\":\"%s\"}",
        channel, stream_target);
    send_ok(d, id, data);
}

static void cmd_stop_monitor(daemon_t *d, const char *id)
{
    char data[128];

    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) {
        send_error(d, id, "NOT_MONITORING",
                   "Monitor mode is not active");
        return;
    }

    ctrl_teardown_monitor(d);

    d->state = STATE_CONNECTED;

    (void)snprintf(data, sizeof(data),
        "{\"monitor_active\":false,"
        "\"frames_captured\":%llu,"
        "\"frames_dropped\":%llu}",
        (unsigned long long)d->frames_captured,
        (unsigned long long)d->frames_dropped);
    send_ok(d, id, data);
}

static void cmd_restore_normal(daemon_t *d, const char *id)
{
    char data[64];

    ctrl_teardown_monitor(d);

    if (radio_restore_normal(d) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to restore normal radio mode");
        return;
    }

    d->state = STATE_CONNECTED;

    (void)snprintf(data, sizeof(data),
        "{\"mode\":\"normal\",\"monitor_active\":false}");
    send_ok(d, id, data);
}

static void cmd_set_channel(daemon_t *d, const char *id, const char *params)
{
    int   channel = 0;
    char  data[64];
    int64_t t_before, t_after;
    int   elapsed_ms;

    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) {
        send_error(d, id, "NOT_MONITORING",
                   "Monitor mode is not active");
        return;
    }

    if (json_get_int(params, "channel", &channel) < 0) {
        send_error(d, id, "INVALID_PARAMS", "Missing channel parameter");
        return;
    }
    if (channel < CHAN_MIN || channel > CHAN_MAX) {
        send_error(d, id, "INVALID_CHANNEL",
                   "Channel outside allowed range (1-13)");
        return;
    }

    t_before = util_monotonic_us();

    if (radio_set_channel(d, channel) < 0) {
        send_error(d, id, "INTERFACE_ERROR", "Channel switch failed");
        return;
    }

    t_after    = util_monotonic_us();
    elapsed_ms = (int)((t_after - t_before) / 1000LL);
    if (elapsed_ms < 0) { elapsed_ms = 0; }

    (void)snprintf(data, sizeof(data),
        "{\"channel\":%d,\"switch_time_ms\":%d}", channel, elapsed_ms);
    send_ok(d, id, data);
}

static void cmd_hop_start(daemon_t *d, const char *id, const char *params)
{
    int channels[CHAN_MAX];
    size_t chan_cnt = 0;
    int dwell_ms = 250;
    char data[128];
    size_t i;

    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) {
        send_error(d, id, "NOT_MONITORING",
                   "Monitor mode must be active before starting channel hopper");
        return;
    }

    (void)json_get_int(params, "dwell_ms", &dwell_ms);
    if (dwell_ms < 50) { dwell_ms = 50; }
    if (dwell_ms > 60000) { dwell_ms = 60000; }

    if (json_get_int_array(params, "channels", channels, CHAN_MAX, &chan_cnt) < 0
        || chan_cnt == 0) {
        /* Default: all 13 channels */
        chan_cnt = 13;
        for (i = 0; i < 13; i++) {
            channels[i] = (int)(i + 1);
        }
    } else {
        for (i = 0; i < chan_cnt; i++) {
            if (channels[i] < CHAN_MIN || channels[i] > CHAN_MAX) {
                send_error(d, id, "INVALID_CHANNEL",
                           "Channel outside allowed range (1-13)");
                return;
            }
        }
    }

    d->hop_channel_count = (int)chan_cnt;
    for (i = 0; i < chan_cnt; i++) {
        d->hop_channels[i] = channels[i];
    }
    d->hop_interval_ms = dwell_ms;
    d->hop_index = 0;
    d->hop_enabled = true;
    d->next_hop_ms = util_monotonic_ms() + (int64_t)d->hop_interval_ms;

    /* Immediately tune to first hopping channel */
    (void)radio_set_channel(d, d->hop_channels[0]);

    (void)snprintf(data, sizeof(data),
        "{\"hop_active\":true,\"dwell_ms\":%d,\"channel_count\":%d,\"current_channel\":%d}",
        d->hop_interval_ms, d->hop_channel_count, d->channel);
    send_ok(d, id, data);
}

static void cmd_hop_stop(daemon_t *d, const char *id)
{
    char data[64];
    d->hop_enabled = false;
    (void)snprintf(data, sizeof(data), "{\"hop_active\":false,\"channel\":%d}", d->channel);
    send_ok(d, id, data);
}

static void cmd_set_filter(daemon_t *d, const char *id, const char *params)
{
    char bssid_str[32];
    uint8_t bssid[6];
    bool has_bssid = false;
    int mgmt_only = 0;
    int reset = 0;
    char data[128];

    (void)json_get_int(params, "reset", &reset);
    if (reset) {
        (void)capture_set_filter(d, false, NULL);
        send_ok(d, id, "{\"filter_active\":false}");
        return;
    }

    (void)json_get_int(params, "mgmt_only", &mgmt_only);

    if (json_get_str(params, "bssid", bssid_str, sizeof(bssid_str)) == 0) {
        if (util_parse_mac(bssid_str, bssid) < 0) {
            send_error(d, id, "INVALID_BSSID", "Malformed BSSID MAC address");
            return;
        }
        has_bssid = true;
    }

    if (capture_set_filter(d, mgmt_only != 0, has_bssid ? bssid : NULL) < 0) {
        send_error(d, id, "FILTER_ERROR", "Failed to attach BPF filter");
        return;
    }

    (void)snprintf(data, sizeof(data),
        "{\"filter_active\":%s,\"mgmt_only\":%s,\"bssid_filtered\":%s}",
        d->filter_active ? "true" : "false",
        d->filter_mgmt_only ? "true" : "false",
        d->filter_bssid_set ? "true" : "false");
    send_ok(d, id, data);
}

static void cmd_send_injection(daemon_t *d, const char *id, const char *params)
{
    static char      frame_hex[4096];
    static uint8_t   frame_bin[2048];
    int              count       = 1;
    int              interval_ms = 0;
    size_t           frame_len   = 0;
    int              sent        = 0;
    int              queued      = 0;
    int              failed      = 0;
    int              i;
    char             data[128];

    if (d->state != STATE_MONITORING && d->state != STATE_INJECTING) {
        send_error(d, id, "NOT_MONITORING",
                   "Monitor mode must be active for injection");
        return;
    }

    if (json_get_str(params, "frame_hex", frame_hex, sizeof(frame_hex)) < 0) {
        send_error(d, id, "INVALID_PARAMS", "Missing frame_hex parameter");
        return;
    }

    if (hex_decode(frame_hex, frame_bin, sizeof(frame_bin), &frame_len) < 0
        || frame_len < 8) {
        send_error(d, id, "INVALID_FRAME",
                   "frame_hex is malformed or too short");
        return;
    }

    (void)json_get_int(params, "count", &count);
    (void)json_get_int(params, "interval_ms", &interval_ms);

    if (count < 1)  { count = 1; }
    if (count > 256) { count = 256; }  /* sanity cap */
    if (interval_ms < 0)     { interval_ms = 0; }
    if (interval_ms > 60000) { interval_ms = 60000; }

    /* Open TX socket lazily */
    if (!d->mock_mode && tx_open(d) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to open injection socket");
        return;
    }

    d->state = STATE_INJECTING;

    /* §3.5.7: pace a new burst; an in-flight burst keeps its original pacing */
    if (d->tx_q.count == 0) {
        d->tx_q.interval_ms = (uint32_t)interval_ms;
        d->tx_q.next_tx_ms  = util_monotonic_ms();
    }

    /* Enqueue frames into non-blocking TX ring (§3.3) */
    for (i = 0; i < count; i++) {
        if (d->tx_q.count >= TX_QUEUE_MAX) {
            failed++;
            d->inject_failures++;
            continue;
        }
        tx_slot_t *slot = &d->tx_q.slots[d->tx_q.head];
        memcpy(slot->frame, frame_bin, frame_len);
        slot->len = (uint16_t)frame_len;
        slot->retries = 0;
        d->tx_q.head = (d->tx_q.head + 1u) % TX_QUEUE_MAX;
        d->tx_q.count++;
        queued++;
    }

    /* Immediate opportunistic non-blocking drain (unpaced bursts only) */
    if (d->tx_q.interval_ms == 0) {
        while (d->tx_q.count > 0) {
            int dr = tx_queue_drain_step(d);
            if (dr > 0) {
                sent++;
            } else {
                break; /* socket buffer full or empty; remainder drained in select loop */
            }
        }
    }

    d->state = STATE_MONITORING;

    if (queued == 0 && failed > 0) {
        send_error(d, id, "TX_QUEUE_FULL",
                   "TX queue saturated");
        return;
    }

    (void)snprintf(data, sizeof(data),
        "{\"frames_sent\":%d,\"frames_queued\":%d,\"frames_failed\":%d}",
        sent, queued - sent, failed);
    send_ok(d, id, data);
}

static void cmd_set_tx_power(daemon_t *d, const char *id, const char *params)
{
    int  dbm = 0;
    char data[32];

    if (json_get_int(params, "power_dbm", &dbm) < 0) {
        send_error(d, id, "INVALID_PARAMS", "Missing power_dbm parameter");
        return;
    }
    if (dbm < 1 || dbm > DAEMON_MAX_TXPWR) {
        send_error(d, id, "INVALID_POWER",
                   "TX power outside 1-20 dBm range");
        return;
    }

    if (radio_set_txpower(d, dbm) < 0) {
        send_error(d, id, "INTERFACE_ERROR", "txpower set failed");
        return;
    }

    (void)snprintf(data, sizeof(data), "{\"power_dbm\":%d}", dbm);
    send_ok(d, id, data);
}

static void cmd_set_mac(daemon_t *d, const char *id, const char *params)
{
    char    macstr[18];
    uint8_t mac[6];
    char    data[32];
    char    result_mac[18];
    int     r;

    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        send_error(d, id, "MONITORING_ACTIVE",
                   "MAC cannot be changed while monitor mode is active");
        return;
    }

    if (json_field_exists(params, "mac")
        && json_get_str(params, "mac", macstr, sizeof(macstr)) == 0) {
        /* Specific MAC requested */
        if (util_parse_mac(macstr, mac) < 0) {
            send_error(d, id, "INVALID_MAC", "Malformed MAC address string");
            return;
        }
    } else {
        /* Random MAC (locally-administered bit set) */
        int urfd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (urfd < 0) {
            send_error(d, id, "INTERNAL_ERROR", "Cannot open /dev/urandom");
            return;
        }
        {
            ssize_t nr;
            do {
                nr = read(urfd, mac, 6);
            } while (nr < 0 && errno == EINTR);
            close(urfd);
            if (nr < 6) {
                send_error(d, id, "INTERNAL_ERROR",
                           "Failed to read random bytes");
                return;
            }
        }
        /* Set locally-administered bit, clear multicast bit */
        mac[0] = (uint8_t)((mac[0] & 0xFEu) | 0x02u);
    }

    r = radio_set_mac(d, mac);
    if (r < 0) {
        send_error(d, id, "INTERFACE_ERROR", "Failed to set MAC address");
        return;
    }

    util_mac_to_str(mac, result_mac, sizeof(result_mac));
    (void)snprintf(data, sizeof(data), "{\"mac\":\"%s\"}", result_mac);
    send_ok(d, id, data);
}

static void cmd_reboot(daemon_t *d, const char *id)
{
    const char *data = "{\"message\":\"Rebooting in 2 seconds\"}";
    send_ok(d, id, data);
    util_sleep_ms(2000);
    ctrl_teardown_monitor(d);
    util_log("ctrl", "REBOOT command — executing reboot");
    (void)util_run_cmd("reboot");
}

static void cmd_get_diagnostics(daemon_t *d, const char *id)
{
    char   data[1024];
    char   kver[64];
    int    uptime;
    int64_t free_bytes   = 0;
    int    cpu_temp      = 0;
    char   wlan_iface[16];

    util_get_kernel_version(kver, sizeof(kver));
    uptime = util_uptime_seconds();
    util_free_ram_bytes(&free_bytes);
    util_cpu_temp(&cpu_temp);
    (void)snprintf(wlan_iface, sizeof(wlan_iface), "%s", d->wlan_iface);

    {
        char lavg[64] = "0.00 0.00 0.00";
        (void)util_read_file("/proc/loadavg", lavg, sizeof(lavg));

        (void)snprintf(data, sizeof(data),
            "{"
            "\"kernel_version\":\"%s\","
            "\"uptime_seconds\":%d,"
            "\"load_average_raw\":\"%s\","
            "\"memory\":{"
                "\"free_bytes\":%lld"
            "},"
            "\"wireless\":{"
                "\"interface\":\"%s\","
                "\"driver\":\"mt76\","
                "\"channel\":%d"
            "}"
            "}",
            kver,
            uptime,
            lavg,
            (long long)free_bytes,
            wlan_iface,
            d->channel
        );
    }
    send_ok(d, id, data);
}

/* ── Wi-Fi management (WIFI_SCAN / WIFI_CONNECT / WIFI_STATUS / DISCONNECT)  */

static void cmd_wifi_scan(daemon_t *d, const char *id, const char *params)
{
    int dwell_ms = 4000;

    (void)json_get_int(params, "dwell_ms", &dwell_ms);

    if (d->mock_mode) {
        char data[512];
        mock_scan_json(data, sizeof(data));
        send_ok(d, id, data);
        return;
    }

    /* Survey response can hold up to SCAN_MAX_NETS entries: static buffer */
    static char scan_json[8192];
    if (scan_run(d, dwell_ms, scan_json, sizeof(scan_json)) < 0) {
        send_error(d, id, "INTERFACE_ERROR", "Wi-Fi survey failed");
        return;
    }
    send_ok(d, id, scan_json);
}

static void cmd_wifi_connect(daemon_t *d, const char *id, const char *params)
{
    char ssid[SCAN_SSID_MAX + 2];
    char psk[80];
    char bssid[32];
    char enc[32];
    char esc_ssid[SCAN_SSID_MAX * 2 + 2];
    char data[160];

    if (d->mock_mode) {
        send_ok(d, id, "{\"connecting\":true,\"mock\":true}");
        return;
    }

    if (json_get_str(params, "ssid", ssid, sizeof(ssid)) < 0
        || ssid[0] == '\0') {
        send_error(d, id, "INVALID_PARAMS", "Missing ssid parameter");
        return;
    }
    (void)json_get_str(params, "psk", psk, sizeof(psk));
    (void)json_get_str(params, "bssid", bssid, sizeof(bssid));
    (void)json_get_str(params, "encryption", enc, sizeof(enc));

    if (wifi_sta_connect(d, ssid, psk, bssid, enc) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to configure the station profile (see logread)");
        return;
    }

    util_json_escape(ssid, esc_ssid, sizeof(esc_ssid));
    (void)snprintf(data, sizeof(data),
        "{\"connecting\":true,\"ssid\":\"%s\"}", esc_ssid);
    send_ok(d, id, data);
}

static void cmd_wifi_status(daemon_t *d, const char *id)
{
    if (d->mock_mode) {
        char data[256];
        mock_sta_status_json(data, sizeof(data));
        send_ok(d, id, data);
        return;
    }

    static char sta_json[512];
    (void)wifi_sta_status(d, sta_json, sizeof(sta_json));
    send_ok(d, id, sta_json);
}

static void cmd_wifi_disconnect(daemon_t *d, const char *id)
{
    if (d->mock_mode) {
        send_ok(d, id, "{\"connected\":false,\"mock\":true}");
        return;
    }

    if (wifi_sta_disconnect(d) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to remove the station profile (see logread)");
        return;
    }
    send_ok(d, id, "{\"connected\":false,\"mode\":\"down\"}");
}

/* ── OTA firmware upgrade (UPGRADE) ───────────────────────────────────────── */

#define UPGRADE_TMP_PATH    "/tmp/pwn4c-upgrade.bin"
#define UPGRADE_MIN_BYTES   (512u * 1024u)
#define UPGRADE_MAX_BYTES   (8u * 1024u * 1024u)

static int hex64_matches(const char *a, const char *b)
{
    size_t i;
    uint8_t diff = 0;

    for (i = 0; i < 64u; i++) {
        diff |= (uint8_t)(tolower((unsigned char)a[i])
                        ^ tolower((unsigned char)b[i]));
    }
    return diff == 0;
}

static void cmd_upgrade(daemon_t *d, const char *id, const char *params)
{
    char        url[256];
    char        sha_hex[80];
    char        sum_out[256];
    char        cmd[640];
    int         expected_size = 0;
    struct stat st;

    if (json_get_str(params, "url", url, sizeof(url)) < 0
        || strncmp(url, "http://", 7) != 0
        || strlen(url) > 200) {
        send_error(d, id, "INVALID_PARAMS",
                   "Missing or malformed url parameter (http://, <=200 chars)");
        return;
    }
    if (json_get_str(params, "sha256", sha_hex, sizeof(sha_hex)) < 0
        || strlen(sha_hex) != 64u) {
        send_error(d, id, "INVALID_PARAMS",
                   "Missing or malformed sha256 parameter (64 hex chars)");
        return;
    }
    if (json_get_int(params, "size", &expected_size) < 0
        || expected_size < (int)UPGRADE_MIN_BYTES
        || expected_size > (int)UPGRADE_MAX_BYTES) {
        send_error(d, id, "INVALID_PARAMS",
                   "Missing or implausible size parameter (512KB-8MB)");
        return;
    }

    if (d->mock_mode) {
        send_ok(d, id,
                "{\"message\":\"mock upgrade accepted (no flash in mock mode)\","
                "\"rebooting\":false}");
        return;
    }

    /* sysupgrade reboots the box: a live capture session ends here anyway */
    ctrl_teardown_monitor(d);

    /* /tmp headroom: the image lands on tmpfs before the flash write */
    {
        struct statvfs vfs;
        if (statvfs("/tmp", &vfs) == 0) {
            int64_t free_bytes = (int64_t)vfs.f_bavail * (int64_t)vfs.f_frsize;
            if (free_bytes < (int64_t)expected_size + 512 * 1024) {
                send_error(d, id, "INTERNAL_ERROR",
                           "Not enough free space in /tmp for the image");
                return;
            }
        }
    }

    util_log("ctrl", "UPGRADE: downloading %s (%d bytes)", url, expected_size);
    (void)util_run_cmd("rm -f " UPGRADE_TMP_PATH);
    (void)snprintf(cmd, sizeof(cmd),
        "uclient-fetch -q -O " UPGRADE_TMP_PATH " '%s' || "
        "wget -q -O " UPGRADE_TMP_PATH " '%s'",
        url, url);
    if (util_run_cmd_timeout(cmd, 180) != 0) {
        (void)util_run_cmd("rm -f " UPGRADE_TMP_PATH);
        send_error(d, id, "UPGRADE_DOWNLOAD_FAILED",
                   "Could not download the image from the host");
        return;
    }

    memset(&st, 0, sizeof(st));
    if (stat(UPGRADE_TMP_PATH, &st) != 0 || st.st_size != (off_t)expected_size) {
        (void)util_run_cmd("rm -f " UPGRADE_TMP_PATH);
        send_error(d, id, "UPGRADE_VERIFY_FAILED",
                   "Downloaded image size mismatch — not flashing");
        return;
    }

    if (util_run_cmd_capture("sha256sum " UPGRADE_TMP_PATH " 2>/dev/null",
                             sum_out, sizeof(sum_out), 60) != 0) {
        (void)util_run_cmd("rm -f " UPGRADE_TMP_PATH);
        send_error(d, id, "UPGRADE_VERIFY_FAILED",
                   "sha256sum unavailable or failed");
        return;
    }

    {
        char got[65];
        size_t i = 0;
        while (i < 64 && sum_out[i] != '\0'
               && ((sum_out[i] >= '0' && sum_out[i] <= '9')
                || (sum_out[i] >= 'a' && sum_out[i] <= 'f')
                || (sum_out[i] >= 'A' && sum_out[i] <= 'F'))) {
            got[i] = sum_out[i];
            i++;
        }
        got[i] = '\0';

        if (i != 64u || !hex64_matches(got, sha_hex)) {
            util_log("ctrl", "UPGRADE: checksum mismatch (got %.16s...)", got);
            (void)util_run_cmd("rm -f " UPGRADE_TMP_PATH);
            send_error(d, id, "UPGRADE_VERIFY_FAILED",
                       "Image checksum mismatch — not flashing");
            return;
        }
    }

    util_log("ctrl", "UPGRADE: image verified, launching sysupgrade");
    send_ok(d, id,
        "{\"message\":\"image verified; flashing now — the drone will reboot "
        "into the new firmware\",\"rebooting\":true}");
    util_sleep_ms(300);
    (void)util_run_detached("sysupgrade " UPGRADE_TMP_PATH);
}

/* ── Public API ───────────────────────────────────────────────────────────── */

int ctrl_setup(daemon_t *d)
{
    struct sockaddr_in addr;
    int                fd;
    int                val;
    int                flags;

    fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        util_log("ctrl", "socket: %s", strerror(errno));
        return -1;
    }

    val = 1;
    (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        util_log("ctrl", "fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(CTRL_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        util_log("ctrl", "bind :4444: %s", strerror(errno));
        close(fd);
        return -1;
    }

    if (listen(fd, 1) < 0) {
        util_log("ctrl", "listen: %s", strerror(errno));
        close(fd);
        return -1;
    }

    d->ctrl_listen_fd = fd;
    util_log("ctrl", "listening on TCP :4444 (fd=%d)", fd);
    return 0;
}

int ctrl_accept(daemon_t *d)
{
    struct sockaddr_in peer;
    socklen_t          peerlen;
    int                cfd;
    int                flags;
    char               peerstr[INET_ADDRSTRLEN];
    static const int   ka_on       = 1;
    static const int   ka_idle     = 10;
    static const int   ka_intvl    = 3;
    static const int   ka_cnt      = 3;

    peerlen = sizeof(peer);
    do {
        cfd = accept(d->ctrl_listen_fd, (struct sockaddr *)&peer, &peerlen);
    } while (cfd < 0 && errno == EINTR);

    if (cfd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { return 0; }
        util_log("ctrl", "accept: %s", strerror(errno));
        return -1;
    }

    if (d->ctrl_client_fd >= 0) {
        util_log("ctrl", "new connection displacing stale client (fd=%d)",
                 d->ctrl_client_fd);
        ctrl_close_client(d);
    }

    flags = fcntl(cfd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
    }

    (void)setsockopt(cfd, SOL_SOCKET,  SO_KEEPALIVE,   &ka_on,    sizeof(ka_on));
    (void)setsockopt(cfd, IPPROTO_TCP, TCP_KEEPIDLE,   &ka_idle,  sizeof(ka_idle));
    (void)setsockopt(cfd, IPPROTO_TCP, TCP_KEEPINTVL,  &ka_intvl, sizeof(ka_intvl));
    (void)setsockopt(cfd, IPPROTO_TCP, TCP_KEEPCNT,    &ka_cnt,   sizeof(ka_cnt));

    d->ctrl_client_fd    = cfd;
    d->host_ip           = peer.sin_addr.s_addr;
    d->state             = STATE_CONNECTED;
    d->client_authed     = !d->psk_required;
    d->last_activity_sec = util_monotonic_sec();
    (void)util_random_hex(d->auth_nonce, 32);

    if (inet_ntop(AF_INET, &peer.sin_addr, peerstr, sizeof(peerstr)) == NULL) {
        (void)snprintf(peerstr, sizeof(peerstr), "?.?.?.?");
    }
    util_log("ctrl", "client connected from %s (fd=%d, auth_req=%s)",
             peerstr, cfd, d->psk_required ? "yes" : "no");

    s_linelen = 0;
    return 1;
}

/*
 * ctrl_handle_line — Dispatch a complete JSON line.
 */
int ctrl_handle_line(daemon_t *d, const char *line)
{
    char cmd[64];
    char id[64];
    char params_buf[JSON_BUF_LEN];
    const char *params;

    d->last_activity_sec = util_monotonic_sec();

    if (json_get_str(line, "command", cmd, sizeof(cmd)) < 0) {
        if (json_get_str(line, "id", id, sizeof(id)) < 0) {
            (void)snprintf(id, sizeof(id), "unknown");
        }
        send_error(d, id, "INVALID_COMMAND", "Missing command field");
        return 0;
    }

    if (json_get_str(line, "id", id, sizeof(id)) < 0) {
        (void)snprintf(id, sizeof(id), "unknown");
    }
    /* Sanitize id */
    {
        size_t ri, wi;
        for (ri = 0, wi = 0; id[ri] != '\0'; ri++) {
            if (id[ri] != '"' && id[ri] != '\\') {
                id[wi++] = id[ri];
            }
        }
        id[wi] = '\0';
    }

    /* Extract params object as raw text */
    params = strstr(line, "\"params\"");
    if (params) {
        params = strchr(params, '{');
    }
    if (params) {
        size_t plen = strlen(params);
        if (plen >= sizeof(params_buf)) { plen = sizeof(params_buf) - 1; }
        memcpy(params_buf, params, plen);
        params_buf[plen] = '\0';
    } else {
        params_buf[0] = '\0';
    }
    params = params_buf;

    util_log("ctrl", "cmd=%s id=%s", cmd, id);

    /* Unauthenticated handshake commands (§4.1) */
    if (strcmp(cmd, "GET_CHALLENGE") == 0) {
        cmd_get_challenge(d, id);
        return 0;
    } else if (strcmp(cmd, "AUTH") == 0) {
        cmd_auth(d, id, params);
        return 0;
    }

    /* Enforce PSK authentication before privileged commands (§4.1) */
    if (d->psk_required && !d->client_authed) {
        send_error(d, id, "AUTH_REQUIRED",
                   "Authentication required: call GET_CHALLENGE and AUTH first");
        return 0;
    }

    if (strcmp(cmd, "GET_STATUS") == 0) {
        cmd_get_status(d, id);
    } else if (strcmp(cmd, "START_MONITOR") == 0) {
        cmd_start_monitor(d, id, params);
    } else if (strcmp(cmd, "STOP_MONITOR") == 0) {
        cmd_stop_monitor(d, id);
    } else if (strcmp(cmd, "RESTORE_NORMAL") == 0) {
        cmd_restore_normal(d, id);
    } else if (strcmp(cmd, "SET_CHANNEL") == 0) {
        cmd_set_channel(d, id, params);
    } else if (strcmp(cmd, "SET_FILTER") == 0) {
        cmd_set_filter(d, id, params);
    } else if (strcmp(cmd, "HOP_START") == 0) {
        cmd_hop_start(d, id, params);
    } else if (strcmp(cmd, "HOP_STOP") == 0) {
        cmd_hop_stop(d, id);
    } else if (strcmp(cmd, "SEND_INJECTION") == 0) {
        cmd_send_injection(d, id, params);
    } else if (strcmp(cmd, "SET_TX_POWER") == 0) {
        cmd_set_tx_power(d, id, params);
    } else if (strcmp(cmd, "SET_MAC") == 0) {
        cmd_set_mac(d, id, params);
    } else if (strcmp(cmd, "REBOOT") == 0) {
        cmd_reboot(d, id);
    } else if (strcmp(cmd, "GET_DIAGNOSTICS") == 0) {
        cmd_get_diagnostics(d, id);
    } else if (strcmp(cmd, "WIFI_SCAN") == 0) {
        cmd_wifi_scan(d, id, params);
    } else if (strcmp(cmd, "WIFI_CONNECT") == 0) {
        cmd_wifi_connect(d, id, params);
    } else if (strcmp(cmd, "WIFI_STATUS") == 0) {
        cmd_wifi_status(d, id);
    } else if (strcmp(cmd, "WIFI_DISCONNECT") == 0) {
        cmd_wifi_disconnect(d, id);
    } else if (strcmp(cmd, "UPGRADE") == 0) {
        cmd_upgrade(d, id, params);
    } else {
        send_error(d, id, "INVALID_COMMAND", "Unknown command name");
    }

    return 0;
}

int ctrl_recv(daemon_t *d)
{
    char   chunk[256];
    ssize_t n;
    int     i;

    if (d->ctrl_client_fd < 0) { return -1; }

    do {
        n = recv(d->ctrl_client_fd, chunk, sizeof(chunk), MSG_DONTWAIT);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { return 0; }
        util_log("ctrl", "recv: %s", strerror(errno));
        ctrl_close_client(d);
        return -1;
    }
    if (n == 0) {
        util_log("ctrl", "client disconnected");
        ctrl_close_client(d);
        return -1;
    }

    for (i = 0; i < (int)n; i++) {
        char c = chunk[i];
        if (c == '\n') {
            if (s_linelen > 0) {
                s_linebuf[s_linelen] = '\0';
                ctrl_handle_line(d, s_linebuf);
                s_linelen = 0;
            }
        } else {
            if (s_linelen < (int)(JSON_BUF_LEN - 1)) {
                s_linebuf[s_linelen++] = c;
            }
        }
    }
    return 1;
}

void ctrl_send(daemon_t *d, const char *json_line)
{
    size_t  len;
    ssize_t sent;
    size_t  off = 0;

    if (d->ctrl_client_fd < 0 || !json_line) { return; }
    len = strlen(json_line);

    while (off < len) {
        do {
            sent = send(d->ctrl_client_fd, json_line + off, len - off, 0);
        } while (sent < 0 && errno == EINTR);

        if (sent < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                util_sleep_ms(1);
                continue;
            }
            util_log("ctrl", "send: %s", strerror(errno));
            ctrl_close_client(d);
            return;
        }
        off += (size_t)sent;
    }
}

void ctrl_close_client(daemon_t *d)
{
    if (d->ctrl_client_fd >= 0) {
        close(d->ctrl_client_fd);
        d->ctrl_client_fd = -1;
    }
    ctrl_teardown_monitor(d);
    util_log("ctrl", "client gone — monitor stopped, radio restored");
    d->state         = STATE_IDLE;
    d->client_authed = false;
    d->host_ip       = 0;
    s_linelen        = 0;
}
