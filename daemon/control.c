/*
 * control.c — TCP control channel (port 4444): JSON command dispatcher.
 *
 * Single-client accept; newline-delimited JSON.
 * All commands per api_reference.md implemented.
 * Unknown command -> INVALID_COMMAND, never crash.
 * Partial read handling: accumulate into line buffer until '\n'.
 *
 * Host IP is derived from the TCP peer address and stored in d->host_ip
 * for use by the stream UDP target.
 *
 * Injection: SEND_INJECTION command decodes hex frame, sends via AF_PACKET
 * with ENOBUFS -> 1ms x10 retry (hardware.md).
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
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>

/* ── Partial-read accumulation buffer (per control client) ────────────────── */
static char s_linebuf[JSON_BUF_LEN];
static int  s_linelen;

/* ── Injection TX socket (AF_PACKET) ─────────────────────────────────────── */
static int  s_tx_fd = -1;

static int tx_open(daemon_t *d)
{
    struct sockaddr_ll sll;
    struct ifreq       ifr;
    int                fd;

    if (s_tx_fd >= 0) { return 0; }
    if (d->mock_mode) { return 0; }

    fd = socket(AF_PACKET, SOCK_RAW | SOCK_CLOEXEC, htons(ETH_P_ALL));
    if (fd < 0) {
        util_log("inject", "socket(AF_PACKET): %s", strerror(errno));
        return -1;
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

    s_tx_fd = fd;
    return 0;
}

static void tx_close(void)
{
    if (s_tx_fd >= 0) {
        close(s_tx_fd);
        s_tx_fd = -1;
    }
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

/* ── Command handlers ─────────────────────────────────────────────────────── */

static void cmd_get_status(daemon_t *d, const char *id)
{
    char data[512];
    char drone_id[32];
    int  cpu_temp = 0;
    int64_t free_ram = 0;
    int  uptime;

    (void)snprintf(drone_id, sizeof(drone_id), "pwn4c-%02x%02x",
                   d->base_mac[4], d->base_mac[5]);

    util_cpu_temp(&cpu_temp);
    util_free_ram_bytes(&free_ram);
    uptime = (int)(util_monotonic_sec() - d->start_sec);

    (void)snprintf(data, sizeof(data),
        "{"
        "\"state\":\"%s\","
        "\"channel\":%d,"
        "\"monitor_active\":%s,"
        "\"tx_queue_depth\":0,"
        "\"tx_queue_max\":64,"
        "\"uptime_seconds\":%d,"
        "\"cpu_temp_celsius\":%d,"
        "\"free_ram_bytes\":%lld,"
        "\"firmware_version\":\"%s\","
        "\"drone_id\":\"%s\""
        "}",
        d->state == STATE_MONITORING || d->state == STATE_INJECTING
            ? "monitor" : "idle",
        d->channel,
        (d->state == STATE_MONITORING || d->state == STATE_INJECTING)
            ? "true" : "false",
        uptime,
        cpu_temp,
        (long long)free_ram,
        DAEMON_VERSION,
        drone_id
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

    capture_close(d);
    stream_close(d);
    tx_close();

    if (radio_exit_monitor(d) < 0) {
        /* Log but still succeed — we've closed sockets */
        util_log("ctrl", "STOP_MONITOR: radio_exit_monitor partial failure");
    }

    d->state = STATE_CONNECTED;

    (void)snprintf(data, sizeof(data),
        "{\"monitor_active\":false,"
        "\"frames_captured\":%llu,"
        "\"frames_dropped\":%llu}",
        (unsigned long long)d->frames_captured,
        (unsigned long long)d->frames_dropped);
    send_ok(d, id, data);
}

/*
 * RESTORE_NORMAL — one-command path back to regular networking.
 * Stops monitor/injection if active, then restores the managed/AP radio
 * (UCI profile is only re-enabled, never rewritten). This is the dual-use
 * escape hatch: the box is always recoverable to normal internet use
 * without serial access.
 */
static void cmd_restore_normal(daemon_t *d, const char *id)
{
    char data[64];

    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        capture_close(d);
        stream_close(d);
        tx_close();
    }

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
    /* integer µs -> ms; max representable ~71 min so no overflow concern */
    elapsed_ms = (int)((t_after - t_before) / 1000LL);
    if (elapsed_ms < 0) { elapsed_ms = 0; }

    (void)snprintf(data, sizeof(data),
        "{\"channel\":%d,\"switch_time_ms\":%d}", channel, elapsed_ms);
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
    int              failed      = 0;
    int              i;
    char             data[64];

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

    /* Open TX socket lazily */
    if (!d->mock_mode && tx_open(d) < 0) {
        send_error(d, id, "INTERFACE_ERROR",
                   "Failed to open injection socket");
        return;
    }

    d->state = STATE_INJECTING;

    for (i = 0; i < count; i++) {
        int retries = 0;
        int ok      = 0;

        if (i > 0 && interval_ms > 0) {
            util_sleep_ms(interval_ms);
        }

        while (retries <= TX_RETRY_COUNT) {
            ssize_t n;

            if (d->mock_mode) {
                /* Simulate TX success */
                ok = 1;
                break;
            }

            do {
                n = send(s_tx_fd, frame_bin, frame_len, 0);
            } while (n < 0 && errno == EINTR);

            if (n >= 0) {
                ok = 1;
                break;
            }

            if (errno == ENOBUFS) {
                /* hardware.md: retry 1ms x10 */
                util_sleep_ms(TX_RETRY_MS);
                retries++;
                continue;
            }

            /* Other error — no retry */
            util_log("inject", "send: %s", strerror(errno));
            break;
        }

        if (ok) { sent++; } else { failed++; }
    }

    d->state = STATE_MONITORING;

    if (failed > 0 && sent == 0) {
        send_error(d, id, "TX_QUEUE_FULL",
                   "TX queue saturated after retries");
        return;
    }

    (void)snprintf(data, sizeof(data),
        "{\"frames_sent\":%d,\"frames_failed\":%d}", sent, failed);
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
        /* Use /dev/urandom for randomness */
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
    /* Flush */
    util_sleep_ms(2000);
    /* Restore radio before reboot */
    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        capture_close(d);
        stream_close(d);
        tx_close();
        (void)radio_exit_monitor(d);
    }
    util_log("ctrl", "REBOOT command — executing reboot");
    (void)util_run_cmd("reboot");
    /* Should not reach here */
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

    /* load_average: we read /proc/loadavg as integers (×100 scale, no float) */
    /* Format: "0.12 0.08 0.03 ..." — we parse as strings and re-emit raw     */
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

    if (listen(fd, 1) < 0) {  /* backlog=1: single client */
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

    if (d->ctrl_client_fd >= 0) {
        /* Already have a client; refuse silently by not accepting */
        return 0;
    }

    peerlen = sizeof(peer);
    do {
        cfd = accept(d->ctrl_listen_fd, (struct sockaddr *)&peer, &peerlen);
    } while (cfd < 0 && errno == EINTR);

    if (cfd < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { return 0; }
        util_log("ctrl", "accept: %s", strerror(errno));
        return -1;
    }

    /* Set non-blocking on client fd */
    flags = fcntl(cfd, F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(cfd, F_SETFL, flags | O_NONBLOCK);
    }

    d->ctrl_client_fd = cfd;
    d->host_ip        = peer.sin_addr.s_addr;  /* network byte order */
    d->state          = STATE_CONNECTED;

    if (inet_ntop(AF_INET, &peer.sin_addr, peerstr, sizeof(peerstr)) == NULL) {
        (void)snprintf(peerstr, sizeof(peerstr), "?.?.?.?");
    }
    util_log("ctrl", "client connected from %s (fd=%d)", peerstr, cfd);

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

    if (json_get_str(line, "command", cmd, sizeof(cmd)) < 0) {
        /* Malformed — try to echo id if present */
        if (json_get_str(line, "id", id, sizeof(id)) < 0) {
            (void)snprintf(id, sizeof(id), "unknown");
        }
        send_error(d, id, "INVALID_COMMAND", "Missing command field");
        return 0;
    }

    if (json_get_str(line, "id", id, sizeof(id)) < 0) {
        (void)snprintf(id, sizeof(id), "unknown");
    }
    /* Sanitize id: it is echoed into JSON responses, so strip characters
     * that would break framing (host-controlled input). */
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
        /* Copy params substring to buffer */
        size_t plen = strlen(params);
        if (plen >= sizeof(params_buf)) { plen = sizeof(params_buf) - 1; }
        memcpy(params_buf, params, plen);
        params_buf[plen] = '\0';
    } else {
        params_buf[0] = '\0';
    }
    params = params_buf;

    util_log("ctrl", "cmd=%s id=%s", cmd, id);

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
    } else {
        send_error(d, id, "INVALID_COMMAND", "Unknown command name");
    }

    return 0;
}

/*
 * ctrl_recv — Non-blocking read from client, accumulate into line buffer.
 * Returns 1 if a complete line was dispatched, 0 if more data needed, -1 err.
 */
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
            /* Complete line */
            if (s_linelen > 0) {
                s_linebuf[s_linelen] = '\0';
                ctrl_handle_line(d, s_linebuf);
                s_linelen = 0;
            }
        } else {
            if (s_linelen < (int)(JSON_BUF_LEN - 1)) {
                s_linebuf[s_linelen++] = c;
            }
            /* else: line too long — discard and reset on next \n */
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
    /* If monitor was active, stop it and restore radio */
    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        capture_close(d);
        stream_close(d);
        tx_close();
        (void)radio_exit_monitor(d);
        util_log("ctrl", "client gone — monitor stopped, radio restored");
    }
    d->state   = STATE_IDLE;
    d->host_ip = 0;
    s_linelen  = 0;
}
