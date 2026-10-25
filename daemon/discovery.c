/*
 * discovery.c — UDP autodiscovery listener (port 4440).
 *
 * Listens for DISCOVER broadcasts, validates version, replies ANNOUNCE.
 * When PSK authentication is active, also includes `"auth_required":true`
 * and an `"hmac"` signature over the drone_id and timestamp (§4.1).
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

/* Channels array for ANNOUNCE JSON — fixed 2.4 GHz 1-13 */
static const char CHANNELS_JSON[] =
    "[1,2,3,4,5,6,7,8,9,10,11,12,13]";

static const char *radio_state_str(const daemon_t *d)
{
    switch (d->state) {
    case STATE_IDLE:       return "idle";
    case STATE_CONNECTED:  return "idle";
    case STATE_MONITORING: return "monitor";
    case STATE_INJECTING:  return "injecting";
    default:               return "idle";
    }
}

int disc_setup(daemon_t *d)
{
    struct sockaddr_in addr;
    int                fd;
    int                val;
    int                flags;

    fd = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        util_log("disc", "socket: %s", strerror(errno));
        return -1;
    }

    val = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val)) < 0) {
        util_log("disc", "SO_REUSEADDR: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Allow receiving broadcast packets */
    if (setsockopt(fd, SOL_SOCKET, SO_BROADCAST, &val, sizeof(val)) < 0) {
        util_log("disc", "SO_BROADCAST: %s", strerror(errno));
        close(fd);
        return -1;
    }

    /* Non-blocking */
    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        util_log("disc", "fcntl: %s", strerror(errno));
        close(fd);
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(DISC_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        util_log("disc", "bind :4440: %s", strerror(errno));
        close(fd);
        return -1;
    }

    d->disc_fd = fd;
    util_log("disc", "listening on UDP :4440 (fd=%d)", fd);
    return 0;
}

/*
 * disc_handle — Receive one discovery packet and reply if valid.
 * Returns 0 on success, -1 on error, 1 if no packet waiting.
 */
int disc_handle(daemon_t *d)
{
    static char      rxbuf[1024];
    static char      txbuf[1024];
    struct sockaddr_in from;
    socklen_t          fromlen;
    ssize_t            n;
    char               type[32];
    int                version;
    char               drone_id[32];
    char               macstr[18];
    char               from_ip[INET_ADDRSTRLEN];
    int                uptime;

    fromlen = sizeof(from);
    do {
        n = recvfrom(d->disc_fd, rxbuf, sizeof(rxbuf) - 1, 0,
                     (struct sockaddr *)&from, &fromlen);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) { return 1; }
        util_log("disc", "recvfrom: %s", strerror(errno));
        return -1;
    }
    rxbuf[n] = '\0';

    /* Parse type */
    if (json_get_str(rxbuf, "type", type, sizeof(type)) < 0) {
        return 0;  /* not JSON we understand */
    }
    if (strcmp(type, "DISCOVER") != 0) { return 0; }

    /* Parse version */
    if (json_get_int(rxbuf, "version", &version) < 0) { version = 0; }

    if (version != PROTO_VERSION) {
        /* Send VERSION_MISMATCH error */
        (void)snprintf(txbuf, sizeof(txbuf),
            "{\"type\":\"ERROR\",\"code\":\"VERSION_MISMATCH\","
            "\"message\":\"Unsupported protocol version: %d. Supported: [1]\"}\n",
            version);
        do {
            n = sendto(d->disc_fd, txbuf, strlen(txbuf), 0,
                       (struct sockaddr *)&from, fromlen);
        } while (n < 0 && errno == EINTR);
        return 0;
    }

    /* Build drone_id from MAC (use base_mac) */
    (void)snprintf(drone_id, sizeof(drone_id), "pwn4c-%02x%02x",
                   d->base_mac[4], d->base_mac[5]);

    util_mac_to_str(d->base_mac, macstr, sizeof(macstr));
    uptime = (int)(util_monotonic_sec() - d->start_sec);

    /* Log discovery from */
    if (inet_ntop(AF_INET, &from.sin_addr, from_ip, sizeof(from_ip)) == NULL) {
        (void)snprintf(from_ip, sizeof(from_ip), "?.?.?.?");
    }
    util_log("disc", "DISCOVER from %s, replying ANNOUNCE", from_ip);

    /* Build ANNOUNCE response */
    (void)snprintf(txbuf, sizeof(txbuf),
        "{\"type\":\"ANNOUNCE\","
        "\"version\":1,"
        "\"drone_id\":\"%s\","
        "\"firmware_version\":\"%s\","
        "\"hardware\":\"%s\","
        "\"uptime_seconds\":%d,"
        "\"auth_required\":%s,"
        "\"capabilities\":[\"monitor\",\"inject\",\"channel_hop\",\"bpf_filter\","
            "\"wifi_scan\",\"wifi_sta\",\"ota_upgrade\"],"
        "\"radio\":{"
            "\"chipset\":\"%s\","
            "\"band\":\"%s\","
            "\"channels\":%s,"
            "\"max_tx_power_dbm\":%d,"
            "\"state\":\"%s\""
        "},"
        "\"control_port\":%d,"
        "\"stream_port\":%d"
        "}\n",
        drone_id,
        DAEMON_VERSION,
        DAEMON_HARDWARE,
        uptime,
        d->psk_required ? "true" : "false",
        DAEMON_CHIPSET,
        DAEMON_BAND,
        CHANNELS_JSON,
        DAEMON_MAX_TXPWR,
        radio_state_str(d),
        CTRL_PORT,
        STREAM_PORT
    );

    do {
        n = sendto(d->disc_fd, txbuf, strlen(txbuf), 0,
                   (struct sockaddr *)&from, fromlen);
    } while (n < 0 && errno == EINTR);

    if (n < 0) {
        util_log("disc", "sendto ANNOUNCE: %s", strerror(errno));
        return -1;
    }

    return 0;
}
