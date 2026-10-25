/*
 * wifi_sta.c — Managed station mode (WIFI_CONNECT / WIFI_STATUS / WIFI_DISCONNECT).
 *
 * Lets the drone join an upstream Wi-Fi network from the control channel:
 * useful for pivoting the implant onto a managed network during an authorized
 * assessment, or for giving the box uplink access in a lab.
 *
 * UCI discipline (extends docs/architecture.md §UCI Profile Safety):
 *   - the stock AP profile (default_radio0) is never modified beyond its
 *     `disabled` flag — the SSID/encryption/key values are never touched
 *   - the station interface is Pwn4C-owned (`pwn4c_sta`), so it is the one
 *     profile the daemon is allowed to create and delete
 *   - the upstream network rides the existing `wan` interface (proto dhcp);
 *     on disconnect everything returns to the boot-safe DOWN state
 *
 * The radio is single-band: while the station is up, monitor mode is not
 * available (and vice versa). WIFI_CONNECT refuses to run while monitor mode
 * is active in another session — the daemon tears its own monitor down first
 * when it owns it.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <ctype.h>

#define STA_IFACE          "pwn4c_sta"
#define STA_CMD_MAX        1400
#define STA_CONNECT_TIMEOUT_SECS  30
#define STA_DISCONNECT_TIMEOUT_SECS 20

/* Allowed UCI encryption values for the station profile */
static const char *STA_ENCRYPTION_OK[] = {
    "psk2", "psk", "sae", "sae-mixed", "psk2-mixed", NULL
};

/* ── Helpers ──────────────────────────────────────────────────────────────── */

/*
 * sh_single_quote — Wrap a value for safe use inside a shell command:
 * 'it'"'"'s' style quoting. Bounded; returns -1 when the buffer is too small.
 */
static int sh_single_quote(const char *in, char *out, size_t outsz)
{
    size_t ri = 0;
    size_t wi = 0;

    if (!in || !out || outsz < 4) { return -1; }
    out[wi++] = '\'';

    while (in[ri] != '\0') {
        if (wi + 5 >= outsz) { return -1; }
        if (in[ri] == '\'') {
            out[wi++] = '\'';
            out[wi++] = '"';
            out[wi++] = '\'';
            out[wi++] = '"';
            out[wi++] = '\'';
        } else {
            out[wi++] = in[ri];
        }
        ri++;
    }

    if (wi + 2 >= outsz) { return -1; }
    out[wi++] = '\'';
    out[wi]   = '\0';
    return 0;
}

static bool sta_encryption_allowed(const char *enc)
{
    size_t i;

    for (i = 0; STA_ENCRYPTION_OK[i] != NULL; i++) {
        if (strcmp(enc, STA_ENCRYPTION_OK[i]) == 0) { return true; }
    }
    return false;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

/*
 * wifi_sta_connect — Create/update the pwn4c_sta profile and bring it up.
 * psk == "" means an open network (encryption none).
 * Returns 0 on success (association completes asynchronously; poll
 * WIFI_STATUS), -1 on failure (message logged).
 */
int wifi_sta_connect(daemon_t *d, const char *ssid, const char *psk,
                     const char *bssid, const char *encryption)
{
    char cmd[STA_CMD_MAX];
    char q_ssid[SCAN_SSID_MAX * 5 + 8];
    char q_psk[64 * 5 + 8];
    char enc[32];
    char piece[512];
    int  r;

    if (!ssid || ssid[0] == '\0' || strlen(ssid) > SCAN_SSID_MAX) { return -1; }
    if (psk && psk[0] != '\0' && (strlen(psk) < 8 || strlen(psk) > 63)) {
        util_log("sta", "WIFI_CONNECT: PSK length must be 8-63 characters");
        return -1;
    }

    /* Encryption selection: default WPA2-PSK, or none for open networks */
    if (!psk || psk[0] == '\0') {
        (void)snprintf(enc, sizeof(enc), "none");
    } else if (encryption && encryption[0] != '\0') {
        if (!sta_encryption_allowed(encryption)) {
            util_log("sta", "WIFI_CONNECT: unsupported encryption '%s'", encryption);
            return -1;
        }
        (void)snprintf(enc, sizeof(enc), "%s", encryption);
    } else {
        (void)snprintf(enc, sizeof(enc), "psk2");
    }

    if (bssid && bssid[0] != '\0') {
        uint8_t mac[6];
        if (util_parse_mac(bssid, mac) < 0) {
            util_log("sta", "WIFI_CONNECT: malformed bssid '%s'", bssid);
            return -1;
        }
    }

    if (sh_single_quote(ssid, q_ssid, sizeof(q_ssid)) < 0) { return -1; }

    /* Monitor mode and station mode are mutually exclusive on this radio */
    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING
        || d->radio_mode == RADIO_MONITOR) {
        util_log("sta", "WIFI_CONNECT: stopping active monitor session first");
        ctrl_teardown_monitor(d);
    }

    (void)snprintf(cmd, sizeof(cmd),
        "uci -q delete wireless.%s; "
        "uci set wireless.%s='wifi-iface'; "
        "uci set wireless.%s.device='radio0'; "
        "uci set wireless.%s.mode='sta'; "
        "uci set wireless.%s.network='wan'; "
        "uci set wireless.%s.disabled='0'; "
        "uci set wireless.%s.ssid=%s",
        STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE, q_ssid);

    if (enc[0] != '\0' && strcmp(enc, "none") != 0) {
        if (sh_single_quote(psk, q_psk, sizeof(q_psk)) < 0) { return -1; }
        (void)snprintf(piece, sizeof(piece),
                       "; uci set wireless.%s.encryption='%s'; "
                       "uci set wireless.%s.key=%s",
                       STA_IFACE, enc, STA_IFACE, q_psk);
        if (strlen(cmd) + strlen(piece) + 1 >= sizeof(cmd)) { return -1; }
        (void)strncat(cmd, piece, sizeof(cmd) - strlen(cmd) - 1);
    }

    if (bssid && bssid[0] != '\0') {
        (void)snprintf(piece, sizeof(piece),
                       "; uci set wireless.%s.bssid='%s'", STA_IFACE, bssid);
        if (strlen(cmd) + strlen(piece) + 1 >= sizeof(cmd)) { return -1; }
        (void)strncat(cmd, piece, sizeof(cmd) - strlen(cmd) - 1);
    }

    (void)snprintf(piece, sizeof(piece),
        "; uci set network.wan.device='phy0-sta0'; "
        "uci set network.wan.proto='dhcp'; "
        "uci set network.wan.auto='1'; "
        "uci set wireless.radio0.disabled='0'; "
        "uci set wireless.default_radio0.disabled='1'; "
        "uci commit wireless; "
        "uci commit network; "
        "sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null; "
        "wifi up; "
        "ifup wan 2>/dev/null; "
        "(sleep 2; udhcpc -i phy0-sta0 -n -q -R 2>/dev/null) &");
    if (strlen(cmd) + strlen(piece) + 1 >= sizeof(cmd)) { return -1; }
    (void)strncat(cmd, piece, sizeof(cmd) - strlen(cmd) - 1);

    r = util_run_cmd_timeout(cmd, STA_CONNECT_TIMEOUT_SECS);
    if (r != 0) {
        util_log("sta", "WIFI_CONNECT: uci/wifi up failed (r=%d)", r);
        return -1;
    }

    d->radio_mode = RADIO_NORMAL;
    util_log("sta", "WIFI_CONNECT: station profile active (ssid=%s, enc=%s)",
             ssid, enc);
    return 0;
}

/*
 * wifi_sta_status — Probe the current station link. Parses `iw dev <wlan>
 * link` for association state and `ifstatus wan` for the IPv4 address.
 * Always writes a valid JSON object into out_json (connected:false on any
 * ambiguity).
 */
int wifi_sta_status(daemon_t *d, char *out_json, size_t outsz)
{
    char link[1024];
    char wan[2048];
    char bssid_str[18] = "";
    char ssid_str[SCAN_SSID_MAX + 1] = "";
    char ip_str[32] = "";
    bool connected = false;
    int  channel   = 0;

    if (util_run_cmd_capture("for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do out=$(iw dev \"$iface\" link 2>/dev/null); if echo \"$out\" | grep -q 'Connected to '; then echo \"$out\"; break; fi; done",
                             link, sizeof(link), 3) == 0) {
        const char *p = strstr(link, "Connected to ");
        if (p) {
            size_t i;
            connected = true;
            p += strlen("Connected to ");
            for (i = 0; i < 17 && p[i] != '\0'; i++) {
                bssid_str[i] = p[i];
            }
            bssid_str[i] = '\0';
        }

        p = strstr(link, "SSID: ");
        if (p) {
            size_t i = 0;
            p += strlen("SSID: ");
            while (p[i] != '\0' && p[i] != '\n' && i < SCAN_SSID_MAX) {
                ssid_str[i] = p[i];
                i++;
            }
            ssid_str[i] = '\0';
        }

        p = strstr(link, "freq: ");
        if (p) {
            int freq = atoi(p + strlen("freq: "));
            if (freq >= 2412 && freq <= 2472) {
                channel = (freq - 2407) / 5;
            } else if (freq == 2484) {
                channel = 14;
            }
        }
    }

    if (util_run_cmd_capture("for dev in phy0-sta0 $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do "
                             "ip=$(ip -4 addr show dev \"$dev\" 2>/dev/null | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1); "
                             "if [ -n \"$ip\" ]; then echo \"$ip\"; break; fi; done",
                             ip_str, sizeof(ip_str), 3) == 0) {
        size_t len = strlen(ip_str);
        while (len > 0 && (ip_str[len - 1] == '\r' || ip_str[len - 1] == '\n')) {
            ip_str[--len] = '\0';
        }
    }
    if (ip_str[0] == '\0' && util_run_cmd_capture("ifstatus wan 2>/dev/null",
                             wan, sizeof(wan), 3) == 0) {
        (void)json_get_str(wan, "address", ip_str, sizeof(ip_str));
    }

    {
        char esc_ssid[SCAN_SSID_MAX * 2 + 2];
        util_json_escape(ssid_str, esc_ssid, sizeof(esc_ssid));
        (void)snprintf(out_json, outsz,
            "{\"connected\":%s,\"ssid\":\"%s\",\"bssid\":\"%s\","
            "\"ip\":\"%s\",\"channel\":%d,\"mode\":\"sta\"}",
            connected ? "true" : "false",
            esc_ssid,
            bssid_str,
            ip_str,
            channel);
    }

    if (connected) {
        d->radio_mode = RADIO_NORMAL;
    }
    return 0;
}

/*
 * wifi_sta_disconnect — Remove the station profile and return the radio to
 * the boot-safe DOWN state (same policy pwn4c-radio enforces at boot).
 */
int wifi_sta_disconnect(daemon_t *d)
{
    int r;

    char cmd[] =
        "uci -q delete wireless." STA_IFACE "; "
        "uci -q set wireless.default_radio0.disabled='0'; "
        "uci set wireless.radio0.disabled='1'; "
        "uci set network.wan.proto='none'; "
        "uci set network.wan.auto='0'; "
        "uci -q delete network.wan.device; "
        "uci commit wireless; "
        "uci commit network; "
        "killall udhcpc 2>/dev/null; "
        "wifi down 2>/dev/null; "
        "ip link set wlan0 down 2>/dev/null; "
        "true";

    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING) {
        ctrl_teardown_monitor(d);
    }

    r = util_run_cmd_timeout(cmd, STA_DISCONNECT_TIMEOUT_SECS);
    if (r != 0) {
        util_log("sta", "WIFI_DISCONNECT: cleanup failed (r=%d)", r);
        return -1;
    }

    d->radio_mode = RADIO_DOWN;
    util_log("sta", "WIFI_DISCONNECT: station profile removed, radio DOWN");
    return 0;
}
