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
#include <stdarg.h>
#include <errno.h>
#include <ctype.h>

#define STA_IFACE          "pwn4c_sta"      /* UCI section name                 */
#define STA_NETDEV         "phy0-sta0"      /* netdev created by mac80211       */
#define STA_CMD_MAX        2048
#define STA_CONNECT_TIMEOUT_SECS  75
#define STA_DISCONNECT_TIMEOUT_SECS 20

/* Allowed UCI encryption values for the station profile */
static const char *STA_ENCRYPTION_OK[] = {
    "psk2", "psk", "sae", "sae-mixed", "psk-mixed", NULL
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

/* Bounded append to a shell-command buffer (returns -1 on overflow). */
static int __attribute__((format(printf, 3, 4)))
cmd_append(char *buf, size_t bufsz, const char *fmt, ...)
{
    size_t used = strlen(buf);
    va_list ap;
    int n;

    if (used >= bufsz) { return -1; }

    va_start(ap, fmt);
    n = vsnprintf(buf + used, bufsz - used, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= bufsz - used) { return -1; }
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

static bool sta_is_hex64(const char *s)
{
    size_t i;

    if (!s || strlen(s) != 64u) { return false; }
    for (i = 0; i < 64u; i++) {
        if (!isxdigit((unsigned char)s[i])) { return false; }
    }
    return true;
}

/*
 * kv_get — Read one "key=value" line from wpa_cli output. wpa_cli -i ...
 * status returns exactly that format. Values may contain '='; only the first
 * one separates key from value.
 */
static int kv_get(const char *text, const char *key, char *out, size_t n)
{
    size_t klen;
    const char *p;

    if (!text || !key || !out || n == 0) { return -1; }
    out[0] = '\0';
    klen = strlen(key);

    p = text;
    while (*p != '\0') {
        const char *eol = strchr(p, '\n');
        size_t linelen = eol ? (size_t)(eol - p) : strlen(p);

        if (linelen > klen && p[klen] == '=' && memcmp(p, key, klen) == 0) {
            size_t vlen = linelen - klen - 1u;
            const char *v = p + klen + 1;
            while (vlen > 0u && v[vlen - 1u] == '\r') { vlen--; }
            if (vlen >= n) { vlen = n - 1u; }
            memcpy(out, v, vlen);
            out[vlen] = '\0';
            return 0;
        }

        if (!eol) { break; }
        p = eol + 1;
    }

    return -1;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

/*
 * wifi_sta_connect — Create/update the pwn4c_sta profile and bring it up.
 * psk == "" means an open network (encryption none).
 *
 * For PSK/PSK2 the passphrase is converted to the 64-hex PSK here. OpenWrt's
 * wpa_supplicant.sh emits a 64-char key as `psk=<hex>` verbatim, so the
 * passphrase never passes through the supplicant's config parser. This fixes
 * keys containing '#', '"', '$', '\' and also avoids the shell-quoting path
 * entirely for those characters.
 *
 * Returns 0 when the profile was applied (association/DHCP complete
 * asynchronously; poll WIFI_STATUS), -1 on configuration failure.
 */
int wifi_sta_connect(daemon_t *d, const char *ssid, const char *psk,
                     const char *bssid, const char *encryption)
{
    char cmd[STA_CMD_MAX];
    char q_ssid[SCAN_SSID_MAX * 5 + 8];
    char q_key[64 * 5 + 8];
    char key[80];
    char enc[32];
    size_t psk_len = 0;
    bool open_net = false;

    if (!ssid || ssid[0] == '\0' || strlen(ssid) > SCAN_SSID_MAX) { return -1; }

    if (psk && psk[0] != '\0') {
        psk_len = strlen(psk);
        /* Accept a pre-derived 64-hex PSK as well as an 8-63 char passphrase */
        if (psk_len != 64u && (psk_len < 8u || psk_len > 63u)) {
            util_log("sta", "WIFI_CONNECT: PSK must be 8-63 chars (or a 64-hex PSK)");
            return -1;
        }
        if (psk_len == 64u && !sta_is_hex64(psk)) {
            util_log("sta", "WIFI_CONNECT: 64-char PSK must be hexadecimal");
            return -1;
        }
    } else {
        open_net = true;
    }

    /* Encryption selection: default WPA2-PSK, or none for open networks */
    if (open_net) {
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

    /* Build the key material. SAE needs the passphrase; PSK/PSK2 use hex. */
    key[0] = '\0';
    if (!open_net) {
        if (psk_len == 64u) {
            (void)snprintf(key, sizeof(key), "%s", psk);
        } else if (strcmp(enc, "sae") == 0 || strcmp(enc, "sae-mixed") == 0) {
            (void)snprintf(key, sizeof(key), "%s", psk);
        } else {
            if (util_wpa_psk_hex(psk, ssid, key) < 0) {
                util_log("sta", "WIFI_CONNECT: failed to derive the WPA PSK");
                return -1;
            }
            util_log("sta", "WIFI_CONNECT: derived 64-hex PSK from passphrase");
        }
    }

    if (sh_single_quote(ssid, q_ssid, sizeof(q_ssid)) < 0) { return -1; }
    if (key[0] != '\0' && sh_single_quote(key, q_key, sizeof(q_key)) < 0) {
        return -1;
    }

    /* Monitor mode and station mode are mutually exclusive on this radio */
    if (d->state == STATE_MONITORING || d->state == STATE_INJECTING
        || d->radio_mode == RADIO_MONITOR) {
        util_log("sta", "WIFI_CONNECT: stopping active monitor session first");
        ctrl_teardown_monitor(d);
    }

    cmd[0] = '\0';
    if (cmd_append(cmd, sizeof(cmd),
            "uci -q delete wireless.%s; "
            "uci set wireless.%s='wifi-iface'; "
            "uci set wireless.%s.device='radio0'; "
            "uci set wireless.%s.mode='sta'; "
            "uci set wireless.%s.network='wan'; "
            "uci set wireless.%s.disabled='0'; "
            "uci set wireless.%s.ssid=%s",
            STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE, STA_IFACE,
            STA_IFACE, STA_IFACE, q_ssid) < 0) {
        return -1;
    }

    if (!open_net) {
        if (cmd_append(cmd, sizeof(cmd),
                "; uci set wireless.%s.encryption='%s'; "
                "uci set wireless.%s.key=%s",
                STA_IFACE, enc, STA_IFACE, q_key) < 0) {
            return -1;
        }
    }

    if (bssid && bssid[0] != '\0') {
        if (cmd_append(cmd, sizeof(cmd),
                "; uci set wireless.%s.bssid='%s'", STA_IFACE, bssid) < 0) {
            return -1;
        }
    }

    /*
     * Ordering matters:
     *   1. commit the new profile/network config
     *   2. stop any old DHCP client and the old supplicant instance. A full
     *      wifi down/up restarts wpa_supplicant, which clears its in-memory
     *      BSSID ignore list — otherwise a corrected password would not be
     *      retried for up to 600 s after a WRONG_KEY failure.
     *   3. wait for phy0-sta0 to exist before asking netifd to DHCP on it.
     *      `ifup wan` used to run while the netdev did not exist yet, which
     *      silently left wan without an address.
     *   4. let netifd own DHCP on wan. If the first ifup loses the race with
     *      netdev creation, restart the logical interface once. (A bare
     *      `udhcpc` fallback is deliberately avoided: OpenWrt's default
     *      udhcpc script path is not installed, and the netifd script needs
     *      INTERFACE=wan plus ubus to apply the lease.)
     */
    if (cmd_append(cmd, sizeof(cmd),
            "; uci set network.wan.device='%s'; "
            "uci set network.wan.proto='dhcp'; "
            "uci set network.wan.auto='1'; "
            "uci set wireless.radio0.disabled='0'; "
            "uci set wireless.default_radio0.disabled='1'; "
            "uci commit wireless && uci commit network || exit 1; "
            "sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null; "
            "ifdown wan 2>/dev/null; "
            "wifi down 2>/dev/null; sleep 1; "
            "wifi up 2>/dev/null; "
            "i=0; while [ ! -e /sys/class/net/%s ] && [ \"$i\" -lt 20 ]; do "
            "sleep 1; i=$((i+1)); done; "
            "ifup wan 2>/dev/null; "
            "i=0; while [ \"$i\" -lt 20 ] && "
            "! ip -4 addr show dev %s 2>/dev/null | grep -q 'inet '; do "
            "sleep 1; i=$((i+1)); done; "
            "if ! ip -4 addr show dev %s 2>/dev/null | grep -q 'inet '; then "
            "ifdown wan 2>/dev/null; sleep 1; ifup wan 2>/dev/null; fi; "
            "true",
            STA_NETDEV, STA_NETDEV, STA_NETDEV, STA_NETDEV) < 0) {
        return -1;
    }

    /* Quiet: the command embeds the Wi-Fi key and logread is readable. */
    if (util_run_cmd_timeout_quiet(cmd, STA_CONNECT_TIMEOUT_SECS) != 0) {
        util_log("sta", "WIFI_CONNECT: failed to apply the station profile");
        return -1;
    }

    d->radio_mode = RADIO_NORMAL;
    util_log("sta", "WIFI_CONNECT: station profile active (ssid=%s, enc=%s, key=%s)",
             ssid, enc, open_net ? "open" :
             (strcmp(enc, "sae") == 0 || strcmp(enc, "sae-mixed") == 0)
                 ? "passphrase" : "64-hex");
    return 0;
}

/*
 * wifi_sta_status — Probe the current station link.
 *
 * WIFI_STATUS reports the truth about the 4-way handshake, not just 802.11
 * association. `iw dev ... link` prints "Connected to" as soon as the station
 * associates, which is *before* the PSK is verified; reporting that as
 * "connected" made a wrong password look like a successful join.
 *
 * wpa_cli is the primary source (wpa_state=COMPLETED means the 4-way
 * handshake succeeded). When it is unavailable (older images) the function
 * falls back to `iw` and requires a DHCP address before claiming success.
 *
 * Extra JSON fields:
 *   associated — 802.11 association exists (may still be authenticating)
 *   state      — connected | dhcp | associating | auth_failed | disconnected
 *   error      — auth_failed when wpa_supplicant temporarily disabled the
 *                network after repeated handshake failures (wrong key)
 *   wpa_state  — raw wpa_supplicant state, when available
 */
int wifi_sta_status(daemon_t *d, char *out_json, size_t outsz)
{
    char link[1024];
    char wpa[2048];
    char nets[2048];
    char wan[2048];
    char bssid_str[18] = "";
    char ssid_str[SCAN_SSID_MAX + 1] = "";
    char ip_str[32] = "";
    char wpa_state[32] = "";
    char kv_ssid[SCAN_SSID_MAX + 1] = "";
    char kv_bssid[18] = "";
    char kv_freq[16] = "";
    bool iw_assoc = false;
    bool wpa_available = false;
    bool authenticated = false;
    bool associated = false;
    bool auth_failed = false;
    bool connected = false;
    const char *state = "disconnected";
    int  channel = 0;

    /* 1. Association fallback / BSSID+SSID details via iw */
    if (util_run_cmd_capture(
            "for iface in $(iw dev 2>/dev/null | awk '/Interface/{print $2}'); do "
            "out=$(iw dev \"$iface\" link 2>/dev/null); "
            "if echo \"$out\" | grep -q 'Connected to '; then "
            "echo \"$out\"; break; fi; done",
            link, sizeof(link), 3) == 0) {
        const char *p = strstr(link, "Connected to ");
        if (p) {
            size_t i;
            iw_assoc = true;
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

    /* 2. Authoritative handshake state from wpa_supplicant */
    if (util_run_cmd_capture("wpa_cli -i " STA_NETDEV " status 2>/dev/null",
                             wpa, sizeof(wpa), 3) == 0
        && kv_get(wpa, "wpa_state", wpa_state, sizeof(wpa_state)) == 0) {
        wpa_available = true;

        if (kv_get(wpa, "ssid", kv_ssid, sizeof(kv_ssid)) == 0 && kv_ssid[0]) {
            (void)snprintf(ssid_str, sizeof(ssid_str), "%s", kv_ssid);
        }
        if (kv_get(wpa, "bssid", kv_bssid, sizeof(kv_bssid)) == 0 && kv_bssid[0]) {
            (void)snprintf(bssid_str, sizeof(bssid_str), "%s", kv_bssid);
        }
        if (kv_get(wpa, "freq", kv_freq, sizeof(kv_freq)) == 0 && kv_freq[0]) {
            int freq = atoi(kv_freq);
            if (freq >= 2412 && freq <= 2472) {
                channel = (freq - 2407) / 5;
            } else if (freq == 2484) {
                channel = 14;
            }
        }

        authenticated = strcmp(wpa_state, "COMPLETED") == 0;
        associated = authenticated
                  || strcmp(wpa_state, "ASSOCIATED") == 0
                  || strcmp(wpa_state, "4WAY_HANDSHAKE") == 0
                  || strcmp(wpa_state, "ASSOCIATING") == 0
                  || strcmp(wpa_state, "AUTHENTICATING") == 0;

        /*
         * After repeated 4-way failures (WRONG_KEY) wpa_supplicant marks the
         * network [TEMP-DISABLED]; it then stops retrying until the network is
         * re-enabled or the supplicant restarts. Surface that as a hard auth
         * error instead of a generic "not connected".
         */
        if (!authenticated
            && util_run_cmd_capture("wpa_cli -i " STA_NETDEV " list_networks 2>/dev/null",
                                    nets, sizeof(nets), 3) == 0
            && strstr(nets, "[TEMP-DISABLED]") != NULL) {
            auth_failed = true;
            associated = false;
        }
    } else {
        /* No wpa_cli: association from iw; require a lease for "connected". */
        associated = iw_assoc;
        authenticated = false;
    }

    /* 3. DHCP address on the station interface (fallback: ifstatus wan) */
    if (util_run_cmd_capture("ip -4 addr show dev " STA_NETDEV " 2>/dev/null",
                             wan, sizeof(wan), 3) == 0) {
        const char *p = strstr(wan, "inet ");
        if (p) {
            size_t i = 0;
            p += strlen("inet ");
            while (p[i] != '\0' && p[i] != '/' && p[i] != ' ' && i + 1 < sizeof(ip_str)) {
                ip_str[i] = p[i];
                i++;
            }
            ip_str[i] = '\0';
        }
    }
    if (ip_str[0] == '\0' && util_run_cmd_capture("ifstatus wan 2>/dev/null",
                             wan, sizeof(wan), 3) == 0) {
        (void)json_get_str(wan, "address", ip_str, sizeof(ip_str));
    }

    /* 4. Derive the public state */
    if (auth_failed) {
        connected = false;
        state = "auth_failed";
    } else if (wpa_available) {
        connected = authenticated;
        if (authenticated && ip_str[0] != '\0') {
            state = "connected";
        } else if (authenticated) {
            state = "dhcp";
        } else if (associated) {
            state = "associating";
        } else {
            state = "disconnected";
        }
    } else {
        /* Legacy fallback: only claim a join once DHCP succeeded. */
        connected = iw_assoc && ip_str[0] != '\0';
        state = connected ? "connected" : (iw_assoc ? "associating" : "disconnected");
    }

    {
        char esc_ssid[SCAN_SSID_MAX * 2 + 2];
        util_json_escape(ssid_str, esc_ssid, sizeof(esc_ssid));
        (void)snprintf(out_json, outsz,
            "{\"connected\":%s,\"associated\":%s,\"ssid\":\"%s\","
            "\"bssid\":\"%s\",\"ip\":\"%s\",\"channel\":%d,\"mode\":\"sta\","
            "\"state\":\"%s\",\"error\":\"%s\",\"wpa_state\":\"%s\"}",
            connected ? "true" : "false",
            associated ? "true" : "false",
            esc_ssid,
            bssid_str,
            ip_str,
            channel,
            state,
            auth_failed ? "auth_failed" : "",
            wpa_state);
    }

    if (connected || associated) {
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
        "killall udhcpc 2>/dev/null; "
        "ifdown wan 2>/dev/null; "
        "uci -q delete wireless." STA_IFACE "; "
        "uci -q set wireless.default_radio0.disabled='0'; "
        "uci set wireless.radio0.disabled='1'; "
        "uci set network.wan.proto='none'; "
        "uci set network.wan.auto='0'; "
        "uci -q delete network.wan.device; "
        "uci commit wireless; "
        "uci commit network; "
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
