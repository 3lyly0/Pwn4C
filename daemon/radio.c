/*
 * radio.c — Radio interface management for pwn4cd.
 *
 * All radio operations are implemented by shelling out to `iw` and `ip`
 * per the architecture.md spec.  Each call is bounded by IW_TIMEOUT_SECS.
 *
 * Mode machine (see docs/architecture.md §Radio Mode Machine):
 *
 *   RADIO_DOWN  ──start_monitor──>  RADIO_MONITOR
 *   RADIO_DOWN  ──restore_normal──> RADIO_NORMAL
 *   RADIO_MONITOR ──exit_monitor──> restores saved mode (DOWN or NORMAL)
 *   RADIO_NORMAL  ──start_monitor──> saves NORMAL, enters MONITOR
 *
 * The UCI wireless profile is NEVER deleted — only disabled/re-enabled.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <time.h>

/* ── Internal helpers ─────────────────────────────────────────────────────── */

static int iw_run(const char *fmt, ...)
{
    char cmd[256];
    va_list ap;
    va_list ap2;

    va_start(ap, fmt);
    va_copy(ap2, ap);
    (void)vsnprintf(cmd, sizeof(cmd), fmt, ap2);
    va_end(ap2);
    va_end(ap);

    return util_run_cmd(cmd);
}

/* In mock mode all radio ops are no-ops that always succeed */
#define MOCK_RETURN(d) do { if ((d)->mock_mode) { return 0; } } while(0)

/* ── Public API ───────────────────────────────────────────────────────────── */

/*
 * radio_set_down — Bring the physical interface down.
 * Does not destroy the UCI profile.
 */
int radio_set_down(daemon_t *d)
{
    int r;
    MOCK_RETURN(d);

    /* Tell hostapd/wpa_supplicant to stop managing the interface */
    r = iw_run("wifi down 2>/dev/null; true");
    (void)r;  /* best-effort */

    /* Bring physical layer down */
    r = iw_run("ip link set %s down 2>/dev/null; true", d->wlan_iface);
    (void)r;

    /* Re-disable in UCI so future `wifi reload` won't bring it up */
    r = iw_run("uci set wireless.radio0.disabled='1' && uci commit wireless");
    (void)r;

    d->radio_mode = RADIO_DOWN;
    util_log("radio", "interface %s is DOWN", d->wlan_iface);
    return 0;
}

/*
 * radio_restore_normal — Re-enable the UCI wireless profile and bring the
 * interface up in managed/AP mode.  This is a one-command recovery path.
 *
 * IMPORTANT: does NOT overwrite the AP SSID/key/mode settings — only flips
 * the `disabled` flag and calls `wifi up`.
 */
int radio_restore_normal(daemon_t *d)
{
    int r;
    MOCK_RETURN(d);

    /* Re-enable UCI profile */
    r = iw_run("uci set wireless.radio0.disabled='0' && uci commit wireless");
    if (r != 0) {
        util_log("radio", "uci re-enable failed (r=%d), continuing", r);
    }

    /* Set channel to saved value first */
    r = iw_run("uci set wireless.radio0.channel='%d' && uci commit wireless",
               d->saved_channel > 0 ? d->saved_channel : 6);
    (void)r;

    /* Bring the interface back up in managed/AP mode */
    r = iw_run("wifi up 2>/dev/null");
    if (r != 0) {
        util_log("radio", "wifi up failed (r=%d)", r);
        return -1;
    }

    d->radio_mode = RADIO_NORMAL;
    util_log("radio", "interface %s restored to NORMAL (managed/AP)", d->wlan_iface);
    return 0;
}

/*
 * radio_enter_monitor — Put the interface into 802.11 monitor mode.
 *
 * Sequence:
 *   1. Save current mode and channel.
 *   2. wifi down (stop hostapd/wpa_supplicant).
 *   3. ip link set ra0 down.
 *   4. iw dev ra0 set type monitor.
 *   5. ip link set ra0 up.
 *   6. iw dev ra0 set channel <N>.
 */
int radio_enter_monitor(daemon_t *d, int channel)
{
    int r;
    MOCK_RETURN(d);

    if (channel < CHAN_MIN || channel > CHAN_MAX) {
        util_log("radio", "invalid channel %d", channel);
        return -1;
    }

    /* Save state before entering monitor */
    d->saved_channel    = d->channel > 0 ? d->channel : 6;
    d->saved_radio_mode = d->radio_mode;

    /* Step 1: stop managed stack */
    r = iw_run("wifi down 2>/dev/null; true");
    (void)r;

    /* Step 2: bring link down */
    r = iw_run("ip link set %s down", d->wlan_iface);
    if (r != 0) {
        util_log("radio", "ip link set down failed: %d", r);
        /* non-fatal, continue */
    }

    /* Step 3: set monitor type */
    r = iw_run("iw dev %s set type monitor", d->wlan_iface);
    if (r != 0) {
        util_log("radio", "iw set type monitor failed: %d — trying del/add", r);
        /* Fallback: delete and re-add as monitor */
        r = iw_run("iw dev %s del 2>/dev/null; "
                   "iw phy phy0 interface add %s type monitor 2>/dev/null",
                   d->wlan_iface, d->wlan_iface);
        if (r != 0) {
            util_log("radio", "monitor mode setup failed: %d", r);
            return -1;
        }
    }

    /* Step 4: bring interface up */
    r = iw_run("ip link set %s up", d->wlan_iface);
    if (r != 0) {
        util_log("radio", "ip link set up failed: %d", r);
        return -1;
    }

    /* Step 5: set channel */
    r = iw_run("iw dev %s set channel %d HT20", d->wlan_iface, channel);
    if (r != 0) {
        /* Some versions of iw on mt76 don't accept HT20 flag, try without */
        r = iw_run("iw dev %s set channel %d", d->wlan_iface, channel);
        if (r != 0) {
            util_log("radio", "channel set failed: %d", r);
            return -1;
        }
    }

    d->radio_mode = RADIO_MONITOR;
    d->channel    = channel;
    util_log("radio", "monitor mode active on %s ch%d", d->wlan_iface, channel);
    return 0;
}

/*
 * radio_exit_monitor — Reverse radio_enter_monitor.
 * Restores the radio to its pre-monitor state (NORMAL or DOWN).
 */
int radio_exit_monitor(daemon_t *d)
{
    int r;
    MOCK_RETURN(d);

    /* Bring link down before switching type */
    r = iw_run("ip link set %s down", d->wlan_iface);
    (void)r;

    /* Restore managed type */
    r = iw_run("iw dev %s set type managed 2>/dev/null; true", d->wlan_iface);
    (void)r;

    if (d->saved_radio_mode == RADIO_NORMAL) {
        return radio_restore_normal(d);
    }

    /* Default: leave DOWN */
    d->radio_mode = RADIO_DOWN;
    util_log("radio", "monitor exited; radio is DOWN");
    return 0;
}

/*
 * radio_set_channel — Change channel while monitor mode is active.
 * Returns 0 on success, -1 on error.
 */
int radio_set_channel(daemon_t *d, int channel)
{
    int r;
    MOCK_RETURN(d);

    if (channel < CHAN_MIN || channel > CHAN_MAX) { return -1; }

    r = iw_run("iw dev %s set channel %d HT20", d->wlan_iface, channel);
    if (r != 0) {
        r = iw_run("iw dev %s set channel %d", d->wlan_iface, channel);
        if (r != 0) {
            util_log("radio", "channel switch to %d failed: %d", channel, r);
            return -1;
        }
    }
    d->channel = channel;
    util_log("radio", "channel -> %d", channel);
    return 0;
}

/*
 * radio_set_txpower — Set TX power in dBm using iw.
 * iw expects mBm (milli-dBm = dBm * 100).
 */
int radio_set_txpower(daemon_t *d, int dbm)
{
    int r;
    int mbm;
    MOCK_RETURN(d);

    if (dbm < 1 || dbm > DAEMON_MAX_TXPWR) { return -1; }

    mbm = dbm * 100;  /* integer, no float */
    r   = iw_run("iw dev %s set txpower fixed %d", d->wlan_iface, mbm);
    if (r != 0) {
        util_log("radio", "txpower %d dBm failed: %d", dbm, r);
        return -1;
    }
    d->tx_power_dbm = dbm;
    util_log("radio", "txpower -> %d dBm", dbm);
    return 0;
}

/*
 * radio_set_mac — Change the interface MAC address.
 * Interface must be DOWN before ip link set ... address works.
 * Caller must ensure monitor is stopped (checked at command layer).
 */
int radio_set_mac(daemon_t *d, const uint8_t mac[6])
{
    int r;
    char macstr[18];
    MOCK_RETURN(d);

    util_mac_to_str(mac, macstr, sizeof(macstr));

    /* Interface must be down */
    r = iw_run("ip link set %s down", d->wlan_iface);
    (void)r;

    r = iw_run("ip link set %s address %s", d->wlan_iface, macstr);
    if (r != 0) {
        util_log("radio", "MAC set %s failed: %d", macstr, r);
        return -1;
    }

    memcpy(d->mac_override, mac, 6);
    d->mac_override_set = true;
    util_log("radio", "MAC -> %s", macstr);
    return 0;
}
