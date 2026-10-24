#!/bin/sh
# Pwn4C first-boot provisioning (idempotent).
#
# Sourced by two callers:
#   /etc/uci-defaults/99-pwn4c   - normal first boot
#   /etc/init.d/pwn4c-net        - boot-time repair when the first-boot
#                                  overlay migration did not persist
#
# Everything here must be safe to run more than once. The marker file at the
# end is what tells pwn4c-net that provisioning already landed on disk.
#
# Documented defaults:
#   Root credentials: NO PASSWORD (OpenWrt blank-password default).
#     - First boot: telnet is accessible (OpenWrt opens telnet when no passwd set).
#     - SSH (dropbear) accepts a blank password until one is set.
#     - First step post-boot: set a password (passwd root) or push a key,
#       see /etc/dropbear/authorized_keys.
#
# CONSERVATIVE POLICY: No credentials are hardcoded here. Automation tooling
# must either push an authorized_keys file or set a password over the initial
# telnet/SSH session before deploying the drone to an untrusted environment.

# ── Hostname ──────────────────────────────────────────────────────────────────
uci set system.@system[0].hostname='pwn4c'

# ── LAN: deterministic static IP, DHCP server ON ─────────────────────────────
uci set network.lan.proto='static'
uci set network.lan.ipaddr='192.168.4.1'
uci set network.lan.netmask='255.255.255.0'

# dnsmasq / DHCP: LAN pool 192.168.4.10 - 192.168.4.254, 12-hour leases.
# dnsmasq itself is enabled by default; we only set the range and interface.
uci set dhcp.lan.interface='lan'
uci set dhcp.lan.start='10'
uci set dhcp.lan.limit='245'
uci set dhcp.lan.leasetime='12h'
uci set dhcp.lan.ignore='0'

# ── WAN: disable entirely (drone is not a router) ────────────────────────────
uci set network.wan.proto='none'
uci set network.wan.auto='0'

# ── Wireless: radio present but interface DOWN by default ────────────────────
# The pwn4cd daemon will bring it up and place it in monitor mode on demand.
# Guarded: on first boot /etc/config/wireless may not exist yet when this runs
# (it is generated later); blindly setting it could create a partial config
# that blocks auto-generation. The pwn4c-radio init script enforces DOWN
# on every boot regardless.
if uci -q get wireless.radio0 >/dev/null 2>&1; then
    uci set wireless.radio0.disabled='1'
    uci commit wireless
fi

# ── Dropbear (SSH): listen on LAN only, standard port 22 ────────────────────
# dropbear is enabled by default in OpenWrt; we just tighten the bind address.
uci set dropbear.@dropbear[0].Interface='lan'
uci set dropbear.@dropbear[0].Port='22'
uci set dropbear.@dropbear[0].PasswordAuth='on'
uci set dropbear.@dropbear[0].RootPasswordAuth='on'

# ── Ports 4444 / 5555: reserved for pwn4cd (no firewall in this build) ───────
# firewall4 is removed from the image. Both ports are unblocked by default.
# No iptables rules are added here — the only listener will be pwn4cd.

# ── LED: system LED = heartbeat (solid on = panic, blink = healthy kernel) ───
# Mi Router 4C has two power LEDs in the DTS: 'blue:power' and 'yellow:power'.
# We use blue:power with the heartbeat trigger: solid = panic, blink = alive.
# The yellow LED is left at its default (off) to avoid ambiguity.
uci set system.led_power=led
uci set system.led_power.name='Power'
uci set system.led_power.sysfs='blue:power'
uci set system.led_power.trigger='heartbeat'

uci commit system
uci commit network
uci commit dhcp
uci commit dropbear

# Enable the radio guard: FILES/ alone places init scripts without enabling
# them (no rc.d symlink). Without this line pwn4c-radio would never run.
[ -x /etc/init.d/pwn4c-radio ] && /etc/init.d/pwn4c-radio enable

# Enable the implant daemon if baked into the image (CI release images
# include it; dev images may not — guarded so first boot never fails here).
[ -x /etc/init.d/pwn4cd ] && /etc/init.d/pwn4cd enable

# Mark provisioning as persisted. If this file is missing on a later boot,
# /etc/init.d/pwn4c-net re-applies everything above (see docs/troubleshooting.md).
touch /etc/pwn4c.initialized

exit 0
