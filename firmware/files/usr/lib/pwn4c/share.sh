#!/bin/sh
# /usr/lib/pwn4c/share.sh - NAT the drone's LAN behind its upstream station.
#
# The image deliberately ships without firewall4 (see firmware/build.sh), so
# there is no zone model and no masquerade. A joined station gets an address on
# the upstream network, but 192.168.4.0/24 stays unroutable: the upstream router
# has no route back to it, so replies to forwarded packets are dropped. This
# script installs the one rule the image is missing.
#
#   share.sh on      forward + masquerade everything leaving phy0-sta0
#   share.sh off     remove the table
#   share.sh status  exit 0 when sharing is active
#
# 'on' is idempotent: it replaces the table, so it is safe to call after every
# connect.

TABLE=pwn4c_share
STA_IFACE=phy0-sta0

on() {
    sysctl -q -w net.ipv4.ip_forward=1 2>/dev/null

    nft delete table ip "$TABLE" 2>/dev/null
    nft add table ip "$TABLE" || return 1
    nft "add chain ip $TABLE post { type nat hook postrouting priority 100 ; }" || return 1
    nft add rule ip "$TABLE" post oifname "$STA_IFACE" masquerade || return 1

    # Clamp MSS to the path MTU. The LAN is 1500 bytes; an upstream behind
    # PPPoE or a tunnel is smaller, and without this TCP hangs on large
    # responses instead of degrading cleanly.
    nft "add chain ip $TABLE clamp { type filter hook forward priority 0 ; policy accept ; }" || return 1
    nft add rule ip "$TABLE" clamp tcp flags syn tcp option maxseg size set rt mtu || return 1

    logger -t pwn4c-share "sharing enabled (masquerade on $STA_IFACE)"
    return 0
}

off() {
    nft delete table ip "$TABLE" 2>/dev/null
    logger -t pwn4c-share "sharing disabled"
    return 0
}

status() {
    nft list table ip "$TABLE" >/dev/null 2>&1
}

case "$1" in
    on)     on ;;
    off)    off ;;
    status) status ;;
    *)      echo "usage: $0 on|off|status" >&2; exit 2 ;;
esac
