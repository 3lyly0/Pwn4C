/*
 * radio.c — Radio interface management for pwn4cd.
 *
 * Implements native Netlink (nl80211 / libnl-tiny) and standard POSIX ioctl
 * interface management for zero-process overhead during active operations.
 *
 * Link up/down and MAC configuration use POSIX ioctls:
 *   SIOCGIFFLAGS / SIOCSIFFLAGS / SIOCSIFHWADDR
 *
 * Wi-Fi frequency and power management use nl80211 Generic Netlink:
 *   NL80211_CMD_SET_WIPHY, NL80211_CMD_SET_CHANNEL, NL80211_CMD_SET_INTERFACE
 *
 * Compile-time fallback (-DUSE_IW_FALLBACK) and runtime fallback preserve
 * compatibility with older shells and legacy iw/ip tools.
 *
 * Mode machine (see docs/architecture.md §Radio Mode Machine):
 *   RADIO_DOWN    ──start_monitor──>  RADIO_MONITOR
 *   RADIO_DOWN    ──restore_normal──> RADIO_NORMAL
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
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/nl80211.h>

#if defined(HAVE_LIBNL_TINY)
#include <netlink/netlink.h>
#include <netlink/genl/genl.h>
#include <netlink/genl/ctrl.h>
#endif

/* ── Fallback iw runner ───────────────────────────────────────────────────── */

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

/* ── Standard POSIX ioctl Interface Management (No /sbin/ip Spawning) ────── */

/*
 * iface_set_up — Set interface UP or DOWN using SIOCGIFFLAGS / SIOCSIFFLAGS.
 */
static int iface_set_up(const char *ifname, bool up)
{
    struct ifreq ifr;
    int fd;
    int r;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        util_log("radio", "socket(AF_INET): %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);

    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        util_log("radio", "SIOCGIFFLAGS %s: %s", ifname, strerror(errno));
        close(fd);
        return -1;
    }

    if (up) {
        ifr.ifr_flags |= (short)(IFF_UP | IFF_RUNNING);
    } else {
        ifr.ifr_flags &= (short)~IFF_UP;
    }

    r = ioctl(fd, SIOCSIFFLAGS, &ifr);
    if (r < 0) {
        util_log("radio", "SIOCSIFFLAGS %s: %s", ifname, strerror(errno));
    }
    close(fd);
    return (r < 0) ? -1 : 0;
}

/*
 * iface_set_mac — Set interface MAC address using SIOCSIFHWADDR.
 * Requires interface to be down.
 */
static int iface_set_mac(const char *ifname, const uint8_t mac[6])
{
    struct ifreq ifr;
    int fd;
    int r;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        util_log("radio", "socket(AF_INET): %s", strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    (void)snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", ifname);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);

    r = ioctl(fd, SIOCSIFHWADDR, &ifr);
    if (r < 0) {
        util_log("radio", "SIOCSIFHWADDR %s: %s", ifname, strerror(errno));
    }
    close(fd);
    return (r < 0) ? -1 : 0;
}

/* ── Generic Netlink (nl80211) Helpers ───────────────────────────────────── */

#ifndef NLA_OK
#define NLA_OK(nla, len) \
    ((len) >= (int)sizeof(struct nlattr) && \
     (nla)->nla_len >= sizeof(struct nlattr) && \
     (int)(nla)->nla_len <= (len))
#endif

#ifndef NLA_NEXT
#define NLA_NEXT(nla, len) \
    ((len) -= (int)NLA_ALIGN((nla)->nla_len), \
     (struct nlattr *)((char *)(nla) + NLA_ALIGN((nla)->nla_len)))
#endif

/*
 * Open Generic Netlink socket. Returns file descriptor or -1.
 */
static int nl_open_socket(void)
{
    int fd;
    struct sockaddr_nl local;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);
    if (fd < 0) {
        return -1;
    }

    memset(&local, 0, sizeof(local));
    local.nl_family = AF_NETLINK;
    if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/*
 * Query nl80211 generic netlink family ID from kernel.
 */
static int nl_get_family_id(int fd)
{
    static int cached_id = -1;
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[128];
    } req;
    struct sockaddr_nl nladdr;
    char resp[1024];
    struct nlmsghdr *nlh;
    struct genlmsghdr *gh;
    struct nlattr *na;
    ssize_t len;
    int attrlen;

    if (cached_id > 0) {
        return cached_id;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = GENL_ID_CTRL;
    req.n.nlmsg_seq = 1;
    req.g.cmd = CTRL_CMD_GETFAMILY;
    req.g.version = 1;

    /* Add attribute: CTRL_ATTR_FAMILY_NAME = "nl80211" */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = CTRL_ATTR_FAMILY_NAME;
    na->nla_len = (uint16_t)(NLA_HDRLEN + strlen("nl80211") + 1);
    memcpy((char *)na + NLA_HDRLEN, "nl80211", strlen("nl80211") + 1);
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    if (sendto(fd, &req, req.n.nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        return -1;
    }

    len = recv(fd, resp, sizeof(resp), 0);
    if (len < 0) {
        return -1;
    }

    nlh = (struct nlmsghdr *)resp;
    while (NLMSG_OK(nlh, len)) {
        if (nlh->nlmsg_type == NLMSG_ERROR) {
            return -1;
        }
        gh = (struct genlmsghdr *)NLMSG_DATA(nlh);
        na = (struct nlattr *)((char *)gh + GENL_HDRLEN);
        attrlen = (int)nlh->nlmsg_len - (int)NLMSG_LENGTH(GENL_HDRLEN);

        while (NLA_OK(na, attrlen)) {
            if (na->nla_type == CTRL_ATTR_FAMILY_ID) {
                cached_id = (int)*(uint16_t *)((char *)na + NLA_HDRLEN);
                return cached_id;
            }
            na = NLA_NEXT(na, attrlen);
        }
        nlh = NLMSG_NEXT(nlh, len);
    }
    return -1;
}

/*
 * Send generic netlink message and wait for ACK or error.
 */
static int nl_send_and_ack(int fd, struct nlmsghdr *nlh)
{
    struct sockaddr_nl nladdr;
    char buf[512];
    ssize_t len;
    struct nlmsghdr *resp;

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;

    if (sendto(fd, nlh, nlh->nlmsg_len, 0,
               (struct sockaddr *)&nladdr, sizeof(nladdr)) < 0) {
        return -1;
    }

    len = recv(fd, buf, sizeof(buf), 0);
    if (len < 0) {
        return -1;
    }

    resp = (struct nlmsghdr *)buf;
    while (NLMSG_OK(resp, len)) {
        if (resp->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(resp);
            return err->error; /* 0 on ACK */
        }
        resp = NLMSG_NEXT(resp, len);
    }
    return 0;
}

/*
 * Native nl80211 set channel/frequency.
 */
static int nl80211_set_channel(const char *ifname, int channel)
{
    int fd;
    int family_id;
    int ret;
    unsigned int ifindex;
    uint32_t freq_mhz;
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } req;
    struct nlattr *na;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return -1;
    }

    freq_mhz = (channel == 14) ? 2484u : (uint32_t)(2407 + channel * 5);

    fd = nl_open_socket();
    if (fd < 0) {
        return -1;
    }

    family_id = nl_get_family_id(fd);
    if (family_id < 0) {
        close(fd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = (uint16_t)family_id;
    req.n.nlmsg_seq = 2;
    req.g.cmd = NL80211_CMD_SET_WIPHY;
    req.g.version = 1;

    /* Attr: NL80211_ATTR_IFINDEX */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_IFINDEX;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = ifindex;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    /* Attr: NL80211_ATTR_WIPHY_FREQ */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_WIPHY_FREQ;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = freq_mhz;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    ret = nl_send_and_ack(fd, &req.n);
    close(fd);
    return ret;
}

/*
 * Native nl80211 set TX power (in mBm).
 */
static int nl80211_set_txpower(const char *ifname, int mbm)
{
    int fd;
    int family_id;
    int ret;
    unsigned int ifindex;
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } req;
    struct nlattr *na;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return -1;
    }

    fd = nl_open_socket();
    if (fd < 0) {
        return -1;
    }

    family_id = nl_get_family_id(fd);
    if (family_id < 0) {
        close(fd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = (uint16_t)family_id;
    req.n.nlmsg_seq = 3;
    req.g.cmd = NL80211_CMD_SET_WIPHY;
    req.g.version = 1;

    /* Attr: NL80211_ATTR_IFINDEX */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_IFINDEX;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = ifindex;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    /* Attr: NL80211_ATTR_WIPHY_TX_POWER_SETTING = FIXED */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_WIPHY_TX_POWER_SETTING;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = (uint32_t)NL80211_TX_POWER_FIXED;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    /* Attr: NL80211_ATTR_WIPHY_TX_POWER_LEVEL = mBm */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_WIPHY_TX_POWER_LEVEL;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = (uint32_t)mbm;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    ret = nl_send_and_ack(fd, &req.n);
    close(fd);
    return ret;
}

/*
 * Native nl80211 set interface type (monitor vs managed).
 */
static int nl80211_set_type(const char *ifname, uint32_t iftype)
{
    int fd;
    int family_id;
    int ret;
    unsigned int ifindex;
    struct {
        struct nlmsghdr n;
        struct genlmsghdr g;
        char buf[256];
    } req;
    struct nlattr *na;

    ifindex = if_nametoindex(ifname);
    if (ifindex == 0) {
        return -1;
    }

    fd = nl_open_socket();
    if (fd < 0) {
        return -1;
    }

    family_id = nl_get_family_id(fd);
    if (family_id < 0) {
        close(fd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(GENL_HDRLEN);
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_type = (uint16_t)family_id;
    req.n.nlmsg_seq = 4;
    req.g.cmd = NL80211_CMD_SET_INTERFACE;
    req.g.version = 1;

    /* Attr: NL80211_ATTR_IFINDEX */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_IFINDEX;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = ifindex;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    /* Attr: NL80211_ATTR_IFTYPE */
    na = (struct nlattr *)((char *)&req + NLMSG_ALIGN(req.n.nlmsg_len));
    na->nla_type = NL80211_ATTR_IFTYPE;
    na->nla_len = (uint16_t)(NLA_HDRLEN + sizeof(uint32_t));
    *(uint32_t *)((char *)na + NLA_HDRLEN) = iftype;
    req.n.nlmsg_len = NLMSG_ALIGN(req.n.nlmsg_len) + (uint32_t)NLA_ALIGN(na->nla_len);

    ret = nl_send_and_ack(fd, &req.n);
    close(fd);
    return ret;
}

/* ── Public API ───────────────────────────────────────────────────────────── */

/*
 * radio_set_down — Bring the physical interface down via POSIX ioctl.
 * Does not destroy the UCI profile.
 */
int radio_set_down(daemon_t *d)
{
    int r;
    MOCK_RETURN(d);

    /* Tell hostapd/wpa_supplicant to stop managing the interface */
    r = iw_run("wifi down 2>/dev/null; true");
    (void)r;  /* best-effort */

    /* Bring physical link down via POSIX ioctl */
    (void)iface_set_up(d->wlan_iface, false);

    /* Re-disable in UCI so future `wifi reload` won't bring it up */
    r = iw_run("uci set wireless.radio0.disabled='1' && uci commit wireless");
    (void)r;

    d->radio_mode = RADIO_DOWN;
    util_log("radio", "interface %s is DOWN", d->wlan_iface);
    return 0;
}

/*
 * radio_restore_normal — Re-enable UCI wireless profile and bring the
 * interface up in managed/AP mode.
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

    /* Bring interface back up in managed/AP mode */
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

    /* Step 2: bring link down via POSIX ioctl */
    (void)iface_set_up(d->wlan_iface, false);

    /* Step 3: set monitor type (Direct netlink with iw fallback) */
#ifndef USE_IW_FALLBACK
    r = nl80211_set_type(d->wlan_iface, NL80211_IFTYPE_MONITOR);
#else
    r = -1;
#endif
    if (r != 0) {
        r = iw_run("iw dev %s set type monitor", d->wlan_iface);
        if (r != 0) {
            util_log("radio", "iw set type monitor failed: %d — trying del/add", r);
            r = iw_run("iw dev %s del 2>/dev/null; "
                       "iw phy phy0 interface add %s type monitor 2>/dev/null",
                       d->wlan_iface, d->wlan_iface);
            if (r != 0) {
                util_log("radio", "monitor mode setup failed: %d", r);
                return -1;
            }
        }
    }

    /* Step 4: bring interface up via POSIX ioctl */
    if (iface_set_up(d->wlan_iface, true) < 0) {
        util_log("radio", "iface_set_up failed for %s", d->wlan_iface);
        return -1;
    }

    /* Step 5: set channel (Direct netlink with iw fallback) */
#ifndef USE_IW_FALLBACK
    r = nl80211_set_channel(d->wlan_iface, channel);
#else
    r = -1;
#endif
    if (r != 0) {
        r = iw_run("iw dev %s set channel %d HT20", d->wlan_iface, channel);
        if (r != 0) {
            r = iw_run("iw dev %s set channel %d", d->wlan_iface, channel);
            if (r != 0) {
                util_log("radio", "channel set failed: %d", r);
                return -1;
            }
        }
    }

    d->radio_mode = RADIO_MONITOR;
    d->channel    = channel;
    util_log("radio", "monitor mode active on %s ch%d", d->wlan_iface, channel);
    return 0;
}

/*
 * radio_exit_monitor — Reverse radio_enter_monitor.
 */
int radio_exit_monitor(daemon_t *d)
{
    MOCK_RETURN(d);

    /* Bring link down via POSIX ioctl before switching type */
    (void)iface_set_up(d->wlan_iface, false);

    /* Restore managed type */
#ifndef USE_IW_FALLBACK
    (void)nl80211_set_type(d->wlan_iface, NL80211_IFTYPE_STATION);
#endif
    (void)iw_run("iw dev %s set type managed 2>/dev/null; true", d->wlan_iface);

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
 * Uses direct nl80211 generic netlink, with fallback to iw.
 */
int radio_set_channel(daemon_t *d, int channel)
{
    int r;
    MOCK_RETURN(d);

    if (channel < CHAN_MIN || channel > CHAN_MAX) { return -1; }

#ifndef USE_IW_FALLBACK
    r = nl80211_set_channel(d->wlan_iface, channel);
    if (r == 0) {
        d->channel = channel;
        util_log("radio", "channel -> %d (nl80211)", channel);
        return 0;
    }
#endif

    /* Fallback to iw */
    r = iw_run("iw dev %s set channel %d HT20", d->wlan_iface, channel);
    if (r != 0) {
        r = iw_run("iw dev %s set channel %d", d->wlan_iface, channel);
        if (r != 0) {
            util_log("radio", "channel switch to %d failed: %d", channel, r);
            return -1;
        }
    }
    d->channel = channel;
    util_log("radio", "channel -> %d (iw fallback)", channel);
    return 0;
}

/*
 * radio_set_txpower — Set TX power in dBm using nl80211 or iw.
 */
int radio_set_txpower(daemon_t *d, int dbm)
{
    int r;
    int mbm;
    MOCK_RETURN(d);

    if (dbm < 1 || dbm > DAEMON_MAX_TXPWR) { return -1; }
    mbm = dbm * 100;

#ifndef USE_IW_FALLBACK
    r = nl80211_set_txpower(d->wlan_iface, mbm);
    if (r == 0) {
        d->tx_power_dbm = dbm;
        util_log("radio", "txpower -> %d dBm (nl80211)", dbm);
        return 0;
    }
#endif

    /* Fallback to iw */
    if (d->radio_mode == RADIO_MONITOR) {
        r = iw_run("iw phy phy0 set txpower fixed %d", mbm);
    } else {
        r = iw_run("iw dev %s set txpower fixed %d", d->wlan_iface, mbm);
    }

    if (r != 0) {
        util_log("radio", "txpower %d dBm failed: %d", dbm, r);
        return -1;
    }
    d->tx_power_dbm = dbm;
    util_log("radio", "txpower -> %d dBm (iw fallback)", dbm);
    return 0;
}

/*
 * radio_set_mac — Change the interface MAC address using standard POSIX ioctl.
 * Interface must be DOWN before changing hardware address.
 */
int radio_set_mac(daemon_t *d, const uint8_t mac[6])
{
    int r;
    char macstr[18];
    MOCK_RETURN(d);

    util_mac_to_str(mac, macstr, sizeof(macstr));

    /* Interface must be down (POSIX ioctl) */
    (void)iface_set_up(d->wlan_iface, false);

    /* Apply MAC via SIOCSIFHWADDR ioctl */
    r = iface_set_mac(d->wlan_iface, mac);
    if (r != 0) {
        /* Fallback if driver requires ip command */
        r = iw_run("ip link set %s address %s", d->wlan_iface, macstr);
        if (r != 0) {
            util_log("radio", "MAC set %s failed: %d", macstr, r);
            return -1;
        }
    }

    memcpy(d->mac_override, mac, 6);
    d->mac_override_set = true;
    util_log("radio", "MAC -> %s (ioctl)", macstr);
    return 0;
}
