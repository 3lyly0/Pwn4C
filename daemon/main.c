/*
 * main.c — pwn4cd: Wi-Fi implant daemon for MediaTek MT7628N / OpenWrt.
 *
 * Usage: pwn4cd [--mock] [--iface <wlan>] [--eth <eth>]
 *               [--psk <secret>] [--psk-file <path>] [--idle-timeout <sec>]
 *
 *   --mock              Run on x86_64 without hardware; replay canned frames.
 *   --iface IF          Wireless interface name (default: wlan0)
 *   --eth   IF          Ethernet interface name (default: eth0)
 *   --psk   SECRET      Require HMAC-SHA256 challenge-response auth on TCP :4444
 *   --psk-file PATH     Read pre-shared key from file (default: /etc/pwn4c.key if present)
 *   --idle-timeout SEC  Dead-man failsafe: stop monitor after SEC seconds of idle
 *
 * Architecture: single-process, select(2)-driven event loop.
 *   No threads.  No dynamic allocation in the frame path.
 *   Fixed 512 KiB ring buffer in BSS (static storage, not stack).
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <unistd.h>
#include <sys/select.h>
#include <syslog.h>

/* Declare mock_tick (mock.c) */
void mock_tick(daemon_t *d);

/* Declare ctrl_recv (control.c) */
int ctrl_recv(daemon_t *d);

/* ── Static ring buffer (512 KiB, in BSS — avoids stack pressure on MIPS) ─── */
static uint8_t g_ring[RING_BYTES];

/* ── Singleton daemon state ───────────────────────────────────────────────── */
static daemon_t g_daemon;

/* ── Signal handler ───────────────────────────────────────────────────────── */
static void sig_handler(int signo)
{
    if (signo == SIGTERM || signo == SIGINT) {
        g_daemon.sig_term = 1;
    }
}

/* ── Usage ────────────────────────────────────────────────────────────────── */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage: %s [--mock] [--iface <wlan_iface>] [--eth <eth_iface>]\n"
        "          [--psk <secret>] [--psk-file <path>] [--idle-timeout <sec>]\n"
        "\n"
        "  --mock              Run without hardware (x86_64 development mode)\n"
        "  --iface IF          Wireless interface (default: wlan0)\n"
        "  --eth   IF          Ethernet interface (default: eth0)\n"
        "  --psk   SECRET      Require HMAC-SHA256 PSK authentication on TCP :4444\n"
        "  --psk-file PATH     Read PSK from file (default: /etc/pwn4c.key if present)\n"
        "  --idle-timeout SEC  Dead-man failsafe timeout in seconds (0 = disabled)\n",
        prog);
}

/* ── main ─────────────────────────────────────────────────────────────────── */
int main(int argc, char *argv[])
{
    int  i;
    struct sigaction sa;
    const char *psk_file = PSK_FILE_DEFAULT;
    bool explicit_psk = false;

    /* ── Initialize daemon state ────────────────────────────────────────── */
    memset(&g_daemon, 0, sizeof(g_daemon));
    g_daemon.ring_buf          = g_ring;
    g_daemon.ring_head         = 0;
    g_daemon.ring_tail         = 0;
    g_daemon.disc_fd           = -1;
    g_daemon.ctrl_listen_fd    = -1;
    g_daemon.ctrl_client_fd    = -1;
    g_daemon.stream_fd         = -1;
    g_daemon.pkt_fd            = -1;
    g_daemon.tx_fd             = -1;
    g_daemon.nl_fd             = -1;
    g_daemon.nl_family_id      = -1;
    g_daemon.state             = STATE_IDLE;
    g_daemon.radio_mode        = RADIO_DOWN;
    g_daemon.channel           = 1;
    g_daemon.tx_power_dbm      = DAEMON_MAX_TXPWR;
    g_daemon.mock_mode         = false;
    g_daemon.start_sec         = util_monotonic_sec();
    g_daemon.last_activity_sec = g_daemon.start_sec;

    /* Default interface names */
    (void)snprintf(g_daemon.wlan_iface, sizeof(g_daemon.wlan_iface),
                   "%s", WLAN_IFACE_DEFAULT);
    (void)snprintf(g_daemon.eth_iface,  sizeof(g_daemon.eth_iface),
                   "%s", ETH_IFACE_DEFAULT);

    /* ── Parse arguments ────────────────────────────────────────────────── */
    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--mock") == 0) {
            g_daemon.mock_mode = true;
        } else if (strcmp(argv[i], "--iface") == 0 && i + 1 < argc) {
            i++;
            (void)snprintf(g_daemon.wlan_iface, sizeof(g_daemon.wlan_iface),
                           "%s", argv[i]);
        } else if (strcmp(argv[i], "--eth") == 0 && i + 1 < argc) {
            i++;
            (void)snprintf(g_daemon.eth_iface, sizeof(g_daemon.eth_iface),
                           "%s", argv[i]);
        } else if (strcmp(argv[i], "--psk") == 0 && i + 1 < argc) {
            i++;
            (void)snprintf(g_daemon.psk, sizeof(g_daemon.psk), "%s", argv[i]);
            g_daemon.psk_required = (g_daemon.psk[0] != '\0');
            explicit_psk = true;
        } else if (strcmp(argv[i], "--psk-file") == 0 && i + 1 < argc) {
            i++;
            psk_file = argv[i];
        } else if (strcmp(argv[i], "--idle-timeout") == 0 && i + 1 < argc) {
            i++;
            g_daemon.idle_timeout_sec = atoi(argv[i]);
            if (g_daemon.idle_timeout_sec < 0) {
                g_daemon.idle_timeout_sec = 0;
            }
        } else if (strcmp(argv[i], "--help") == 0
                || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            usage(argv[0]);
            return 1;
        }
    }

    /* Load PSK from file if not explicitly passed via --psk (§4.1) */
    if (!explicit_psk && psk_file && psk_file[0] != '\0') {
        if (util_read_file(psk_file, g_daemon.psk, sizeof(g_daemon.psk)) > 0) {
            g_daemon.psk_required = true;
        }
    }

    /* ── Open syslog ────────────────────────────────────────────────────── */
    openlog("pwn4cd", LOG_PID | LOG_CONS, LOG_DAEMON);
    util_log("main", "pwn4cd %s starting (mock=%s, iface=%s, eth=%s, psk=%s, idle_timeout=%ds)",
             DAEMON_VERSION,
             g_daemon.mock_mode ? "yes" : "no",
             g_daemon.wlan_iface,
             g_daemon.eth_iface,
             g_daemon.psk_required ? "enabled" : "off",
             g_daemon.idle_timeout_sec);

    /* ── Install signal handlers ────────────────────────────────────────── */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;   /* no SA_RESTART so select() is interrupted */

    if (sigaction(SIGTERM, &sa, NULL) < 0
     || sigaction(SIGINT,  &sa, NULL) < 0) {
        util_log("main", "sigaction failed: %s", strerror(errno));
        return 1;
    }
    /* Ignore SIGPIPE — we check write() return values */
    signal(SIGPIPE, SIG_IGN);

    /* ── Read base MAC from Ethernet interface ──────────────────────────── */
    if (util_read_mac(g_daemon.eth_iface, g_daemon.base_mac) < 0) {
        /* Fallback: try wlan interface */
        if (util_read_mac(g_daemon.wlan_iface, g_daemon.base_mac) < 0) {
            util_log("main", "cannot read MAC from %s or %s; using fallback",
                     g_daemon.eth_iface, g_daemon.wlan_iface);
        }
    }

    /* ── Mock mode initialization ───────────────────────────────────────── */
    if (g_daemon.mock_mode) {
        mock_run(&g_daemon);
    }

    /* ── Bind sockets ───────────────────────────────────────────────────── */
    if (disc_setup(&g_daemon) < 0) {
        util_log("main", "disc_setup failed");
        return 1;
    }
    if (ctrl_setup(&g_daemon) < 0) {
        util_log("main", "ctrl_setup failed");
        return 1;
    }

    util_log("main", "ready. Listening on UDP :4440 / TCP :4444");

    /* ── Main event loop ────────────────────────────────────────────────── */
    while (!g_daemon.sig_term) {
        fd_set   rfds;
        fd_set   wfds;
        int      maxfd;
        struct timeval tv;
        int      r;
        bool     monitoring;

        monitoring = (g_daemon.state == STATE_MONITORING
                   || g_daemon.state == STATE_INJECTING);

        FD_ZERO(&rfds);
        FD_ZERO(&wfds);

        FD_SET(g_daemon.disc_fd, &rfds);
        maxfd = g_daemon.disc_fd;

        FD_SET(g_daemon.ctrl_listen_fd, &rfds);
        if (g_daemon.ctrl_listen_fd > maxfd) {
            maxfd = g_daemon.ctrl_listen_fd;
        }

        if (g_daemon.ctrl_client_fd >= 0) {
            FD_SET(g_daemon.ctrl_client_fd, &rfds);
            if (g_daemon.ctrl_client_fd > maxfd) {
                maxfd = g_daemon.ctrl_client_fd;
            }
        }

        /* If capturing, include packet socket */
        if (monitoring && !g_daemon.mock_mode && g_daemon.pkt_fd >= 0) {
            FD_SET(g_daemon.pkt_fd, &rfds);
            if (g_daemon.pkt_fd > maxfd) { maxfd = g_daemon.pkt_fd; }
        }

        /* If frames are pending in TX injection queue and are not paced,
         * monitor write readiness (§3.3). */
        if (monitoring && g_daemon.tx_q.count > 0
         && g_daemon.tx_q.interval_ms == 0
         && g_daemon.tx_fd >= 0 && !g_daemon.mock_mode) {
            FD_SET(g_daemon.tx_fd, &wfds);
            if (g_daemon.tx_fd > maxfd) { maxfd = g_daemon.tx_fd; }
        }

        /* Timeout: 10ms while monitoring; 1s if dead-man timer active;
         * block indefinitely when completely idle. */
        tv.tv_sec  = 0;
        tv.tv_usec = 10000;  /* 10ms */
        if (!monitoring && !g_daemon.hop_enabled && g_daemon.idle_timeout_sec > 0) {
            tv.tv_sec  = 1;
            tv.tv_usec = 0;
        }

        if (g_daemon.hop_enabled && g_daemon.hop_channel_count > 0) {
            int64_t now_ms = util_monotonic_ms();
            int64_t diff_ms = g_daemon.next_hop_ms - now_ms;
            if (diff_ms <= 0) {
                g_daemon.hop_index = (g_daemon.hop_index + 1) % g_daemon.hop_channel_count;
                int nxt_chan = g_daemon.hop_channels[g_daemon.hop_index];
                (void)radio_set_channel(&g_daemon, nxt_chan);
                g_daemon.next_hop_ms = now_ms + (int64_t)g_daemon.hop_interval_ms;
                diff_ms = g_daemon.hop_interval_ms;
            }
            long hop_usec = (long)(diff_ms * 1000LL);
            if (hop_usec > 0 && hop_usec < tv.tv_usec) {
                tv.tv_usec = hop_usec;
            }
        }
        /* §3.5.7: wake up in time for the next paced injection frame */
        if (monitoring && g_daemon.tx_q.count > 0
         && g_daemon.tx_q.interval_ms > 0) {
            int64_t now_ms = util_monotonic_ms();
            int64_t diff_ms = g_daemon.tx_q.next_tx_ms - now_ms;
            long    tx_usec;

            if (diff_ms < 1) { diff_ms = 1; }
            tx_usec = (long)(diff_ms * 1000LL);
            if (tx_usec < tv.tv_usec) {
                tv.tv_usec = tx_usec;
            }
        }
        {
            struct timeval *tvp = (monitoring || g_daemon.hop_enabled || g_daemon.idle_timeout_sec > 0)
                                ? &tv : NULL;
            fd_set *wset = (monitoring && g_daemon.tx_q.count > 0
                         && g_daemon.tx_q.interval_ms == 0
                         && g_daemon.tx_fd >= 0 && !g_daemon.mock_mode) ? &wfds : NULL;

            r = select(maxfd + 1, &rfds, wset, NULL, tvp);
        }

        if (r < 0) {
            if (errno == EINTR) { continue; }
            util_log("main", "select: %s", strerror(errno));
            break;
        }

        /* ── Dead-man failsafe check (§4.2) ───────────────────────────── */
        if (g_daemon.idle_timeout_sec > 0 && g_daemon.ctrl_client_fd >= 0) {
            int64_t now_sec = util_monotonic_sec();
            if (now_sec - g_daemon.last_activity_sec >= (int64_t)g_daemon.idle_timeout_sec) {
                util_log("main", "dead-man failsafe: client idle for %ds — stopping monitor",
                         g_daemon.idle_timeout_sec);
                ctrl_close_client(&g_daemon);
                continue;
            }
        }

        /* ── Autonomous channel hopping (§3.2) ────────────────────────── */
        if (g_daemon.hop_enabled && g_daemon.hop_channel_count > 0) {
            int64_t now_ms = util_monotonic_ms();
            if (now_ms >= g_daemon.next_hop_ms) {
                g_daemon.hop_index = (g_daemon.hop_index + 1) % g_daemon.hop_channel_count;
                int nxt_chan = g_daemon.hop_channels[g_daemon.hop_index];
                (void)radio_set_channel(&g_daemon, nxt_chan);
                g_daemon.next_hop_ms = now_ms + (int64_t)g_daemon.hop_interval_ms;
            }
        }

        /* ── Discovery ────────────────────────────────────────────────── */
        if (FD_ISSET(g_daemon.disc_fd, &rfds)) {
            (void)disc_handle(&g_daemon);
        }

        /* ── Accept new control client ────────────────────────────────── */
        if (FD_ISSET(g_daemon.ctrl_listen_fd, &rfds)) {
            (void)ctrl_accept(&g_daemon);
        }

        /* ── Read control commands ────────────────────────────────────── */
        if (g_daemon.ctrl_client_fd >= 0
         && FD_ISSET(g_daemon.ctrl_client_fd, &rfds)) {
            (void)ctrl_recv(&g_daemon);
        }

        /* ── Non-blocking TX frame injection drain (§3.3, §3.5.7) ─────── */
        if (monitoring && g_daemon.tx_q.count > 0) {
            if (g_daemon.tx_q.interval_ms > 0) {
                int64_t now_ms = util_monotonic_ms();
                if (now_ms >= g_daemon.tx_q.next_tx_ms) {
                    (void)tx_queue_drain_step(&g_daemon);
                    g_daemon.tx_q.next_tx_ms =
                        now_ms + (int64_t)g_daemon.tx_q.interval_ms;
                }
            } else if (g_daemon.mock_mode
                    || (g_daemon.tx_fd >= 0
                     && FD_ISSET(g_daemon.tx_fd, &wfds))) {
                int tx_limit = 16;
                while (tx_limit-- > 0 && g_daemon.tx_q.count > 0) {
                    int dr = tx_queue_drain_step(&g_daemon);
                    if (dr <= 0) { break; }
                }
            }

            if (g_daemon.tx_q.count == 0) {
                g_daemon.tx_q.interval_ms = 0;
                g_daemon.tx_q.next_tx_ms  = 0;
            }
        }

        /* ── Capture frames (with §4.2 Self-Healing on interface drop) ── */
        if (monitoring) {
            if (g_daemon.mock_mode) {
                mock_tick(&g_daemon);
            } else if (g_daemon.pkt_fd >= 0
                    && FD_ISSET(g_daemon.pkt_fd, &rfds)) {
                int cap_limit = 32;
                while (cap_limit-- > 0) {
                    int cr = capture_read_frame(&g_daemon);
                    if (cr == -2) {
                        /* §4.2: Self-heal interface if wlan0 dropped */
                        (void)capture_recover_interface(&g_daemon);
                        break;
                    }
                    if (cr <= 0) { break; }
                }
            }
        }

        /* ── Stream frames to host ────────────────────────────────────── */
        if (monitoring && g_daemon.stream_fd >= 0 && g_daemon.host_ip != 0) {
            int strim = 16;
            while (strim-- > 0) {
                int sr = stream_send_next(&g_daemon);
                if (sr > 0) {
                    g_daemon.last_activity_sec = util_monotonic_sec();
                } else {
                    break;
                }
            }

            /* Push BUFFER_OVERFLOW async event if drops occurred */
            if (g_daemon.frames_dropped > 0
             && g_daemon.ctrl_client_fd >= 0) {
                static uint64_t s_last_reported_drops;
                if (g_daemon.frames_dropped != s_last_reported_drops) {
                    char ev[256];
                    uint64_t new_drops =
                        g_daemon.frames_dropped - s_last_reported_drops;
                    s_last_reported_drops = g_daemon.frames_dropped;
                    (void)snprintf(ev, sizeof(ev),
                        "{\"id\":null,\"event\":\"BUFFER_OVERFLOW\","
                        "\"data\":{"
                        "\"dropped_frames\":%llu,"
                        "\"buffer_size_bytes\":%u,"
                        "\"channel\":%d}}\n",
                        (unsigned long long)new_drops,
                        RING_BYTES,
                        g_daemon.channel);
                    ctrl_send(&g_daemon, ev);
                }
            }
        }
    }

    /* ── Shutdown ───────────────────────────────────────────────────────── */
    util_log("main", "SIGTERM received — shutting down");

    ctrl_teardown_monitor(&g_daemon);

    if (g_daemon.ctrl_client_fd >= 0) { close(g_daemon.ctrl_client_fd); }
    if (g_daemon.ctrl_listen_fd >= 0) { close(g_daemon.ctrl_listen_fd); }
    if (g_daemon.disc_fd >= 0)        { close(g_daemon.disc_fd); }
    if (g_daemon.stream_fd >= 0)      { close(g_daemon.stream_fd); }
    if (g_daemon.tx_fd >= 0)          { close(g_daemon.tx_fd); }
    radio_netlink_close(&g_daemon);

    util_log("main", "pwn4cd stopped cleanly");
    closelog();
    return 0;
}
