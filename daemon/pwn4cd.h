/*
 * pwn4cd.h — Shared types, constants, and declarations for the pwn4cd daemon.
 *
 * Target: mipsel-openwrt-linux-musl (MT7628N, MIPS 24KEc, no FPU)
 * C standard: C99
 * Constraints: no float/double, no dynamic allocation in hot paths,
 *              snprintf bounds everywhere, check every syscall.
 */

#ifndef PWN4CD_H
#define PWN4CD_H

/* ── Portability ──────────────────────────────────────────────────────────── */
/* _GNU_SOURCE and _POSIX_C_SOURCE are defined via -D on the compiler CLI
 * (see Makefile COMMON_CFLAGS).  Do NOT redefine here to avoid -Werror
 * redefinition diagnostics. */

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <sys/types.h>
#include <linux/filter.h>

/* ── Build-time constants ─────────────────────────────────────────────────── */
/* DAEMON_VERSION comes from the build (Makefile VERSION, default: git
 * describe). Keep the fallback for direct cc invocations. */
#ifndef DAEMON_VERSION
#define DAEMON_VERSION      "1.3.0"
#endif
#define DAEMON_HARDWARE     "mi4c-mt7628n"
#define DAEMON_CHIPSET      "MT7628N"
#define DAEMON_BAND         "2.4GHz"
#define DAEMON_MAX_TXPWR    20          /* dBm — hardware ceiling             */

#define DISC_PORT           4440        /* UDP discovery                      */
#define CTRL_PORT           4444        /* TCP control                        */
#define STREAM_PORT         5555        /* UDP frame stream                   */

#define PROTO_VERSION       1

/* Ring-buffer capacity (bytes): must be power-of-two for mask trick */
#define RING_BYTES          (512u * 1024u)  /* 512 KiB — 8x burst headroom   */
#define RING_MASK           (RING_BYTES - 1u)

/* Per-frame slot inside the ring: 16-byte stream header + up to 2316 bytes  *
 * (max 802.11 MPDU with RadioTap).  We cap at this so the slot fits.        */
#define FRAME_SLOT_MAX      2332u

/* UDP stream: max payload per datagram (1500 - 20 IP - 8 UDP = 1472)        */
#define STREAM_FRAG_MAX     1472u
#define STREAM_HDR_LEN      16u

/* Control JSON line buffer */
#define JSON_BUF_LEN        8192

/* Interface names (mt76 default names on OpenWrt for MT7628N — verified live:
 * `iw dev` shows wlan0; ra0 is the old Ralink proprietary naming) */
#define WLAN_IFACE_DEFAULT  "wlan0"
#define ETH_IFACE_DEFAULT   "eth0"

/* Default pre-shared key file path on OpenWrt rootfs (§4.1) */
#define PSK_FILE_DEFAULT    "/etc/pwn4c.key"

/* Max channels in the 2.4 GHz band */
#define CHAN_MIN            1
#define CHAN_MAX            13

/* TX injection retry policy (hardware.md §kmod-mt76) */
#define TX_RETRY_COUNT      10
#define TX_RETRY_MS         1

/* iw timeout: 2-second hard limit per architecture.md */
#define IW_TIMEOUT_SECS     2

/* ── Radio mode states ────────────────────────────────────────────────────── */
typedef enum {
    RADIO_DOWN    = 0,  /* boot-safe: radio administratively down            */
    RADIO_NORMAL  = 1,  /* managed / AP: UCI wireless profile active          */
    RADIO_MONITOR = 2,  /* monitor: AF_PACKET capture active                  */
} radio_mode_t;

/* ── Daemon lifecycle states ──────────────────────────────────────────────── */
typedef enum {
    STATE_IDLE       = 0,
    STATE_CONNECTED  = 1,
    STATE_MONITORING = 2,
    STATE_INJECTING  = 3,
} daemon_state_t;

/* ── Stream datagram header (network byte order = big-endian) ─────────────── */
/* Matches api_reference.md §UDP Frame Stream Format exactly.                 */
typedef struct __attribute__((packed)) {
    uint32_t seq_num;         /* monotonically increasing, wraps at 2^32       */
    uint32_t timestamp_lo32;  /* lower 32 bits of µs since START_MONITOR       */
    uint16_t frag_index;      /* 0-based                                        */
    uint16_t frag_count;      /* 1 = unfragmented                               */
    uint16_t frame_len;       /* total reassembled frame length                 */
    uint16_t timestamp_hi16;  /* upper 16 bits of 48-bit µs timestamp          */
} stream_hdr_t;

/* ── Ring-buffer slot header ──────────────────────────────────────────────── */
/* Stored in the ring before each captured frame's bytes.                     */
typedef struct __attribute__((packed)) {
    uint16_t frame_bytes;   /* byte count of the RadioTap+802.11 payload      */
    uint16_t _pad;
} slot_hdr_t;

/* ── Non-blocking TX Injection Queue (§3.3, §3.5.7) ───────────────────────── */
#define TX_QUEUE_MAX        64u

typedef struct {
    uint8_t  frame[FRAME_SLOT_MAX];
    uint16_t len;
    uint8_t  retries;
} tx_slot_t;

typedef struct {
    tx_slot_t slots[TX_QUEUE_MAX];
    uint32_t  head;
    uint32_t  tail;
    uint32_t  count;
    uint32_t  interval_ms;   /* inter-frame pacing; 0 = drain immediately  */
    int64_t   next_tx_ms;    /* monotonic ms of next permitted transmission */
} tx_queue_t;

/* ── Daemon global state ──────────────────────────────────────────────────── */
typedef struct {
    /* Identity */
    char        drone_id[32];           /* "pwn4c-XXXX" derived from MAC     */
    char        wlan_iface[16];         /* e.g. "wlan0"                      */
    char        eth_iface[16];          /* e.g. "eth0"                       */
    uint8_t     base_mac[6];            /* read from /sys/class/net/.../address */

    /* Radio state */
    radio_mode_t radio_mode;
    int          channel;               /* 1-13, current channel              */
    int          tx_power_dbm;          /* 1-20                               */
    uint8_t      mac_override[6];       /* 0-filled = no override             */
    bool         mac_override_set;

    /* Daemon lifecycle */
    daemon_state_t state;
    bool         mock_mode;             /* --mock: no hardware ops            */

    /* Sockets */
    int          disc_fd;               /* UDP :4440                          */
    int          ctrl_listen_fd;        /* TCP :4444 listen                   */
    int          ctrl_client_fd;        /* TCP accepted client (-1 = none)    */
    int          stream_fd;             /* UDP tx socket for :5555            */
    int          pkt_fd;                /* AF_PACKET raw capture socket (-1)  */
    int          tx_fd;                 /* AF_PACKET injection socket (-1)    */
    int          nl_fd;                 /* persistent Generic Netlink (-1)     */
    int          nl_family_id;          /* cached nl80211 family id (-1)       */

    /* Non-blocking frame injection queue (§3.3) */
    tx_queue_t   tx_q;

    /* Classic BPF kernel filter state (§3.4) */
    bool         filter_active;
    bool         filter_mgmt_only;
    bool         filter_bssid_set;
    uint8_t      filter_bssid[6];

    /* Control & Discovery Pre-Shared Key Authentication (§4.1) */
    bool         psk_required;          /* true if --psk or /etc/pwn4c.key set*/
    char         psk[128];              /* pre-shared key secret              */
    bool         client_authed;         /* true if current TCP client authed  */
    char         auth_nonce[33];        /* 32-hex-char per-connection nonce   */

    /* Self-healing & dead-man failsafe (§4.2) */
    int          idle_timeout_sec;      /* 0 = disabled; >0 = dead-man timer  */
    int64_t      last_activity_sec;     /* monotonic sec of last ctrl activity*/
    uint64_t     iface_recoveries;      /* count of self-healed ENETDOWN/DEV  */

    /* Peer address (filled from TCP connect, used for stream UDP target)     */
    uint32_t     host_ip;               /* network byte order                 */

    /* Capture ring buffer (fixed, BSS-allocated in main)                     */
    uint8_t     *ring_buf;              /* pointer to 512KB static array      */
    uint32_t     ring_head;             /* write cursor                       */
    uint32_t     ring_tail;             /* read cursor                        */

    /* Telemetry counters */
    uint64_t     frames_captured;
    uint64_t     frames_dropped;
    uint64_t     ring_overruns;         /* ring buffer drops (tail advance count)  */
    uint64_t     inject_failures;       /* injection TX failures                   */
    uint32_t     stream_seq;            /* next stream sequence number        */

    /* Autonomous channel hopping state (§3.2) */
    bool         hop_enabled;
    int          hop_interval_ms;            /* dwell time in ms (e.g. 250)    */
    int          hop_channels[CHAN_MAX];     /* list of channels 1-13          */
    int          hop_channel_count;          /* count of channels in hop_channels */
    int          hop_index;                  /* current index in hop_channels  */
    int64_t      next_hop_ms;                /* monotonic millisecond timestamp*/

    /* Monitor session start (for timestamp_us) — stored as struct timespec   *
     * to avoid float; we compute µs diff using integer arithmetic.           */
    int64_t      monitor_start_sec;
    int32_t      monitor_start_nsec;

    /* Uptime (daemon start) */
    int64_t      start_sec;

    /* Saved pre-monitor radio state (for restoration) */
    int          saved_channel;
    radio_mode_t saved_radio_mode;

    /* Signal flags (set by signal handler, read in main loop) */
    volatile int sig_term;
    volatile int sig_hup;
} daemon_t;

/* ── Function declarations ────────────────────────────────────────────────── */

/* util.c */
int     util_read_file(const char *path, char *buf, size_t bufsize);
int     util_read_int_file(const char *path, int *out);
void    util_log(const char *tag, const char *fmt, ...);
void    util_trace(const char *tag, const char *fmt, ...);
int     util_run_cmd(const char *cmd);
int     util_run_cmd_timeout(const char *cmd, int timeout_secs);
int     util_run_cmd_timeout_quiet(const char *cmd, int timeout_secs);
int     util_run_cmd_capture(const char *cmd, char *out, size_t outsz, int timeout_secs);
int     util_run_detached(const char *cmd);
void    util_json_escape(const char *in, char *out, size_t outsz);
int     util_uptime_seconds(void);
int     util_free_ram_bytes(int64_t *out);
int     util_cpu_temp(int *out_celsius);  /* integer tenths → rounded int    */
int     util_read_mac(const char *iface, uint8_t mac[6]);
void    util_mac_to_str(const uint8_t mac[6], char *buf, size_t n);
int     util_parse_mac(const char *s, uint8_t mac[6]);
int64_t util_monotonic_sec(void);
int64_t util_monotonic_ms(void);
int64_t util_monotonic_us(void);
int     util_clock_gettime_sec(int64_t *sec, int32_t *nsec);
void    util_sleep_ms(int ms);
int     util_get_kernel_version(char *buf, size_t n);
void    util_sha256(const uint8_t *data, size_t len, uint8_t out[32]);
void    util_hmac_sha256(const uint8_t *key, size_t key_len,
                         const uint8_t *data, size_t data_len,
                         uint8_t out[32]);
void    util_hmac_sha256_hex(const char *key, const char *msg, char out_hex[65]);
int     util_random_hex(char *out, size_t hex_chars);

/*
 * util_wpa_psk_hex — Derive the 64-hex WPA PSK from an 8-63 char passphrase
 * and the SSID using PBKDF2-HMAC-SHA1 (4096 iterations, IEEE 802.11i).
 * Returns 0 on success, -1 on invalid input.
 *
 * Feeding the derived hex key to wpa_supplicant avoids every passphrase
 * parsing/quoting corner case in the UCI -> netifd -> supplicant chain.
 */
int     util_wpa_psk_hex(const char *passphrase, const char *ssid,
                         char out_hex[65]);

/* radio.c */
int     radio_set_down(daemon_t *d);
int     radio_enter_monitor(daemon_t *d, int channel);
int     radio_exit_monitor(daemon_t *d);
int     radio_set_channel(daemon_t *d, int channel);
int     radio_set_txpower(daemon_t *d, int dbm);
int     radio_set_mac(daemon_t *d, const uint8_t mac[6]);
int     radio_restore_normal(daemon_t *d);
void    radio_netlink_close(daemon_t *d);

/* capture.c */
int     capture_open(daemon_t *d);
void    capture_close(daemon_t *d);
int     capture_read_frame(daemon_t *d);   /* returns 1=frame, 0=none, -1=err, -2=ifdown */
int     capture_get_kernel_drops(daemon_t *d, uint32_t *tp_drops_out);
int     capture_build_bpf(bool mgmt_only, const uint8_t *bssid,
                          struct sock_filter *insns, unsigned short max_insns,
                          unsigned short *len_out);
int     capture_set_filter(daemon_t *d, bool mgmt_only, const uint8_t *bssid);
int     capture_recover_interface(daemon_t *d);

/* stream.c */
int     stream_open(daemon_t *d);
void    stream_close(daemon_t *d);
int     stream_send_next(daemon_t *d);     /* drain one ring slot to UDP      */

/* control.c */
int     ctrl_setup(daemon_t *d);
int     ctrl_accept(daemon_t *d);
int     ctrl_handle_line(daemon_t *d, const char *line);
void    ctrl_send(daemon_t *d, const char *json_line);
void    ctrl_close_client(daemon_t *d);
void    ctrl_teardown_monitor(daemon_t *d);
/*
 * ctrl_teardown_monitor covers every path that ends a capture session.
 * It also fires when radio_mode is RADIO_MONITOR (e.g. an in-flight
 * WIFI_SCAN) even if the daemon state has not been flipped.
 */
int     tx_queue_drain_step(daemon_t *d);

/* discovery.c */
int     disc_setup(daemon_t *d);
int     disc_handle(daemon_t *d);

/* json_parse.c */
/* Tiny zero-allocation JSON field extractor */
int     json_get_str(const char *json, const char *key, char *out, size_t n);
int     json_get_int(const char *json, const char *key, int *out);
int     json_get_int_array(const char *json, const char *key, int *out, size_t max_out, size_t *out_len);
int     json_field_exists(const char *json, const char *key);

/* wifi_scan.c — monitor-mode survey (WIFI_SCAN) */
#define SCAN_MAX_NETS       24
#define SCAN_SSID_MAX       32

typedef struct {
    char     ssid[SCAN_SSID_MAX + 1];
    uint8_t  bssid[6];
    int      channel;
    int      signal_dbm;      /* 0 when unknown                              */
    uint16_t ssid_len;        /* advertised length even when hidden          */
    bool     hidden;
    uint16_t beacons;         /* announcement frames seen for this BSSID     */
} scan_net_t;

int     scan_run(daemon_t *d, int dwell_ms, char *out_json, size_t out_sz);
int     scan_parse_beacon(const uint8_t *frame, size_t len,
                          int fallback_channel, scan_net_t *out);

/* wifi_sta.c — managed station mode (WIFI_CONNECT / STATUS / DISCONNECT)   */
int     wifi_sta_connect(daemon_t *d, const char *ssid, const char *psk,
                         const char *bssid, const char *encryption);
int     wifi_sta_status(daemon_t *d, char *out_json, size_t out_sz);
int     wifi_sta_disconnect(daemon_t *d);

/* mock.c */
void    mock_run(daemon_t *d);
void    mock_scan_json(char *out, size_t n);
void    mock_sta_status_json(char *out, size_t n);

#endif /* PWN4CD_H */
