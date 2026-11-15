/*
 * tests/test_rogue_ap.c — Unit tests for the evil-twin configuration builders
 * and the mock start/stop/report path.
 *
 * The generated hostapd and dnsmasq files are the whole attack surface of the
 * twin, so they are pinned exactly: interface, channel, hidden flag, the
 * hex-encoded SSID, the derived PSK (never the passphrase), and the DHCP
 * scope on 192.168.66.0/24 with DNS disabled.
 */

#include <stdio.h>
#include <string.h>

#include "../pwn4cd.h"

static int g_passed;
static int g_failed;

#define PASS(name) do { printf("  PASS: %s\n", name); g_passed++; } while(0)
#define FAIL(name, ...) do { \
    printf("  FAIL: %s — ", name); printf(__VA_ARGS__); printf("\n"); \
    g_failed++; } while(0)
#define CHECK(name, expr) do { \
    if (expr) { PASS(name); } else { FAIL(name, "assertion failed"); } \
} while(0)

static const char *BSSID = "02:00:00:de:ad:01";

/* ── hostapd configuration ────────────────────────────────────────────────── */

static void test_hostapd_open(void)
{
    char conf[1024];

    CHECK("open conf renders",
          rogue_hostapd_conf("mock-lab", "", 6, false, conf, sizeof(conf)) == 0);

    CHECK("open conf: driver", strstr(conf, "driver=nl80211\n") != NULL);
    CHECK("open conf: interface", strstr(conf, "interface=pwn4c-ap\n") != NULL);
    CHECK("open conf: hw_mode", strstr(conf, "hw_mode=g\n") != NULL);
    CHECK("open conf: channel", strstr(conf, "channel=6\n") != NULL);
    CHECK("open conf: ssid hex",
          strstr(conf, "ssid2=6d6f636b2d6c6162\n") != NULL);
    CHECK("open conf: not hidden",
          strstr(conf, "ignore_broadcast_ssid=0\n") != NULL);
    CHECK("open conf: wpa disabled", strstr(conf, "wpa=0\n") != NULL);
    CHECK("open conf: no PSK", strstr(conf, "wpa_psk=") == NULL);
}

static void test_hostapd_wpa2(void)
{
    char conf[1024];
    char want_psk[65];
    char want_line[80];

    CHECK("wpa2 conf renders",
          rogue_hostapd_conf("mock-lab", "supersecret", 11, true,
                             conf, sizeof(conf)) == 0);
    CHECK("wpa2 conf: channel", strstr(conf, "channel=11\n") != NULL);
    CHECK("wpa2 conf: hidden",
          strstr(conf, "ignore_broadcast_ssid=1\n") != NULL);
    CHECK("wpa2 conf: wpa=2", strstr(conf, "wpa=2\n") != NULL);
    CHECK("wpa2 conf: key mgmt",
          strstr(conf, "wpa_key_mgmt=WPA-PSK\n") != NULL);
    CHECK("wpa2 conf: ccmp", strstr(conf, "rsn_pairwise=CCMP\n") != NULL);

    /* The passphrase must never appear: only the derived 64-hex PSK. */
    CHECK("wpa2 conf: no passphrase", strstr(conf, "supersecret") == NULL);

    if (util_wpa_psk_hex("supersecret", "mock-lab", want_psk) == 0) {
        (void)snprintf(want_line, sizeof(want_line), "wpa_psk=%s\n", want_psk);
        CHECK("wpa2 conf: derived PSK", strstr(conf, want_line) != NULL);
    } else {
        FAIL("wpa2 conf: derived PSK", "util_wpa_psk_hex failed");
    }
}

static void test_hostapd_validation(void)
{
    char conf[1024];
    char small[8];
    char long_ssid[40];
    char long_pass[80];

    memset(long_ssid, 'a', sizeof(long_ssid) - 1);
    long_ssid[sizeof(long_ssid) - 1] = '\0';
    memset(long_pass, 'p', sizeof(long_pass) - 1);
    long_pass[sizeof(long_pass) - 1] = '\0';

    CHECK("reject empty ssid",
          rogue_hostapd_conf("", NULL, 6, false, conf, sizeof(conf)) < 0);
    CHECK("reject 39-byte ssid",
          rogue_hostapd_conf(long_ssid, NULL, 6, false, conf, sizeof(conf)) < 0);
    CHECK("reject channel 0",
          rogue_hostapd_conf("lab", NULL, 0, false, conf, sizeof(conf)) < 0);
    CHECK("reject channel 14",
          rogue_hostapd_conf("lab", NULL, 14, false, conf, sizeof(conf)) < 0);
    CHECK("reject short passphrase",
          rogue_hostapd_conf("lab", "short", 6, false, conf, sizeof(conf)) < 0);
    CHECK("reject 79-char passphrase",
          rogue_hostapd_conf("lab", long_pass, 6, false, conf, sizeof(conf)) < 0);
    CHECK("reject null out",
          rogue_hostapd_conf("lab", NULL, 6, false, NULL, 0) < 0);
    CHECK("reject tiny buffer",
          rogue_hostapd_conf("lab", NULL, 6, false, small, sizeof(small)) < 0);
}

/* ── dnsmasq configuration ────────────────────────────────────────────────── */

static void test_dnsmasq_conf(void)
{
    char conf[1024];

    CHECK("dnsmasq conf renders",
          rogue_dnsmasq_conf(conf, sizeof(conf)) == 0);

    CHECK("dnsmasq: DNS disabled", strstr(conf, "port=0\n") != NULL);
    CHECK("dnsmasq: bound to the twin",
          strstr(conf, "interface=pwn4c-ap\n") != NULL);
    CHECK("dnsmasq: dynamic bind", strstr(conf, "bind-dynamic\n") != NULL);
    CHECK("dnsmasq: DHCP scope",
          strstr(conf, "dhcp-range=192.168.66.10,192.168.66.200,"
                       "255.255.255.0,12h\n") != NULL);
    CHECK("dnsmasq: gateway option",
          strstr(conf, "dhcp-option=3,192.168.66.1\n") != NULL);
    CHECK("dnsmasq: DNS option",
          strstr(conf, "dhcp-option=6,192.168.66.1\n") != NULL);
    CHECK("dnsmasq: own log",
          strstr(conf, "log-facility=/tmp/pwn4c-dnsmasq.log\n") != NULL);
    CHECK("dnsmasq: tiny buffer rejected",
          rogue_dnsmasq_conf(conf, 8) < 0);
}

/* ── Mock lifecycle ───────────────────────────────────────────────────────── */

static void test_mock_lifecycle(void)
{
    daemon_t d;
    const char *report;

    memset(&d, 0, sizeof(d));
    d.mock_mode = true;
    d.state     = STATE_MONITORING;
    d.channel   = 6;

    /* Two stations from the mock capture feed, so the report has something to
     * count without touching a radio. */
    cl_reset();
    cl_mock_inject(&d);

    CHECK("mock start",
          rogue_start(&d, "mock-lab", BSSID, 6, "supersecret", false) == 0);

    report = rogue_report(&d);
    CHECK("mock report: active", strstr(report, "\"active\":true") != NULL);
    CHECK("mock report: ssid", strstr(report, "\"ssid\":\"mock-lab\"") != NULL);
    CHECK("mock report: bssid",
          strstr(report, "\"bssid\":\"02:00:00:DE:AD:01\"") != NULL);
    CHECK("mock report: wpa2",
          strstr(report, "\"security\":\"wpa2-psk\"") != NULL);
    CHECK("mock report: interface",
          strstr(report, "\"interface\":\"pwn4c-ap\"") != NULL);
    CHECK("mock report: ip", strstr(report, "\"ip\":\"192.168.66.1\"") != NULL);
    CHECK("mock report: two clients", strstr(report, "\"clients\":2") != NULL);
    CHECK("mock report: monitor active",
          strstr(report, "\"monitor_active\":true") != NULL);

    CHECK("second start refused",
          rogue_start(&d, "mock-lab", BSSID, 6, "", false) < 0);

    CHECK("mock stop", rogue_stop(&d) == 0);
    report = rogue_report(&d);
    CHECK("mock report after stop",
          strcmp(report, "{\"active\":false}") == 0);

    CHECK("stop is idempotent", rogue_stop(&d) == 0);
}

static void test_mock_open_network(void)
{
    daemon_t d;

    memset(&d, 0, sizeof(d));
    d.mock_mode = true;
    d.state     = STATE_CONNECTED;   /* no capture running */
    d.channel   = 1;

    CHECK("open twin starts",
          rogue_start(&d, "Free WiFi", BSSID, 1, "", false) == 0);
    CHECK("open twin report",
          strstr(rogue_report(&d), "\"security\":\"open\"") != NULL);
    CHECK("open twin monitor inactive",
          strstr(rogue_report(&d), "\"monitor_active\":false") != NULL);
    CHECK("open twin stops", rogue_stop(&d) == 0);
}

static void test_mock_validation(void)
{
    daemon_t d;

    memset(&d, 0, sizeof(d));
    d.mock_mode = true;
    d.state     = STATE_MONITORING;
    d.channel   = 6;

    CHECK("reject bad bssid",
          rogue_start(&d, "lab", "nope", 6, "", false) == -1);
    CHECK("reject broadcast bssid",
          rogue_start(&d, "lab", "ff:ff:ff:ff:ff:ff", 6, "", false) == -1);
    CHECK("reject bad channel",
          rogue_start(&d, "lab", BSSID, 0, "", false) == -1);
    CHECK("reject short passphrase",
          rogue_start(&d, "lab", BSSID, 6, "short", false) == -1);
    CHECK("reject empty ssid",
          rogue_start(&d, "", BSSID, 6, "", false) == -1);

    /* A live monitor pinned to channel 6 cannot host a channel-11 twin. */
    CHECK("reject channel mismatch",
          rogue_start(&d, "lab", BSSID, 11, "", false) == -2);
    CHECK("channel mismatch explains itself",
          strstr(rogue_error(), "channel 6") != NULL);

    CHECK("failed start leaves the twin inactive", !d.rogue.active);
}

/* ── Suite entry point ────────────────────────────────────────────────────── */

int run_rogue_ap_tests(void)
{
    g_passed = 0;
    g_failed = 0;

    printf("── Rogue AP (evil twin) tests ─────────────────────────────\n");

    test_hostapd_open();
    test_hostapd_wpa2();
    test_hostapd_validation();
    test_dnsmasq_conf();
    test_mock_lifecycle();
    test_mock_open_network();
    test_mock_validation();

    printf("  %d passed, %d failed\n", g_passed, g_failed);
    return g_failed;
}
