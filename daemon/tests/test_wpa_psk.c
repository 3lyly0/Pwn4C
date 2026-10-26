/*
 * tests/test_wpa_psk.c — Unit tests for util_wpa_psk_hex()
 *
 * The WPA PSK must match the IEEE 802.11i PBKDF2-HMAC-SHA1 definition
 * (4096 iterations, SSID as salt). A mismatch here would make every
 * passphrase-derived key wrong, so pin it with published vectors.
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

static void test_known_vectors(void)
{
    char hex[65];

    /* IEEE 802.11i / wpa_passphrase reference vector */
    CHECK("wpa_psk IEEE/password",
          util_wpa_psk_hex("password", "IEEE", hex) == 0 &&
          strcmp(hex, "f42c6fc52df0ebef9ebb4b90b38a5f90"
                      "2e83fe1b135a70e23aed762e9710a12e") == 0);

    /* wpa_supplicant test-suite vector */
    CHECK("wpa_psk ThisIsAPassword/ThisIsASSID",
          util_wpa_psk_hex("ThisIsAPassword", "ThisIsASSID", hex) == 0 &&
          strcmp(hex, "0dc0d6eb90555ed6419756b9a15ec3e3"
                      "209b63df707dd508d14581f8982721af") == 0);

    /* Special characters are just bytes to PBKDF2 — this exercises
     * length and SSID handling without pinning a real network. */
    CHECK("wpa_psk p@ssw0rd!/TestNet",
          util_wpa_psk_hex("p@ssw0rd!", "TestNet", hex) == 0 &&
          strlen(hex) == 64);
}

static void test_invalid_input(void)
{
    char hex[65];

    CHECK("wpa_psk rejects short key",
          util_wpa_psk_hex("short", "IEEE", hex) < 0);
    CHECK("wpa_psk rejects long key",
          util_wpa_psk_hex("0123456789012345678901234567890123456789"
                           "0123456789012345678901234", "IEEE", hex) < 0);
    CHECK("wpa_psk rejects long SSID",
          util_wpa_psk_hex("password",
                           "012345678901234567890123456789012", hex) < 0);
    CHECK("wpa_psk rejects NULL",
          util_wpa_psk_hex(NULL, "IEEE", hex) < 0);
}

int run_wpa_psk_tests(void)
{
    printf("=== WPA PSK (PBKDF2-HMAC-SHA1) Tests ===\n");
    test_known_vectors();
    test_invalid_input();
    return g_failed;
}

#ifndef TEST_COMBINED
int main(void)
{
    run_wpa_psk_tests();
    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
#endif
