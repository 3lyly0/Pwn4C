/*
 * tests/test_json.c — Unit tests for json_parse.c
 *
 * Tests:
 *   1. json_get_str: happy path
 *   2. json_get_str: missing key
 *   3. json_get_str: value truncated to buffer size
 *   4. json_get_int: integer value
 *   5. json_get_int: negative integer
 *   6. json_get_int: missing key
 *   7. json_get_int: string value (should fail)
 *   8. json_field_exists: present
 *   9. json_field_exists: absent
 *  10. Malformed JSON (no closing quote) — should not crash
 *  11. Real command envelope: GET_STATUS
 *  12. Real command envelope: START_MONITOR with channel
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>

/* Include json_parse declarations */
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

static void test_json_get_str(void)
{
    char out[64];
    int r;

    /* 1. Happy path */
    r = json_get_str("{\"command\":\"GET_STATUS\",\"id\":\"abc\"}", "command",
                     out, sizeof(out));
    CHECK("get_str happy", r == 0 && strcmp(out, "GET_STATUS") == 0);

    /* 2. Missing key */
    r = json_get_str("{\"command\":\"GET_STATUS\"}", "nonexistent",
                     out, sizeof(out));
    CHECK("get_str missing", r < 0);

    /* 3. Truncation */
    r = json_get_str("{\"key\":\"ABCDEFGHIJ\"}", "key", out, 5);
    /* Should succeed but truncate to 4 chars */
    CHECK("get_str truncated", r == 0 && strlen(out) == 4
          && strncmp(out, "ABCD", 4) == 0);

    /* 4. Empty string value */
    r = json_get_str("{\"key\":\"\"}", "key", out, sizeof(out));
    CHECK("get_str empty", r == 0 && strcmp(out, "") == 0);

    /* 5. Value that looks like JSON (not parsed as nested) */
    r = json_get_str("{\"a\":\"hello world\",\"b\":\"world\"}",
                     "a", out, sizeof(out));
    CHECK("get_str with spaces", r == 0 && strcmp(out, "hello world") == 0);

    /* 6. Malformed (no closing quote) — must not crash, must return error */
    r = json_get_str("{\"key\":\"unclosed", "key", out, sizeof(out));
    CHECK("get_str unclosed", r < 0);

    /* ── §1.4 edge-case: key name embedded inside a string value ────────── *
     * {"cmd":"SET_CHANNEL","channel":6} — looking up "channel" must NOT     *
     * match the substring inside the value "SET_CHANNEL".                   */
    r = json_get_str("{\"cmd\":\"SET_CHANNEL\",\"channel\":\"6\"}",
                     "channel", out, sizeof(out));
    CHECK("get_str no value-substring match", r == 0 && strcmp(out, "6") == 0);

    /* §1.4: key name is a prefix of another key — must not cross-match */
    r = json_get_str("{\"ch\":\"A\",\"channel\":\"B\"}", "ch", out, sizeof(out));
    CHECK("get_str prefix key no spill", r == 0 && strcmp(out, "A") == 0);

    /* §1.4: value contains literal "\"cmd\"" substring — must not confuse */
    r = json_get_str("{\"data\":\"has \\\"cmd\\\" in value\",\"cmd\":\"REAL\"}",
                     "cmd", out, sizeof(out));
    CHECK("get_str escaped-quote in value", r == 0 && strcmp(out, "REAL") == 0);
}

static void test_json_get_int(void)
{
    int v;
    int r;

    /* 1. Positive integer */
    r = json_get_int("{\"channel\":6}", "channel", &v);
    CHECK("get_int positive", r == 0 && v == 6);

    /* 2. Negative integer */
    r = json_get_int("{\"temp\":-42}", "temp", &v);
    CHECK("get_int negative", r == 0 && v == -42);

    /* 3. Zero */
    r = json_get_int("{\"x\":0}", "x", &v);
    CHECK("get_int zero", r == 0 && v == 0);

    /* 4. Missing key */
    r = json_get_int("{\"a\":1}", "b", &v);
    CHECK("get_int missing", r < 0);

    /* 5. String value (should fail) */
    r = json_get_int("{\"cmd\":\"hello\"}", "cmd", &v);
    CHECK("get_int string", r < 0);

    /* 6. null value (should fail) */
    r = json_get_int("{\"id\":null}", "id", &v);
    CHECK("get_int null", r < 0);

    /* 7. Large number */
    r = json_get_int("{\"bytes\":65536}", "bytes", &v);
    CHECK("get_int large", r == 0 && v == 65536);

    /* ── §1.4 edge-case: integer key name substring inside string value ─── *
     * {"cmd":"SET_CHANNEL","channel":11} — lookup "channel" must return 11, *
     * not accidentally match the substring in the value "SET_CHANNEL".      */
    r = json_get_int("{\"cmd\":\"SET_CHANNEL\",\"channel\":11}", "channel", &v);
    CHECK("get_int no value-substring match", r == 0 && v == 11);

    /* §1.4: key appears as value in a neighbour field */
    r = json_get_int("{\"info\":\"channel is here\",\"channel\":3}", "channel", &v);
    CHECK("get_int key-in-string-value", r == 0 && v == 3);
}

static void test_json_field_exists(void)
{
    CHECK("exists yes",
          json_field_exists("{\"mac\":\"AA:BB:CC:DD:EE:FF\"}", "mac") == 1);
    CHECK("exists no",
          json_field_exists("{\"mac\":\"AA:BB:CC:DD:EE:FF\"}", "key") == 0);
    CHECK("exists empty",
          json_field_exists("{}", "x") == 0);
}

static void test_real_commands(void)
{
    char cmd[64], id[64];
    int  channel, v;
    int  r;

    /* GET_STATUS envelope */
    const char *gs = "{\"id\":\"cmd-001\",\"command\":\"GET_STATUS\","
                     "\"params\":{}}";
    r = json_get_str(gs, "id", id, sizeof(id));
    CHECK("gs id",  r == 0 && strcmp(id, "cmd-001") == 0);
    r = json_get_str(gs, "command", cmd, sizeof(cmd));
    CHECK("gs cmd", r == 0 && strcmp(cmd, "GET_STATUS") == 0);

    /* START_MONITOR with channel */
    const char *sm = "{\"id\":\"cmd-002\",\"command\":\"START_MONITOR\","
                     "\"params\":{\"channel\":6,\"ht_mode\":\"HT20\"}}";
    r = json_get_str(sm, "command", cmd, sizeof(cmd));
    CHECK("sm cmd", r == 0 && strcmp(cmd, "START_MONITOR") == 0);

    /* Extract from params substring */
    const char *params = strstr(sm, "\"params\"");
    params = strchr(params, '{');
    r = json_get_int(params, "channel", &channel);
    CHECK("sm channel", r == 0 && channel == 6);

    /* SET_CHANNEL */
    const char *sc = "{\"id\":\"cmd-004\",\"command\":\"SET_CHANNEL\","
                     "\"params\":{\"channel\":11}}";
    params = strstr(sc, "\"params\"");
    params = strchr(params, '{');
    r = json_get_int(params, "channel", &v);
    CHECK("sc channel", r == 0 && v == 11);

    /* SET_TX_POWER */
    const char *stp = "{\"id\":\"cmd-006\",\"command\":\"SET_TX_POWER\","
                      "\"params\":{\"power_dbm\":15}}";
    params = strstr(stp, "\"params\"");
    params = strchr(params, '{');
    r = json_get_int(params, "power_dbm", &v);
    CHECK("stp power", r == 0 && v == 15);

    /* Unknown command still has parseable id */
    const char *unk = "{\"id\":\"cmd-999\",\"command\":\"FROBNICATE\","
                      "\"params\":{}}";
    r = json_get_str(unk, "id", id, sizeof(id));
    CHECK("unk id", r == 0 && strcmp(id, "cmd-999") == 0);
    r = json_get_str(unk, "command", cmd, sizeof(cmd));
    CHECK("unk cmd", r == 0 && strcmp(cmd, "FROBNICATE") == 0);
}

void run_json_tests(void)
{
    printf("=== JSON Parser Tests ===\n");
    test_json_get_str();
    test_json_get_int();
    test_json_field_exists();
    test_real_commands();
}

#ifndef TEST_COMBINED
int main(void)
{
    run_json_tests();
    printf("\n%d passed, %d failed\n", g_passed, g_failed);
    return g_failed > 0 ? 1 : 0;
}
#endif
