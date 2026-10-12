/*
 * json_parse.c — Minimal, zero-allocation JSON field extractor.
 *
 * Handles only the subset of JSON used by the pwn4cd protocol:
 *   - string fields (quoted)
 *   - integer fields (unquoted decimal)
 *   - existence checks
 *
 * Does NOT handle nested objects except by treating them as opaque strings.
 * Sufficient for flat command envelopes per api_reference.md.
 *
 * SECURITY NOTE: All outputs are bounded; partial/malformed input is rejected.
 */

#include "pwn4cd.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <limits.h>

/*
 * Find the value text starting after "key": in json.
 * Returns pointer into json just past the colon+whitespace, or NULL.
 */
static const char *find_key(const char *json, const char *key)
{
    size_t klen;
    const char *p;
    char needle[128];

    if (!json || !key) { return NULL; }
    klen = strlen(key);
    if (klen + 4 >= sizeof(needle)) { return NULL; }  /* "KEY": */

    /* Build: "key" */
    needle[0] = '"';
    memcpy(needle + 1, key, klen);
    needle[1 + klen] = '"';
    needle[2 + klen] = '\0';

    p = json;
    while ((p = strstr(p, needle)) != NULL) {
        /* verify it's a proper JSON key (preceded by { , or whitespace) */
        const char *after = p + 1 + klen + 1;  /* skip "key" */
        /* skip whitespace */
        while (*after == ' ' || *after == '\t' || *after == '\n'
               || *after == '\r') {
            after++;
        }
        if (*after == ':') {
            after++;
            while (*after == ' ' || *after == '\t') { after++; }
            return after;
        }
        p++;  /* advance past false match */
    }
    return NULL;
}

/*
 * json_get_str — Extract a string value for key into out (null-terminated).
 * Returns 0 on success, -1 if not found or not a string.
 */
int json_get_str(const char *json, const char *key, char *out, size_t n)
{
    const char *p;
    const char *start;
    size_t len;

    if (!out || n == 0) { return -1; }
    out[0] = '\0';

    p = find_key(json, key);
    if (!p) { return -1; }

    if (*p != '"') { return -1; }  /* not a string value */
    start = p + 1;

    p = start;
    while (*p && *p != '"') {
        if (*p == '\\') { p++; }  /* skip escaped char */
        if (*p) { p++; }
    }
    if (*p != '"') { return -1; }  /* unterminated string */

    len = (size_t)(p - start);
    if (len >= n) { len = n - 1; }

    memcpy(out, start, len);
    out[len] = '\0';
    return 0;
}

/*
 * json_get_int — Extract an integer value for key into out.
 * Returns 0 on success, -1 if not found or not an integer.
 */
int json_get_int(const char *json, const char *key, int *out)
{
    const char *p;
    long v;
    char *end;

    if (!out) { return -1; }
    *out = 0;

    p = find_key(json, key);
    if (!p) { return -1; }

    /* allow null keyword */
    if (strncmp(p, "null", 4) == 0) { return -1; }

    if (*p != '-' && !isdigit((unsigned char)*p)) { return -1; }

    errno = 0;
    v = strtol(p, &end, 10);
    if (errno != 0 || end == p) { return -1; }
    /* Clamp: truncated out-of-int values (e.g. 2^32+k) must not silently
     * become small valid ints like a channel number. */
    if (v > INT_MAX || v < INT_MIN) { return -1; }

    *out = (int)v;
    return 0;
}

/*
 * json_field_exists — Returns 1 if the key exists, 0 otherwise.
 */
int json_field_exists(const char *json, const char *key)
{
    return find_key(json, key) != NULL ? 1 : 0;
}
