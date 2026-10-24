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
 *
 * Fix §1.4: advance through the JSON token by token so that string *values*
 * containing the target key name (e.g. "cmd":"SET_CHANNEL") can never cause
 * a false match on a subsequent lookup for "channel".  We skip over quoted
 * strings (both keys and values) to stay structurally aware.
 */
static const char *find_key(const char *json, const char *key)
{
    size_t      klen;
    const char *p;
    char        needle[130];  /* "key"\0 */

    if (!json || !key) { return NULL; }
    klen = strlen(key);
    if (klen + 3 >= sizeof(needle)) { return NULL; }  /* safety */

    /* Build the quoted key pattern: "key" */
    needle[0] = '"';
    memcpy(needle + 1, key, klen);
    needle[1 + klen] = '"';
    needle[2 + klen] = '\0';

    p = json;
    while (*p != '\0') {
        /* Skip whitespace and structural characters */
        if (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'
            || *p == '{' || *p == '}' || *p == '[' || *p == ']'
            || *p == ',' || *p == ':') {
            p++;
            continue;
        }

        if (*p == '"') {
            /* Scan a quoted token (key or string value) */
            const char *tok_start = p;
            p++;  /* skip opening quote */
            while (*p != '\0') {
                if (*p == '\\') {
                    p++;             /* skip escape prefix */
                    if (*p) { p++; } /* skip escaped char  */
                    continue;
                }
                if (*p == '"') {
                    p++;  /* skip closing quote */
                    break;
                }
                p++;
            }
            /* Now p points just past the closing quote.
             * Skip optional whitespace and check for ':' to distinguish
             * a key from a string value. */
            const char *after = p;
            while (*after == ' ' || *after == '\t' || *after == '\n'
                   || *after == '\r') {
                after++;
            }
            if (*after == ':') {
                /* This token is a key.  Check if it matches our target. */
                size_t tok_len = (size_t)(p - tok_start);
                size_t needle_len = klen + 2;  /* "key" */
                if (tok_len == needle_len
                    && memcmp(tok_start, needle, needle_len) == 0) {
                    /* Match!  Skip past the colon and optional whitespace. */
                    after++;  /* skip ':' */
                    while (*after == ' ' || *after == '\t') { after++; }
                    return after;
                }
                /* Not our key — skip past ':' and continue with the value */
                p = after + 1;  /* advance past ':' */
            }
            /* else: string value — p is already past it; continue */
            continue;
        }

        /* Non-string token (number, boolean, null) — skip it */
        while (*p != '\0' && *p != ',' && *p != '}' && *p != ']'
               && *p != ' ' && *p != '\t' && *p != '\n' && *p != '\r') {
            p++;
        }
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

/*
 * json_get_int_array — Extract an array of integers for key into out array.
 * Returns 0 on success, -1 if key missing or not an array.
 */
int json_get_int_array(const char *json, const char *key, int *out,
                       size_t max_out, size_t *out_len)
{
    const char *p;
    size_t count = 0;

    if (!out || max_out == 0 || !out_len) { return -1; }
    *out_len = 0;

    p = find_key(json, key);
    if (!p) { return -1; }

    while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n') { p++; }
    if (*p != '[') { return -1; }
    p++; /* skip '[' */

    while (*p != '\0' && *p != ']') {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ',') {
            p++;
        }
        if (*p == ']') { break; }
        if (*p == '-' || isdigit((unsigned char)*p)) {
            char *end = NULL;
            long v;
            errno = 0;
            v = strtol(p, &end, 10);
            if (errno != 0 || end == p) { return -1; }
            if (v > INT_MAX || v < INT_MIN) { return -1; }
            if (count < max_out) {
                out[count++] = (int)v;
            }
            p = end;
        } else {
            return -1;
        }
    }

    if (*p != ']') { return -1; }
    *out_len = count;
    return 0;
}

