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

static int json_hexval(char c)
{
    if (c >= '0' && c <= '9') { return c - '0'; }
    if (c >= 'a' && c <= 'f') { return c - 'a' + 10; }
    if (c >= 'A' && c <= 'F') { return c - 'A' + 10; }
    return -1;
}

/*
 * json_get_str — Extract a string value for key into out (null-terminated).
 *
 * Decodes the JSON escapes (\", \\, \/, \b, \f, \n, \r, \t, \uXXXX) instead
 * of copying them verbatim.  This matters for parameters sent by Go's
 * encoding/json, which HTML-escapes '<', '>' and '&' as \u003c/\u003e/\u0026:
 * without decoding, a Wi-Fi passphrase containing either character would be
 * written to UCI with the literal escape text and the AP would reject the key.
 *
 * Returns 0 on success, -1 if not found, malformed, or not a string.
 */
int json_get_str(const char *json, const char *key, char *out, size_t n)
{
    const char *p;
    size_t wi = 0;

    if (!out || n == 0) { return -1; }
    out[0] = '\0';

    p = find_key(json, key);
    if (!p || *p != '"') { return -1; }
    p++;  /* skip opening quote */

    while (*p != '\0') {
        unsigned char c;

        if (*p == '"') {
            out[wi] = '\0';
            return 0;
        }

        c = (unsigned char)*p++;
        if (c != '\\') {
            if (wi + 1 < n) { out[wi++] = (char)c; }
            continue;
        }

        if (*p == '\0') { return -1; }
        {
            char esc = *p++;

            switch (esc) {
            case '"':  c = '"';  break;
            case '\\': c = '\\'; break;
            case '/':  c = '/';  break;
            case 'b':  c = '\b'; break;
            case 'f':  c = '\f'; break;
            case 'n':  c = '\n'; break;
            case 'r':  c = '\r'; break;
            case 't':  c = '\t'; break;
            case 'u': {
                uint32_t cp = 0;
                int k;

                for (k = 0; k < 4; k++) {
                    int h = json_hexval(p[k]);
                    if (h < 0) { return -1; }
                    cp = (cp << 4) | (uint32_t)h;
                }
                p += 4;

                /* Combine UTF-16 surrogate pairs. */
                if (cp >= 0xD800u && cp <= 0xDBFFu) {
                    uint32_t lo = 0;
                    if (p[0] != '\\' || p[1] != 'u') { return -1; }
                    p += 2;
                    for (k = 0; k < 4; k++) {
                        int h = json_hexval(p[k]);
                        if (h < 0) { return -1; }
                        lo = (lo << 4) | (uint32_t)h;
                    }
                    p += 4;
                    if (lo < 0xDC00u || lo > 0xDFFFu) { return -1; }
                    cp = 0x10000u + ((cp - 0xD800u) << 10) + (lo - 0xDC00u);
                } else if (cp >= 0xDC00u && cp <= 0xDFFFu) {
                    return -1;
                }

                /* Emit UTF-8; drop the tail if the caller's buffer is full. */
                if (cp < 0x80u) {
                    if (wi + 1 < n) { out[wi++] = (char)cp; }
                } else if (cp < 0x800u) {
                    if (wi + 2 < n) {
                        out[wi++] = (char)(0xC0u | (cp >> 6));
                        out[wi++] = (char)(0x80u | (cp & 0x3Fu));
                    }
                } else if (cp < 0x10000u) {
                    if (wi + 3 < n) {
                        out[wi++] = (char)(0xE0u | (cp >> 12));
                        out[wi++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
                        out[wi++] = (char)(0x80u | (cp & 0x3Fu));
                    }
                } else {
                    if (wi + 4 < n) {
                        out[wi++] = (char)(0xF0u | (cp >> 18));
                        out[wi++] = (char)(0x80u | ((cp >> 12) & 0x3Fu));
                        out[wi++] = (char)(0x80u | ((cp >> 6) & 0x3Fu));
                        out[wi++] = (char)(0x80u | (cp & 0x3Fu));
                    }
                }
                continue;
            }
            default:
                return -1;
            }
        }

        if (wi + 1 < n) { out[wi++] = (char)c; }
    }

    return -1;  /* unterminated string */
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

