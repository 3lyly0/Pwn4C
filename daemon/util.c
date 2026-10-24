/*
 * util.c — Utility helpers: logging, file I/O, clock, shell commands,
 *          and zero-dependency SHA-256 / HMAC-SHA256 (§4.1).
 *
 * All functions here are POSIX/libc only, no float, bounds-checked.
 */

#include "pwn4cd.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <syslog.h>
#include <ctype.h>
#include <sys/wait.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>

/* ── Logging ──────────────────────────────────────────────────────────────── */

void util_log(const char *tag, const char *fmt, ...)
{
    char buf[512];
    va_list ap;
    va_start(ap, fmt);
    (void)vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    syslog(LOG_DAEMON | LOG_INFO, "[%s] %s", tag, buf);
}

/* ── File helpers ─────────────────────────────────────────────────────────── */

int util_read_file(const char *path, char *buf, size_t bufsize)
{
    int fd;
    ssize_t n;
    size_t total = 0;

    if (!path || !buf || bufsize == 0) { return -1; }

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) { return -1; }

    while (total < bufsize - 1) {
        do {
            n = read(fd, buf + total, bufsize - 1 - total);
        } while (n < 0 && errno == EINTR);

        if (n <= 0) { break; }
        total += (size_t)n;
    }

    close(fd);
    buf[total] = '\0';

    /* strip trailing newline/whitespace */
    while (total > 0 && (buf[total-1] == '\n' || buf[total-1] == '\r'
                      || buf[total-1] == ' ')) {
        buf[--total] = '\0';
    }
    return (int)total;
}

int util_read_int_file(const char *path, int *out)
{
    char buf[64];
    int r;
    long v;
    char *end;

    if (!out) { return -1; }
    r = util_read_file(path, buf, sizeof(buf));
    if (r <= 0) { return -1; }

    errno = 0;
    v = strtol(buf, &end, 10);
    if (errno != 0 || end == buf) { return -1; }
    *out = (int)v;
    return 0;
}

/* ── Shell command execution ──────────────────────────────────────────────── */
/*
 * Run cmd via /bin/sh -c, wait up to IW_TIMEOUT_SECS.
 * Returns the exit status (0 = success, >0 = failure, -1 = fork error).
 */
int util_run_cmd(const char *cmd)
{
    pid_t pid;
    int status;
    int waited;
    struct timespec ts;

    if (!cmd) { return -1; }

    util_log("cmd", "run: %s", cmd);

    pid = fork();
    if (pid < 0) {
        util_log("cmd", "fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        /* child */
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    /* parent: poll with timeout */
    ts.tv_sec  = 0;
    ts.tv_nsec = 100L * 1000L * 1000L; /* 100ms poll interval */

    for (waited = 0; waited < IW_TIMEOUT_SECS * 10; waited++) {
        pid_t r;
        int   st = 0;
        do {
            r = waitpid(pid, &st, WNOHANG);
        } while (r < 0 && errno == EINTR);

        if (r == pid) {
            if (WIFEXITED(st))   { return WEXITSTATUS(st); }
            if (WIFSIGNALED(st)) { return 128 + WTERMSIG(st); }
            return -1;
        }
        /* still running — sleep 100ms */
        nanosleep(&ts, NULL);
    }

    /* timeout: kill it */
    util_log("cmd", "timeout killing pid %d", (int)pid);
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

/* ── Monotonic clock helpers ─────────────────────────────────────────────── */

int64_t util_monotonic_sec(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (int64_t)ts.tv_sec;
}

int64_t util_monotonic_ms(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (int64_t)ts.tv_sec * 1000LL + (int64_t)ts.tv_nsec / 1000000LL;
}

int64_t util_monotonic_us(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return 0; }
    return (int64_t)ts.tv_sec * 1000000LL + (int64_t)ts.tv_nsec / 1000LL;
}

int util_clock_gettime_sec(int64_t *sec, int32_t *nsec)
{
    struct timespec ts;
    if (!sec || !nsec) { return -1; }
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) { return -1; }
    *sec  = (int64_t)ts.tv_sec;
    *nsec = (int32_t)ts.tv_nsec;
    return 0;
}

void util_sleep_ms(int ms)
{
    struct timespec ts;
    ts.tv_sec  = ms / 1000;
    ts.tv_nsec = (long)(ms % 1000) * 1000000L;
    while (nanosleep(&ts, &ts) < 0 && errno == EINTR) { /* retry */ }
}

/* ── Uptime ───────────────────────────────────────────────────────────────── */

int util_uptime_seconds(void)
{
    struct sysinfo si;
    if (sysinfo(&si) < 0) { return 0; }
    return (int)si.uptime;
}

/* ── Memory ───────────────────────────────────────────────────────────────── */

int util_free_ram_bytes(int64_t *out)
{
    struct sysinfo si;
    if (!out) { return -1; }
    if (sysinfo(&si) < 0) { return -1; }
    /* si.freeram * si.mem_unit = bytes */
    *out = (int64_t)si.freeram * (int64_t)si.mem_unit;
    return 0;
}

/* ── CPU temperature ──────────────────────────────────────────────────────── */

int util_cpu_temp(int *out_celsius)
{
    int raw = 0;

    if (!out_celsius) { return -1; }

    /* temperature in millidegrees */
    if (util_read_int_file("/sys/class/thermal/thermal_zone0/temp", &raw) == 0) {
        /* round to nearest integer Celsius */
        *out_celsius = (raw + 500) / 1000;
        return 0;
    }
    /* Fallback: mt76 does not always expose thermal zone; return 0 */
    *out_celsius = 0;
    return 0;
}

/* ── MAC address helpers ──────────────────────────────────────────────────── */

int util_read_mac(const char *iface, uint8_t mac[6])
{
    char path[64];
    char buf[32];
    int i;
    unsigned int v[6];

    if (!iface || !mac) { return -1; }
    (void)snprintf(path, sizeof(path), "/sys/class/net/%s/address", iface);

    if (util_read_file(path, buf, sizeof(buf)) <= 0) { return -1; }

    if (sscanf(buf, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return -1;
    }
    for (i = 0; i < 6; i++) {
        mac[i] = (uint8_t)v[i];
    }
    return 0;
}

void util_mac_to_str(const uint8_t mac[6], char *buf, size_t n)
{
    if (!mac || !buf || n < 18) { return; }
    (void)snprintf(buf, n, "%02X:%02X:%02X:%02X:%02X:%02X",
                   mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int util_parse_mac(const char *s, uint8_t mac[6])
{
    unsigned int v[6];
    int i;

    if (!s || !mac) { return -1; }
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) != 6) {
        return -1;
    }
    for (i = 0; i < 6; i++) {
        if (v[i] > 0xff) { return -1; }
        mac[i] = (uint8_t)v[i];
    }
    return 0;
}

/* ── Kernel version ───────────────────────────────────────────────────────── */

int util_get_kernel_version(char *buf, size_t n)
{
    struct utsname u;
    if (!buf || n == 0) { return -1; }
    if (uname(&u) < 0)  { return -1; }
    (void)snprintf(buf, n, "%s", u.release);
    return 0;
}

/* ── Compact C99 SHA-256 & HMAC-SHA256 (§4.1 — Zero External Dependencies) ── */

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t  buffer[64];
} sha256_ctx_t;

static const uint32_t K256[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcU, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffaU, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u
};

#define ROR32(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROR32(x, 2) ^ ROR32(x, 13) ^ ROR32(x, 22))
#define EP1(x) (ROR32(x, 6) ^ ROR32(x, 11) ^ ROR32(x, 25))
#define SIG0(x) (ROR32(x, 7) ^ ROR32(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROR32(x, 17) ^ ROR32(x, 19) ^ ((x) >> 10))

static void sha256_transform(sha256_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; i++) {
        m[i] = ((uint32_t)data[i * 4 + 0] << 24)
             | ((uint32_t)data[i * 4 + 1] << 16)
             | ((uint32_t)data[i * 4 + 2] << 8)
             |  (uint32_t)data[i * 4 + 3];
    }
    for (; i < 64; i++) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init(sha256_ctx_t *ctx)
{
    ctx->state[0] = 0x6a09e667u; ctx->state[1] = 0xbb67ae85u;
    ctx->state[2] = 0x3c6ef372u; ctx->state[3] = 0xa54ff53au;
    ctx->state[4] = 0x510e527fu; ctx->state[5] = 0x9b05688cu;
    ctx->state[6] = 0x1f83d9abu; ctx->state[7] = 0x5be0cd19u;
    ctx->bitcount = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3Fu);

    ctx->bitcount += (uint64_t)len << 3;
    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64u) {
            sha256_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32])
{
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3Fu);
    int i;

    ctx->buffer[idx++] = 0x80u;
    if (idx > 56u) {
        while (idx < 64u) { ctx->buffer[idx++] = 0; }
        sha256_transform(ctx, ctx->buffer);
        idx = 0;
    }
    while (idx < 56u) { ctx->buffer[idx++] = 0; }

    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(ctx->bitcount >> ((7 - i) * 8));
    }
    sha256_transform(ctx, ctx->buffer);

    for (i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

void util_sha256(const uint8_t *data, size_t len, uint8_t out[32])
{
    sha256_ctx_t ctx;
    sha256_init(&ctx);
    if (data && len > 0) {
        sha256_update(&ctx, data, len);
    }
    sha256_final(&ctx, out);
}

void util_hmac_sha256(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[32])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[32];
    uint8_t inner[32];
    sha256_ctx_t ctx;
    size_t i;

    if (key_len > 64u) {
        util_sha256(key, key_len, tk);
        key = tk;
        key_len = 32u;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, 64u);
    if (data && data_len > 0) {
        sha256_update(&ctx, data, data_len);
    }
    sha256_final(&ctx, inner);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, 64u);
    sha256_update(&ctx, inner, 32u);
    sha256_final(&ctx, out);
}

void util_hmac_sha256_hex(const char *key, const char *msg, char out_hex[65])
{
    static const char hex_tbl[] = "0123456789abcdef";
    uint8_t mac[32];
    size_t i;

    if (!key) { key = ""; }
    if (!msg) { msg = ""; }

    util_hmac_sha256((const uint8_t *)key, strlen(key),
                     (const uint8_t *)msg, strlen(msg), mac);
    for (i = 0; i < 32u; i++) {
        out_hex[i * 2 + 0] = hex_tbl[(mac[i] >> 4) & 0x0Fu];
        out_hex[i * 2 + 1] = hex_tbl[mac[i] & 0x0Fu];
    }
    out_hex[64] = '\0';
}

int util_random_hex(char *out, size_t hex_chars)
{
    static const char hex_tbl[] = "0123456789abcdef";
    uint8_t raw[32];
    size_t bytes_needed;
    size_t i;
    int fd;

    if (!out || hex_chars == 0 || hex_chars > 64u) { return -1; }
    bytes_needed = (hex_chars + 1u) / 2u;

    fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t n;
        do {
            n = read(fd, raw, bytes_needed);
        } while (n < 0 && errno == EINTR);
        close(fd);
        if (n < (ssize_t)bytes_needed) {
            return -1;
        }
    } else {
        /* Fallback deterministic-mixed seed if /dev/urandom unavailable */
        uint64_t t = (uint64_t)util_monotonic_us();
        util_sha256((const uint8_t *)&t, sizeof(t), raw);
    }

    for (i = 0; i < hex_chars; i++) {
        uint8_t b = raw[i / 2u];
        uint8_t nib = (i % 2u == 0) ? (uint8_t)(b >> 4) : (uint8_t)(b & 0x0Fu);
        out[i] = hex_tbl[nib];
    }
    out[hex_chars] = '\0';
    return 0;
}
