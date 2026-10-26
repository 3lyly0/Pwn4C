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

/*
 * util_run_cmd_timeout — Run cmd via /bin/sh -c and wait up to timeout_secs.
 * Used by the long-running management commands (WIFI_CONNECT, UPGRADE) where
 * the 2-second iw budget does not apply.
 * Returns the exit status (0 = success, >0 = failure, -1 = fork/timeout error).
 */
static int run_cmd_timeout(const char *cmd, int timeout_secs, bool log_cmd)
{
    pid_t pid;
    int   status;
    int   waited;
    struct timespec ts;

    if (!cmd) { return -1; }
    if (timeout_secs < 1) { timeout_secs = 1; }

    if (log_cmd) {
        util_log("cmd", "run(%ds): %s", timeout_secs, cmd);
    }

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

    for (waited = 0; waited < timeout_secs * 10; waited++) {
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
        nanosleep(&ts, NULL);
    }

    /* timeout: kill it */
    util_log("cmd", "timeout killing pid %d", (int)pid);
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
    return -1;
}

int util_run_cmd_timeout(const char *cmd, int timeout_secs)
{
    return run_cmd_timeout(cmd, timeout_secs, true);
}

/*
 * util_run_cmd_timeout_quiet — Same as util_run_cmd_timeout but does not log
 * the command line. Used when the command embeds a Wi-Fi key: logread is
 * world-readable on OpenWrt, so secrets must never appear there.
 */
int util_run_cmd_timeout_quiet(const char *cmd, int timeout_secs)
{
    return run_cmd_timeout(cmd, timeout_secs, false);
}

/*
 * util_run_cmd_capture — Run cmd and capture its stdout (bounded, NUL
 * terminated, trailing whitespace stripped) with a hard timeout.
 * Returns the exit status (0 = success, >0 = failure, -1 = fork/timeout).
 */
int util_run_cmd_capture(const char *cmd, char *out, size_t outsz, int timeout_secs)
{
    int      pipefd[2];
    pid_t    pid;
    int      status = -1;
    int      flags;
    size_t   total = 0;
    int64_t  deadline;

    if (!cmd || !out || outsz == 0) { return -1; }
    out[0] = '\0';
    if (timeout_secs < 1) { timeout_secs = 1; }

    if (pipe(pipefd) < 0) {
        util_log("cmd", "pipe failed: %s", strerror(errno));
        return -1;
    }

    pid = fork();
    if (pid < 0) {
        util_log("cmd", "fork failed: %s", strerror(errno));
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (pid == 0) {
        /* child: stdout -> pipe, stderr discarded */
        close(pipefd[0]);
        if (dup2(pipefd[1], STDOUT_FILENO) < 0) { _exit(126); }
        close(pipefd[1]);
        if (freopen("/dev/null", "w", stderr) == NULL) { /* best-effort */ }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);

    flags = fcntl(pipefd[0], F_GETFL, 0);
    if (flags >= 0) {
        (void)fcntl(pipefd[0], F_SETFL, flags | O_NONBLOCK);
    }

    deadline = util_monotonic_ms() + (int64_t)timeout_secs * 1000LL;

    for (;;) {
        ssize_t   n;
        pid_t     r;
        int       st = 0;
        bool      exited = false;

        do {
            n = read(pipefd[0], out + total, outsz - 1 - total);
        } while (n < 0 && errno == EINTR);

        if (n > 0) {
            total += (size_t)n;
            if (total >= outsz - 1) { break; }   /* output buffer full */
        }

        do {
            r = waitpid(pid, &st, WNOHANG);
        } while (r < 0 && errno == EINTR);

        if (r == pid) {
            exited = true;
            /* drain whatever is left in the pipe (bounded) */
            for (;;) {
                do {
                    n = read(pipefd[0], out + total, outsz - 1 - total);
                } while (n < 0 && errno == EINTR);
                if (n <= 0 || total >= outsz - 1) { break; }
                total += (size_t)n;
            }
            if (WIFEXITED(st))   { status = WEXITSTATUS(st); }
            else if (WIFSIGNALED(st)) { status = 128 + WTERMSIG(st); }
            else { status = -1; }
            break;
        }

        if (util_monotonic_ms() >= deadline) {
            util_log("cmd", "capture timeout killing pid %d", (int)pid);
            kill(pid, SIGKILL);
            waitpid(pid, &st, 0);
            status = -1;
            break;
        }

        /* still running and nothing to read — brief sleep */
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct timespec ts = { .tv_sec = 0, .tv_nsec = 20L * 1000L * 1000L };
            nanosleep(&ts, NULL);
        }
        (void)exited;
    }

    close(pipefd[0]);

    /* Wait for the child if the buffer filled before it exited */
    if (status == -1) {
        int st = 0;
        kill(pid, SIGKILL);
        waitpid(pid, &st, 0);
    }

    /* strip trailing whitespace */
    while (total > 0 && (out[total-1] == '\n' || out[total-1] == '\r'
                      || out[total-1] == ' ' || out[total-1] == '\t')) {
        out[--total] = '\0';
    }

    return status;
}

/*
 * util_run_detached — Fork-and-forget execution for commands that outlive the
 * daemon (sysupgrade reboots the box it runs on). The child gets its own
 * session so procd shutdown signals aimed at pwn4cd do not reach it.
 * Returns the child pid, or -1 on fork failure.
 */
int util_run_detached(const char *cmd)
{
    pid_t pid;

    if (!cmd) { return -1; }

    util_log("cmd", "detached: %s", cmd);

    pid = fork();
    if (pid < 0) {
        util_log("cmd", "fork failed: %s", strerror(errno));
        return -1;
    }

    if (pid == 0) {
        (void)setsid();
        if (freopen("/dev/null", "w", stdout) == NULL) { /* best-effort */ }
        if (freopen("/dev/null", "w", stderr) == NULL) { /* best-effort */ }
        execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);
        _exit(127);
    }

    return (int)pid;
}

/*
 * util_json_escape — Copy a string into JSON string content, escaping '"'
 * and '\\' and dropping non-printable control bytes. Bytes >= 0x80 (UTF-8)
 * are passed through: JSON strings are Unicode, so an SSID like "Café" must
 * survive intact instead of being silently truncated to "Caf". Bounded;
 * always NUL terminates.
 */
void util_json_escape(const char *in, char *out, size_t outsz)
{
    size_t ri = 0;
    size_t wi = 0;

    if (!out || outsz == 0) { return; }
    if (!in) { out[0] = '\0'; return; }

    while (in[ri] != '\0' && wi + 2 < outsz) {
        unsigned char c = (unsigned char)in[ri];
        if (c == '"' || c == '\\') {
            if (wi + 3 >= outsz) { break; }
            out[wi++] = '\\';
            out[wi++] = (char)c;
            ri++;
        } else if (c >= 0x20u) {
            out[wi++] = (char)c;
            ri++;
        } else {
            ri++;   /* drop ASCII control bytes (not valid raw in JSON) */
        }
    }
    out[wi] = '\0';
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

/* ── Compact C99 SHA-1 / HMAC-SHA1 / PBKDF2 (WPA PSK derivation) ──────────── */
/* WPA-PSK = PBKDF2(HMAC-SHA1, passphrase, SSID, 4096, 32).  Deriving the
 * 64-hex key here means wpa_supplicant never has to parse the passphrase,
 * which sidesteps shell/UCI/supplicant quoting bugs for keys containing
 * '#', '"', '$', '\\' or other metacharacters. */

typedef struct {
    uint32_t state[5];
    uint64_t bitcount;
    uint8_t  buffer[64];
} sha1_ctx_t;

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t data[64])
{
    uint32_t w[80];
    uint32_t a, b, c, d, e, f, k, t;
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = ((uint32_t)data[i * 4 + 0] << 24)
             | ((uint32_t)data[i * 4 + 1] << 16)
             | ((uint32_t)data[i * 4 + 2] << 8)
             |  (uint32_t)data[i * 4 + 3];
    }
    for (; i < 80; i++) {
        w[i] = ROL32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2];
    d = ctx->state[3]; e = ctx->state[4];

    for (i = 0; i < 80; i++) {
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5A827999u;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ED9EBA1u;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8F1BBCDCu;
        } else {
            f = b ^ c ^ d;
            k = 0xCA62C1D6u;
        }
        t = ROL32(a, 5) + f + e + k + w[i];
        e = d; d = c; c = ROL32(b, 30); b = a; a = t;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c;
    ctx->state[3] += d; ctx->state[4] += e;
}

static void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301u;
    ctx->state[1] = 0xEFCDAB89u;
    ctx->state[2] = 0x98BADCFEu;
    ctx->state[3] = 0x10325476u;
    ctx->state[4] = 0xC3D2E1F0u;
    ctx->bitcount = 0;
}

static void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t i;
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3Fu);

    ctx->bitcount += (uint64_t)len << 3;
    for (i = 0; i < len; i++) {
        ctx->buffer[idx++] = data[i];
        if (idx == 64u) {
            sha1_transform(ctx, ctx->buffer);
            idx = 0;
        }
    }
}

static void sha1_final(sha1_ctx_t *ctx, uint8_t hash[20])
{
    size_t idx = (size_t)((ctx->bitcount >> 3) & 0x3Fu);
    int i;

    ctx->buffer[idx++] = 0x80u;
    if (idx > 56u) {
        while (idx < 64u) { ctx->buffer[idx++] = 0; }
        sha1_transform(ctx, ctx->buffer);
        idx = 0;
    }
    while (idx < 56u) { ctx->buffer[idx++] = 0; }

    for (i = 0; i < 8; i++) {
        ctx->buffer[56 + i] = (uint8_t)(ctx->bitcount >> ((7 - i) * 8));
    }
    sha1_transform(ctx, ctx->buffer);

    for (i = 0; i < 5; i++) {
        hash[i * 4 + 0] = (uint8_t)(ctx->state[i] >> 24);
        hash[i * 4 + 1] = (uint8_t)(ctx->state[i] >> 16);
        hash[i * 4 + 2] = (uint8_t)(ctx->state[i] >> 8);
        hash[i * 4 + 3] = (uint8_t)(ctx->state[i]);
    }
}

static void sha1_hash(const uint8_t *data, size_t len, uint8_t out[20])
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    if (data && len > 0) {
        sha1_update(&ctx, data, len);
    }
    sha1_final(&ctx, out);
}

static void hmac_sha1(const uint8_t *key, size_t key_len,
                      const uint8_t *data, size_t data_len,
                      uint8_t out[20])
{
    uint8_t k_ipad[64];
    uint8_t k_opad[64];
    uint8_t tk[20];
    uint8_t inner[20];
    sha1_ctx_t ctx;
    size_t i;

    if (key_len > 64u) {
        sha1_hash(key, key_len, tk);
        key = tk;
        key_len = 20u;
    }

    memset(k_ipad, 0x36, sizeof(k_ipad));
    memset(k_opad, 0x5c, sizeof(k_opad));
    for (i = 0; i < key_len; i++) {
        k_ipad[i] ^= key[i];
        k_opad[i] ^= key[i];
    }

    sha1_init(&ctx);
    sha1_update(&ctx, k_ipad, 64u);
    if (data && data_len > 0) {
        sha1_update(&ctx, data, data_len);
    }
    sha1_final(&ctx, inner);

    sha1_init(&ctx);
    sha1_update(&ctx, k_opad, 64u);
    sha1_update(&ctx, inner, 20u);
    sha1_final(&ctx, out);
}

int util_wpa_psk_hex(const char *passphrase, const char *ssid,
                     char out_hex[65])
{
    static const char hex_tbl[] = "0123456789abcdef";
    uint8_t  psk[32];
    uint8_t  saltblock[32 + 4];
    uint8_t  u[20];
    uint8_t  t[20];
    uint8_t  u2[20];
    size_t   plen;
    size_t   slen;
    size_t   offset = 0;
    uint32_t blk = 1;
    size_t   i;
    int      j;

    if (!passphrase || !ssid || !out_hex) { return -1; }
    plen = strlen(passphrase);
    slen = strlen(ssid);
    if (plen < 8u || plen > 63u || slen > 32u) { return -1; }

    memcpy(saltblock, ssid, slen);

    while (offset < sizeof(psk)) {
        saltblock[slen + 0] = (uint8_t)(blk >> 24);
        saltblock[slen + 1] = (uint8_t)(blk >> 16);
        saltblock[slen + 2] = (uint8_t)(blk >> 8);
        saltblock[slen + 3] = (uint8_t)(blk);

        hmac_sha1((const uint8_t *)passphrase, plen,
                  saltblock, slen + 4u, u);
        memcpy(t, u, sizeof(t));

        for (i = 1; i < 4096u; i++) {
            hmac_sha1((const uint8_t *)passphrase, plen, u, sizeof(u), u2);
            memcpy(u, u2, sizeof(u));
            for (j = 0; j < 20; j++) {
                t[j] ^= u[j];
            }
        }

        for (j = 0; j < 20 && offset < sizeof(psk); j++) {
            psk[offset++] = t[j];
        }
        blk++;
    }

    for (i = 0; i < sizeof(psk); i++) {
        out_hex[i * 2 + 0] = hex_tbl[(psk[i] >> 4) & 0x0Fu];
        out_hex[i * 2 + 1] = hex_tbl[psk[i] & 0x0Fu];
    }
    out_hex[64] = '\0';
    return 0;
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
