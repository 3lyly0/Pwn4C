/*
 * util.c — Utility helpers: logging, file I/O, clock, shell commands.
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
 * Uses waitpid with a simple alarm-less spin so we don't need signal()
 * side-effects.  For a daemon on an embedded box this is fine.
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
/*
 * OpenWrt on MT7628N exposes the SoC temperature via the thermal zone.
 * Try /sys/class/thermal/thermal_zone0/temp (millidegrees Celsius).
 * In mock mode or if unavailable, return a static plausible value.
 */
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
