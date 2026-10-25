# Makefile — pwn4cd daemon build system
#
# Targets:
#   make                  — native (host) build for development/testing
#   make CROSS=1          — cross-compile for mipsel-openwrt-linux-musl
#   make mock             — build native with mock mode (same as default)
#   make test             — build and run host-side unit tests
#   make clean            — remove build artifacts
#
# Cross-compile requires the OpenWrt SDK unpacked at $(SDK_DIR).
# Set SDK_DIR on the command line or in the environment.
#
# SDK_DIR example:
#   make CROSS=1 SDK_DIR=/opt/openwrt-sdk-23.05.5-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64

.PHONY: all mock cross test clean

# ── Source files ──────────────────────────────────────────────────────────── #
SRCS := main.c util.c json_parse.c radio.c capture.c stream.c \
        discovery.c control.c mock.c wifi_scan.c wifi_sta.c beacon_parse.c

OBJS := $(SRCS:.c=.o)

# ── Common flags ──────────────────────────────────────────────────────────── #
# -Os:          optimize for size (target ~50KB budget)
# -s:           strip symbols
# -ffunction-sections -fdata-sections: enable --gc-sections dead stripping
# -Wall -Wextra -Werror: zero-warning policy
# -std=c99:     C99 strictly
# No -mfpu, no -mhard-float (MT7628N has no FPU)
#
# VERSION: embedded as DAEMON_VERSION (default: git describe; CI passes tag).
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMON_CFLAGS := -std=c99 -Wall -Wextra -Werror -Os \
                 -ffunction-sections -fdata-sections \
                 -D_GNU_SOURCE -D_POSIX_C_SOURCE=200809L \
                 -DDAEMON_VERSION=\"$(VERSION)\"

COMMON_LDFLAGS := -Wl,--gc-sections

# ── Native (host / mock) build ────────────────────────────────────────────── #
CC_NATIVE  := gcc
CFLAGS_NATIVE  := $(COMMON_CFLAGS)
LDFLAGS_NATIVE := $(COMMON_LDFLAGS)

# ── Cross-compile build ───────────────────────────────────────────────────── #
SDK_DIR    ?= /opt/openwrt-sdk-23.05.5-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64
TOOLCHAIN  := $(SDK_DIR)/staging_dir/toolchain-mipsel_24kc_gcc-12.3.0_musl
SYSROOT    := $(SDK_DIR)/staging_dir/target-mipsel_24kc_musl
CROSS_CC   := $(TOOLCHAIN)/bin/mipsel-openwrt-linux-musl-gcc

CFLAGS_CROSS := $(COMMON_CFLAGS) \
                -march=24kc \
                -mno-branch-likely \
                --sysroot=$(SYSROOT)

# Static link against musl; --gc-sections for size
LDFLAGS_CROSS := $(COMMON_LDFLAGS) -static \
                 --sysroot=$(SYSROOT)

# ── Default target: native build ──────────────────────────────────────────── #
all: pwn4cd

pwn4cd: $(OBJS)
	$(CC_NATIVE) $(LDFLAGS_NATIVE) -o $@ $^
	@echo "[native] built: $@"

%.o: %.c pwn4cd.h
	$(CC_NATIVE) $(CFLAGS_NATIVE) -c -o $@ $<

# ── Mock alias ────────────────────────────────────────────────────────────── #
mock: all

# ── Cross-compile target ──────────────────────────────────────────────────── #
cross: $(SRCS) pwn4cd.h
	$(CROSS_CC) $(CFLAGS_CROSS) $(LDFLAGS_CROSS) -o pwn4cd-mips $(SRCS)
	$(TOOLCHAIN)/bin/mipsel-openwrt-linux-musl-strip pwn4cd-mips
	@echo "[cross] built: pwn4cd-mips"
	@ls -lh pwn4cd-mips
	@file pwn4cd-mips

# ── Unit tests ────────────────────────────────────────────────────────────── #
TEST_SRCS := tests/test_json.c tests/test_stream_hdr.c \
             tests/test_hex_decode.c tests/test_bpf.c tests/test_beacon.c
TEST_BIN  := tests/run_tests

test: $(TEST_BIN)
	@echo "[test] running unit tests..."
	./$(TEST_BIN)

$(TEST_BIN): $(TEST_SRCS) tests/run_tests.c json_parse.c util.c capture.c beacon_parse.c
	@mkdir -p tests
	$(CC_NATIVE) $(CFLAGS_NATIVE) $(LDFLAGS_NATIVE) -DTEST_COMBINED -I. -o $@ \
		$(TEST_SRCS) tests/run_tests.c json_parse.c util.c capture.c beacon_parse.c
	@echo "[test] built: $@"

# ── Clean ─────────────────────────────────────────────────────────────────── #
clean:
	rm -f $(OBJS) pwn4cd pwn4cd-mips $(TEST_BIN)
	@echo "[clean] done"
