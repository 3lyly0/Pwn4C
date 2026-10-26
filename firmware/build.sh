#!/bin/sh
# Pwn4C firmware image builder (Xiaomi Mi Router 4C / R4CM, MT7628N).
#
# Runs on any Linux host (or inside the Dockerfile in this directory):
#   ./build.sh [--ssh-key <path_to_pub_key>] [--psk <secret>]
#
# Env overrides:
#   WORK_DIR  scratch dir for the ImageBuilder tree (default: <this-dir>/.ib-work)
#   OUT_DIR   where the finished images land (default: <this-dir>/output)
#
# Result: output/pwn4c-firmware-mi4c-sysupgrade.bin + checksums.sha256
set -eu

OPENWRT_VERSION="23.05.5"
TARGET="ramips/mt76x8"
PROFILE="xiaomi_mi-router-4c"
IB_TARBALL="openwrt-imagebuilder-${OPENWRT_VERSION}-ramips-mt76x8.Linux-x86_64.tar.xz"
# Pinned hash from https://downloads.openwrt.org/releases/23.05.5/targets/ramips/mt76x8/
IB_SHA256="5980bd2b70d8a18cca6407ea1984719536f2cc937bd2011c56e62f26c8ad9bfb"
IB_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/ramips/mt76x8/${IB_TARBALL}"

FW_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$FW_DIR/.ib-work}"
OUT_DIR="${OUT_DIR:-$FW_DIR/output}"
SSH_KEY_FILE="${SSH_KEY_FILE:-}"
PWN4C_PSK_VAL="${PWN4C_PSK_VAL:-}"

while [ $# -gt 0 ]; do
    case "$1" in
        --ssh-key)
            SSH_KEY_FILE="$2"
            shift 2
            ;;
        --psk)
            PWN4C_PSK_VAL="$2"
            shift 2
            ;;
        *)
            echo "[ERROR] Unknown argument: $1" >&2
            exit 1
            ;;
    esac
done

# §4.1: Optional operator-supplied SSH public key & PSK staging
if [ -n "$SSH_KEY_FILE" ]; then
    if [ ! -f "$SSH_KEY_FILE" ]; then
        echo "[ERROR] SSH public key file not found: $SSH_KEY_FILE" >&2
        exit 1
    fi
    mkdir -p "$FW_DIR/files/etc/dropbear"
    cp "$SSH_KEY_FILE" "$FW_DIR/files/etc/dropbear/authorized_keys"
    chmod 0600 "$FW_DIR/files/etc/dropbear/authorized_keys"
    echo "[*] Staged SSH public key from $SSH_KEY_FILE into etc/dropbear/authorized_keys"
fi

if [ -n "$PWN4C_PSK_VAL" ]; then
    mkdir -p "$FW_DIR/files/etc"
    printf "%s\n" "$PWN4C_PSK_VAL" > "$FW_DIR/files/etc/pwn4c.key"
    chmod 0600 "$FW_DIR/files/etc/pwn4c.key"
    echo "[*] Staged control channel PSK into etc/pwn4c.key"
fi

# Keep the squashfs rootfs well under the 4 MB budget (see docs/hardware.md):
# add monitor-mode tooling, drop everything the headless drone never uses.
# NOTE: dnsmasq stays — it is the drone's DHCP server on 192.168.4.0/24.
# wpa-cli is required by WIFI_STATUS: it distinguishes a completed 4-way
# handshake (wpa_state=COMPLETED) from a bare association, and reports the
# [TEMP-DISABLED] flag that a wrong PSK produces. Without it the daemon can
# only fall back to `iw link`, which looks "connected" before authentication.
PACKAGES="iw wpa-cli tcpdump-mini -ppp -ppp-mod-pppoe -firewall4 -odhcpd-ipv6only -odhcp6c -kmod-ipv6"

# Patched mt76 driver (monitor-mode TX fix). The stock 23.05.5 driver panics
# MT7628 on the very first injected deauth frame; the fix is a kernel change,
# which the ImageBuilder cannot apply. build-mt76-kmod.sh builds the two kmods
# with the matching SDK and drops them in prebuilt/; their PKG_RELEASE=2
# overrides the stock release 1 packages.
MT76_IPKS=""
for ipk in "$FW_DIR"/prebuilt/kmod-mt76-core_*.ipk "$FW_DIR"/prebuilt/kmod-mt7603_*.ipk; do
    [ -f "$ipk" ] || continue
    MT76_IPKS="$MT76_IPKS $ipk"
done
if [ -n "$MT76_IPKS" ]; then
    echo "[*] Using patched mt76 kmods:$MT76_IPKS"
    PACKAGES="$PACKAGES$MT76_IPKS"
else
    echo "[!] No prebuilt mt76 kmods in $FW_DIR/prebuilt — the image keeps the" \
         "stock driver and 'deauth' will reboot the drone." >&2
fi

chmod +x "$FW_DIR/files/etc/init.d/"* 2>/dev/null || true
chmod +x "$FW_DIR/files/etc/uci-defaults/"* 2>/dev/null || true
chmod +x "$FW_DIR/files/usr/lib/pwn4c/"*.sh 2>/dev/null || true

# ── 1.1: Auto-stage pwn4cd binary + init script into firmware/files/ ───────
if [ -z "${PWN4CD_BIN:-}" ]; then
    DAEMON_DIR="$(cd "$FW_DIR/../daemon" 2>/dev/null && pwd)" || true
    if [ -d "$DAEMON_DIR" ] && [ -f "$DAEMON_DIR/Makefile" ]; then
        echo "[*] PWN4CD_BIN not set — attempting auto cross-compile (make -C daemon cross)..."
        if make -C "$DAEMON_DIR" cross; then
            PWN4CD_BIN="$DAEMON_DIR/pwn4cd-mips"
            echo "[*] Cross-compile succeeded: $PWN4CD_BIN"
        else
            echo "[!] Cross-compile failed (missing SDK?). Continuing without daemon binary." \
                 "Set PWN4CD_BIN= to suppress this attempt." >&2
        fi
    fi
fi

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

if [ ! -f "$IB_TARBALL" ]; then
    echo "[*] Downloading ImageBuilder ${OPENWRT_VERSION} (${TARGET})..."
    wget -O "$IB_TARBALL" "$IB_URL"
fi

echo "[*] Verifying sha256..."
echo "${IB_SHA256}  ${IB_TARBALL}" | sha256sum -c -

IB_DIR="$WORK_DIR/${IB_TARBALL%.tar.xz}"
if [ ! -d "$IB_DIR" ]; then
    echo "[*] Extracting ImageBuilder..."
    tar -xf "$IB_TARBALL"
fi

echo "[*] Building image for PROFILE=${PROFILE}..."
cd "$IB_DIR"
IB_BIN_DIR="$WORK_DIR/imagebuilder-bin"

if [ -n "${PWN4CD_BIN:-}" ]; then
    if [ ! -f "$PWN4CD_BIN" ]; then
        echo "[ERROR] PWN4CD_BIN not found: $PWN4CD_BIN" >&2
        exit 1
    fi
    echo "[*] Baking pwn4cd daemon into image files..."
    mkdir -p "$FW_DIR/files/usr/sbin"
    cp "$PWN4CD_BIN" "$FW_DIR/files/usr/sbin/pwn4cd"
    chmod 0755 "$FW_DIR/files/usr/sbin/pwn4cd"
    mkdir -p "$FW_DIR/files/etc/init.d"
    cp "$FW_DIR/../daemon/etc/init.d/pwn4cd" "$FW_DIR/files/etc/init.d/pwn4cd"
    chmod 0755 "$FW_DIR/files/etc/init.d/pwn4cd"
    echo "[*] Staged: usr/sbin/pwn4cd + etc/init.d/pwn4cd"
fi

# ── rc.d symlinks for FILES/ init scripts ──────────────────────────────────
# The ImageBuilder only creates /etc/rc.d links for *packaged* init scripts
# (opkg postinst runs `enable`). Files dropped in via FILES/ never get them:
# uci-defaults creates the links on first boot instead, which is exactly what
# is lost when the first-boot jffs2 overlay migration fails. Baking the links
# means the drone still comes up with LAN + daemon on an empty overlay.
mkdir -p "$FW_DIR/files/etc/rc.d"
for svc in S19pwn4c-net S21pwn4c-radio S95pwn4cd; do
    name="${svc#S??}"
    [ -f "$FW_DIR/files/etc/init.d/$name" ] || continue
    ln -sfn "../init.d/$name" "$FW_DIR/files/etc/rc.d/$svc"
    echo "[*] rc.d: $svc -> ../init.d/$name"
done

make image PROFILE="$PROFILE" PACKAGES="$PACKAGES" FILES="$FW_DIR/files/" \
    EXTRA_IMAGE_NAME="pwn4c" BIN_DIR="$IB_BIN_DIR"

echo "[*] Collecting output..."
SYSUPGRADE="$(ls "$IB_BIN_DIR/"*sysupgrade.bin | head -n 1)"
cp "$SYSUPGRADE" "$OUT_DIR/pwn4c-firmware-mi4c-sysupgrade.bin"

# ── Rootfs size guard (4 MB budget) ────────────────────────────────────────
ROOTFS="$(ls "$IB_DIR"/build_dir/target-*/linux-*/root.squashfs 2>/dev/null | head -n 1)"
if [ -z "$ROOTFS" ]; then
    ROOTFS="$(ls "$IB_BIN_DIR/"*root.squashfs 2>/dev/null | head -n 1)"
fi
if [ -z "$ROOTFS" ]; then
    echo "[ERROR] root.squashfs not found under $IB_DIR" >&2
    exit 1
fi
ROOTFS_BYTES="$(wc -c < "$ROOTFS")"
SYSUPGRADE_BYTES="$(wc -c < "$SYSUPGRADE")"
BUDGET_BYTES=4194304  # 4 MB

echo ""
echo "══ Size report ═══════════════════════════════════════════════"
echo "  Rootfs (budgeted) : ${ROOTFS_BYTES} bytes"
echo "  Sysupgrade (info) : ${SYSUPGRADE_BYTES} bytes"
echo "  Budget            : ${BUDGET_BYTES} bytes (4 MB)"
echo "══════════════════════════════════════════════════════════════"

if [ "$ROOTFS_BYTES" -gt "$BUDGET_BYTES" ]; then
    echo "[ERROR] rootfs exceeds 4 MB budget." >&2
    exit 1
fi

# ── Package manifest assertions ────────────────────────────────────────────
MANIFEST="$IB_BIN_DIR/$(ls "$IB_BIN_DIR/" | grep '\.manifest$' | head -n 1)"
if [ -f "$MANIFEST" ]; then
    echo ""
    echo "── Package manifest checks ──────────────────────────────────"
    for req in iw wpa-cli tcpdump-mini dropbear dnsmasq kmod-mac80211; do
        if grep -q "^${req}" "$MANIFEST"; then
            echo "  [PASS] ${req} present"
        else
            echo "  [FAIL] ${req} MISSING from manifest"
            BUILD_FAIL=1
        fi
    done
    for banned in luci firewall4 ppp kmod-ipv6 odhcp6c odhcpd-ipv6only; do
        if grep -q "^${banned}" "$MANIFEST"; then
            echo "  [FAIL] ${banned} present (should be excluded)"
            BUILD_FAIL=1
        else
            echo "  [PASS] ${banned} absent"
        fi
    done
    if [ -n "${MT76_IPKS:-}" ]; then
        if grep -qE '^kmod-mt7603 - .*-2$' "$MANIFEST" &&
           grep -qE '^kmod-mt76-core - .*-2$' "$MANIFEST"; then
            echo "  [PASS] patched mt76 kmods (release -2)"
        else
            echo "  [FAIL] stock mt76 kmods in image (deauth would panic)"
            BUILD_FAIL=1
        fi
    fi
    echo "─────────────────────────────────────────────────────────────"
else
    echo "[!] No manifest file found in $IB_BIN_DIR — skipping package checks"
fi

cd "$OUT_DIR"
sha256sum pwn4c-firmware-mi4c-sysupgrade.bin > checksums.sha256
ls -l pwn4c-firmware-mi4c-sysupgrade.bin
cat checksums.sha256

if [ -n "${BUILD_FAIL:-}" ]; then
    echo "[ERROR] One or more build assertions failed." >&2
    exit 1
fi
echo "[+] Done: $OUT_DIR/pwn4c-firmware-mi4c-sysupgrade.bin"
