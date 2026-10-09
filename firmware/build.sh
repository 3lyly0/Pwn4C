#!/bin/sh
# Pwn4C firmware image builder (Xiaomi Mi Router 4C / R4CM, MT7628N).
#
# Runs on any Linux host (or inside the Dockerfile in this directory):
#   ./build.sh
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

# Keep the squashfs rootfs well under the 4 MB budget (see docs/hardware.md):
# add monitor-mode tooling, drop everything the headless drone never uses.
# NOTE: dnsmasq stays — it is the drone's DHCP server on 192.168.4.0/24.
# (23.05 names: firewall4 + odhcp6c; plain -firewall/-odhcpd match nothing.)
PACKAGES="iw tcpdump-mini -ppp -ppp-mod-pppoe -firewall4 -odhcpd-ipv6only -odhcp6c -kmod-ipv6"

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

if [ ! -f "$IB_TARBALL" ]; then
    echo "[*] Downloading ImageBuilder ${OPENWRT_VERSION} (${TARGET})..."
    wget -O "$IB_TARBALL" "$IB_URL"
fi

echo "[*] Verifying sha256..."
echo "${IB_SHA256}  ${IB_TARBALL}" | sha256sum -c -

IB_DIR="${IB_TARBALL%.tar.xz}"
if [ ! -d "$IB_DIR" ]; then
    echo "[*] Extracting ImageBuilder..."
    tar -xf "$IB_TARBALL"
fi

echo "[*] Building image for PROFILE=${PROFILE}..."
cd "$IB_DIR"
# NOTE: intermediates stay in WORK_DIR; OUT_DIR receives only the final
# image + checksums (keeps artifacts and releases clean).
IB_BIN_DIR="$WORK_DIR/imagebuilder-bin"
make image PROFILE="$PROFILE" PACKAGES="$PACKAGES" FILES="$FW_DIR/files/" \
    EXTRA_IMAGE_NAME="pwn4c" BIN_DIR="$IB_BIN_DIR"

echo "[*] Collecting output..."
SYSUPGRADE="$(ls "$IB_BIN_DIR/"*sysupgrade.bin | head -n 1)"
cp "$SYSUPGRADE" "$OUT_DIR/pwn4c-firmware-mi4c-sysupgrade.bin"
cd "$OUT_DIR"
sha256sum pwn4c-firmware-mi4c-sysupgrade.bin > checksums.sha256
ls -l pwn4c-firmware-mi4c-sysupgrade.bin
cat checksums.sha256
echo "[+] Done: $OUT_DIR/pwn4c-firmware-mi4c-sysupgrade.bin"
