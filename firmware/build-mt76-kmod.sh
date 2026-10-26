#!/bin/sh
# Build the patched mt76 driver for OpenWrt 23.05.5 / ramips-mt76x8.
#
# Why: on MT7628 the stock 23.05.5 mt76 driver reboots the board on the first
# injected monitor-mode frame (deauth), because mt7603 publishes its private
# global station WCID without calling mt76_wcid_init(), so mt76_tx() queues the
# frame on a zeroed sk_buff_head and faults on a NULL prev pointer.
# See firmware/patches/mt76/*.patch and docs/troubleshooting.md.
#
# The ImageBuilder cannot compile kernel modules, so this script uses the
# matching OpenWrt SDK to produce two ipks:
#
#   prebuilt/kmod-mt76-core_*.ipk (defensive guard in mt76_tx)
#   prebuilt/kmod-mt7603_*.ipk    (initialise the global station WCID)
#
# build.sh installs them over the stock packages when they are present.
#
# Requirements (Linux or WSL): curl, xz, git, GNU make, gcc, ~4 GB free.
#
# Env overrides:
#   WORK_DIR   scratch dir (default: <firmware-dir>/.mt76-work)
#   JOBS       parallel build jobs (default: number of CPUs)
set -eu

OPENWRT_VERSION="23.05.5"
TARGET="ramips/mt76x8"
SDK_NAME="openwrt-sdk-${OPENWRT_VERSION}-ramips-mt76x8_gcc-12.3.0_musl.Linux-x86_64"
SDK_SHA256="d3fc656e5ecc5099f16379860582c22fd57b9e03a81521b17c9ad31034cde1c0"
SDK_URL="https://downloads.openwrt.org/releases/${OPENWRT_VERSION}/targets/${TARGET}/${SDK_NAME}.tar.xz"

FW_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
WORK_DIR="${WORK_DIR:-$FW_DIR/.mt76-work}"
OUT_DIR="$FW_DIR/prebuilt"
JOBS="${JOBS:-$(nproc 2>/dev/null || echo 4)}"

# OpenWrt's prereq check trips over Windows PATH entries inside WSL and over a
# non-GNU install in some containers; the SDK ships working host tools, so use
# a clean PATH and pre-satisfy the prereq stamp.
CLEAN_PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

mkdir -p "$WORK_DIR" "$OUT_DIR"
cd "$WORK_DIR"

if [ ! -f "${SDK_NAME}.tar.xz" ]; then
    echo "[*] Downloading ${SDK_NAME}..."
    curl -fL -o "${SDK_NAME}.tar.xz" "$SDK_URL"
fi
echo "[*] Verifying SDK sha256..."
echo "${SDK_SHA256}  ${SDK_NAME}.tar.xz" | sha256sum -c -

if [ ! -d "$SDK_NAME" ]; then
    echo "[*] Extracting SDK..."
    tar -xf "${SDK_NAME}.tar.xz"
fi
SDK_DIR="$WORK_DIR/$SDK_NAME"

# The SDK only ships package/kernel/linux, so fetch mac80211 (needed to stage
# the backport headers mt76 compiles against) and mt76 from the pinned tree.
if [ ! -d openwrt-src/.git ]; then
    echo "[*] Fetching OpenWrt ${OPENWRT_VERSION} package sources..."
    git clone --depth 1 --branch "v${OPENWRT_VERSION}" --filter=blob:none \
        --sparse https://github.com/openwrt/openwrt.git openwrt-src
fi
git -C openwrt-src sparse-checkout set package/kernel/mac80211 \
    package/kernel/mt76 package/libs/libnl-tiny

echo "[*] Staging package sources and patches..."
rm -rf "$SDK_DIR/package/kernel/mac80211" "$SDK_DIR/package/kernel/mt76" \
    "$SDK_DIR/package/libs/libnl-tiny"
mkdir -p "$SDK_DIR/package/libs"
cp -r openwrt-src/package/kernel/mac80211 "$SDK_DIR/package/kernel/"
cp -r openwrt-src/package/kernel/mt76 "$SDK_DIR/package/kernel/"
cp -r openwrt-src/package/libs/libnl-tiny "$SDK_DIR/package/libs/"
cp "$FW_DIR"/patches/mt76/00*.patch "$SDK_DIR/package/kernel/mt76/patches/"
# Bump the release so the ipks win over the stock ones in the image.
sed -i 's/^PKG_RELEASE=.*/PKG_RELEASE=2/' "$SDK_DIR/package/kernel/mt76/Makefile"

cd "$SDK_DIR"
mkdir -p staging_dir/host
touch staging_dir/host/.prereq-build
env -i HOME="$HOME" PATH="$CLEAN_PATH" make defconfig >/dev/null

# kmod-mt76's Build/Compile also builds the mt76-test userspace tool, which
# needs libnl-tiny's headers in staging even though the tool is not shipped.
echo "[*] Building libnl-tiny headers..."
env -i HOME="$HOME" PATH="$CLEAN_PATH" \
    make package/libs/libnl-tiny/compile -j"$JOBS" \
    >"$WORK_DIR/libnl.log" 2>&1 || {
        echo "[ERROR] libnl-tiny build failed; see $WORK_DIR/libnl.log" >&2
        tail -20 "$WORK_DIR/libnl.log" >&2
        exit 1
    }

echo "[*] Building kmod-mt76-core + kmod-mt7603 (this takes a few minutes)..."
env -i HOME="$HOME" PATH="$CLEAN_PATH" \
    make package/kernel/mt76/compile -j"$JOBS" V=s >"$WORK_DIR/build.log" 2>&1 || {
        echo "[ERROR] Build failed; last 40 lines of $WORK_DIR/build.log:" >&2
        tail -40 "$WORK_DIR/build.log" >&2
        exit 1
    }

echo "[*] Verifying the patched objects..."
MT_SRC="$(find build_dir/target-*/linux-*/mt76-*/mt7603/init.c | head -n 1)"
MT7603_KO="$(find build_dir/target-*/linux-*/mt76-*/mt7603 -name mt7603e.ko | head -n 1)"
MT76_KO="$(find build_dir/target-*/linux-*/mt76-* -maxdepth 1 -name mt76.ko | head -n 1)"
if [ -z "$MT_SRC" ] || [ -z "$MT7603_KO" ] || [ -z "$MT76_KO" ]; then
    echo "[ERROR] Built modules not found under $SDK_DIR/build_dir" >&2
    exit 1
fi
if ! grep -q 'mt76_wcid_init(&dev->global_sta.wcid)' "$MT_SRC"; then
    echo "[ERROR] $MT_SRC does not contain the global WCID fix" >&2
    exit 1
fi

for pattern in "kmod-mt76-core_*" "kmod-mt7603_*"; do
    ipk="$(ls bin/targets/"${TARGET%/*}"/*/packages/${pattern}.ipk 2>/dev/null | head -n 1 || true)"
    [ -n "$ipk" ] || continue
    cp "$ipk" "$OUT_DIR/"
done

echo "[*] Prebuilt kmods in $OUT_DIR:"
ls -l "$OUT_DIR"
sha256sum "$OUT_DIR"/*.ipk | tee "$OUT_DIR/checksums.sha256"
echo "[+] Done. Re-run firmware/build.sh to bake them into the image."
