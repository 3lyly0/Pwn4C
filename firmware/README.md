# Pwn4C Firmware Build

OpenWrt 23.05.5 image for the Xiaomi Mi Router 4C (R4CM, MT7628N, mipsel).

## Quick Build (Docker — recommended)

```bash
# From the repo root:
docker build -t pwn4c-builder ./firmware
docker run --rm -v "$(pwd)/firmware/output:/output" pwn4c-builder
```

Output: `firmware/output/pwn4c-firmware-mi4c-sysupgrade.bin`

## Quick Build (Native Linux)

Requires: `wget`, `sha256sum`, `tar`, `make`, `python3`, standard build tools.

```bash
cd firmware
./build.sh
```

ImageBuilder is downloaded automatically (~100 MB, cached in `.ib-work/`).

## Files overlay (`files/`)

Files placed under `firmware/files/` are injected verbatim into the rootfs:

| Path | Purpose |
|------|---------|
| `etc/uci-defaults/99-pwn4c` | First-boot configuration (LAN, DHCP, wireless, dropbear) |
| `etc/sysupgrade.conf` | Paths preserved across sysupgrade |
| `etc/dropbear/authorized_keys` | SSH public keys (empty by default — see credential policy) |
| `etc/init.d/pwn4c-radio` | Boot-safety guard: keeps wireless DOWN until daemon drives it |
| `etc/banner` | Login banner |

## Packages

```
iw tcpdump-mini
```

Removed from the OpenWrt default set:
```
-ppp -ppp-mod-pppoe -firewall4 -odhcpd-ipv6only -odhcp6c -kmod-ipv6
```

`dnsmasq` is **kept** — it serves DHCP on `192.168.4.0/24`.

## Budget

| Component | Approx. size |
|-----------|-------------|
| Linux kernel (lzma) | ~1.6 MB |
| SquashFS rootfs | ~3.0 MB (budget: **< 4 MB**) |
| JFFS2 overlay | ~10 MB |

## Flash Method

From the initial telnet session on stock Xiaomi firmware:

```bash
# On the host:
python3 -m http.server 8080 --directory ./firmware/output/

# On the router (telnet 192.168.31.1, root/root):
wget http://<host-ip>:8080/pwn4c-firmware-mi4c-sysupgrade.bin -O /tmp/pwn4c.bin
mtd -r write /tmp/pwn4c.bin OS1
```

**Never touch**: `factory` (Wi-Fi calibration), `bootloader`, `mtd0`–`mtd3`.

## Credentials (default)

No root password. No authorized keys. See `files/etc/dropbear/authorized_keys`
for the credential policy and how to add SSH keys.
