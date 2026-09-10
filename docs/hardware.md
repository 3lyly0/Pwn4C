# Hardware Reference

## Platform: Xiaomi Mi Router 4C

| Specification | Value |
|---------------|-------|
| Model | Xiaomi Mi Router 4C (R4CM) |
| SoC | MediaTek MT7628N |
| Architecture | MIPS 24KEc (mips_24kc), little-endian |
| CPU Clock | 580 MHz |
| RAM | 64 MB DDR2 (Winbond W9751G6KB-25) |
| Flash | 16 MB SPI NOR (GigaDevice GD25Q128CSIG) |
| Wireless | Integrated 2.4 GHz 802.11b/g/n, 2x2 MIMO |
| Antennas | 4x external omni-directional (2 active, 2 passive/decorative) |
| Ethernet | 3x 10/100 Mbps ports (1x WAN, 2x LAN) via MT7628N integrated MAC |
| Power | 5V / 1A via Micro-USB |
| Bootloader | U-Boot (Xiaomi-modified) |

---

## SoC: MediaTek MT7628N

The MT7628N is a highly integrated MIPS-based wireless router SoC designed for cost-optimized 802.11n devices.

### CPU Core

- **ISA:** MIPS 24KEc rev 2, no FPU
- **Pipeline:** 7-stage, single-issue, in-order
- **Caches:** 64 KB I-cache, 32 KB D-cache
- **Clock:** 580 MHz (fixed; no DVFS on MT7628N)
- **Endianness:** Little-endian (mipsel)

At 580 MHz with no floating-point unit, the CPU handles packet forwarding and daemon control logic but is unsuitable for cryptographic brute-force. All computation-intensive work runs on the Host by design.

### Integrated Peripherals

| Peripheral | Usage in Pwn4C |
|------------|----------------|
| SPI Controller | Flash read/write (firmware, overlay) |
| Ethernet MAC + PHY Switch | Host-Drone Ethernet link |
| Wi-Fi BBP/RF | 802.11 frame capture and injection |
| UART0 | Serial console (115200 8N1, pin header J1) |
| GPIO | LED control (system status indicator) |

### UART Serial Console

The board exposes UART on an unpopulated 4-pin header (J1):

```
Pin 1: VCC (3.3V) - do NOT connect
Pin 2: TX  (Drone -> Host)
Pin 3: RX  (Host -> Drone)
Pin 4: GND
```

Settings: 115200 baud, 8N1, no flow control. Connect a 3.3V USB-UART adapter (e.g., CP2102) for bootloader access and early-boot debugging.

---

## Flash Layout (16 MB SPI NOR)

The 16 MB flash is partitioned by U-Boot at fixed offsets:

```
Offset        Size        Partition         Contents
──────────────────────────────────────────────────────────────
0x000000      0x030000    Bootloader        U-Boot (192 KB)
0x030000      0x010000    Config            U-Boot env variables (64 KB)
0x040000      0x010000    Factory           Wi-Fi calibration data, MAC addr (64 KB)
0x050000      0xFB0000    Firmware          Kernel + rootfs (15,808 KB)
──────────────────────────────────────────────────────────────
Total:                                      16,384 KB (16 MB)
```

### Firmware Partition Internals

The `Firmware` partition is further divided by the OpenWrt image:

```
Offset (within Firmware)    Contents
──────────────────────────────────────────────
0x000000                    uImage header (64 B)
0x000040                    Linux kernel (lzma compressed, ~1.6 MB)
~0x1A0000                   SquashFS rootfs (variable, target <4 MB)
remaining                   JFFS2 overlay (writable config storage)
```

### Factory Partition (Critical: Do Not Erase)

The `Factory` partition at offset `0x040000` contains:

- **Wi-Fi calibration data** programmed at the factory: TX power tables, frequency offsets, RSSI correction curves.
- **MAC addresses** for the wireless and Ethernet interfaces.

This partition is not included in firmware images and must never be overwritten. Erasing it permanently disables Wi-Fi calibration, resulting in degraded RF performance. The OpenWrt build system and `sysupgrade` exclude this region by default.

The `pwn4c infect` command also preserves this partition: it writes only to the OS partition via `mtd write`.

---

## RAM Layout (64 MB DDR2)

Total physical RAM: 64 MB (67,108,864 bytes). Typical runtime allocation:

| Consumer | Approximate Usage |
|----------|-------------------|
| Linux kernel + modules | ~8 MB |
| `kmod-mt76` driver buffers | ~4 MB |
| `pwn4cd` daemon (heap + stack) | ~256 KB |
| Dropbear SSH | ~512 KB (when active) |
| tmpfs (`/tmp`) | ~2 MB baseline |
| Filesystem caches | Remainder (~49 MB) |

The primary constraint is flash storage, not RAM. `pwn4cd` uses a fixed 64 KB ring buffer for captured frames, keeping its memory footprint predictable.

---

## RF Architecture

### Radio Specifications

| Parameter | Value |
|-----------|-------|
| Frequency Band | 2.4 GHz ISM (2400-2484 MHz) |
| Standards | IEEE 802.11b/g/n |
| Channel Width | 20 MHz (HT40 supported but unused in monitor mode) |
| Channels | 1-13 (region-dependent; defaults to world regulatory domain) |
| MIMO Configuration | 2T2R (2 spatial streams) |
| Max PHY Rate | 300 Mbps (HT40, 2SS, irrelevant in monitor mode) |
| TX Power | Up to 20 dBm (100 mW) per chain (driver/regulatory limited) |
| Antenna Connectors | Internal; 2 active chains routed to external omni antennas |

### Monitor Mode Behavior

When `pwn4cd` places the radio in monitor mode via `iw dev ra0 set monitor none`:

1. The interface detaches from all BSS associations.
2. The driver disables hardware frame filtering: all received 802.11 frames (management, control, data) are delivered to user-space.
3. Each frame is prefixed with a RadioTap header containing: TSFT (timestamp), channel frequency/flags, signal strength (dBm), noise (dBm), and data rate.
4. The radio locks to a single 20 MHz channel. Channel hopping requires explicit `SET_CHANNEL` commands from the Host.

### `kmod-mt76` Driver Behavior

The `mt76` driver is the mainline Linux driver for MediaTek MT76x0/MT76x2 radios. Key behaviors:

**Frame Injection:**
- Injection is performed by writing raw 802.11 frames (with RadioTap header) to a raw packet socket bound to the monitor interface.
- The driver respects RadioTap TX flags: data rate, channel, and `IEEE80211_RADIOTAP_F_TX_NOACK` (suppress ACK expectation).
- Injection timing is non-deterministic. The frame enters the hardware TX queue and transmits at the next DIFS/SIFS boundary. Typical latency from `sendto()` to on-air: 200-800 us under low contention.
- Back-to-back injection (e.g., deauthentication floods) can saturate the TX queue. The driver returns `ENOBUFS` when full. `pwn4cd` handles this by sleeping 1 ms and retrying up to 10 times before reporting failure.

**Channel Switching:**
- Channel changes via `iw dev ra0 set channel <N>` complete in ~5 ms on the MT7628N.
- During a switch, the RX path halts briefly. Expect a 5-15 ms gap in the capture stream. The Host should account for this when correlating timestamps.

**Known Limitations:**
- No 5 GHz support. The MT7628N is a single-band SoC.
- HT40 monitor mode is unreliable on `mt76` for the MT7628N variant. Pwn4C forces HT20.
- Some management frame subtypes (e.g., Action frames with vendor-specific IEs) may be truncated by the hardware before reaching the driver. This is a silicon limitation.

### Thermal Behavior

The MT7628N has no thermal throttling or thermal shutdown circuitry.

| Condition | Die Temperature (approx.) |
|-----------|---------------------------|
| Idle (SSH only) | 45-50 C |
| Active monitor mode | 55-65 C |
| Sustained injection flood | 65-75 C |

The SoC is rated for operation up to 105 C (junction). At sustained injection loads, the plastic enclosure becomes warm but remains within safe limits.

In enclosed deployments (ceiling tiles, equipment cabinets), ensure passive airflow. No active cooling is required.

---

## Storage Budgeting

### The 4 MB Rootfs Constraint

The firmware partition provides ~15.5 MB of raw space, split as follows:

| Component | Size |
|-----------|------|
| Linux kernel (lzma compressed) | ~1.6 MB |
| SquashFS rootfs | Target: **< 4.0 MB** |
| JFFS2 overlay | Remaining (~10 MB) |

The JFFS2 overlay provides runtime-writable storage (SSH host keys, configuration changes, logs). Keeping the rootfs under 4 MB maximizes overlay space and provides a safety margin against flash wear-leveling overhead.

### Rootfs Size Breakdown

The custom OpenWrt rootfs is stripped to the minimum required for `pwn4cd` operation:

| Component | Approximate Size | Notes |
|-----------|------------------|-------|
| Base system (busybox, musl, procd) | 1.2 MB | Minimal init, shell, coreutils |
| Linux kernel modules | 0.9 MB | `kmod-mt76`, `kmod-mac80211`, `kmod-cfg80211`, `kmod-crypto-*` |
| `iw` utility | 0.1 MB | Wireless configuration |
| Dropbear SSH | 0.2 MB | Emergency access |
| `pwn4cd` binary | 0.05 MB | Static, stripped |
| Network base (`ip`, `ifconfig`) | 0.1 MB | Interface management |
| UCI configuration | 0.05 MB | System config framework |
| **Total** | **~2.6 MB** | Well under 4 MB ceiling |

### Excluded Components

The following standard OpenWrt packages are deliberately removed:

| Excluded Component | Size Saved | Reason |
|--------------------|------------|--------|
| LuCI web interface | ~4.0 MB | No web UI; Drone is headless |
| IPv6 stack (`kmod-ipv6`, `odhcp6c`) | ~0.5 MB | Ethernet link is IPv4-only |
| PPPoE / 3G / LTE modules | ~0.3 MB | No WAN connectivity |
| `dnsmasq` | ~0.3 MB | No DHCP/DNS server role |
| `firewall` (iptables/nftables) | ~0.4 MB | No routing; direct link only |
| `opkg` package manager | ~0.1 MB | No runtime package installation |
| USB / storage modules | ~0.2 MB | No USB hardware on R4CM |
