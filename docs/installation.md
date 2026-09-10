# Installation Guide

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Xiaomi Mi Router 4C (R4CM) | Stock firmware (for Path A) or any state (for Path B) |
| Ethernet cable | Cat5e or better, direct connection Host to Drone |
| Host PC | Linux, macOS, or Windows with Go 1.21+ installed |
| USB-UART adapter (optional) | 3.3V logic (e.g., CP2102) for serial console recovery |

---

## Path A: Automated Zero-Touch Installation (Recommended)

This is the simplest method. The Go client exploits a known command injection vulnerability in stock Xiaomi firmware (CVE-2019-18370/18371) to automatically deploy the Pwn4C firmware. No manual flashing, TFTP servers, or serial adapters required.

### Requirements

- The router must be running **stock Xiaomi firmware** that is vulnerable to CVE-2019-18370/18371. Most firmware versions shipped before mid-2020 are vulnerable.
- The Host must be on the **same LAN segment** as the router. Connect via Ethernet to any LAN port, or join the router's default Wi-Fi network.

### A.1 Install the Go Client

**Option 1: Build from source**

```bash
git clone https://github.com/3lyly0/Pwn4C.git
cd Pwn4C/cmd/pwn4c
go build -ldflags="-s -w" -o pwn4c .
sudo cp pwn4c /usr/local/bin/
```

**Option 2: Download pre-built binary**

Download the appropriate binary from the [GitHub Releases](https://github.com/3lyly0/Pwn4C/releases) page:

```
pwn4c-linux-amd64
pwn4c-linux-arm64
pwn4c-darwin-amd64
pwn4c-darwin-arm64
pwn4c-windows-amd64.exe
```

Verify integrity:

```bash
sha256sum -c checksums.sha256
```

### A.2 Run the Infect Command

Connect the Host to any LAN port on the stock Xiaomi router. The router's default IP is `192.168.31.1`.

```bash
pwn4c infect 192.168.31.1
```

Expected output:

```
[*] Target: 192.168.31.1
[*] Extracting stok token via CVE-2019-18371...
[+] Got stok: a1b2c3d4e5f6
[*] Injecting payload via CVE-2019-18370...
[+] Command injection successful. SSH enabled.
[*] Connecting via SSH...
[+] Connected as root.
[*] Uploading pwn4c-firmware.bin to /tmp (2.8 MB)...
[+] Upload complete.
[*] Writing firmware: mtd write /tmp/pwn4c-firmware.bin OS1
[+] Flash write complete.
[*] Rebooting router...
[*] Waiting for Drone to come online (timeout: 120s)...
[+] Drone discovered!
    Address:    192.168.4.1
    Firmware:   pwn4c-0.1.0
    Uptime:     12s
[+] Infection complete. Drone is operational.
```

The entire process takes 60-90 seconds. The router reboots into the Pwn4C OpenWrt image and is immediately ready for use.

### A.3 Post-Infection Network Setup

After infection, the Drone operates on the `192.168.4.0/24` subnet (not the stock Xiaomi `192.168.31.0/24`). Reconnect the Host directly to any LAN port on the Drone. The Drone's built-in DHCP server assigns the Host an address automatically.

If DHCP does not work, set a static IP:

```bash
# Linux
sudo ip addr flush dev eth0
sudo ip addr add 192.168.4.10/24 dev eth0
sudo ip link set eth0 up
```

### A.4 What If `infect` Fails?

| Failure | Cause | Solution |
|---------|-------|----------|
| `stok extraction failed` | Router firmware is patched against CVE-2019-18371 | Use Path B (manual TFTP or UART flash) |
| `SSH connection refused` | Command injection succeeded but SSH did not start | Retry. If persistent, use Path B |
| `mtd write failed` | Insufficient `/tmp` space or flash write error | Reboot router to stock, retry. If persistent, use UART |
| `Drone not discovered after reboot` | Firmware did not boot correctly | Connect via UART serial console and reflash (see Path B) |

See [troubleshooting.md](troubleshooting.md#exploit-failures) for detailed diagnosis.

---

## Path B: Manual Build and Advanced Installation

Use this path if:
- The stock firmware is patched and `pwn4c infect` fails.
- You want to build the firmware from source with custom modifications.
- You need to recover a bricked Drone.

### B.1 Build the Firmware from Source

The firmware build uses the OpenWrt ImageBuilder inside a Docker container:

```bash
git clone https://github.com/3lyly0/Pwn4C.git
cd Pwn4C/firmware
docker build -t pwn4c-builder .
docker run --rm -v $(pwd)/output:/output pwn4c-builder
```

The output directory will contain:

```
output/
  pwn4c-firmware-mi4c.bin      # Flashable firmware image
  checksums.sha256             # Integrity hashes
```

To build without Docker, install the OpenWrt ImageBuilder for `ramips/mt76x8` manually and run:

```bash
cd Pwn4C/firmware
./build.sh
```

See [firmware/README.md](../firmware/README.md) for build dependencies.

### B.2 Flash via TFTP (Stock Recovery Mode)

The stock Xiaomi bootloader includes a TFTP-based recovery mechanism.

**Step 1: Enter recovery mode**

1. Power off the router.
2. Hold the RESET button (pinhole on the back).
3. While holding RESET, power on.
4. Continue holding until the front LED blinks amber rapidly (~10 seconds).
5. Release RESET. The router is now in recovery mode at `192.168.1.1`.

**Step 2: Configure Host network**

```bash
# Linux
sudo ip addr flush dev eth0
sudo ip addr add 192.168.1.2/24 dev eth0
sudo ip link set eth0 up

# macOS
sudo ifconfig en0 192.168.1.2 netmask 255.255.255.0 up
```

```powershell
# Windows (PowerShell, as Administrator)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.1.2 -PrefixLength 24
```

Verify: `ping 192.168.1.1`

**Step 3: Transfer via TFTP**

```bash
# Linux / macOS
tftp 192.168.1.1
> binary
> put pwn4c-firmware-mi4c.bin
> quit
```

```powershell
# Windows (enable TFTP Client via Windows Features first)
tftp -i 192.168.1.1 PUT pwn4c-firmware-mi4c.bin
```

Transfer takes 20-40 seconds. The LED blinks during flash write. **Do not power off during this process.**

**Step 4: Wait for reboot**

The router reboots automatically after flashing. First boot takes 45-60 seconds (JFFS2 overlay initialization). The LED turns solid blue when `pwn4cd` is ready.

### B.3 Flash via UART Serial Console

Use this if recovery mode is inaccessible (corrupted bootloader env) or the router is bricked.

1. Connect a 3.3V USB-UART adapter to header J1 (see [hardware.md](hardware.md#uart-serial-console)).
2. Open a serial terminal at 115200 8N1 (e.g., `screen /dev/ttyUSB0 115200`).
3. Power on the router and press any key within 1 second to interrupt U-Boot.
4. At the U-Boot prompt, configure TFTP and flash:

```
MT7628 # setenv serverip 192.168.1.2
MT7628 # setenv ipaddr 192.168.1.1
MT7628 # tftpboot 0x80010000 pwn4c-firmware-mi4c.bin
MT7628 # erase 0xbc050000 +${filesize}
MT7628 # cp.b 0x80010000 0xbc050000 ${filesize}
MT7628 # bootm 0xbc050000
```

This method bypasses all software-level recovery mechanisms.

---

## Verification

After flashing (via either Path A or Path B), verify the Drone is operational.

### Network Setup

Connect the Host to any **LAN port** on the Drone. The Drone runs DHCP on `192.168.4.0/24`. Alternatively, configure a static IP:

```bash
sudo ip addr add 192.168.4.10/24 dev eth0
sudo ip link set eth0 up
```

### Test Autodiscovery

```bash
pwn4c discover
```

Expected:

```
[*] Broadcasting discovery on 255.255.255.255:4440...
[+] Drone found!
    Address:    192.168.4.1
    Firmware:   pwn4c-0.1.0
    Uptime:     47s
    Radio:      MT7628N 2.4GHz (idle)
    Protocol:   v1
```

### Test Control Channel

```bash
pwn4c status
```

Expected:

```
[*] Connecting to 192.168.4.1:4444...
[+] Connected.
    State:        idle
    Channel:      1
    Monitor:      off
    Uptime:       2m13s
    Firmware:     pwn4c-0.1.0
```

### Test Frame Capture

```bash
pwn4c monitor --channel 6 --output test.pcap --duration 10s
```

Expected:

```
[+] Monitor active on channel 6.
[*] Received 1,247 frames in 10.0s (avg 124.7 fps)
[*] Dropped: 0 frames (0.00%)
[*] Saved: test.pcap (487 KB)
```

Verify with Wireshark:

```bash
tshark -r test.pcap -c 5
```

### Test SSH Emergency Access

```bash
ssh root@192.168.4.1
```

Default: `root` with no password. Change immediately:

```bash
passwd
```

### Verification Checklist

| Check | Command | Expected |
|-------|---------|----------|
| Drone reachable | `ping 192.168.4.1` | Reply |
| Discovery works | `pwn4c discover` | Drone found |
| Control channel | `pwn4c status` | State: idle |
| Frame capture | `pwn4c monitor --channel 6 --duration 5s` | Frames received |
| SSH access | `ssh root@192.168.4.1` | Shell prompt |
