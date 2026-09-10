# Troubleshooting

## Drone Not Discovered

### Symptom

`pwn4c discover` times out with no response:

```
[*] Broadcasting discovery on 255.255.255.255:4440...
[!] No Drone found after 3 attempts.
```

### Diagnosis Checklist

**1. Verify physical link**

Check that the Ethernet cable is connected and the link LED is active on both ends.

```bash
# Linux
ip link show eth0 | grep "state UP"

# Windows (PowerShell)
Get-NetAdapter -Name "Ethernet" | Select-Object Status
```

If the link is down, try a different cable or port. The Mi Router 4C has 3 Ethernet ports: use any **LAN** port (not WAN, which is isolated in the default config).

**2. Verify IP configuration**

The Drone's DHCP server assigns addresses in `192.168.4.0/24`. If DHCP fails, configure a static address:

```bash
# Linux
sudo ip addr add 192.168.4.10/24 dev eth0
sudo ip link set eth0 up

# macOS
sudo ifconfig en0 192.168.4.10 netmask 255.255.255.0 up
```

```powershell
# Windows (as Administrator)
New-NetIPAddress -InterfaceAlias "Ethernet" -IPAddress 192.168.4.10 -PrefixLength 24
```

Verify: `ping 192.168.4.1`

**3. Verify broadcast routing**

UDP broadcasts must egress on the correct interface. If the Host has multiple interfaces (Wi-Fi, VPN, etc.), the OS may route broadcasts out the wrong one.

```bash
# Linux: force discovery on a specific interface
pwn4c discover --interface eth0

# Check broadcast routing
ip route get 255.255.255.255
```

Fix broadcast routing if it exits via the wrong interface:

```bash
# Linux
sudo ip route add 255.255.255.255/32 dev eth0

# macOS
sudo route add -host 255.255.255.255 -interface en0
```

On Windows, ensure the Ethernet adapter has a lower metric than Wi-Fi:

```powershell
Set-NetIPInterface -InterfaceAlias "Ethernet" -InterfaceMetric 10
Set-NetIPInterface -InterfaceAlias "Wi-Fi" -InterfaceMetric 100
```

**4. Firewall blocking UDP port 4440**

```bash
# Linux (iptables)
sudo iptables -L -n | grep 4440

# macOS
sudo pfctl -sr | grep 4440
```

```powershell
# Windows
Get-NetFirewallRule | Where-Object { $_.LocalPort -eq 4440 }
```

Add exceptions:

```bash
# Linux
sudo iptables -A INPUT -p udp --dport 4440 -j ACCEPT
sudo iptables -A OUTPUT -p udp --dport 4440 -j ACCEPT
```

```powershell
# Windows
New-NetFirewallRule -DisplayName "Pwn4C Discovery" -Direction Inbound -Protocol UDP -LocalPort 4440 -Action Allow
New-NetFirewallRule -DisplayName "Pwn4C Discovery Out" -Direction Outbound -Protocol UDP -RemotePort 4440 -Action Allow
```

**5. `pwn4cd` not running**

If the Drone is reachable via ping but does not respond to discovery:

```bash
ssh root@192.168.4.1 "ps | grep pwn4cd"
```

If not running:

```bash
ssh root@192.168.4.1 "/etc/init.d/pwn4cd start"
ssh root@192.168.4.1 "logread | grep pwn4cd"
```

---

## Exploit Failures

### Symptom

`pwn4c infect` fails at one of its stages.

### `stok extraction failed`

```
[!] Failed to extract stok token from 192.168.31.1
```

**Cause:** The router's firmware is patched against CVE-2019-18371. Xiaomi firmware updates released after mid-2020 often close this vulnerability.

**Fix:** Use manual installation (Path B). Flash via TFTP recovery mode or UART. See [installation.md](installation.md#path-b-manual-build-and-advanced-installation).

**Verification:** Check the router's firmware version via its web interface at `http://192.168.31.1`. Compare against known vulnerable versions listed in the OpenWRTInvasion project.

### `Command injection failed`

```
[!] Payload injection via stok endpoint returned HTTP 403
```

**Cause:** The `stok` token was extracted, but the injection endpoint is patched (CVE-2019-18370 closed independently of 18371 in some firmware builds).

**Fix:** Same as above. Fall back to Path B.

### `SSH connection refused after injection`

```
[+] Command injection successful. SSH enabled.
[!] SSH connection to 192.168.31.1:22 refused.
```

**Cause:** The injected payload executed, but the SSH/telnet daemon failed to start. Possible reasons: insufficient `/tmp` space, or a modified init system that blocks new services.

**Fix:**
1. Retry `pwn4c infect` once. The injection is not always deterministic.
2. If it persists, attempt a manual telnet connection: `telnet 192.168.31.1`. If telnet works but SSH does not, use telnet to manually upload and flash the firmware.
3. If neither works, use Path B.

### `mtd write failed`

```
[!] mtd write returned exit code 1
```

**Cause:** Flash write error. Possible insufficient space in `/tmp` (the firmware binary is uploaded there before flashing), or a flash hardware issue.

**Fix:**
1. Reboot the router to stock firmware.
2. Clear `/tmp`: `rm -rf /tmp/*`
3. Retry `pwn4c infect`.
4. If persistent, the flash chip may have bad blocks. Use UART to flash directly from U-Boot (see [installation.md](installation.md#b3-flash-via-uart-serial-console)).

### `Drone not discovered after reboot`

```
[*] Waiting for Drone to come online (timeout: 120s)...
[!] Timeout: Drone did not respond.
```

**Cause:** The firmware was written but did not boot successfully.

**Fix:**
1. Wait an additional 60 seconds. First boot with JFFS2 initialization can be slow.
2. Try `ping 192.168.4.1`. If reachable, try `pwn4c discover` again.
3. Connect via UART serial console to observe boot output and identify kernel panics or mount failures.
4. Reflash via UART if the image is corrupted.

---

## Dropped Frames on High-Traffic Channels

### Symptom

High drop rate during capture:

```
[*] Received 8,412 frames in 60.0s (avg 140.2 fps)
[*] Dropped: 1,247 frames (12.91%)
```

Or `BUFFER_OVERFLOW` events on the control channel.

### Fixes

**1. Increase Host UDP socket buffer**

The default OS UDP receive buffer is often too small for burst traffic.

```bash
# Linux: check current values
sysctl net.core.rmem_default
sysctl net.core.rmem_max

# Increase to 4 MB
sudo sysctl -w net.core.rmem_default=4194304
sudo sysctl -w net.core.rmem_max=4194304

# Persist across reboots
echo "net.core.rmem_default=4194304" | sudo tee -a /etc/sysctl.conf
echo "net.core.rmem_max=4194304" | sudo tee -a /etc/sysctl.conf
```

```powershell
# Windows: increase via registry
# HKLM\SYSTEM\CurrentControlSet\Services\AFD\Parameters
# Add DWORD: DefaultReceiveWindow = 4194304
# Requires reboot.
```

**2. Avoid dense channels**

Use `pwn4c scan` to survey channel utilization before committing to a capture channel. Channels 1, 6, and 11 are typically the busiest in urban environments.

**3. Ethernet bandwidth limits**

At 100 Mbps (the Mi Router 4C's Ethernet speed), theoretical max throughput is ~11.9 MB/s.

| Frame Rate | Avg Frame Size | Bandwidth | Status |
|------------|----------------|-----------|--------|
| 500 fps | 200 bytes | 0.8 Mbps | Fine |
| 2,000 fps | 500 bytes | 8.0 Mbps | Fine |
| 5,000 fps | 1,000 bytes | 40 Mbps | Moderate |
| 10,000 fps | 1,000 bytes | 80 Mbps | Near saturation |

Exceeding ~80 Mbps causes Ethernet-layer drops. This is rare under normal monitoring conditions.

**4. Drone CPU bottleneck**

```bash
ssh root@192.168.4.1 "top -bn1 | head -5"
```

If `pwn4cd` exceeds 90% CPU, the frame rate exceeds daemon processing capacity. This is unlikely under typical conditions.

---

## Firmware Recovery

### Scenario A: Drone boots but `pwn4cd` is broken

SSH in and inspect:

```bash
ssh root@192.168.4.1
logread | grep pwn4cd
dmesg | grep -i error
/etc/init.d/pwn4cd stop
/etc/init.d/pwn4cd start
```

Reflash via `sysupgrade` (preserves config):

```bash
scp pwn4c-firmware-mi4c.bin root@192.168.4.1:/tmp/
ssh root@192.168.4.1 "sysupgrade /tmp/pwn4c-firmware-mi4c.bin"
```

Reset all configuration:

```bash
ssh root@192.168.4.1 "sysupgrade -n /tmp/pwn4c-firmware-mi4c.bin"
```

### Scenario B: Drone boots but network is unreachable

Connect via UART serial console (see [hardware.md](hardware.md#uart-serial-console)):

```bash
screen /dev/ttyUSB0 115200
```

Log in as `root`, then fix networking:

```bash
uci show network
uci set network.lan.ipaddr='192.168.4.1'
uci commit network
/etc/init.d/network restart
ip link show eth0   # verify "state UP"
```

### Scenario C: Drone does not boot (bricked)

1. Enter U-Boot recovery mode:
   - Power off.
   - Hold RESET.
   - Power on while holding RESET.
   - Wait for rapid amber LED (~10 seconds).
   - Release RESET.

2. Flash via TFTP (see [installation.md](installation.md#b2-flash-via-tftp-stock-recovery-mode)).

3. If U-Boot recovery fails, use UART:
   - Connect USB-UART adapter.
   - Interrupt U-Boot by pressing a key within 1 second of power-on.
   - Flash from the U-Boot command line (see [installation.md](installation.md#b3-flash-via-uart-serial-console)).

### Scenario D: Factory partition corrupted

If Wi-Fi calibration is lost (no beacons received, wildly inaccurate RSSI):

```bash
ssh root@192.168.4.1 "hexdump -C /dev/mtd2 | head -5"
```

If all `0xFF`, the partition is erased.

**Restore from backup** (if available):

```bash
scp factory_backup.bin root@192.168.4.1:/tmp/
ssh root@192.168.4.1 "mtd write /tmp/factory_backup.bin factory"
ssh root@192.168.4.1 "reboot"
```

If no backup exists, calibration data is unrecoverable. The radio will operate with default (uncalibrated) parameters.

**Prevention:** Back up the factory partition before first flash:

```bash
# On the Drone
dd if=/dev/mtd2 of=/tmp/factory_backup.bin
scp root@192.168.4.1:/tmp/factory_backup.bin ./
```

---

## Control Channel Connection Refused

### Symptom

```
[*] Connecting to 192.168.4.1:4444...
[!] Connection refused.
```

### Causes

1. **Another client is connected.** `pwn4cd` accepts only one TCP connection. Check:

```bash
# Linux
ss -tnp | grep 4444

# macOS
lsof -i :4444

# Windows
netstat -an | findstr 4444
```

Kill the other client or wait for it to disconnect.

2. **`pwn4cd` is not running.** See [pwn4cd not running](#5-pwn4cd-not-running) above.

---

## Frame Stream Not Received

### Symptom

`START_MONITOR` succeeds but no frames arrive.

**1. Firewall blocking UDP 5555**

```bash
# Linux
sudo iptables -A INPUT -p udp --dport 5555 -j ACCEPT
```

```powershell
# Windows
New-NetFirewallRule -DisplayName "Pwn4C Stream" -Direction Inbound -Protocol UDP -LocalPort 5555 -Action Allow
```

**2. Wrong stream target IP**

The Drone derives the Host's IP from the TCP connection's peer address. Check:

```bash
pwn4c status
# Look for "stream_target"
```

Ensure the reported address matches an IP the Host is listening on.

**3. Empty channel**

If monitoring a genuinely empty channel (e.g., channel 13 in a sparse environment), zero frames is correct. Switch to a busier channel (1, 6, or 11).

---

## SSH Issues

### `Connection refused` on port 22

Dropbear may not have started. Via UART:

```bash
/etc/init.d/dropbear start
```

### `Host key verification failed`

After reflashing, the Drone generates new host keys. Remove the stale entry:

```bash
ssh-keygen -R 192.168.4.1
```

### SSH works but `pwn4c` commands fail

SSH and `pwn4cd` are independent services. SSH confirms network connectivity but not daemon health. Check via SSH:

```bash
ssh root@192.168.4.1 "ps | grep pwn4cd"
ssh root@192.168.4.1 "logread | grep pwn4cd"
```

---

## Quick Reference

| Issue | Command | Expected |
|-------|---------|----------|
| Link status | `ip link show eth0` | `state UP` |
| IP config | `ip addr show eth0` | `192.168.4.x/24` |
| Drone reachable | `ping 192.168.4.1` | Reply |
| Daemon running | `ssh root@192.168.4.1 "ps \| grep pwn4cd"` | Process listed |
| Daemon logs | `ssh root@192.168.4.1 "logread \| grep pwn4cd"` | Check for errors |
| TCP port open | `nc -zv 192.168.4.1 4444` | Connection succeeded |
| UDP buffer size | `sysctl net.core.rmem_default` | >= 4194304 |
| Broadcast route | `ip route get 255.255.255.255` | Exits via `eth0` |
| Firewall rules | `sudo iptables -L -n` | No DROP on 4440/4444/5555 |
| Flash partitions | `ssh root@192.168.4.1 "cat /proc/mtd"` | All partitions present |
| System resources | `ssh root@192.168.4.1 "free -m; df -h"` | Sufficient RAM and flash |
