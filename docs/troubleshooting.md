# Troubleshooting

## Drone Not Discovered

### Symptom

`pwn4c discover` times out with no response:

```
[+] Probing all IPv4 interfaces (timeout 3s)...
[-] No active Pwn4C drones discovered on the local subnet.
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

`pwn4c discover` binds one UDP socket per IPv4 interface and sends both the
subnet-directed broadcast (e.g. `192.168.4.255`) and the limited broadcast
(`255.255.255.255`) from it. That way a multi-homed host — Hyper-V/WSL
`vEthernet`, VMware VMnet, VPN adapters — cannot silently send the probe out
the wrong NIC. Send failures are reported instead of being ignored.

To restrict the probe to one interface, name it explicitly:

```bash
# Linux
pwn4c discover --interface eth0
```

```powershell
# Windows: list interface names first
Get-NetIPAddress -AddressFamily IPv4 | Select-Object InterfaceAlias,IPAddress
pwn4c discover --interface "Ethernet"
```

If discovery still fails, run it again with `--interface` for the LAN adapter.
A send error such as `discovery broadcast failed on every interface` points at
the host (firewall/permissions), not at the drone.

> **Why the old single-broadcast probe failed on Windows:** a packet sent to
> `255.255.255.255` from a socket bound to `0.0.0.0` follows the lowest
> *interface metric*, not the route to the drone's subnet. With WSL/Hyper-V
> adapters (metric 15) and Ethernet (metric 35), the probe left via the virtual
> switch and never reached the router, while TCP to the same router worked
> normally.

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

## Drone Disappears After a Deauth Burst

### Symptom

Right after `pwn4c deauth` finishes, the drone stops answering: discovery
fails, TCP 4444 refuses connections, and a minute later the drone is back
with a fresh uptime (the daemon restarted, or the whole box rebooted).

```
[+] Injection completed. Frames sent: 15, Failed: 0
PS> pwn4c discover
[-] No active Pwn4C drones discovered on the local subnet.
...
[+] Found 1 drone(s):   ... UPTIME 6s
```

### What used to happen

`deauth` responded and dropped the control session immediately. The daemon
then tore the radio down while the paced TX queue still held deauth frames:
the TX ring was ripped out mid-transmission and the interface was flipped out
of monitor mode a fraction of a second after real RF activity. mt76x8 does
not tolerate that sequence, and the drone either restarted the daemon or
rebooted outright.

### Fix (v1.2.0)

Two changes, one on each side:

1. **Daemon** — every teardown path (STOP_MONITOR, RESTORE_NORMAL, REBOOT,
   client disconnect, SIGTERM) now runs `ctrl_teardown_monitor()`: it gives
   queued injection frames a bounded 2-second window to leave the air, lets
   the driver settle for 100 ms, and only then closes sockets and restores
   the radio mode.
2. **CLI** — `deauth` now reports transmitted / queued / failed separately
   (`Frames sent: N` used to count still-queued frames), waits for the drone
   TX queue to drain, and stops monitor mode explicitly before closing.

### Verification

```bash
pwn4c deauth -b AA:BB:CC:DD:EE:FF -i 6 -n 15 --interval 10
pwn4c discover        # should answer immediately with the SAME uptime
```

If the drone still disappears after this fix, capture the evidence before
reconnecting:

```bash
ssh root@192.168.4.1 "logread | grep -iE 'pwn4cd|procd' | tail -20"
ssh root@192.168.4.1 "dmesg | tail -30"
```

`procd` respawn messages point at a daemon crash; kernel trace lines point at
a driver-level fault (include both when reporting).

### Prefer the combined flow

`pwn4c deauth --monitor -o handshake.pcap` keeps a single control session
open — inject, then listen — so the teardown storm never happens in the first
place and the handshake lands in the PCAP.

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

**Verification:** Check the router's firmware version via its web interface at `http://192.168.31.1`. Compare against the known vulnerable versions listed in [installation.md](installation.md#path-a-automated-zero-touch-installation-recommended).

### `Command injection failed`

```
[!] Payload injection via stok endpoint returned HTTP 403
```

**Cause:** The `stok` token was extracted, but the injection endpoint is patched (CVE-2019-18370 closed independently of 18371 in some firmware builds).

**Fix:** Same as above. Fall back to Path B.

### Direct flash: router did not request the firmware

```
[!] Infection failed: router did not request the firmware within 1m0s; ...
```

**Cause:** The primary `--flash` path does not use BusyBox or an interactive
shell. The uploaded tarball contains only `speedtest_urls.xml` and `script.sh`
(a few KB). Success requires the injected script to connect back to the host's
temporary TCP listener and request `firmware`. If that request never arrives,
either the command injection did not run or the router could not reach the
host listener.

**Fix:**
1. Retry `pwn4c infect <ip> --flash <image>` once; the netspeed trigger is not
   always deterministic.
2. **Windows firewall:** allow `pwn4c.exe` on the **Private** network when
   prompted, or allow the random TCP port printed by the CLI. Check
   third-party firewalls too.
3. **LAN:** the host must be on the router's LAN subnet
   (`192.168.31.0/24` by default), connected to a **LAN** port (not WAN).
   Try `ping 192.168.31.1` and open `http://192.168.31.1`.
4. If the upload returned `1629` and the router never requests the firmware,
   the firmware is probably patched. Downgrade to a vulnerable build or use
   Path B.

> **Payload detail (CVE-2019-18370):** the stock speedtest collects every
> `<item url="..."/>` entry from `speedtest_urls.xml`, then picks `cfg.nc`
> random entries (10 on `LESSMEM` builds, 15 otherwise). If the list holds
> fewer entries than `cfg.nc`, it executes **nothing at all** — the log still
> shows `download using /tmp/speedtest_urls.xml...`, which makes this look like
> a network or firewall problem. Pwn4C repeats the injection 15 times so that
> any random subset the router picks still triggers it.

### `busybox` / `telnetd` / SSH are not used by the primary flash path

The primary `--flash` path does not need BusyBox, dropbear, telnetd, or an
interactive root shell. The payload is only XML + script, and the injected
script fetches the sysupgrade image from the host and runs
`mtd -r write /tmp/pwn4c.bin OS1`. A stock telnetd/dropbear attempt is made
only when `--flash` is omitted (debug path).

### `router rejected archive: code=1629` (解压失败，可能文件已经损坏)

```
[!] WARNING: router reported upload code=1629 msg=解压失败，可能文件已经损坏
```

**Cause:** This is returned by the router's `c_upload` endpoint itself, not by `pwn4c`'s payload construction. Verified: even a trivial hand-made `tar.gz` (single 12-byte text file, USTAR/PAX/GNU, with or without inner `Content-Type`) uploaded with stock `python-requests` gets the same `1629` on affected firmware. Known-affected: R4CM (Mi Router 4C) on `2.14.502` (latest release channel; supported versions stop at `2.14.92`). Same pattern as the 4A Gigabit on `2.30.20`, where Xiaomi changed the upload/speedtest handling server-side. Your tarball is almost certainly fine — the firmware refuses all archives.

**Fix:**
1. Confirm your firmware at `http://192.168.31.1` (or `api/misystem/status` → `hardware.version`). If it is newer than the last known-vulnerable build for your model, the CVE-2019-18370 upload path is closed.
2. Downgrade to a vulnerable build (4C: `2.14.75`–`2.14.92`, or Global `3.0.23` per community reports), then re-run `pwn4c infect`. Note the stock web UI usually rejects downgrade images at file-check, so use the Xiaomi Repair Tool / `mtd write` route (see OpenWrt wiki for the 4C) or UART.
3. Alternatively try a newer exploit primitive for your model/firmware (e.g. the `get_icon` vector used by community patcher tools), or fall back to Path B (TFTP/UART flash).

**Note:** `pwn4c infect` deliberately does not abort on `1629` — it still runs the `netspeed` trigger. On the `--flash` path, success is decided by whether the router requests the firmware and completes the transfer, not by ports 22/23.

### `router rejected archive: code=1630` (payload too large)

```
[!] Infection failed: payload too large: router rejected the <n>-byte archive with code=1630 ...
```

**Cause:** `c_upload` rejected the archive because it exceeded the router's size
limit. With the current XML + script payload (a few KB) this should not happen;
it usually means a build accidentally re-added binaries or a different archive
was uploaded. The CLI also enforces a local 100 KB safety limit.

**Fix:** Rebuild the CLI from current sources and confirm the `payload size=`
log is a few KB. Do not embed BusyBox, dropbear, or the firmware image in the
tarball.

### Stock shell path: `telnet (23) and ssh (22) are both closed`

This only applies when `--flash` is **not** provided. The primary flash path
does not depend on these ports. If the stock shell path fails, check:

1. **Patched firmware** — the upload or command-injection vector is closed
   (China `2.14.502`, some 4A Gigabit builds). Downgrade to a vulnerable build
   or use Path B (TFTP/UART). This is the most common cause.
2. **Wrong admin password** — authentication normally fails earlier with
   `login rejected (code=...)`, but a stale/incorrect saved password can leave
   you triggering against a session that never had permission to upload.
3. **LAN issues** — the host must be on a LAN port (not WAN), on the router's
   subnet (`192.168.31.0/24` by default), with no host firewall blocking
   outbound TCP to the router. Try `ping 192.168.31.1` and open
   `http://192.168.31.1` in a browser.
4. **Trigger not deterministic** — retry `pwn4c infect` once. The `netspeed`
   request occasionally does not execute the injected command.
5. **No `/tmp` space or noexec** — reboot the router to clear `/tmp`, then
   retry. A full tmpfs prevents the archive from being extracted.

To diagnose manually, watch the port check while retrying:

```bash
# Linux/macOS
nc -vz 192.168.31.1 23
nc -vz 192.168.31.1 22
```

### Stock shell path: `SSH connection refused after injection`

```
[+] Command injection successful. SSH enabled.
[!] SSH connection to 192.168.31.1:22 refused.
```

**Cause:** The optional stock-shell path ran, but the stock SSH/telnet daemon
failed to start. The primary `--flash` path does not use these daemons.
Possible reasons: stock dropbear is disabled or missing, `/tmp` is full, or the
init system blocks new services.

**Fix:**
1. Use `--flash` for deployment.
2. Retry `pwn4c infect <ip>` once. The injection is not always deterministic.
3. If you need a debug shell, try `telnet 192.168.31.1`; otherwise use Path B.

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

**Cause:** The firmware was written but did not boot successfully, or it booted
with the wrong LAN address (see the JFFS2 section below).

**Fix:**
1. Wait an additional 60 seconds. First boot with JFFS2 initialization can be slow.
2. Try `ping 192.168.4.1`. If reachable, try `pwn4c discover` again.
3. Try `ping 192.168.1.1` as well — if that answers, the overlay did not
   persist and the drone fell back to the stock OpenWrt LAN address. See
   [`mount_root: failed to sync jffs2 overlay`](#mount_root-failed-to-sync-jffs2-overlay).
4. Connect via UART serial console to observe boot output and identify kernel panics or mount failures.
5. Reflash via UART if the image is corrupted.

### `mount_root: failed to sync jffs2 overlay`

```
user.notice kernel: mount_root: jffs2 not ready yet, using temporary tmpfs overlay
daemon.info mount_root: synchronizing overlay
daemon.err mount_root: failed to sync jffs2 overlay
```

**What happened:** on the very first boot after flashing, `rootfs_data`
(`/dev/mtdblock9`) is blank, so OpenWrt boots on a temporary tmpfs overlay
while it formats JFFS2 in the background. When the format finishes, fstools
copies the tmpfs upper layer into the new JFFS2 overlay
(`cp -a /tmp/root/upper/* /`) and logs the error if that copy returns non-zero.
Anything written during that ~60–90 s window — including everything
`/etc/uci-defaults/99-pwn4c` sets — may therefore be partially or fully lost.

**Symptom after the next reboot:** the drone comes back at the stock
`192.168.1.1`, `pwn4cd` is not running, and `/etc/rc.d/S95pwn4cd` is missing.

**Built-in protection:** the image bakes `/etc/rc.d/S19pwn4c-net` into the
squashfs (not the overlay), and that script re-applies
`/usr/lib/pwn4c/provision.sh` whenever the marker `/etc/pwn4c.initialized` is
missing. So a wiped overlay is repaired before `network` starts, and the drone
returns on `192.168.4.1` without a reflash. It never touches a config that has
the marker, so operator changes are preserved.

**Verify persistence once, after the first flash:**

```bash
ssh root@192.168.4.1
uci get network.lan.ipaddr        # expect 192.168.4.1
ls /etc/rc.d/S95pwn4cd            # expect the symlink
ls /etc/pwn4c.initialized         # expect the marker
reboot
# after ~60 s:
ping 192.168.4.1
pwn4c discover
```

If the marker is gone after a reboot, the overlay migration failed again; the
repair script has re-applied the defaults (check
`logread | grep pwn4c-net`), but the flash may be worn or the overlay
partition may be too small. Re-flash with `sysupgrade -n` to recreate
`rootfs_data` from scratch.


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

## SSH Credential Policy and Non-Interactive Access

### Default State

The Pwn4C drone ships with **no root password and no authorized keys**. This
matches the OpenWrt first-boot default: telnet is available on port 23 until a
password is set.

| Condition | Telnet (23) | SSH (22) |
|-----------|------------|----------|
| No password, no authorized_keys | Open | Refused — nothing to authenticate against (set a password or key first) |
| Password set, no authorized_keys | Closed | Password auth |
| No password, authorized_keys present | Closed | Key auth |
| Password + authorized_keys | Closed | Key auth (password also works) |

> [!CAUTION]
> Deploy a drone without credentials only on air-gapped or physically controlled
> networks. On any shared network, set a password or install an authorized key
> **before** operational use.

### Setting Up Non-Interactive SSH for Automation

The host CLI (`pwn4c`) uses SSH for the `infect`→flash sequence. For
non-interactive (passwordless) access:

```bash
# Generate a deployment key pair (one-time):
ssh-keygen -t ed25519 -f ~/.ssh/pwn4c_deploy -N "" -C "pwn4c-deploy"

# Push the public key over the initial passwordless session:
ssh-copy-id -i ~/.ssh/pwn4c_deploy.pub -o StrictHostKeyChecking=no \
    root@192.168.4.1

# Verify:
ssh -i ~/.ssh/pwn4c_deploy -o StrictHostKeyChecking=no root@192.168.4.1 "id"
```

The key persists across `sysupgrade` because `/etc/dropbear/authorized_keys`
is listed in `/etc/sysupgrade.conf`.

### Changing the Root Password

```bash
ssh root@192.168.4.1 "passwd root"
# Enter new password twice.
# Once set, telnet is disabled (OpenWrt default behaviour).
```

To revert to no-password (re-enable telnet for recovery):

```bash
ssh root@192.168.4.1 "passwd -d root"
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
