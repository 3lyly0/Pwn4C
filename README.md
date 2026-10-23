# Pwn4C

[![CLI Tool](https://github.com/3lyly0/Pwn4C/actions/workflows/cli.yml/badge.svg)](https://github.com/3lyly0/Pwn4C/actions/workflows/cli.yml)
[![Daemon](https://github.com/3lyly0/Pwn4C/actions/workflows/daemon.yml/badge.svg)](https://github.com/3lyly0/Pwn4C/actions/workflows/daemon.yml)
[![Firmware](https://github.com/3lyly0/Pwn4C/actions/workflows/firmware.yml/badge.svg)](https://github.com/3lyly0/Pwn4C/actions/workflows/firmware.yml)
[![Release](https://github.com/3lyly0/Pwn4C/actions/workflows/release.yml/badge.svg)](https://github.com/3lyly0/Pwn4C/actions/workflows/release.yml)

<img src="assets/router_drone.png" alt="Xiaomi Mi Router 4C" align="left" width="260">

Pwn4C converts a stock Xiaomi Mi Router 4C (MediaTek MT7628N, ~$15 USD) into a headless Wi-Fi penetration testing implant. It exploits CVE-2019-18370/18371 to silently deploy a custom OpenWrt firmware (<4MB) over the LAN in under 90 seconds, turning the router into a remote RF drone controlled from a host PC over Ethernet.

<br clear="left"/>

---

## Features

- **Zero-Touch Deployment (`pwn4c infect`)**: Exploits stock firmware Web API authentication & command injection to push payloads and flash custom firmware silently over LAN with zero serial or TFTP intervention.
- **Dual-Port Architecture**: Dedicated TCP control channel (port 4444) carries structured JSON telemetry and commands; high-throughput UDP channel (port 5555) streams raw 802.11 frames (RadioTap/PCAP) without TCP head-of-line blocking.
- **Zero-Conf Autodiscovery (`pwn4c discover`)**: Drone implants broadcast periodic discovery beacons over UDP 4440; host CLI automatically detects all reachable drones on the subnet without manual IP configuration.
- **Active 802.11 Frame Injection & Deauth (`pwn4c deauth`)**: Generates and transmits raw 802.11 management frames over the air to target specific clients or broadcast deauthentication against an access point.
- **Spectrum Channel Hopping (`pwn4c hop`)**: Sweeps across 2.4 GHz channels (1–13) with configurable dwell times (e.g. 250ms) for broad-spectrum reconnaissance.
- **Hardware-Level RF Control (`pwn4c config`)**: Full control via `kmod-mt76` over transmission power (0–20 dBm), dynamic MAC address spoofing and randomization, and remote mode resets or reboots.
- **Real-Time Telemetry (`pwn4c status`)**: Live hardware metrics including CPU temperature, available RAM, TX queue depth, and link state.

---

## CLI Reference

| Command | Syntax / Example | Description |
|---|---|---|
| `infect` | `pwn4c infect 192.168.31.1` | Exploits stock Xiaomi firmware and enables root access |
| `discover` | `pwn4c discover [-t 3]` | Scans subnet for active Pwn4C drone implants via UDP broadcast |
| `status` | `pwn4c status [target_ip]` | Queries live telemetry, link health, and radio state over TCP |
| `monitor` | `pwn4c monitor [target_ip] -c 6 -o capture.pcap` | Starts 802.11 monitor mode and streams live PCAP frames |
| `hop` | `pwn4c hop [target_ip] -d 250 -c 1,6,11` | Continuously cycles Wi-Fi channels with configurable dwell time |
| `deauth` | `pwn4c deauth [target_ip] -b <bssid> [-c <client>]` | Injects raw IEEE 802.11 deauthentication frames |
| `config` | `pwn4c config [target_ip] --power 20 --mac random` | Adjusts TX power, randomizes/spoofs MAC, or restores normal mode |

---

## Quick Start

### 1. Build the Host CLI

```bash
git clone https://github.com/3lyly0/Pwn4C.git
cd Pwn4C
go build -ldflags="-s -w" -o pwn4c ./cmd/pwn4c
sudo cp pwn4c /usr/local/bin/   # On Linux/macOS
```

*(Pre-compiled binaries for Linux, macOS, and Windows are also available in [Releases](https://github.com/3lyly0/Pwn4C/releases).)*

### 2. Infect Stock Router

Connect your host PC to the router's LAN port:

```bash
pwn4c infect 192.168.31.1
```

### 3. Discover Active Drone

Once the custom firmware is booted, discover the implant on the link:

```bash
pwn4c discover
```

### 4. Monitor & Capture Live Traffic

Capture live 802.11 traffic on channel 6 and save directly to a Wireshark-compatible PCAP:

```bash
pwn4c monitor -c 6 -o capture.pcap
```

### 5. RF Attacks & Spectrum Sweeping

```bash
# Sweep channels 1, 6, 11 with 250ms dwell time
pwn4c hop -d 250 -c 1,6,11

# Inject 20 deauth frames against target AP client
pwn4c deauth -b AA:BB:CC:DD:EE:FF -c 11:22:33:44:55:66 -i 6 -n 20

# Maximize TX power and randomize drone MAC
pwn4c config --power 20 --mac random
```

---

## Documentation

- [Architecture](docs/architecture.md): System diagram, Drone/Host roles, transport spec, infection lifecycle.
- [Hardware Reference](docs/hardware.md): MT7628N specs, flash layout, RF constraints, storage budget.
- [Installation Guide](docs/installation.md): Automated (Path A) and manual (Path B) deployment instructions.
- [API Reference](docs/api_reference.md): Wire protocol, TCP JSON commands, UDP stream format, error codes.
- [Troubleshooting](docs/troubleshooting.md): Discovery failures, exploit issues, dropped frames, firmware recovery.

---

## Repository Structure

```
Pwn4C/
├── .github/workflows/  # Modular CI/CD pipelines (CLI, Daemon, Firmware, Release)
├── cmd/pwn4c/          # Host Controller (Go CLI): C2, autodiscovery, exploit deployer
├── daemon/             # pwn4cd (C): embedded daemon for Drone (mips_24kc, musl, static)
├── firmware/           # OpenWrt ImageBuilder scripts, Dockerized build, rootfs config
├── internal/
│   ├── drone/          # C2 TCP client, UDP PCAP receiver, 802.11 frame builders
│   └── exploit/        # CVE-2019-18370/18371 automated exploit engine
├── docs/               # Architecture, API wire specs, and hardware documentation
└── LICENSE             # Dual-license specification
```

---

## Disclaimer

This software is provided strictly for **educational purposes** and **authorized security auditing**. Unauthorized access to computer networks is illegal under the Computer Fraud and Abuse Act (18 U.S.C. 1030), the Computer Misuse Act 1990, and equivalent legislation in most jurisdictions. You are solely responsible for ensuring you have explicit, written authorization before using this tool against any network or device. The authors assume no liability for misuse.

---

## License

This project uses a dual-license model:

| Component | License |
|-----------|---------|
| Firmware and Daemon (`daemon/`, `firmware/`) | [GNU General Public License v3.0](LICENSE) |
| Host Client (`cmd/pwn4c/`, `internal/`) | MIT License |
