# Pwn4C

<img src="assets/router_drone.png" alt="Xiaomi Mi Router 4C" align="left" width="260">

Pwn4C converts a stock Xiaomi Mi Router 4C (MediaTek MT7628N, $15 USD) into a headless Wi-Fi penetration testing implant. It exploits CVE-2019-18370/18371 to silently deploy a custom OpenWrt firmware (<4MB) over the LAN in under 90 seconds, turning the router into a remote RF drone controlled from a host PC over Ethernet.

<br clear="left"/>


---

## Features

- **Zero-Touch Deployment**: `pwn4c infect <ip>` exploits the stock firmware, uploads the image, flashes it, and waits for the Drone to come online. No manual TFTP, no serial cables.
- **Dual-Port Architecture**: TCP 4444 carries JSON command/response traffic. UDP 5555 streams raw 802.11 frames (RadioTap/PCAP) without TCP head-of-line blocking.
- **UDP Autodiscovery**: The Host broadcasts on UDP 4440; the Drone announces itself. Zero IP configuration required.
- **Hardware-Level RF Control**: Direct integration with `kmod-mt76` for monitor mode, channel hopping, packet injection, TX power adjustment, and MAC randomization on the 2.4 GHz radio.

---

## Quick Start

```bash
# 1. Build the Go client
git clone https://github.com/3lyly0/Pwn4C.git
cd Pwn4C/cmd/pwn4c
go build -ldflags="-s -w" -o pwn4c .
sudo cp pwn4c /usr/local/bin/

# 2. Infect a stock Xiaomi Mi Router 4C (connect via LAN first)
pwn4c infect 192.168.31.1

# 3. Reconnect Ethernet to the Drone, then discover it
pwn4c discover

# 4. Start a monitor session on channel 6
pwn4c monitor -c 6 -o capture.pcap
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
├── cmd/pwn4c/       # Host Controller (Go CLI): C2, autodiscovery, exploit deployer
├── daemon/          # pwn4cd (C): embedded daemon for the Drone (mips_24kc, musl, static)
├── firmware/        # OpenWrt ImageBuilder scripts, Dockerized build, rootfs config
├── docs/            # Full documentation suite
└── LICENSE          # License file
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
| Host Client (`cmd/pwn4c/`) | MIT License |
