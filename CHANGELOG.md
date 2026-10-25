# Changelog

All notable changes to Pwn4C are documented here. For releases prior to
v1.2.0 see the [GitHub releases page](https://github.com/3lyly0/Pwn4C/releases).

## [1.2.0] - 2026-10-26

### Fixed
- **Drone no longer disappears after a deauth burst.** The CLI used to drop
  the control session while injection frames were still queued, and the daemon
  tore the radio down mid-transmission — a sequence mt76x8 does not survive.
  All teardown paths (STOP_MONITOR, RESTORE_NORMAL, REBOOT, client disconnect,
  SIGTERM) now drain the TX queue, settle the driver, and only then restore
  the radio (`ctrl_teardown_monitor`).
- `deauth` now reports transmitted / queued / failed frames separately instead
  of presenting queued frames as sent.
- `infect` no longer prints the misleading `WARNING: trigger request failed`
  (or the "still running" notice) for the netspeed trigger — a client-side
  timeout there is the normal outcome of a working injection, and the final
  verdict is decided by the firmware-transfer wait.
- The drone login banner is regenerated with figlet instead of the mangled
  hand-drawn ASCII art.

### Added
- `pwn4c deauth --monitor [-o out.pcap]`: deauth-and-listen in a single
  control session — inject the burst, keep streaming probe requests,
  re-associations and EAPOL handshakes to a PCAP until Ctrl+C.
- `pwn4c discover` keeps probing for a drone instead of failing after one
  round: `--wait-timeout` (default 15s, `0` = wait forever), `--retry-every`,
  `--no-wait` for the old single-round behaviour.
