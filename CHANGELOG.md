# Changelog

All notable changes to Pwn4C are documented here. For releases prior to
v1.2.0 see the [GitHub releases page](https://github.com/3lyly0/Pwn4C/releases).

## [1.3.1] - 2026-10-26

### Fixed
- **WIFI_SCAN JSON syntax error:** Fixed a leading comma in the `networks` array (`"networks":[,{...}]`) that broke unmarshaling in the CLI.
- **Radiotap extension bitmasks:** The beacon parser now handles multi-word radiotap present headers (as emitted by `mt76`), properly extracting `signal_dbm`.
- **TX power setting when radio is idle:** `radio_set_txpower` now targets `phy0` so power adjustments succeed even when the virtual interface is down.
- **CLI connect & shell usability:** `pwn4c connect` accepts the passphrase as an optional second positional argument and warns if a MAC is passed as the SSID; `pwn4c shell` `use` matches by BSSID as well as SSID.

## [1.3.0] - 2026-10-26

### Added
- **Wi-Fi survey** (`pwn4c networks`, daemon `WIFI_SCAN`): monitor-mode sweep
  of the 2.4 GHz band with in-place beacon parsing. Networks come back
  deduplicated by BSSID and signal-sorted; hidden networks are reported with
  their advertised SSID length (blanked-IE heuristics). Unit-tested parser
  (`test_beacon.c`).
- **Station mode** (`pwn4c connect`, `pwn4c wifi-status`,
  `pwn4c wifi-disconnect`; daemon `WIFI_CONNECT`/`WIFI_STATUS`/
  `WIFI_DISCONNECT`): the drone joins an upstream network through a
  Pwn4C-owned `pwn4c_sta` UCI profile. Hidden SSIDs are supported, the stock
  AP profile is only ever toggled through its `disabled` flag, and
  disconnecting returns the radio to the boot-safe DOWN state.
- **Verified OTA updates** (`pwn4c upgrade`, daemon `UPGRADE`): the host
  serves the sysupgrade image; the drone checks `/tmp` headroom, download
  size and SHA-256 before flashing, and `sysupgrade` runs detached so procd
  shutdown signals cannot kill the flash. The CLI waits through the reboot
  and reports the new firmware version.
- **Interactive shell** (`pwn4c shell`): one persistent control session with
  a numbered menu — status, survey, select, join, listen, deauth-then-capture,
  hop, power, reboot. The in-shell deauth flow injects the burst and keeps
  listening on the same session for the handshake.

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
