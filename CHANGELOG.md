# Changelog

All notable changes to Pwn4C are documented here. For releases prior to
v1.2.0 see the [GitHub releases page](https://github.com/3lyly0/Pwn4C/releases).

## [1.5.0] - 2026-11-15

### Fixed
- **Boolean parameters were ignored:** the Go CLI sends real JSON booleans
  (`"mgmt_only": true`, `"share": false`), but the daemon parsed them with
  `json_get_int()`, which rejects a `t`/`f` prefix. `monitor --mgmt-only` and
  `connect --no-share` therefore did nothing on v1.4.0. A `json_get_bool()`
  helper now accepts `true`/`false` and the legacy `1`/`0` spellings, and the
  mock transcript exercises the boolean form end to end.
- **Release downloads were the wrong platform:** `cli.yml` never set
  `GOOS`/`GOARCH`, so `macos-latest` built a darwin/arm64 binary under the
  plain name `pwn4c` and the Linux build was overwritten when the artifacts
  were merged — the published `pwn4c` was not a Linux executable. Each target
  is now cross-compiled explicitly, named `pwn4c-<os>-<arch>`, and checked
  with `go version -m` so a mismatched binary fails the build.
- **Hardcoded interface names:** `pwn4cd` assumed `wlan0` / `phy0-sta0`, which
  do not exist on OpenWrt 23.05 (`phy0-ap0` / `phy0-sta0`). The AP and station
  netdevs are now detected at runtime (`iw dev`, `ifstatus`, UCI) and reported
  in `GET_STATUS` as `ap_iface` / `sta_iface`; `--iface` still overrides.
- **TX power lied:** `SET_TX_POWER` returned the requested value even when the
  MT7628 PA clamped it. It now reads the power back from the driver, reports
  `requested_dbm` / `clamped`, and persists the applied value to UCI.
- **MAC changes were not durable:** `SET_MAC` bounced the radio even when it
  was down, never persisted the address, and reported success unconditionally.
  It now leaves a down radio down, writes `wireless.*.macaddr`, reads the
  address back (`applied`), and refuses to run while monitor mode is active.
- **Channel reporting:** `GET_STATUS.channel` was the daemon's cached value.
  AP and STA channels are now read from the driver (`ap_channel`,
  `sta_channel`), and `SET_CHANNEL` verifies the switch with `iw`.
- **Injection frames never reached the air:** the frame builder emitted an
  8-byte RadioTap header with an empty present bitmap. mt76 accepted the frame
  and transmitted nothing. The builder now emits a 16-byte header with Flags,
  Rate, Channel and TX flags.
- **Silent TX drops above 64 frames:** the injection queue was 64 slots. It is
  now 256 slots of 1024 bytes, paced by `interval_ms`, and `SEND_INJECTION`
  reports `frames_requested` / `frames_queued` / `frames_sent` /
  `frames_failed` / `frames_pending` so a shortfall is never hidden.
- **BPF filter dropped client discovery:** a BSSID filter rejected undirected
  probe requests (broadcast Addr1), which are the signal a deauth-and-listen
  capture needs. Broadcast probe requests are now accepted; directed ones still
  go through the address check. The management-only branch was also patched
  incorrectly and could reject valid management frames.
- **Monitor mode outlived its session (or died too early):** a client
  disconnect always tore the radio down, and a stale capture vif made netifd
  create `phy0-ap1`. `START_MONITOR` now accepts `persist` and `ttl_sec`, the
  daemon enforces the deadline itself, and teardown deletes the vif. The CLI
  gained `monitor --seconds` and `--persist`.
- **Wrong passwords blamed for association failures:** `[TEMP-DISABLED]` was
  treated as a bad key, but wpa_supplicant sets it for `reason=CONN_FAILED`
  too. The daemon now parses the reason from `logread` and reports
  `auth_failed` only for `WRONG_KEY`; other failures become `connect_failed`
  with `error_detail`.
- **`connect` could not pin a MAC or retry:** added `--mac`, `--random-mac`
  and `--retry`. The station netdev is resolved dynamically, and
  `share.sh on <iface>` masquerades on the real station interface.
- **Shell input race:** the interactive shell mixed a `bufio.Scanner` with
  direct `term.ReadPassword` reads, losing typed-ahead input, and recreated the
  scanner on error. One buffered reader now backs every prompt. A listen
  session also stops monitor mode when it ends, instead of leaving the radio
  unavailable for the next command.

### Added
- `networks --wps` and WPS fields (`wps`, `wps_state`, `wps_dp_id`,
  `wps_config_methods`, `wps_locked`) parsed from the WSC information element.
- `deauth --rate`, `--reverse`, `--disassoc` and `--seconds`.
- `config --mac` with no value now generates a random locally-administered
  address; `config` and `status` print the applied/requested MAC, whether the
  driver accepted it, and whether it was persisted.
- `status` shows AP/STA channels and interfaces, radio MAC, TX power, monitor
  persistence/TTL, and injection request/drop counters.

## [1.4.0] - 2026-10-26

### Added
- **LAN sharing on `pwn4c connect`:** joining an upstream network now also
  NATs `192.168.4.0/24` behind the station link, so a host plugged into a LAN
  port reaches the internet through the drone's Wi-Fi. The image ships without
  `firewall4`, so there is no zone model and no masquerade: `connect` gave the
  drone upstream connectivity while forwarded packets died on the return path,
  because the upstream router has no route back to `192.168.4.0/24`. Sharing is
  a single nftables table (`/usr/lib/pwn4c/share.sh`) with a postrouting
  `masquerade` on `phy0-sta0` and an MSS clamp; `wifi-disconnect` removes it.
  `--no-share` keeps the old isolated behaviour, and `wifi-status` reports
  whether sharing is active. `WIFI_CONNECT` takes a `share` parameter and
  `WIFI_STATUS` returns a `sharing` field.
- `nftables` and `kmod-nft-nat` are now part of the firmware image. `firewall4`
  stays excluded; the manifest assertions require `nftables` and still reject
  the zone model.
- **`pwn4c reboot`:** the daemon and control client already supported `REBOOT`
  and the interactive shell exposed it, but there was no top-level command, so
  `pwn4c reboot` failed with `unknown command`. It now reboots the drone,
  confirms first unless `--yes` is given, and waits for the drone to
  re-announce (or returns immediately with `--no-wait`).

## [1.3.3] - 2026-10-26

### Fixed
- **Empty handshake captures:** `deauth --monitor` now refuses the broadcast
  client default, because most clients ignore group-addressed deauth frames and
  stay associated. Pass `-c <CLIENT_MAC>`, or `--all-clients` to opt into a
  broadcast burst deliberately. The interactive `deauth` menu asks for a client
  MAC too, warns before a broadcast burst, and applies the selected BSSID as a
  capture filter. Group/multicast client addresses are rejected, since they are
  never a valid single-client target.
- **Misleading TX reporting:** `deauth` now prints how many frames were
  *queued* (and how many were accepted synchronously), waits for the paced ring
  to drain, and then reports the real delta of the drone's new `inject_frames`
  counter instead of claiming `Transmitted: 0` for frames that leave
  asynchronously. The old `tx_frames` field is the stream sequence (frames
  captured and sent to the host), so it never measured injection; `status` now
  labels it `TX Stream Frames` and shows `Injected Frames` when the firmware
  reports it.
- **BPF filter leaking between sessions:** the daemon keeps filter state across
  monitor sessions, so a `--filter-bssid` run silently narrowed later captures.
  `monitor` and `deauth --monitor` now clear an inherited filter when none is
  requested.
- **`deauth` rebooting the drone:** the stock 23.05.5 `mt7603` driver never
  initialises the global station WCID it hands to `mt76_tx()` for injected
  monitor frames, so the first deauth queued the skb on a zeroed
  `sk_buff_head` and panicked the MIPS core (`BadVA : 00000000`,
  `epc : mt76_tx`). The image now ships patched `kmod-mt76-core`/`kmod-mt7603`
  (backport of upstream `c50f17ec046e` plus a defensive queue guard), built
  by `firmware/build-mt76-kmod.sh`.
- **Radio left administratively down after a capture session:** at boot the
  daemon starts with `radio_mode = RADIO_DOWN` while netifd has already applied
  the saved wireless profile, so the first `listen`/`deauth`/`networks` saved
  the wrong mode and "restored" the radio to down, silently taking the drone
  off the air until the next reboot. Monitor entry now derives the saved mode
  from the actual UCI/radio state, and the teardown log reports what really
  happened instead of always claiming "radio restored".
- **Station rejoin after monitor:** `radio_restore_normal` no longer pins
  `radio0.channel` when a station profile exists (the STA follows its AP), so
  the uplink comes back after a capture session.
- **Silent capture failures:** `listen`/`deauth` now warn when a capture window
  produced zero frames, and the CLI reports a lost control connection during
  the TX drain instead of claiming the burst was sent.

### Added
- **BPF filtering for `deauth --monitor`:** `--filter-bssid <AP_BSSID>` and
  `--mgmt-only` narrow the capture on the drone, matching the options that
  `monitor` already had. The BSSID filter checks Addr1/Addr2/Addr3, so EAPOL
  frames survive it; `--mgmt-only` warns because it excludes the handshake.
- **Persistent radio trace:** `util_trace` appends rare state transitions
  (monitor enter/exit, injection, teardown) to `/root/pwn4c-trace.log`, which
  survives a watchdog reset or kernel panic — the RAM-only `logread` does not.

## [1.3.2] - 2026-10-26

### Fixed
- **Shell persistence across Ctrl+C & deauth:** Stopping capture in `deauth` or `listen` now closes the receiver without tearing down monitor mode or triggering mt76 kernel teardown panics; pressing Ctrl+C in the menu recreates the console scanner rather than killing the shell.
- **Wi-Fi Station Mode association:** Default encryption set to `psk-mixed` (WPA/WPA2 compatible); removed default BSSID pinning in shell connect; dynamically discover the connected wireless interface name in `WIFI_STATUS`.
- **Clean monitor mode transitions:** `radio_enter_monitor` now terminates any background `wpa_supplicant` and settles before switching mode, eliminating transient EBUSY errors after failed station joins.

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
