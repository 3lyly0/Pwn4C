# Changelog

All notable changes to Pwn4C are documented here. For releases prior to
v1.2.0 see the [GitHub releases page](https://github.com/3lyly0/Pwn4C/releases).

## [Unreleased]

### Added
- **Handshake harvesting (`pwn4c harvest`)**: the drone now decodes EAPOL-Key
  frames in real time instead of leaving handshake hunting to a PCAP
  post-mortem. A standalone parser (`daemon/eapol_parse.c`) classifies M1-M4,
  extracts the ANonce/SNonce, MIC, replay counter and the RSN PMKID KDE, and
  feeds a bounded 16-slot `(BSSID, STA)` table (`daemon/handshake.c`) that also
  caches `BSSID -> SSID` from beacons. `pwn4c harvest` polls the new
  `GET_HANDSHAKES` command, stops as soon as a crackable unit exists, and writes
  hashcat mode-22000 lines — both `WPA*01*` (PMKID) and `WPA*02*` (M1+M2,
  M1+M4, M3+M2, M3+M4). `--deauth` optionally kicks clients first, and
  `--all` keeps collecting until `--timeout`.
- **`GET_HANDSHAKES` control command**: pages through ready units (six per
  page, keeping responses inside the 8 KB line limit), accepts `{"reset":true}`
  to clear the table, and survives `STOP_MONITOR` so results can be collected
  after the radio is restored.
- **Mock and test coverage**: the daemon injects a synthetic beacon plus one
  PMKID unit and one M1+M2 unit in mock mode, `tests/test_eapol.c` covers the
  parser and table (48 assertions), and `internal/drone/handshake_test.go`
  pins the hashcat line format.
- **`harvest` in the interactive shell**: menu entry 9 captures a handshake or
  PMKID for the selected network (or a channel you type), optionally sends a
  deauth kick, and writes the same hashcat file — reusing the CLI's polling and
  writer, without leaving the session. Both paths also clear any BSSID frame
  filter left behind by an earlier `listen`, which would otherwise hide the
  beacons needed for the ESSID.
- **Channel Switch Announcements (`pwn4c csa`)**: spoofs the AP's beacon (or a
  Spectrum Management action frame) with a CSA element to move associated
  clients to another channel — the herd step before an evil twin, and a direct
  test of CSA hardening. The frame builder (`internal/drone/csa.go`) is a pure
  function with unit tests, and shares the RadioTap/management-header helpers
  with the deauth builder. Each announcement carries an incrementing sequence
  number and a countdown so clients do not discard the copies as duplicates;
  `--follow` leaves the radio watching the new channel.
- **Station inventory (`pwn4c clients`)**: the daemon now keeps a bounded
  32-slot table of stations seen on the air — associated clients and
  probe-only ones. A standalone parser (`daemon/client_parse.c`) turns each
  captured frame into an observation: probe request (the station's PNL entry),
  auth/association request, ToDS/FromDS data, and deauth/disassoc (which clears
  the association flag but keeps the station). `daemon/clients.c` tracks the
  BSSID, last RSSI, probed SSID, frame count and first/last-seen timestamps, and
  evicts the station that has been quiet the longest when the table is full.
  `pwn4c clients` prints a table or `--json`, filters with `--bssid`,
  `--assoc-only` and `--min-rssi`, and refreshes with `--watch`.
- **`GET_CLIENTS` control command**: pages through the inventory (six stations
  per page, same 8 KB limit as `GET_HANDSHAKES`), accepts `{"reset":true}`, and
  survives `STOP_MONITOR`. MACs are serialised uppercase; the host normalises
  them for display.
- **Mock and test coverage for the inventory**: mock mode now feeds one
  associated client and one probe-only client, `tests/test_clients.c` covers the
  parser and table (56 assertions across both suites), and
  `internal/drone/clients_test.go` pins the payload decoding and display
  helpers.
- **`clients` in the interactive shell**: menu entry 10 inventories the stations
  around the selected network (or a channel you type) and prints the same table
  as the CLI. The remaining entries shift down by one (`stop` is now 11,
  `reboot` 14).
- **Frame floods (`pwn4c beacon-flood`, `pwn4c auth-flood`)**: pure host-side
  builders in `internal/drone/flood.go` over the existing `SEND_INJECTION`
  path — no daemon change. `beacon-flood` sends beacons with fresh locally
  administered BSSIDs and plausible SSIDs (built-in router-name list plus a
  random suffix, `--ssid`, `--ssid-file`, or `--hidden`) to bury the real
  networks in a client's scan list. `auth-flood` sends Open System
  authentication requests at one BSSID from random source MACs, exhausting the
  AP's client state table; it prints an explicit denial-of-service warning.
  Both accept `--count` (0 = until Ctrl+C), `--duration`, `--interval` and
  `--rate`, and report a live frames-per-second line plus the final injection
  count.
- **`flood` in the interactive shell**: menu entry 11 asks for beacon or auth
  and runs the same loop. The remaining entries shift down again (`stop` is now
  12, `reboot` 15).
- **Evil twin (`pwn4c eviltwin`)**: the drone now runs a rogue access point
  that copies a real network's SSID, BSSID and channel and captures what
  clients send it. The daemon module (`daemon/rogue_ap.c`) adds a second
  virtual interface to the same phy (`iw ... interface add pwn4c-ap type
  __ap`), runs hostapd on it from a generated `/tmp` config, and runs a second
  dnsmasq serving `192.168.66.0/24` on that interface only — so the monitor
  vif keeps capturing on the shared channel, which is what makes the
  kick-and-join flow work. The SSID goes into the config as hex `ssid2` and the
  passphrase is turned into a 64-hex PSK before anything is written, so no
  value is ever interpolated into a shell command or a config file. A WPA2
  twin yields crackable 4-way handshakes when clients join it; an open twin
  (empty passphrase) is for captive-portal style testing only and can never
  produce one. `--kick` sends a broadcast deauth from the real BSSID first so
  associated clients drop, rescan and see the twin; `--duration` bounds the
  session; `-o` writes hashcat mode-22000 lines (default
  `eviltwin.hc22000`) with the same writer `harvest` uses.
- **`START_ROGUE_AP` / `STOP_ROGUE_AP` / `GET_ROGUE_AP` control commands**:
  the daemon validates the SSID (1-32 bytes), a unicast BSSID and the channel
  (1-13) before touching the radio; refuses a second twin (`ALREADY_RUNNING`);
  refuses `SET_CHANNEL` and `HOP_START` while one runs (`ROGUE_AP_ACTIVE`);
  and refuses a twin whose channel differs from the active monitor's, because
  hostapd would silently drag the whole phy — the capture with it — onto the
  twin's channel. `STOP_ROGUE_AP` is idempotent, and `STOP_MONITOR`,
  `RESTORE_NORMAL`, monitor TTL expiry and daemon shutdown all tear the twin
  down too. `GET_ROGUE_AP` reports the SSID, BSSID, channel, security, the
  `pwn4c-ap` interface and IP, the associated-client count (refreshed from
  `iw station dump` at most every 2 s) and whether hostapd and dnsmasq are
  alive. DHCP is a convenience, not a prerequisite: the handshake does not
  care whether dnsmasq started.
- **Mock and test coverage for the twin**: mock mode exercises the full twin
  lifecycle without a radio, `tests/test_rogue_ap.c` covers the hostapd and
  dnsmasq config builders plus the start/stop/report lifecycle (59
  assertions), `internal/drone/rogue_ap_test.go` pins the payload decoding and
  parameter validation, `cmd/pwn4c/cmd/eviltwin_test.go` pins the CLI flag
  validation, and `tests/mock_transcript.sh` asserts the twin end to end
  (start, report, double-start refusal, channel-change refusal, stop
  idempotence, restart).
- **`eviltwin` in the interactive shell**: menu entry 12 twins the selected
  network (or asks for the real AP's BSSID, SSID and channel) with a hidden
  passphrase prompt, the same optional kick and the same hashcat output as the
  CLI. The remaining entries shift down again (`stop` is now 13, `reboot` 16).

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
