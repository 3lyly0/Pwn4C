# API Reference: Wire Protocol Specification

All communication between the Host (`pwn4c`) and the Drone (`pwn4cd`) occurs over three network channels on a direct Ethernet link.

---

## UDP Autodiscovery Protocol

**Port:** 4440 (UDP)
**Direction:** Host -> Drone (broadcast), Drone -> Host (unicast response)

### Discovery Request

The Host sends this packet from a socket bound to each usable IPv4 interface
address, to both the subnet-directed broadcast (e.g. `192.168.4.255:4440`) and
the limited broadcast `255.255.255.255:4440`. The Drone replies unicast to the
source address and port it observed.

> Binding one socket per interface (instead of a single `0.0.0.0` socket) is
> required on multi-homed hosts: a packet sent to `255.255.255.255` from a
> wildcard socket egresses the lowest-metric interface, which is often a
> Hyper-V/WSL/VMware adapter rather than the LAN port.

```json
{
  "type": "DISCOVER",
  "version": 1,
  "client": "pwn4c",
  "client_version": "0.1.0",
  "timestamp": 1694352000
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `type` | string | Yes | Must be `"DISCOVER"` |
| `version` | integer | Yes | Protocol version. Current: `1` |
| `client` | string | Yes | Client identifier string |
| `client_version` | string | Yes | Semantic version of the client |
| `timestamp` | integer | Yes | Unix epoch seconds (UTC) at send time |

### Discovery Response (Announce)

The Drone responds with a unicast UDP packet to the Host's source IP and port.

```json
{
  "type": "ANNOUNCE",
  "version": 1,
  "drone_id": "pwn4c-a3f7",
  "firmware_version": "0.1.0",
  "hardware": "mi4c-mt7628n",
  "uptime_seconds": 127,
  "capabilities": ["monitor", "inject", "channel_hop"],
  "radio": {
    "chipset": "MT7628N",
    "band": "2.4GHz",
    "channels": [1,2,3,4,5,6,7,8,9,10,11,12,13],
    "max_tx_power_dbm": 20,
    "state": "idle"
  },
  "control_port": 4444,
  "stream_port": 5555
}
```

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Always `"ANNOUNCE"` |
| `version` | integer | Protocol version (must match request) |
| `drone_id` | string | Unique identifier derived from MAC address |
| `firmware_version` | string | Semantic version of the Drone firmware |
| `hardware` | string | Hardware platform identifier |
| `uptime_seconds` | integer | Seconds since `pwn4cd` started |
| `capabilities` | string[] | Supported feature set |
| `radio.chipset` | string | Radio hardware identifier |
| `radio.band` | string | Operating frequency band |
| `radio.channels` | integer[] | Available channels (regulatory domain dependent) |
| `radio.max_tx_power_dbm` | integer | Maximum transmit power in dBm |
| `radio.state` | string | Current radio state: `"idle"`, `"monitor"`, `"injecting"` |
| `control_port` | integer | TCP port for the control channel |
| `stream_port` | integer | UDP port for the frame stream |

### Error Response

If the protocol version is unsupported:

```json
{
  "type": "ERROR",
  "code": "VERSION_MISMATCH",
  "message": "Unsupported protocol version: 2. Supported: [1]"
}
```

### Timing

- The Host sends up to 3 discovery rounds, 50 ms apart, to every interface.
- The Drone must respond within 500 ms of receiving a `DISCOVER` packet.
- If no response arrives before the timeout, the Host reports that no drones were discovered.

---

## TCP Control Protocol

**Port:** 4444 (TCP)
**Framing:** Newline-delimited JSON (each message is a UTF-8 JSON object terminated by `\n`, byte `0x0A`)
**Connection:** Single client only. The Drone accepts one TCP connection; additional connections are refused with `ECONNREFUSED`.

### Message Envelope

**Command (Host -> Drone):**

```json
{
  "id": "cmd-001",
  "command": "COMMAND_NAME",
  "params": { }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Client-assigned unique command ID for correlation |
| `command` | string | Command name (see catalog below) |
| `params` | object | Command-specific parameters (may be empty `{}`) |

**Response (Drone -> Host):**

```json
{
  "id": "cmd-001",
  "status": "ok",
  "data": { }
}
```

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Echoes the command `id` for correlation |
| `status` | string | `"ok"` or `"error"` |
| `data` | object | Response payload (command-specific) |
| `error` | object | Present only when `status` is `"error"` (see Error Codes) |

**Async Event (Drone -> Host):**

```json
{
  "id": null,
  "event": "EVENT_NAME",
  "data": { }
}
```

Events have a `null` id and an `event` field instead of `command`.

---

### Command Catalog

#### `GET_STATUS`

Returns the current operational state of the Drone.

**Request:**

```json
{
  "id": "cmd-001",
  "command": "GET_STATUS",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-001",
  "status": "ok",
  "data": {
    "state": "idle",
    "channel": 1,
    "ap_channel": 1,
    "sta_channel": 0,
    "ap_iface": "phy0-ap0",
    "sta_iface": "phy0-sta0",
    "mac": "02:11:22:33:44:55",
    "tx_power_dbm": 14,
    "monitor_active": false,
    "monitor_persist": false,
    "monitor_ttl_sec": 0,
    "tx_queue_depth": 0,
    "tx_queue_max": 256,
    "uptime_seconds": 342,
    "cpu_temp_celsius": 52,
    "free_ram_bytes": 50593792,
    "firmware_version": "1.4.0",
    "drone_id": "pwn4c-a3f7",
    "rx_frames": 12054,
    "tx_frames": 11980,
    "inject_frames": 450,
    "inject_requested": 460,
    "inject_dropped": 0,
    "ring_overruns": 0,
    "inject_failures": 0,
    "kernel_drops": 0
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `state` | string | `"idle"` or `"monitor"` |
| `channel` | integer | Monitor channel (the last selected channel while idle) |
| `ap_channel` | integer | Channel the AP netdev currently uses (read from the driver, 0 if down) |
| `sta_channel` | integer | Channel the station netdev currently uses (0 when not associated) |
| `ap_iface` | string | Detected AP netdev name (`phy0-ap0`, or `wlan0` on older images) |
| `sta_iface` | string | Detected station netdev name |
| `mac` | string | MAC address read back from the radio |
| `tx_power_dbm` | integer | TX power the driver reports, not the last value requested |
| `monitor_active` | boolean | Whether monitor mode is enabled |
| `monitor_persist` | boolean | Monitor keeps running after the control client disconnects |
| `monitor_ttl_sec` | integer | Configured daemon-side capture lifetime (0 = unlimited) |
| `tx_queue_depth` | integer | Frames currently queued for injection |
| `tx_queue_max` | integer | Maximum TX queue capacity (256) |
| `uptime_seconds` | integer | Daemon uptime |
| `cpu_temp_celsius` | integer | SoC die temperature |
| `free_ram_bytes` | integer | Available system memory |
| `firmware_version` | string | Running firmware version |
| `drone_id` | string | Drone identifier |
| `rx_frames` | integer | Total frames captured into the ring buffer |
| `tx_frames` | integer | Total frames successfully drained and streamed over UDP (legacy name: this is the stream sequence, not injections) |
| `inject_frames` | integer | Cumulative frames the driver accepted for injection (firmware v1.3.3+) |
| `inject_requested` | integer | Cumulative frames the CLI asked to inject |
| `inject_dropped` | integer | Cumulative frames the TX ring refused (queue full) |
| `ring_overruns` | integer | Frames dropped due to ring buffer saturation |
| `inject_failures` | integer | Number of raw 802.11 injection failures |
| `kernel_drops` | integer | Dropped frames reported by Linux socket `PACKET_STATISTICS` |

---

#### `START_MONITOR`

Places the radio into monitor mode and begins streaming captured frames to the Host.

**Request:**

```json
{
  "id": "cmd-002",
  "command": "START_MONITOR",
  "params": {
    "channel": 6,
    "ht_mode": "HT20"
  }
}
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `channel` | integer | No | 1 | Channel to monitor (1-13) |
| `ht_mode` | string | No | `"HT20"` | Channel width. Only `"HT20"` is supported |
| `persist` | boolean | No | false | Keep capturing after the control client disconnects |
| `ttl_sec` | integer | No | 0 | Daemon-side capture deadline in seconds (0 = unlimited) |

**Response:**

```json
{
  "id": "cmd-002",
  "status": "ok",
  "data": {
    "monitor_active": true,
    "channel": 6,
    "persist": false,
    "ttl_sec": 0,
    "stream_target": "192.168.4.10:5555"
  }
}
```

The Drone resolves the Host's IP from the TCP connection's peer address and begins sending UDP frames to port 5555 on that address.

Without `persist`, a client disconnect tears the monitor interface down and restores the radio. With `persist`, the capture survives reconnects (for example after a Wi-Fi roam on the control path); `ttl_sec` bounds that survival so the radio is never left in monitor mode indefinitely.

**Errors:**
- `ALREADY_MONITORING`: Monitor mode is already active. Send `STOP_MONITOR` first.
- `INVALID_CHANNEL`: Channel outside the allowed range.
- `INTERFACE_ERROR`: Failed to configure the wireless interface.

---

#### `STOP_MONITOR`

Stops monitor mode and halts the frame stream.

**Request:**

```json
{
  "id": "cmd-003",
  "command": "STOP_MONITOR",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-003",
  "status": "ok",
  "data": {
    "monitor_active": false,
    "frames_captured": 48201,
    "frames_dropped": 12
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `frames_captured` | integer | Total frames captured during the session |
| `frames_dropped` | integer | Frames dropped due to ring buffer overflow |

---

#### `RESTORE_NORMAL` (Pwn4C extension)

One-command path back to regular networking (dual-use escape hatch). Stops
monitor/injection if active, then re-enables the managed/AP radio via the
untouched UCI wireless profile. Works from any state, including while
monitoring — the box is always recoverable to normal internet use without
serial access.

**Request:**

```json
{
  "id": "cmd-004",
  "command": "RESTORE_NORMAL",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-004",
  "status": "ok",
  "data": {
    "mode": "normal",
    "monitor_active": false
  }
}
```

---

#### `SET_CHANNEL`

Switches the radio to a different channel while monitor mode is active.

**Request:**

```json
{
  "id": "cmd-004",
  "command": "SET_CHANNEL",
  "params": {
    "channel": 11
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `channel` | integer | Yes | Target channel (1-13) |

**Response:**

```json
{
  "id": "cmd-004",
  "status": "ok",
  "data": {
    "channel": 11,
    "switch_time_ms": 7
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `channel` | integer | Confirmed active channel |
| `switch_time_ms` | integer | Time taken for the channel switch (milliseconds) |

**Errors:**
- `NOT_MONITORING`: Monitor mode is not active.
- `INVALID_CHANNEL`: Channel out of range.

---

#### `HOP_START`

Starts autonomous channel hopping directly inside the daemon event loop without requiring host-side control polling.

**Request:**

```json
{
  "id": "cmd-005",
  "command": "HOP_START",
  "params": {
    "channels": [1, 6, 11],
    "dwell_ms": 250
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `channels` | integer[] | No | Array of channels (1-13) to cycle through (defaults to 1-13) |
| `dwell_ms` | integer | No | Time to dwell on each channel in milliseconds (default: 250) |

**Response:**

```json
{
  "id": "cmd-005",
  "status": "ok",
  "data": {
    "hop_active": true,
    "dwell_ms": 250,
    "channel_count": 3,
    "current_channel": 1
  }
}
```

---

#### `HOP_STOP`

Stops autonomous channel hopping on the drone.

**Request:**

```json
{
  "id": "cmd-006",
  "command": "HOP_STOP",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-006",
  "status": "ok",
  "data": {
    "hop_active": false,
    "channel": 1
  }
}
```

---

#### `SET_FILTER`

Attaches a classic BPF bytecode filter to the packet capture socket (`SO_ATTACH_FILTER`) to filter by frame type and/or target BSSID in the Linux kernel before packets enter userspace.

**Request:**

```json
{
  "id": "cmd-007",
  "command": "SET_FILTER",
  "params": {
    "mgmt_only": true,
    "bssid": "00:11:22:33:44:55"
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mgmt_only` | boolean | No | Pass only 802.11 management frames (beacons, probe req/resp, deauth) |
| `bssid` | string | No | Filter frames matching specified BSSID MAC address |
| `reset` | boolean | No | When true, detaches BPF filter and accepts all frames |

**Response:**

```json
{
  "id": "cmd-007",
  "status": "ok",
  "data": {
    "filter_active": true,
    "mgmt_only": true,
    "bssid_filtered": true
  }
}
```

---

#### `SEND_INJECTION`

Transmits a raw 802.11 frame on the current channel.

**Request:**

```json
{
  "id": "cmd-005",
  "command": "SEND_INJECTION",
  "params": {
    "frame_hex": "000010001e000000000202a00400001000c0000000...",
    "count": 5,
    "interval_ms": 10,
    "rate_mbps": 1
  }
}
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `frame_hex` | string | Yes | - | Complete 802.11 frame with a full RadioTap header, hex-encoded |
| `count` | integer | No | 1 | Number of times to transmit the frame |
| `interval_ms` | integer | No | 0 | Delay between repeated transmissions (milliseconds) |
| `rate_mbps` | integer | No | 1 | PHY TX rate in Mbps (1, 2, 5, 6, 9, 11, 12, 18, 24, 36, 48, 54) |

The frame must carry the fields mt76 needs to transmit it: a 16-byte
RadioTap header with Flags, Rate, Channel and TX flags. An 8-byte header with
an empty present bitmap is accepted by the driver and silently never reaches
the air.

**Response:**

```json
{
  "id": "cmd-005",
  "status": "ok",
  "data": {
    "frames_requested": 5,
    "frames_queued": 5,
    "frames_sent": 2,
    "frames_failed": 0,
    "frames_pending": 3,
    "tx_queue_depth": 3,
    "tx_queue_max": 256
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `frames_requested` | integer | Frames the caller asked for |
| `frames_queued` | integer | Frames accepted into the paced TX ring |
| `frames_sent` | integer | Frames that already left the driver synchronously |
| `frames_failed` | integer | Frames the ring refused (queue full) |
| `frames_pending` | integer | Frames still queued when the response was written |
| `tx_queue_depth` | integer | Current ring depth |
| `tx_queue_max` | integer | Ring capacity (256 frames) |

`frames_requested == frames_queued + frames_failed`, and queued frames leave the
air over the next `interval_ms * frames_queued` milliseconds. A shortfall is
always reported; the queue no longer drops silently above 64 frames.

**Errors:**
- `NOT_MONITORING`: Monitor mode must be active for injection.
- `INVALID_FRAME`: Frame data is malformed or too short.
- `TX_QUEUE_FULL`: TX queue saturated after retries.

---

#### `SET_TX_POWER`

Adjusts the transmit power of the radio.

**Request:**

```json
{
  "id": "cmd-006",
  "command": "SET_TX_POWER",
  "params": {
    "power_dbm": 15
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `power_dbm` | integer | Yes | TX power in dBm (1-20) |

**Response:**

```json
{
  "id": "cmd-006",
  "status": "ok",
  "data": {
    "power_dbm": 14,
    "requested_dbm": 20,
    "clamped": true,
    "persisted": true
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `power_dbm` | integer | TX power the driver actually reports |
| `requested_dbm` | integer | Value the caller asked for |
| `clamped` | boolean | True when the PA/driver capped the request |
| `persisted` | boolean | Value written to UCI and re-applied at boot |

The MT7628 PA typically clamps at 14-15 dBm; requesting 20 dBm now reports
the clamp instead of claiming success.

**Errors:**
- `INVALID_POWER`: Value outside 1-20 dBm range.

---

#### `SET_MAC`

Sets a specific MAC address on the monitor interface, or randomizes it.

**Request:**

```json
{
  "id": "cmd-007",
  "command": "SET_MAC",
  "params": {
    "mac": "AA:BB:CC:DD:EE:FF"
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `mac` | string | No | MAC address in `XX:XX:XX:XX:XX:XX` format. Omit for random generation (locally-administered bit set) |

**Response:**

```json
{
  "id": "cmd-007",
  "status": "ok",
  "data": {
    "mac": "AA:BB:CC:DD:EE:FF",
    "requested_mac": "AA:BB:CC:DD:EE:FF",
    "applied": true,
    "persisted": true
  }
}
```

| Response Field | Type | Description |
|----------------|------|-------------|
| `mac` | string | Address read back from the driver after the change |
| `requested_mac` | string | Address that was requested (generated when omitted) |
| `applied` | boolean | False when the driver kept a different address |
| `persisted` | boolean | Address written to UCI and re-applied at boot |

The change is applied while the radio is down, then read back, so a driver that
silently rejects the address no longer makes the CLI print a success message.

**Errors:**
- `MONITORING_ACTIVE`: MAC cannot be changed while monitor mode is active. Stop monitoring first.
- `INVALID_MAC`: Malformed MAC address string.

---

#### `REBOOT`

Reboots the Drone. The TCP connection will be dropped. The Host must re-discover after reboot.

**Request:**

```json
{
  "id": "cmd-008",
  "command": "REBOOT",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-008",
  "status": "ok",
  "data": {
    "message": "Rebooting in 2 seconds"
  }
}
```

The Drone sends the response, waits 2 seconds, then executes `reboot`.

---

#### `GET_DIAGNOSTICS`

Returns detailed system diagnostics for debugging.

**Request:**

```json
{
  "id": "cmd-009",
  "command": "GET_DIAGNOSTICS",
  "params": {}
}
```

**Response:**

```json
{
  "id": "cmd-009",
  "status": "ok",
  "data": {
    "kernel_version": "5.15.134",
    "uptime_seconds": 3847,
    "load_average": [0.12, 0.08, 0.03],
    "memory": {
      "total_bytes": 67108864,
      "free_bytes": 50593792,
      "buffers_bytes": 2097152
    },
    "flash": {
      "rootfs_bytes_used": 2752512,
      "overlay_bytes_used": 81920,
      "overlay_bytes_free": 10321920
    },
    "network": {
      "eth0_rx_bytes": 48291,
      "eth0_tx_bytes": 1293847,
      "eth0_link_speed": "100Mbps"
    },
    "wireless": {
      "interface": "ra0",
      "driver": "mt76",
      "mode": "monitor",
      "channel": 6,
      "noise_dbm": -95,
      "rx_frames_total": 192847,
      "tx_frames_total": 450
    }
  }
}
```

---

#### `WIFI_SCAN` (Pwn4C extension)

Surveys nearby access points from the monitor radio without touching the
managed wireless stack. The daemon reuses an active monitor session when one
exists (sweeping channels only when the autonomous hopper is idle), otherwise
it enters monitor mode, sweeps channels 1-13, and restores the previous radio
state. The response blocks until the sweep completes.

**Request:**

```json
{
  "id": "cmd-010",
  "command": "WIFI_SCAN",
  "params": {
    "dwell_ms": 4000
  }
}
```

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `dwell_ms` | integer | No | 4000 | Sweep duration, clamped to 1000-15000 ms |

**Response:**

```json
{
  "id": "cmd-010",
  "status": "ok",
  "data": {
    "count": 2,
    "dwell_ms": 4000,
    "networks": [
      {"ssid": "MyNetwork", "bssid": "aa:bb:cc:dd:ee:ff", "channel": 11,
       "signal_dbm": -52, "hidden": false,
       "wps": true, "wps_state": 2, "wps_dp_id": 0, "wps_config_methods": 148, "wps_locked": false},
      {"ssid": "", "bssid": "11:22:33:44:55:66", "channel": 6,
       "signal_dbm": -55, "hidden": true, "ssid_len": 8}
    ]
  }
}
```

Networks are deduplicated by BSSID and sorted by signal strength (strongest
first). Hidden networks carry `"hidden": true`; `ssid_len` reports the
advertised SSID length when the AP broadcasts a blanked IE with its real size
(omit when unknown).

APs advertising WPS add `wps`, `wps_state` (1 = not configured, 2 =
configured), `wps_dp_id` (device-password id, 0 = PIN), `wps_config_methods`
(the WSC bitmap) and `wps_locked`. The fields are omitted entirely when the
beacon has no WSC information element.

---

#### `WIFI_CONNECT` (Pwn4C extension)

Joins the drone to an upstream Wi-Fi network through the Pwn4C-owned
`pwn4c_sta` UCI profile (station mode, riding the `wan` interface). Monitor
mode and station mode are mutually exclusive on the single radio; an active
monitor session is torn down first.

**Request:**

```json
{
  "id": "cmd-011",
  "command": "WIFI_CONNECT",
  "params": {
    "ssid": "MyNetwork",
    "psk": "wireless-password",
    "bssid": "AA:BB:CC:DD:EE:FF",
    "encryption": "psk2",
    "mac": "02:11:22:33:44:55",
    "share": true
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `ssid` | string | Yes | Network name (1-32 characters) |
| `psk` | string | No | WPA passphrase (8-63 chars) or a 64-hex PSK. Omit or empty = open network |
| `bssid` | string | No | Pin a specific AP |
| `encryption` | string | No | Override UCI encryption: `psk2` (default), `psk`, `psk-mixed`, `sae`, `sae-mixed` |
| `mac` | string | No | Station MAC written to the `pwn4c_sta` profile; netifd applies it when the vif is created |
| `share` | boolean | No | NAT `192.168.4.0/24` behind the station link so LAN hosts reach the internet. Default `true`; a daemon older than v1.4.0 ignores it |

**Response:** `{"connecting": true, "ssid": "MyNetwork", "share": true}` —
association completes asynchronously; poll `WIFI_STATUS`.

The station netdev is resolved at runtime (`phy0-sta0` on OpenWrt 23.05,
`wlan0` on older images) instead of being hardcoded.

The stock AP profile is never modified — only its `disabled` flag is toggled
while the station is up.

With `share` the daemon runs `/usr/lib/pwn4c/share.sh on <sta_iface>` after
writing the profile. The image ships without `firewall4`, so there is no zone
model: the script installs one nftables table with a postrouting `masquerade`
on the station netdev and an MSS clamp. `WIFI_DISCONNECT` removes it. Sharing is
not persistent across a reboot, because `pwn4c-radio` returns the radio to the
boot-safe DOWN state on every boot.

---

#### `WIFI_STATUS` (Pwn4C extension)

Reports the drone's upstream station link.

**Response data:**

```json
{
  "connected": true,
  "associated": true,
  "ssid": "MyNetwork",
  "bssid": "AA:BB:CC:DD:EE:FF",
  "ip": "192.168.1.44",
  "channel": 6,
  "mode": "sta",
  "iface": "phy0-sta0",
  "state": "connected",
  "error": "",
  "error_detail": "",
  "wpa_state": "COMPLETED",
  "sharing": true
}
```

| Field | Meaning |
|-------|---------|
| `connected` | WPA 4-way handshake completed (or, on images without `wpa-cli`, an address was leased) |
| `associated` | 802.11 association exists; authentication may still be in progress |
| `iface` | Station netdev resolved at runtime |
| `state` | `connected`, `dhcp` (key accepted, no lease yet), `associating`, `auth_failed`, `connect_failed`, `disconnected` |
| `error` | `auth_failed` when the AP rejected the key; `connect_failed` for association/timeout problems |
| `error_detail` | Raw supplicant reason (`WRONG_KEY`, `CONN_FAILED`, ...) parsed from `CTRL-EVENT-SSID-TEMP-DISABLED` |
| `wpa_state` | Raw `wpa_cli status` state (`COMPLETED`, `4WAY_HANDSHAKE`, ...) when available |
| `sharing` | `true` when the LAN is NATed behind the station link (firmware v1.4.0+; absent on older images) |

`[TEMP-DISABLED]` in `list_networks` only says the supplicant gave up; it is
set for a rejected key *and* for ordinary association failures. The daemon
reads the `reason=` field from `logread` so a correct password is no longer
reported as `auth_failed`.

Because `connected` is set from `wpa_state=COMPLETED`, a bare association no
longer looks like a successful join. Callers that need end-to-end
connectivity must also wait for a non-empty `ip`.

The daemon derives a 64-hex PSK from the passphrase for `psk`/`psk2`, so
special characters in the key never traverse the UCI/supplicant config
parser.

---

#### `WIFI_DISCONNECT` (Pwn4C extension)

Removes the `pwn4c_sta` profile and returns the radio to the boot-safe DOWN
state. **Response data:** `{"connected": false, "mode": "down"}`.

---

#### `UPGRADE` (Pwn4C extension)

Verified over-the-air firmware update. The Host serves the sysupgrade image
on a temporary HTTP server; the daemon downloads it, verifies the size and
SHA-256, and only then launches `sysupgrade` in a detached session. The drone
reboots right after the response is delivered — the TCP connection drops.

**Request:**

```json
{
  "id": "cmd-012",
  "command": "UPGRADE",
  "params": {
    "url": "http://192.168.4.10:43111/image",
    "size": 5571371,
    "sha256": "6f4723750cdebfe452994e2724c0f1e9ba91011874433278d1b2b77ee9e6c5f8"
  }
}
```

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `url` | string | Yes | `http://` URL served by the Host (<= 200 chars) |
| `size` | integer | Yes | Exact image size in bytes (512KB-8MB) |
| `sha256` | string | Yes | 64 hex chars; mismatch aborts before flashing |

**Response data:**

```json
{"message": "image verified; flashing now — the drone will reboot into the new firmware", "rebooting": true}
```

**Errors:** `INVALID_PARAMS`, `INTERNAL_ERROR` (no `/tmp` headroom),
`UPGRADE_DOWNLOAD_FAILED`, `UPGRADE_VERIFY_FAILED` (size or checksum
mismatch — the image is never flashed).

---

### Async Events

Events are pushed from the Drone without a preceding command. They always have `"id": null`.

#### `BUFFER_OVERFLOW`

The capture ring buffer is full; frames are being dropped.

```json
{
  "id": null,
  "event": "BUFFER_OVERFLOW",
  "data": {
    "dropped_frames": 37,
    "buffer_size_bytes": 65536,
    "channel": 6
  }
}
```

#### `LINK_DOWN`

The Ethernet link has gone down. The Drone stops streaming and returns to idle after a 5-second grace period.

```json
{
  "id": null,
  "event": "LINK_DOWN",
  "data": {
    "interface": "eth0",
    "last_seen_seconds_ago": 2
  }
}
```

#### `INTERFACE_ERROR`

A wireless interface operation failed unexpectedly.

```json
{
  "id": null,
  "event": "INTERFACE_ERROR",
  "data": {
    "operation": "channel_switch",
    "error": "iw returned exit code 234",
    "interface": "ra0"
  }
}
```

---

### Error Codes

All error responses use this structure:

```json
{
  "id": "cmd-005",
  "status": "error",
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable description"
  }
}
```

| Code | HTTP Analogy | Description |
|------|--------------|-------------|
| `VERSION_MISMATCH` | 400 | Protocol version not supported |
| `INVALID_COMMAND` | 400 | Unrecognized command name |
| `INVALID_PARAMS` | 400 | Missing or malformed parameters |
| `INVALID_CHANNEL` | 400 | Channel number outside allowed range |
| `INVALID_FRAME` | 400 | Injection frame data is malformed |
| `INVALID_POWER` | 400 | TX power outside 1-20 dBm |
| `INVALID_MAC` | 400 | Malformed MAC address |
| `NOT_MONITORING` | 409 | Command requires active monitor mode |
| `ALREADY_MONITORING` | 409 | Monitor mode is already active |
| `MONITORING_ACTIVE` | 409 | Operation blocked while monitoring |
| `TX_QUEUE_FULL` | 503 | Injection TX queue saturated |
| `INTERFACE_ERROR` | 500 | Wireless interface operation failed |
| `INTERNAL_ERROR` | 500 | Unexpected daemon error |

---

## UDP Frame Stream Format

**Port:** 5555 (UDP)
**Direction:** Drone -> Host (unidirectional)
**Activation:** Begins after `START_MONITOR` succeeds; stops on `STOP_MONITOR` or TCP disconnect

### Datagram Layout

Each UDP datagram contains exactly one captured frame (or one fragment of a large frame):

```
 0                   1                   2                   3
 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                       Sequence Number                         |  Bytes 0-3
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Timestamp (microseconds)                   |  Bytes 4-7
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Fragment Index          |       Fragment Count          |  Bytes 8-11
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|       Frame Length            |    Timestamp Hi16 (48-bit ts)  |  Bytes 12-15
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                                                               |
|              Payload: RadioTap Header + 802.11 Frame          |
|                        (variable length)                      |
|                                                               |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

### Stream Header Fields (16 bytes, network byte order / big-endian)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0 | 4 bytes | `sequence_number` | Monotonically increasing 32-bit counter. Wraps at 2^32. Used for drop detection. |
| 4 | 4 bytes | `timestamp_lo32` | Lower 32 bits of a 48-bit µs timestamp since `START_MONITOR`. Combine with `timestamp_hi16` (bytes 14-15) for full 48-bit precision. |
| 8 | 2 bytes | `fragment_index` | 0-based fragment index. `0` for unfragmented frames. |
| 10 | 2 bytes | `fragment_count` | Total fragments for this frame. `1` for unfragmented frames. |
| 12 | 2 bytes | `frame_length` | Total reassembled frame length in bytes (not fragment payload length). |
| 14 | 2 bytes | `timestamp_hi16` | Upper 16 bits of the 48-bit µs timestamp (bytes 14-15). Combined with `timestamp_lo32` (bytes 4-7) to form a 48-bit µs counter: `(timestamp_hi16 << 32) | timestamp_lo32`. No rollover for ~8.9 years. |

### Fragmentation

Frames exceeding the maximum payload size per datagram are split across multiple datagrams. Maximum payload per datagram: **1472 bytes** (1500 byte Ethernet MTU minus 20 byte IP header minus 8 byte UDP header).

- Fragments share the same `sequence_number`.
- `fragment_index` ranges from `0` to `fragment_count - 1`.
- The Host reassembles by buffering until all `fragment_count` fragments for a given `sequence_number` arrive.
- If any fragment is missing after 100 ms, the entire frame is discarded.

### Payload: RadioTap + 802.11

The payload following the 16-byte stream header is a standard RadioTap-encapsulated 802.11 frame:

```
+-------------------+---------------------------+
| RadioTap Header   | 802.11 Frame              |
| (variable, >=8 B) | (management/control/data) |
+-------------------+---------------------------+
```

**RadioTap fields present** (as provided by `kmod-mt76`):

| RadioTap Field | Size | Description |
|----------------|------|-------------|
| `TSFT` | 8 bytes | Timer synchronization function timer (us) |
| `Flags` | 1 byte | Frame flags (FCS present, short preamble, etc.) |
| `Rate` | 1 byte | Data rate in 500 Kbps units |
| `Channel` | 4 bytes | Frequency (MHz) + channel flags |
| `dBm Antenna Signal` | 1 byte | RF signal power in dBm |
| `dBm Antenna Noise` | 1 byte | RF noise floor in dBm |
| `Antenna` | 1 byte | Antenna index |

The Host can write these payloads directly into a PCAP file with linktype `DLT_IEEE802_11_RADIO` (127) for analysis with Wireshark, `tshark`, or `tcpdump`.

### PCAP File Construction

To build a valid PCAP file from the stream, the Host writes:

1. **Global PCAP Header** (24 bytes):

| Field | Value |
|-------|-------|
| Magic Number | `0xA1B2C3D4` (native byte order) |
| Version Major | 2 |
| Version Minor | 4 |
| Timezone | 0 (UTC) |
| Sigfigs | 0 |
| Snaplen | 65535 |
| Link Type | 127 (`DLT_IEEE802_11_RADIO`) |

2. **Per-frame Record Header** (16 bytes per frame):

| Field | Source |
|-------|--------|
| Timestamp seconds | `timestamp_us / 1,000,000` + capture start epoch |
| Timestamp microseconds | `timestamp_us % 1,000,000` |
| Captured length | Payload size after reassembly |
| Original length | `frame_length` from stream header |

3. **Frame data**: The reassembled RadioTap + 802.11 payload.
