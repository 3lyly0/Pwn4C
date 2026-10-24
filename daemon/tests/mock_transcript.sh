#!/bin/bash
# daemon/tests/mock_transcript.sh
#
# Demonstrates mock mode end-to-end (including Phase 2, 3, and 4 features):
#   1. Build pwn4cd with native gcc
#   2. Start pwn4cd --mock --psk test-secret-key in background
#   3. Send a UDP DISCOVER packet, capture ANNOUNCE response (verify auth_required=true)
#   4. Connect TCP, verify unauthenticated command returns AUTH_REQUIRED
#   5. Perform GET_CHALLENGE + HMAC-SHA256 AUTH handshake, then send GET_STATUS
#   6. Send START_MONITOR, SET_FILTER, HOP_START, receive 48-bit timestamped datagrams on UDP :5555
#   7. Send HOP_STOP, STOP_MONITOR, RESTORE_NORMAL, and unknown command (expect INVALID_COMMAND)

set -euo pipefail

BINARY=./pwn4cd
LOG=/tmp/pwn4cd_mock_test.log
DISC_PORT=4440
CTRL_PORT=4444
STREAM_PORT=5555
TEST_PSK="pwn4c-phase4-secret"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " pwn4cd --mock end-to-end integration transcript"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Build ─────────────────────────────────────────────────────────── #
echo "[1] Building pwn4cd (native)..."
make --no-print-directory 2>&1 | tail -5
echo "    Binary: $(ls -lh $BINARY | awk '{print $5, $9}')"
echo ""

# ── Step 2: Start daemon in mock mode with PSK enabled ────────────────────── #
echo "[2] Starting pwn4cd --mock --psk $TEST_PSK..."
$BINARY --mock --psk "$TEST_PSK" >"$LOG" 2>&1 &
DAEMON_PID=$!
sleep 0.4   # let it bind sockets

echo "    Daemon PID: $DAEMON_PID"
echo ""

trap "kill $DAEMON_PID 2>/dev/null || true; wait $DAEMON_PID 2>/dev/null || true; echo ''; echo '[8] Daemon stopped'" EXIT

# ── Step 3: UDP Discovery ─────────────────────────────────────────────────── #
echo "[3] Sending DISCOVER broadcast to 127.0.0.1:$DISC_PORT..."
ANNOUNCE=$(python3 - <<'PYEOF'
import socket, json, time

disc = json.dumps({
    "type": "DISCOVER",
    "version": 1,
    "client": "pwn4c",
    "client_version": "1.0.0",
    "timestamp": int(time.time())
}).encode()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.bind(('', 0))
sock.sendto(disc, ('127.0.0.1', 4440))
try:
    data, addr = sock.recvfrom(4096)
    parsed = json.loads(data.decode())
    assert parsed.get("type") == "ANNOUNCE", "Expected ANNOUNCE"
    assert parsed.get("auth_required") is True, "Expected auth_required=True"
    print(json.dumps(parsed, indent=2))
finally:
    sock.close()
PYEOF
)
echo "$ANNOUNCE"
echo "    [assert ANNOUNCE + auth_required==True: PASS]"
echo ""

# ── Step 4 & 5: PSK Auth Handshake + Full Lifecycle ──────────────────────── #
echo "[4] Testing AUTH_REQUIRED guard, HMAC-SHA256 AUTH, Monitor, BPF Filter, Hopper & 48-bit Stream..."
python3 - <<PYEOF
import socket, time, json, hmac, hashlib, struct

ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctrl.settimeout(5.0)
ctrl.connect(('127.0.0.1', $CTRL_PORT))

def send_cmd(cmd_obj):
    ctrl.sendall((json.dumps(cmd_obj) + '\n').encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = ctrl.recv(4096)
        if not chunk:
            break
        buf += chunk
    for line in buf.decode().splitlines():
        msg = json.loads(line)
        if msg.get("event"):
            continue
        return msg

# 4a. Unauthenticated GET_STATUS must fail with AUTH_REQUIRED
unauth = send_cmd({"id": "cmd-0", "command": "GET_STATUS", "params": {}})
assert unauth["status"] == "error" and unauth["error"]["code"] == "AUTH_REQUIRED", f"Expected AUTH_REQUIRED, got {unauth}"
print("    [assert unauthenticated command blocked (AUTH_REQUIRED): PASS]")

# 4b. GET_CHALLENGE + AUTH with HMAC-SHA256
chal = send_cmd({"id": "cmd-1", "command": "GET_CHALLENGE", "params": {}})
assert chal["status"] == "ok", f"GET_CHALLENGE failed: {chal}"
nonce = chal["data"]["nonce"]
sig = hmac.new(b"$TEST_PSK", nonce.encode(), hashlib.sha256).hexdigest()

auth = send_cmd({"id": "cmd-2", "command": "AUTH", "params": {"hmac": sig}})
assert auth["status"] == "ok" and auth["data"]["authenticated"] is True, f"AUTH failed: {auth}"
print(f"    [assert HMAC-SHA256 AUTH succeeded (nonce={nonce[:8]}...): PASS]")

# 5. GET_STATUS
st = send_cmd({"id": "cmd-3", "command": "GET_STATUS", "params": {}})
assert st["status"] == "ok" and "ring_overruns" in st["data"] and "iface_recoveries" in st["data"], f"GET_STATUS invalid: {st}"
print("    [assert GET_STATUS telemetry fields present: PASS]")

# 6. Bind UDP stream receiver & START_MONITOR
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(('0.0.0.0', $STREAM_PORT))
udp.settimeout(3.0)

mon = send_cmd({"id": "cmd-4", "command": "START_MONITOR", "params": {"channel": 6, "ht_mode": "HT20"}})
assert mon["status"] == "ok" and mon["data"]["monitor_active"] is True
print("    [assert START_MONITOR ch=6: PASS]")

# Attach BPF filter (matching mock BSSID 02:00:00:de:ad:01)
flt = send_cmd({"id": "cmd-5", "command": "SET_FILTER", "params": {"mgmt_only": 1, "bssid": "02:00:00:de:ad:01"}})
assert flt["status"] == "ok" and flt["data"]["filter_active"] is True
print("    [assert SET_FILTER (mgmt_only + bssid): PASS]")

# Start autonomous hopping
hop = send_cmd({"id": "cmd-6", "command": "HOP_START", "params": {"channels": [1, 6, 11], "dwell_ms": 100}})
assert hop["status"] == "ok" and hop["data"]["hop_active"] is True
print("    [assert HOP_START ([1,6,11] @ 100ms): PASS]")

# Receive UDP datagrams and verify 16-byte header with 48-bit timestamp
datagrams_rx = 0
deadline = time.time() + 0.6
while time.time() < deadline:
    try:
        pkt, _ = udp.recvfrom(65535)
        datagrams_rx += 1
        seq, ts_lo32, frag_idx, frag_cnt, frame_len, ts_hi16 = struct.unpack('!IIHHHH', pkt[:16])
        ts_us48 = (ts_hi16 << 32) | ts_lo32
        if datagrams_rx <= 2:
            print(f"      dgram#{datagrams_rx}: seq={seq} ts_us48={ts_us48} frag={frag_idx+1}/{frag_cnt} len={frame_len}")
    except socket.timeout:
        break

assert datagrams_rx >= 2, f"Expected >=2 datagrams, got {datagrams_rx}"
print(f"    [assert UDP stream received {datagrams_rx} frames: PASS]")

hop_stop = send_cmd({"id": "cmd-7", "command": "HOP_STOP", "params": {}})
assert hop_stop["status"] == "ok" and hop_stop["data"]["hop_active"] is False
print("    [assert HOP_STOP: PASS]")

stop_mon = send_cmd({"id": "cmd-8", "command": "STOP_MONITOR", "params": {}})
assert stop_mon["status"] == "ok" and stop_mon["data"]["monitor_active"] is False
print("    [assert STOP_MONITOR: PASS]")

rest = send_cmd({"id": "cmd-9", "command": "RESTORE_NORMAL", "params": {}})
assert rest["status"] == "ok" and rest["data"]["mode"] == "normal"
print("    [assert RESTORE_NORMAL: PASS]")

unk = send_cmd({"id": "cmd-10", "command": "FROBNICATE", "params": {}})
assert unk["status"] == "error" and unk["error"]["code"] == "INVALID_COMMAND"
print("    [assert INVALID_COMMAND handling: PASS]")

ctrl.close()
udp.close()
PYEOF

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " All end-to-end integration assertions PASSED."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
