#!/bin/bash
# daemon/tests/mock_transcript.sh
#
# Demonstrates mock mode end-to-end:
#   1. Build pwn4cd with native gcc
#   2. Start pwn4cd --mock in background
#   3. Send a UDP DISCOVER packet, capture ANNOUNCE response
#   4. Connect TCP, send GET_STATUS command, receive response
#   5. Send START_MONITOR, receive stream datagrams on UDP :5555
#   6. Send STOP_MONITOR, re-enter monitor, send RESTORE_NORMAL (assert normal)
#   7. Send unknown command (expect INVALID_COMMAND), kill daemon, show output
#
# Prerequisites: nc (netcat), bash, sleep, dd (all standard on Linux)
# Run from daemon/ directory.

set -euo pipefail

BINARY=./pwn4cd
LOG=/tmp/pwn4cd_mock_test.log
DISC_PORT=4440
CTRL_PORT=4444
STREAM_PORT=5555

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " pwn4cd --mock transcript"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# ── Step 1: Build ─────────────────────────────────────────────────────────── #
echo "[1] Building pwn4cd (native)..."
make --no-print-directory 2>&1 | tail -5
echo "    Binary: $(ls -lh $BINARY | awk '{print $5, $9}')"
echo ""

# ── Step 2: Start daemon in mock mode ─────────────────────────────────────── #
echo "[2] Starting pwn4cd --mock..."
$BINARY --mock >"$LOG" 2>&1 &
DAEMON_PID=$!
sleep 0.4   # let it bind sockets

echo "    Daemon PID: $DAEMON_PID"
echo ""

# Ensure we kill daemon on exit
trap "kill $DAEMON_PID 2>/dev/null; wait $DAEMON_PID 2>/dev/null; echo ''; echo '[7] Daemon stopped'; cat $LOG" EXIT

# ── Step 3: UDP Discovery ─────────────────────────────────────────────────── #
echo "[3] Sending DISCOVER broadcast to 127.255.255.255:$DISC_PORT..."
DISCOVER_PKT='{"type":"DISCOVER","version":1,"client":"pwn4c","client_version":"0.1.0","timestamp":1694352000}'

# Send discover and capture response (5-second timeout)
ANNOUNCE=$(echo "$DISCOVER_PKT" |
    nc -u -w2 -p 19876 127.0.0.1 $DISC_PORT < <(echo "$DISCOVER_PKT"; sleep 1) \
    2>/dev/null || true)

# Alternative: use Python if nc doesn't work well on this OS
if [ -z "$ANNOUNCE" ]; then
    echo "    Trying Python fallback for UDP..."
    ANNOUNCE=$(python3 - <<'PYEOF'
import socket, json, time

disc = json.dumps({
    "type": "DISCOVER",
    "version": 1,
    "client": "pwn4c",
    "client_version": "0.1.0",
    "timestamp": int(time.time())
}).encode()

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(2.0)
sock.bind(('', 19877))
sock.sendto(disc, ('127.0.0.1', 4440))
try:
    data, addr = sock.recvfrom(4096)
    print(data.decode())
except socket.timeout:
    print('TIMEOUT')
finally:
    sock.close()
PYEOF
)
fi

echo "    ANNOUNCE response:"
echo "    $ANNOUNCE" | python3 -m json.tool 2>/dev/null || echo "    $ANNOUNCE"
echo ""

# ── Step 4: TCP control — GET_STATUS ─────────────────────────────────────── #
echo "[4] Sending GET_STATUS via TCP :$CTRL_PORT..."
STATUS_CMD='{"id":"cmd-001","command":"GET_STATUS","params":{}}'

STATUS_RESP=$(python3 - <<PYEOF
import socket, time, json

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
try:
    s.connect(('127.0.0.1', $CTRL_PORT))
    s.sendall(b'$STATUS_CMD\n')
    time.sleep(0.2)
    data = s.recv(4096)
    print(data.decode().strip())
finally:
    s.close()
PYEOF
)

echo "    GET_STATUS response:"
echo "    $STATUS_RESP" | python3 -m json.tool 2>/dev/null || echo "    $STATUS_RESP"
echo ""

# ── Step 5: START_MONITOR + stream datagrams ──────────────────────────────── #
echo "[5] Sending START_MONITOR + collecting stream datagrams..."
START_CMD='{"id":"cmd-002","command":"START_MONITOR","params":{"channel":6,"ht_mode":"HT20"}}'

python3 - <<PYEOF
import socket, time, json, threading

ctrl = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ctrl.settimeout(5.0)
ctrl.connect(('127.0.0.1', $CTRL_PORT))

# UDP listener for stream
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
udp.bind(('0.0.0.0', $STREAM_PORT))
udp.settimeout(3.0)

# Send START_MONITOR
ctrl.sendall(b'$START_CMD\n')
time.sleep(0.2)
resp = ctrl.recv(4096)
print("    START_MONITOR response:")
try:
    parsed = json.loads(resp.decode().strip())
    print(f"      {json.dumps(parsed, indent=2)}")
except:
    print(f"      {resp.decode().strip()}")

print("")
print("    Receiving stream datagrams (3 seconds)...")
datagrams_rx = 0
try:
    deadline = time.time() + 3.0
    while time.time() < deadline:
        try:
            pkt, addr = udp.recvfrom(65535)
            datagrams_rx += 1
            if datagrams_rx <= 3:
                # Parse stream header (16 bytes, big-endian)
                import struct
                if len(pkt) >= 16:
                    hdr = struct.unpack('!IIHHHH', pkt[:16])
                    seq, ts_us, frag_idx, frag_cnt, frame_len, rsv = hdr
                    payload_len = len(pkt) - 16
                    print(f"      dgram#{datagrams_rx}: seq={seq} ts_us={ts_us} "
                          f"frag={frag_idx+1}/{frag_cnt} frame_len={frame_len} "
                          f"payload_bytes={payload_len}")
        except socket.timeout:
            break
except Exception as e:
    print(f"      recv error: {e}")

print(f"    Total datagrams received: {datagrams_rx}")

# Send STOP_MONITOR
stop_cmd = json.dumps({"id":"cmd-003","command":"STOP_MONITOR","params":{}})
ctrl.sendall((stop_cmd + '\n').encode())
time.sleep(0.2)
stop_resp = ctrl.recv(4096)
print("")
print("    STOP_MONITOR response:")
try:
    parsed = json.loads(stop_resp.decode().strip())
    print(f"      {json.dumps(parsed, indent=2)}")
except:
    print(f"      {stop_resp.decode().strip()}")

# Re-enter monitor, then RESTORE_NORMAL (dual-use escape hatch)
mon2_cmd = json.dumps({"id":"cmd-004","command":"START_MONITOR","params":{"channel":11}})
ctrl.sendall((mon2_cmd + '\n').encode())
time.sleep(0.2)
ctrl.recv(4096)
rest_cmd = json.dumps({"id":"cmd-005","command":"RESTORE_NORMAL","params":{}})
ctrl.sendall((rest_cmd + '\n').encode())
time.sleep(0.2)
rest_resp = ctrl.recv(4096)
print("")
print("    RESTORE_NORMAL response:")
try:
    parsed = json.loads(rest_resp.decode().strip())
    print(f"      {json.dumps(parsed, indent=2)}")
    assert parsed.get("status") == "ok" and parsed.get("data", {}).get("mode") == "normal", "RESTORE_NORMAL failed"
    print("      [assert mode==normal: PASS]")
except AssertionError as e:
    print(f"      ASSERT FAILED: {e}")

ctrl.close()
udp.close()
PYEOF

echo ""

# ── Step 6: Unknown command ───────────────────────────────────────────────── #
echo "[6] Sending unknown command (should return INVALID_COMMAND)..."
UNK_CMD='{"id":"cmd-999","command":"FROBNICATE","params":{}}'

UNK_RESP=$(python3 - <<PYEOF
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(3.0)
s.connect(('127.0.0.1', $CTRL_PORT))
s.sendall(b'$UNK_CMD\n')
time.sleep(0.2)
data = s.recv(4096)
s.close()
print(data.decode().strip())
PYEOF
)
echo "    Unknown cmd response:"
echo "    $UNK_RESP" | python3 -m json.tool 2>/dev/null || echo "    $UNK_RESP"
echo ""

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo " Transcript complete."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
