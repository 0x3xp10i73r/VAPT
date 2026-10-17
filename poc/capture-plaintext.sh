#!/usr/bin/env bash
# capture-plaintext.sh - record the cleartext LLM traffic to a .pcap.
#
# Runs tcpdump, drives poc/17-check-plaintext.py against a pinned port, stops the
# capture, and (if tshark is installed) proves the credential is extractable from
# the file you are about to open in Wireshark.
#
#   ./poc/capture-plaintext.sh                    # loopback, port 8899
#   ./poc/capture-plaintext.sh --port 9999 --host 172.20.10.2
#
# Needs tcpdump. On WSL/Linux that is usually `sudo apt install -y tcpdump`; the
# capture itself needs root, which this script requests through sudo.
set -u

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
PORT=8899
HOST=127.0.0.1
OUT="$ROOT/poc/captures/17-plaintext.pcap"
IFACE=""
BIN=""

while [ $# -gt 0 ]; do
    case "$1" in
        --port)  PORT=$2; shift 2 ;;
        --host)  HOST=$2; shift 2 ;;
        --out)   OUT=$2; shift 2 ;;
        --iface) IFACE=$2; shift 2 ;;
        --binary) BIN=$2; shift 2 ;;
        -h|--help)
            sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

# loopback traffic is on 'lo'; anything else needs the interface that owns it
[ -n "$IFACE" ] || { case "$HOST" in 127.*|localhost) IFACE=lo ;; *) IFACE=any ;; esac; }

fail() { echo "ERROR: $*" >&2; exit 2; }

command -v tcpdump >/dev/null 2>&1 || fail "tcpdump not found - sudo apt install -y tcpdump"
[ -x "$ROOT/signal-pyarmor-linux-x86_64" ] || [ -n "$BIN" ] || \
    fail "binary not found at $ROOT/signal-pyarmor-linux-x86_64 (or pass --binary)"
mkdir -p "$(dirname "$OUT")" || fail "cannot create $(dirname "$OUT")"

echo "== checking sudo =="
if ! sudo -n true 2>/dev/null; then
    echo "   sudo needs a password; you will be asked once for tcpdump"
    sudo true || fail "no sudo - capture requires root"
fi

echo "== starting capture on $IFACE (tcp port $PORT) =="
sudo tcpdump -i "$IFACE" -s 0 -U -w "$OUT" "tcp port $PORT" 2>"$OUT.tcpdump.log" &
TCPDUMP_PID=$!
trap 'sudo kill "$TCPDUMP_PID" 2>/dev/null' EXIT INT TERM

# give tcpdump time to open the interface before any traffic exists
for _ in $(seq 1 50); do
    grep -q "listening on" "$OUT.tcpdump.log" 2>/dev/null && break
    kill -0 "$TCPDUMP_PID" 2>/dev/null || { cat "$OUT.tcpdump.log" >&2; fail "tcpdump exited"; }
    sleep 0.1
done
echo "   pid $TCPDUMP_PID -> $OUT"

echo
echo "== driving the PoC at http://$HOST:$PORT/v1 =="
BINARG=""
[ -n "$BIN" ] && BINARG="--binary $BIN"
# shellcheck disable=SC2086
env -u PYTHONHOME -u PYTHONPATH python3 "$HERE/17-check-plaintext.py" \
    --host "$HOST" --port "$PORT" $BINARG
POC_RC=$?

echo
echo "== stopping capture =="
sleep 1
sudo kill -INT "$TCPDUMP_PID" 2>/dev/null
wait "$TCPDUMP_PID" 2>/dev/null
trap - EXIT INT TERM

if [ ! -s "$OUT" ]; then
    rm -f "$OUT.tcpdump.log"
    fail "capture file is empty - did the run reach the network?"
fi
SIZE=$(stat -c%s "$OUT")
echo "   $OUT ($SIZE bytes)"
rm -f "$OUT.tcpdump.log"

echo
echo "== what Wireshark will show =="
if command -v tshark >/dev/null 2>&1; then
    # the traffic is HTTP on a non-standard port, so tell tshark to decode it
    tshark -r "$OUT" -d "tcp.port==$PORT,http" -Y http.request \
        -T fields -e frame.number -e ip.src -e ip.dst \
        -e http.request.method -e http.request.uri -e http.authorization \
        2>/dev/null | sed 's/^/   /'
    echo
    echo "   credential lines:"
    tshark -r "$OUT" -d "tcp.port==$PORT,http" -Y 'http.authorization' \
        -T fields -e http.authorization 2>/dev/null | sort | uniq -c | sed 's/^/   /'
    if tshark -r "$OUT" -d "tcp.port==$PORT,http" -Y 'http.authorization contains "Bearer"' \
            -T fields -e frame.number 2>/dev/null | grep -q .; then
        echo "   PASS - an Authorization header is readable in the capture"
    else
        echo "   NOTE - no Authorization header decoded; check the port filter"
    fi
else
    echo "   tshark not installed - open the file and follow the steps below"
fi

cat <<EOF

== open it in Wireshark ==
   wireshark "$OUT"

   1. Display filter:            tcp.port == $PORT
   2. If packets show as plain TCP (grey, "TCP segment of a reassembled PDU"):
      right-click one -> Decode As... -> set the TCP port $PORT row to HTTP.
      Wireshark only auto-detects HTTP on well-known ports, so this step is
      normal for a custom port.
   3. Now filter:                http.request
   4. Right-click a request -> Follow -> HTTP Stream.
      The request headers, including "Authorization: Bearer ..." and the JSON
      body, are in the top pane in clear text - no decryption, no keys.
   5. Prove there is no TLS:     tls.handshake
      That should match zero packets. The stream starts with "POST /v1/...
      HTTP/1.1" as the first application bytes.

== save the evidence ==
   File -> Export Specified Packets... -> All packets -> save as .pcapng
   Then in the report: File -> Export As -> Plain Text -> the packet list, or
   screenshot the Follow HTTP Stream window with the Authorization header visible.

   The token in this capture is the canary CANARY_PLAINTEXT_9f31c2, so the file
   contains no real credential. Check that before attaching it to a report if you
   change the config.
EOF

exit $POC_RC
