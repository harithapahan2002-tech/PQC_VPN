#!/bin/bash
# bench_handshake.sh
# Measures real end-to-end VPN handshake time over N connection attempts
# against the live cloud server, with sufficient cooldown between runs
# to avoid the shared-UDP-socket slot-recycling race documented in
# session.c (see SESSION_STATE_TUNNEL_READY barrier).
#
# Usage:
#   ./bench_handshake.sh [server_ip] [num_runs]
#
# Output: handshake_log.txt (raw output) + handshake_results.csv (parsed)

SERVER_IP="${1:-209.97.191.183}"
NUM_RUNS="${2:-20}"
LOG_FILE="handshake_log.txt"
COOLDOWN_SEC=50   # must exceed server idle timeout (45s)   # Longer than the 5s TUNNEL_READY wait + margin

rm -f "$LOG_FILE"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  End-to-End Handshake Benchmark"
echo "  Server: $SERVER_IP   Runs: $NUM_RUNS   Cooldown: ${COOLDOWN_SEC}s"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

for i in $(seq 1 "$NUM_RUNS"); do
    echo "=== Run $i ===" >> "$LOG_FILE"
    echo -n "  Run $i/$NUM_RUNS... "

    START=$(date +%s.%N)
    sudo timeout 10 ./bin/vpn_client --server "$SERVER_IP" >> "$LOG_FILE" 2>&1 &
    CLIENT_PID=$!

    # Let it connect and run briefly, then disconnect cleanly with SIGINT
    # (not SIGTERM/timeout-kill) so the worker thread exits via its
    # normal should_stop path rather than being abruptly killed.
    sleep 3
    sudo kill -INT "$CLIENT_PID" 2>/dev/null
    wait "$CLIENT_PID" 2>/dev/null
    END=$(date +%s.%N)

    if grep -q "Handshake complete" <(tail -50 "$LOG_FILE"); then
        echo "✅ ($(echo "$END - $START" | bc)s)"
    else
        echo "❌ failed"
    fi

    # Cooldown — let the server's session slot fully recycle
    sleep "$COOLDOWN_SEC"
done

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  Done. Raw log: $LOG_FILE"
echo "  Run: python3 parse_handshake_log.py to extract statistics"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
