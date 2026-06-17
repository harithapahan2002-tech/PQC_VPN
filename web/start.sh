#!/bin/bash
# start.sh — Start VPN server and status page together
#
# Usage:
#   cd pqvpn
#   sudo ./web/start.sh
#
# Then:
#   VPN server runs in background, logs to /tmp/vpn_server.log
#   Status page available at http://<server-ip>:8080

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/tmp/vpn_server.log"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PQ-VPN Startup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Run server setup if not already done
if ! sysctl net.ipv4.ip_forward | grep -q "= 1"; then
    echo "▶ Running server_setup.sh..."
    sudo "$PROJECT_DIR/server_setup.sh"
fi

# 2. Start vpn_server in background, log to file
echo "▶ Starting vpn_server (log: $LOG_FILE)..."
sudo "$PROJECT_DIR/bin/vpn_server" 2>&1 | tee "$LOG_FILE" &
VPN_PID=$!
echo "  PID: $VPN_PID"
sleep 2

# 3. Install Flask if needed
if ! python3 -c "import flask" 2>/dev/null; then
    echo "▶ Installing Flask..."
    pip3 install flask --quiet
fi

# 4. Start status page
echo "▶ Starting status page on port 8080..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  VPN server  : running (PID $VPN_PID)"
echo "  Status page : http://$(curl -s ifconfig.me 2>/dev/null || echo '<server-ip>'):8080"
echo "  Log file    : $LOG_FILE"
echo ""
echo "  Ctrl+C to stop everything"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Trap Ctrl+C to clean up
trap "echo ''; echo 'Stopping...'; sudo kill $VPN_PID 2>/dev/null; exit 0" INT

VPN_LOG="$LOG_FILE" python3 "$SCRIPT_DIR/app.py"
