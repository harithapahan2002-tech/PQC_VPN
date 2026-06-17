#!/bin/bash
# start.sh — Start VPN server and status page together
#
# Usage:
#   cd pqvpn
#   sudo ./web/start.sh
#
# First run creates a Python venv in web/venv and installs Flask there.
# Subsequent runs reuse the existing venv.
#
# Then:
#   VPN server runs in background, logs to /tmp/vpn_server.log
#   Status page available at http://<server-ip>:8080

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOG_FILE="/tmp/vpn_server.log"
VENV_DIR="$SCRIPT_DIR/venv"

echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  PQ-VPN Startup"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. Run server setup if not already done
if ! sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "= 1"; then
    echo "▶ Running server_setup.sh..."
    sudo "$PROJECT_DIR/server_setup.sh"
fi

# 2. Start vpn_server in background, log to file
echo "▶ Starting vpn_server (log: $LOG_FILE)..."
sudo "$PROJECT_DIR/bin/vpn_server" > "$LOG_FILE" 2>&1 &
VPN_PID=$!
echo "  PID: $VPN_PID"
sleep 2

# 3. Set up Python virtual environment if it doesn't exist
# Modern Debian/Ubuntu (PEP 668) blocks system-wide pip installs,
# so Flask must be installed inside a venv.
if [ ! -d "$VENV_DIR" ]; then
    echo "▶ Creating Python virtual environment..."
    if ! python3 -m venv "$VENV_DIR" 2>/dev/null; then
        echo "  python3-venv not found, installing..."
        sudo apt install -y python3-venv python3-full
        python3 -m venv "$VENV_DIR"
    fi
fi

# 4. Install Flask inside the venv if not already present
if ! "$VENV_DIR/bin/python" -c "import flask" 2>/dev/null; then
    echo "▶ Installing Flask in venv..."
    "$VENV_DIR/bin/pip" install --quiet flask
fi

# 5. Start status page using the venv's Python
echo "▶ Starting status page on port 8080..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "  VPN server  : running (PID $VPN_PID)"
echo "  Status page : http://$(curl -s ifconfig.me 2>/dev/null || echo '<server-ip>'):8080"
echo "  Log file    : $LOG_FILE"
echo ""
echo "  Ctrl+C to stop everything"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Trap Ctrl+C to clean up the server process too
trap "echo ''; echo 'Stopping...'; sudo kill $VPN_PID 2>/dev/null; exit 0" INT

VPN_LOG="$LOG_FILE" "$VENV_DIR/bin/python" "$SCRIPT_DIR/app.py"