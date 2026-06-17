#!/usr/bin/env python3
# app.py
# PQ-VPN Web Status Page
# Parses vpn_server log output and serves a live status dashboard.
#
# Usage:
#   # Start vpn_server with log output
#   sudo ./bin/vpn_server 2>&1 | tee /tmp/vpn_server.log &
#
#   # Start Flask status page
#   cd web && python3 app.py
#
# Then open http://<server-ip>:8080 in a browser.
#
# Install Flask if needed:
#   pip3 install flask

import re
import os
import time
import json
from datetime import datetime, timedelta
from flask import Flask, render_template, jsonify

import sys

# Use absolute paths so Flask finds templates/static regardless of
# the working directory the script was launched from (important when
# run via start.sh through a venv from the project root).
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

app = Flask(
    __name__,
    template_folder=os.path.join(BASE_DIR, "templates"),
    static_folder=os.path.join(BASE_DIR, "static"),
)

# Path to the vpn_server log file
LOG_FILE = os.environ.get("VPN_LOG", "/tmp/vpn_server.log")

# ============================================================================
# LOG PARSER
# ============================================================================

def parse_server_log():
    """
    Parse the vpn_server log file and extract status information.
    Returns a dict with server status and per-client session info.
    """
    status = {
        "server_online":   False,
        "server_ip":       os.environ.get("SERVER_IP", "209.97.191.183"),
        "server_port":     5555,
        "algorithm_kem":   "ML-KEM-768 (NIST FIPS 203)",
        "algorithm_auth":  "ML-DSA-65 (NIST FIPS 204)",
        "algorithm_sym":   "AES-256-GCM",
        "max_clients":     8,
        "active_clients":  0,
        "total_connections": 0,
        "server_started":  None,
        "uptime":          "—",
        "clients":         [],
        "log_updated":     datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
    }

    if not os.path.exists(LOG_FILE):
        status["error"] = f"Log file not found: {LOG_FILE}"
        return status

    try:
        with open(LOG_FILE, "r") as f:
            lines = f.readlines()
    except Exception as e:
        status["error"] = str(e)
        return status

    if not lines:
        return status

    # Track per-slot session data
    slots = {}
    server_start_time = None

    for line in lines:
        line = line.strip()

        # Server startup
        if "Listening on 0.0.0.0:5555" in line:
            status["server_online"] = True
            # Estimate start time from log position
            server_start_time = time.time() - (len(lines) * 0.1)

        if "Server ready — waiting for clients" in line:
            status["server_online"] = True

        # Total connections
        m = re.search(r"total connections: (\d+)", line)
        if m:
            status["total_connections"] = int(m.group(1))

        # Active client count
        m = re.search(r"active: (\d+)/(\d+)", line)
        if m:
            status["active_clients"] = int(m.group(1))
            status["max_clients"]    = int(m.group(2))

        # Client authenticated
        m = re.search(r"\[slot (\d+)\] ✅ Client authenticated: ([\d.]+):(\d+)", line)
        if m:
            slot = int(m.group(1))
            if slot not in slots:
                slots[slot] = {
                    "slot":            slot,
                    "ip":              m.group(2),
                    "port":            int(m.group(3)),
                    "identity":        "—",
                    "state":           "authenticating",
                    "bytes_sent":      0,
                    "bytes_recv":      0,
                    "pkts_sent":       0,
                    "pkts_recv":       0,
                    "keepalives_recv": 0,
                    "connected_at":    datetime.now().strftime("%H:%M:%S"),
                    "duration":        "—",
                }
            else:
                slots[slot]["ip"]   = m.group(2)
                slots[slot]["port"] = int(m.group(3))

        # Certificate identity
        m = re.search(r"Received certificate from [\d.]+:\d+ \(identity: '([^']+)'\)", line)
        if m:
            # Find which slot this belongs to — look for nearest slot reference
            for slot in slots:
                if slots[slot]["identity"] == "—":
                    slots[slot]["identity"] = m.group(1)
                    break

        # Tunnel active
        m = re.search(r"\[slot (\d+)\] ── Tunnel active", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["state"] = "active"

        # Keepalive received
        m = re.search(r"\[slot (\d+)\] 💓 Keepalive seq=(\d+)", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["keepalives_recv"] += 1

        # Packet stats from tunnel output
        # "📤 #N seq=X Y→Z bytes"
        m = re.search(r"\[slot (\d+)\].*📤 #(\d+) seq=\d+ (\d+)→(\d+)", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["pkts_sent"]  = int(m.group(2))
                slots[slot]["bytes_sent"] = int(m.group(4)) * int(m.group(2))

        m = re.search(r"\[slot (\d+)\].*📥 #(\d+) seq=\d+ (\d+) bytes", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["pkts_recv"]  = int(m.group(2))
                slots[slot]["bytes_recv"] = int(m.group(3)) * int(m.group(2))

        # Session stats block (from completed session)
        m = re.search(r"\[slot (\d+)\] Session stats", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["state"] = "closed"

        # Duration from stats
        m = re.search(r"Duration\s+:\s+(\d+) seconds", line)
        if m:
            # Apply to most recently closed slot
            for slot in reversed(list(slots.keys())):
                if slots[slot]["state"] == "closed":
                    secs = int(m.group(1))
                    slots[slot]["duration"] = format_duration(secs)
                    break

        # Bytes from stats block
        m = re.search(r"Bytes sent\s+:\s+(\d+)", line)
        if m:
            for slot in reversed(list(slots.keys())):
                if slots[slot].get("state") in ["closed", "active"]:
                    slots[slot]["bytes_sent"] = int(m.group(1))
                    break

        m = re.search(r"Bytes received\s+:\s+(\d+)", line)
        if m:
            for slot in reversed(list(slots.keys())):
                if slots[slot].get("state") in ["closed", "active"]:
                    slots[slot]["bytes_recv"] = int(m.group(1))
                    break

        # Worker thread exited — slot closed
        m = re.search(r"\[slot (\d+)\] ✅ Worker thread exited", line)
        if m:
            slot = int(m.group(1))
            if slot in slots:
                slots[slot]["state"] = "closed"

    # Calculate uptime
    if status["server_online"] and server_start_time:
        uptime_secs = int(time.time() - server_start_time)
        status["uptime"] = format_duration(uptime_secs)

    # Only include active slots in client list
    status["clients"] = [
        s for s in slots.values()
        if s["state"] in ["active", "authenticating"]
    ]
    status["active_clients"] = len(status["clients"])

    return status


def format_duration(seconds):
    """Format seconds into human-readable duration."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        m, s = divmod(seconds, 60)
        return f"{m}m {s}s"
    else:
        h, remainder = divmod(seconds, 3600)
        m, s = divmod(remainder, 60)
        return f"{h}h {m}m"


def format_bytes(b):
    """Format bytes into human-readable size."""
    if b < 1024:
        return f"{b} B"
    elif b < 1024 * 1024:
        return f"{b/1024:.1f} KB"
    else:
        return f"{b/(1024*1024):.2f} MB"


# ============================================================================
# ROUTES
# ============================================================================

@app.route("/")
def index():
    status = parse_server_log()
    # Format bytes for display
    for client in status["clients"]:
        client["bytes_sent_fmt"] = format_bytes(client["bytes_sent"])
        client["bytes_recv_fmt"] = format_bytes(client["bytes_recv"])
    return render_template("index.html", status=status)


@app.route("/api/status")
def api_status():
    """JSON API endpoint for live updates."""
    status = parse_server_log()
    for client in status["clients"]:
        client["bytes_sent_fmt"] = format_bytes(client["bytes_sent"])
        client["bytes_recv_fmt"] = format_bytes(client["bytes_recv"])
    return jsonify(status)


# ============================================================================
# MAIN
# ============================================================================

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    print(f"PQ-VPN Status Page running on http://0.0.0.0:{port}")
    print(f"Reading log from: {LOG_FILE}")
    app.run(host="0.0.0.0", port=port, debug=False)