#!/bin/bash
# server_setup.sh
# Run once on the VPN server after vpn_server starts.
# Enables IP forwarding and NAT so client traffic reaches the internet.
#
# Usage: sudo ./server_setup.sh
# To undo: sudo ./server_setup.sh --undo

set -e

# Detect the outbound interface (the one with the default route)
OUTBOUND=$(ip route show default | awk '/default/ {print $5; exit}')

if [ -z "$OUTBOUND" ]; then
    echo "❌ Could not detect outbound interface"
    echo "   Set it manually: OUTBOUND=eth0 sudo ./server_setup.sh"
    exit 1
fi

if [ "$1" = "--undo" ]; then
    echo "🔄 Removing VPN routing rules..."

    iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$OUTBOUND" -j MASQUERADE 2>/dev/null || true
    iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null || true
    iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null || true

    echo "   ✅ iptables rules removed"
    echo "   ⚠️  IP forwarding left enabled — reboot or manually set to 0"
    exit 0
fi

echo "🔧 Configuring server for VPN traffic routing..."
echo "   Outbound interface: $OUTBOUND"
echo ""

# 1. Enable IP forwarding — kernel will forward between tun0 and eth0
echo "1️⃣  Enabling IP forwarding..."
echo 1 > /proc/sys/net/ipv4/ip_forward

# Make it persist across reboots
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
echo "   ✅ IP forwarding enabled"

# 2. NAT — rewrite the source IP of packets leaving the tunnel
#    so the internet sees the server's real IP, not 10.8.0.x
echo ""
echo "2️⃣  Adding NAT rule (MASQUERADE)..."
# Remove existing rule first to avoid duplicates on re-run
iptables -t nat -D POSTROUTING -s 10.8.0.0/24 -o "$OUTBOUND" -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o "$OUTBOUND" -j MASQUERADE
echo "   ✅ NAT: 10.8.0.0/24 → $OUTBOUND (MASQUERADE)"

# 3. Allow forwarded packets through the firewall
echo ""
echo "3️⃣  Opening firewall for forwarded traffic..."
iptables -D FORWARD -i tun0 -j ACCEPT 2>/dev/null || true
iptables -D FORWARD -o tun0 -j ACCEPT 2>/dev/null || true
iptables -A FORWARD -i tun0 -j ACCEPT
iptables -A FORWARD -o tun0 -j ACCEPT
echo "   ✅ FORWARD rules set for tun0"

# 4. Allow UDP 5555 inbound (VPN port)
echo ""
echo "4️⃣  Opening UDP port 5555..."
iptables -D INPUT -p udp --dport 5555 -j ACCEPT 2>/dev/null || true
iptables -A INPUT -p udp --dport 5555 -j ACCEPT
echo "   ✅ UDP 5555 open"

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "✅ Server routing configured"
echo ""
echo "   Start server:  sudo ./bin/vpn_server"
echo "   Verify NAT:    iptables -t nat -L POSTROUTING -n -v"
echo ""
echo "   To remove rules: sudo ./server_setup.sh --undo"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"