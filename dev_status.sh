#!/bin/bash
# dev_status.sh - Quick project status

echo "╔════════════════════════════════════════╗"
echo "║     PQ-VPN Development Status          ║"
echo "╚════════════════════════════════════════╝"
echo ""

echo "📁 Project Structure:"
tree -L 2 -I 'build|bin' .
echo ""

echo "📊 Git Status:"
git status -s
echo ""

echo "📝 Recent Commits:"
git log --oneline -5
echo ""

echo "✅ Environment Check:"
which gcc > /dev/null && echo "  GCC: ✓" || echo "  GCC: ✗"
which git > /dev/null && echo "  Git: ✓" || echo "  Git: ✗"
pkg-config --exists libcrypto && echo "  OpenSSL: ✓" || echo "  OpenSSL: ✗"
ldconfig -p | grep liboqs > /dev/null && echo "  liboqs: ✓" || echo "  liboqs: ✗"
