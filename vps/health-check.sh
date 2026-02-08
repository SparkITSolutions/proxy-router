#!/bin/bash
# VPS Health Check Script
# Validates all VPS components are correctly configured
# Updated: 2026-01-15 with WireGuard iptables fixes

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

pass() { echo -e "${GREEN}[PASS]${NC} $1"; }
fail() { echo -e "${RED}[FAIL]${NC} $1"; FAILURES=$((FAILURES + 1)); }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
info() { echo -e "[INFO] $1"; }

FAILURES=0

echo "=========================================="
echo "  VPS Health Check"
echo "=========================================="
echo ""

# 1. Docker containers running
echo "=== Docker Containers ==="
for container in nordvpn wireguard tor; do
    if docker ps --format '{{.Names}}' | grep -q "^${container}$"; then
        pass "$container container running"
    else
        fail "$container container NOT running"
    fi
done
echo ""

# 2. NordVPN status
echo "=== NordVPN Status ==="
NORDVPN_STATUS=$(docker exec nordvpn nordvpn status 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_STATUS" | grep -q "Status: Connected"; then
    pass "NordVPN connected"
    NORDVPN_IP=$(echo "$NORDVPN_STATUS" | grep "^IP:" | awk '{print $2}')
    info "NordVPN IP: $NORDVPN_IP"
else
    fail "NordVPN NOT connected"
    echo "$NORDVPN_STATUS"
fi
echo ""

# 3. External IP through VPN
echo "=== External IP ==="
VPN_EXTERNAL_IP=$(docker exec nordvpn curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "FAILED")
if [[ "$VPN_EXTERNAL_IP" != "FAILED" && -n "$VPN_EXTERNAL_IP" ]]; then
    pass "Can reach internet through VPN"
    info "External IP: $VPN_EXTERNAL_IP"
else
    fail "Cannot reach internet through VPN"
fi
echo ""

# 4. WireGuard server status
echo "=== WireGuard Server ==="
WG_STATUS=$(docker exec wireguard wg show wg0 2>/dev/null || echo "FAILED")
if [[ "$WG_STATUS" != "FAILED" ]]; then
    pass "WireGuard interface wg0 exists"

    # Check listening port
    if echo "$WG_STATUS" | grep -q "listening port: 51820"; then
        pass "WireGuard listening on port 51820"
    else
        fail "WireGuard NOT listening on port 51820"
    fi

    # Check peer configured
    if echo "$WG_STATUS" | grep -q "peer:"; then
        pass "WireGuard peer configured"
        PEER_PUBKEY=$(echo "$WG_STATUS" | grep "peer:" | awk '{print $2}')
        info "Peer public key: ${PEER_PUBKEY:0:20}..."
    else
        fail "No WireGuard peer configured"
    fi

    # Check fwmark (2026-01-15 fix)
    if echo "$WG_STATUS" | grep -q "fwmark: 0xe1f1"; then
        pass "WireGuard fwmark set to 0xe1f1 (bypasses NordVPN routing)"
    else
        fail "WireGuard fwmark NOT set - responses will go through nordlynx!"
        warn "Fix with: docker exec nordvpn wg set wg0 fwmark 0xe1f1"
    fi
else
    fail "WireGuard interface wg0 NOT found"
fi
echo ""

# 5. Host port listening
echo "=== Host Network ==="
if ss -ulnp | grep -q ":51820 "; then
    pass "UDP port 51820 listening on host"
else
    fail "UDP port 51820 NOT listening on host"
fi
echo ""

# 6. UFW firewall
echo "=== UFW Firewall ==="
if ufw status | grep -q "Status: active"; then
    pass "UFW is active"
    if ufw status | grep -q "51820/udp.*ALLOW"; then
        pass "UFW allows UDP 51820"
    else
        fail "UFW does NOT allow UDP 51820"
    fi
else
    warn "UFW is not active"
fi
echo ""

# 7. NordVPN container iptables - filter table (2026-01-15 fix)
echo "=== NordVPN Container iptables (filter) ==="
NORDVPN_INPUT=$(docker exec nordvpn iptables -L INPUT -n 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_INPUT" | grep -q "ACCEPT.*udp dpt:51820"; then
    pass "nordvpn container allows UDP 51820 INPUT"
else
    fail "nordvpn container does NOT allow UDP 51820 INPUT"
    warn "Fix with: docker exec nordvpn iptables -A INPUT -p udp --dport 51820 -j ACCEPT"
fi

NORDVPN_OUTPUT=$(docker exec nordvpn iptables -L OUTPUT -n 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_OUTPUT" | grep -q "ACCEPT.*udp spt:51820"; then
    pass "nordvpn container allows UDP 51820 OUTPUT (sport)"
else
    fail "nordvpn container does NOT allow UDP 51820 OUTPUT"
    warn "Fix with: docker exec nordvpn iptables -A OUTPUT -p udp --sport 51820 -j ACCEPT"
fi
echo ""

# 8. NordVPN container iptables - mangle table (2026-01-15 fix)
echo "=== NordVPN Container iptables (mangle) ==="
NORDVPN_MANGLE_PRE=$(docker exec nordvpn iptables -t mangle -L PREROUTING -n 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_MANGLE_PRE" | grep -q "ACCEPT.*udp dpt:51820"; then
    pass "mangle PREROUTING allows UDP 51820 (bypasses NordVPN kill-switch)"
else
    fail "mangle PREROUTING does NOT allow UDP 51820"
    warn "Fix with: docker exec nordvpn iptables -t mangle -I PREROUTING -i eth0 -p udp --dport 51820 -j ACCEPT"
fi

NORDVPN_MANGLE_POST=$(docker exec nordvpn iptables -t mangle -L POSTROUTING -n 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_MANGLE_POST" | grep -q "ACCEPT.*udp spt:51820"; then
    pass "mangle POSTROUTING allows UDP 51820 responses"
else
    fail "mangle POSTROUTING does NOT allow UDP 51820 responses"
    warn "Fix with: docker exec nordvpn iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 51820 -j ACCEPT"
fi
echo ""

# 9. NAT for WireGuard clients (2026-01-15 fix)
echo "=== NAT for WireGuard Clients ==="
NORDVPN_NAT=$(docker exec nordvpn iptables -t nat -L POSTROUTING -n 2>/dev/null || echo "FAILED")
if echo "$NORDVPN_NAT" | grep -q "MASQUERADE.*10.100.0.0/24"; then
    pass "NAT masquerade for WireGuard clients"
else
    fail "NAT masquerade for WireGuard clients NOT found"
    warn "Fix with: docker exec nordvpn iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -o nordlynx -j MASQUERADE"
fi
echo ""

# 10. Client config exists
echo "=== Client Configuration ==="
if [[ -f /opt/proxy-router/keys/client.conf ]]; then
    pass "Client config exists at /opt/proxy-router/keys/client.conf"
    if grep -q "Endpoint" /opt/proxy-router/keys/client.conf; then
        ENDPOINT=$(grep "Endpoint" /opt/proxy-router/keys/client.conf | awk '{print $3}')
        info "Endpoint: $ENDPOINT"
    fi
else
    fail "Client config NOT found"
fi
echo ""

# Summary
echo "=========================================="
if [[ $FAILURES -eq 0 ]]; then
    echo -e "${GREEN}All checks passed!${NC}"
else
    echo -e "${RED}$FAILURES check(s) failed${NC}"
fi
echo "=========================================="

exit $FAILURES
