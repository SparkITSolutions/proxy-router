#!/bin/bash
# RPI Gateway Health Check Script
# Validates all gateway components are correctly configured
# Updated: 2026-01-15

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
echo "  RPI Gateway Health Check"
echo "=========================================="
echo ""

# 0. Gateway Network Service (boot resilience)
echo "=== Gateway Network Service ==="
if systemctl is-enabled --quiet gateway-network.service 2>/dev/null; then
    pass "gateway-network.service is enabled"
    if systemctl is-active --quiet gateway-network.service; then
        pass "gateway-network.service is active"
    else
        warn "gateway-network.service is not active (may have completed)"
    fi
else
    warn "gateway-network.service not found (older install?)"
fi
echo ""

# 1. Services running
echo "=== Services ==="
for service in hostapd dnsmasq wg-quick@wg0; do
    if systemctl is-active --quiet "$service"; then
        pass "$service is running"
    else
        fail "$service is NOT running"
    fi
done
echo ""

# 2. WiFi AP broadcasting
echo "=== WiFi Access Point ==="
if [[ -f /etc/hostapd/hostapd.conf ]]; then
    SSID=$(grep "^ssid=" /etc/hostapd/hostapd.conf | cut -d= -f2)
    CHANNEL=$(grep "^channel=" /etc/hostapd/hostapd.conf | cut -d= -f2)
    AP_IFACE=$(grep "^interface=" /etc/hostapd/hostapd.conf | cut -d= -f2)
    pass "hostapd config exists"
    info "SSID: $SSID, Channel: $CHANNEL, Interface: $AP_IFACE"
else
    fail "hostapd config NOT found"
fi
echo ""

# 2b. Interface IPs
echo "=== Interface IPs ==="
# Load gateway config if it exists
MODE=""
AP_IP=""
ETH_IP=""
UPSTREAM_IFACE=""
if [[ -f /opt/proxy-router/rpi/gateway.conf ]]; then
    source /opt/proxy-router/rpi/gateway.conf
    info "Mode: $MODE"
fi

# Check AP interface has IP
if [[ -n "$AP_IFACE" ]]; then
    AP_ACTUAL_IP=$(ip -4 addr show "$AP_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
    if [[ -n "$AP_ACTUAL_IP" ]]; then
        if [[ -n "$AP_IP" && "$AP_ACTUAL_IP" == "$AP_IP" ]]; then
            pass "AP interface $AP_IFACE has correct IP: $AP_ACTUAL_IP"
        else
            pass "AP interface $AP_IFACE has IP: $AP_ACTUAL_IP"
        fi
    else
        fail "AP interface $AP_IFACE has NO IP address"
    fi
fi

# Check eth0 based on mode
ETH0_IP=$(ip -4 addr show eth0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
if [[ "$MODE" == "usb-wifi" ]]; then
    # USB WiFi mode: eth0 should have static IP for DHCP server
    if [[ -n "$ETH0_IP" ]]; then
        if [[ "$ETH0_IP" == "$ETH_IP" ]] || [[ "$ETH0_IP" =~ ^192\.168\.51\. ]]; then
            pass "eth0 has static IP for DHCP server: $ETH0_IP"
        else
            pass "eth0 has IP: $ETH0_IP"
        fi
    else
        fail "eth0 has NO IP (DHCP server won't work)"
    fi
else
    # Ethernet-upstream mode: eth0 should have DHCP IP from router
    if [[ -n "$ETH0_IP" ]]; then
        pass "eth0 has IP from upstream: $ETH0_IP"
    else
        fail "eth0 has NO IP (no upstream connection)"
    fi
fi

# Check wlan0 for USB WiFi mode (upstream WiFi)
if [[ "$MODE" == "usb-wifi" ]]; then
    WLAN0_IP=$(ip -4 addr show wlan0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | head -1 || echo "")
    if [[ -n "$WLAN0_IP" ]]; then
        pass "wlan0 connected to upstream WiFi: $WLAN0_IP"
    else
        fail "wlan0 has NO IP (not connected to upstream WiFi)"
    fi
fi
echo ""

# 3. WireGuard status
echo "=== WireGuard Tunnel ==="
if ip link show wg0 &>/dev/null; then
    pass "WireGuard interface wg0 exists"

    # Check for handshake
    HANDSHAKE=$(wg show wg0 latest-handshakes 2>/dev/null | awk '{print $2}')
    if [[ -n "$HANDSHAKE" && "$HANDSHAKE" != "0" ]]; then
        HANDSHAKE_AGO=$(($(date +%s) - HANDSHAKE))
        if [[ $HANDSHAKE_AGO -lt 180 ]]; then
            pass "Recent handshake (${HANDSHAKE_AGO}s ago)"
        else
            warn "Handshake is old (${HANDSHAKE_AGO}s ago)"
        fi
    else
        fail "No WireGuard handshake - tunnel NOT established"
    fi

    # Check endpoint
    ENDPOINT=$(wg show wg0 endpoints 2>/dev/null | awk '{print $2}')
    if [[ -n "$ENDPOINT" ]]; then
        info "Endpoint: $ENDPOINT"
    fi

    # Check transfer
    TRANSFER=$(wg show wg0 transfer 2>/dev/null)
    RX=$(echo "$TRANSFER" | awk '{print $2}')
    TX=$(echo "$TRANSFER" | awk '{print $3}')
    if [[ -n "$RX" && -n "$TX" ]]; then
        info "Transfer: RX=$RX TX=$TX"
    fi
else
    fail "WireGuard interface wg0 NOT found"
fi
echo ""

# 4. VPS endpoint config
echo "=== VPS Endpoint ==="
VPS_IP=""
VPS_PORT=""
if [[ -f /etc/wireguard/wg0.conf ]]; then
    VPS_ENDPOINT=$(grep -i "^Endpoint" /etc/wireguard/wg0.conf | sed 's/.*= *//' | tr -d ' ')
    VPS_IP=$(echo "$VPS_ENDPOINT" | cut -d: -f1)
    VPS_PORT=$(echo "$VPS_ENDPOINT" | cut -d: -f2)
    pass "WireGuard config exists"
    info "VPS Endpoint: $VPS_ENDPOINT"
else
    fail "WireGuard config NOT found"
fi
echo ""

# 5. VPS direct route
echo "=== VPS Direct Route ==="
if [[ -n "$VPS_IP" ]]; then
    if ip route | grep -q "$VPS_IP"; then
        pass "Direct route to VPS exists"
        ROUTE=$(ip route | grep "$VPS_IP")
        info "Route: $ROUTE"
    else
        fail "No direct route to VPS - WireGuard will have routing loop!"
    fi
fi
echo ""

# 5b. WireGuard policy routing (critical for client traffic forwarding)
echo "=== WireGuard Policy Routing ==="
# wg-quick creates these rules when AllowedIPs = 0.0.0.0/0
# Without them, forwarded client traffic won't go through the tunnel
WG_FWMARK=$(wg show wg0 fwmark 2>/dev/null || echo "")
if [[ -n "$WG_FWMARK" ]]; then
    # Check for the "not fwmark X lookup Y" rule
    if ip rule list | grep -q "not from all fwmark.*lookup"; then
        pass "WireGuard policy routing rule exists"
        RULE=$(ip rule list | grep "not from all fwmark.*lookup")
        info "Rule: $RULE"
    else
        fail "WireGuard policy routing rule MISSING - client traffic won't route through tunnel!"
        warn "Fix: sudo wg-quick down wg0 && sudo wg-quick up wg0"
    fi

    # Check for suppress_prefixlength rule
    if ip rule list | grep -q "suppress_prefixlength"; then
        pass "WireGuard suppress_prefixlength rule exists"
    else
        fail "WireGuard suppress_prefixlength rule MISSING"
        warn "Fix: sudo wg-quick down wg0 && sudo wg-quick up wg0"
    fi

    # Check that table 51820 (or similar) has default route through wg0
    WG_TABLE=$(ip rule list | grep "not from all fwmark.*lookup" | grep -oE 'lookup [0-9]+' | awk '{print $2}' | head -1)
    if [[ -n "$WG_TABLE" ]]; then
        if ip route show table "$WG_TABLE" 2>/dev/null | grep -q "dev wg0"; then
            pass "WireGuard routing table $WG_TABLE has wg0 route"
        else
            fail "WireGuard routing table $WG_TABLE missing wg0 route"
        fi
    fi
else
    warn "Could not get WireGuard fwmark"
fi
echo ""

# 6. IP Forwarding
echo "=== IP Forwarding ==="
IP_FORWARD=$(cat /proc/sys/net/ipv4/ip_forward)
if [[ "$IP_FORWARD" == "1" ]]; then
    pass "IPv4 forwarding enabled"
else
    fail "IPv4 forwarding NOT enabled"
fi
echo ""

# 7. IPv6 disabled
echo "=== IPv6 Status ==="
IPV6_ALL=$(cat /proc/sys/net/ipv6/conf/all/disable_ipv6 2>/dev/null || echo "0")
if [[ "$IPV6_ALL" == "1" ]]; then
    pass "IPv6 disabled"
else
    warn "IPv6 may not be fully disabled"
fi
echo ""

# 8. iptables rules
echo "=== iptables Firewall ==="
INPUT_POLICY=$(iptables -L INPUT -n 2>/dev/null | head -1 | grep -o "policy [A-Z]*" | awk '{print $2}')
OUTPUT_POLICY=$(iptables -L OUTPUT -n 2>/dev/null | head -1 | grep -o "policy [A-Z]*" | awk '{print $2}')
FORWARD_POLICY=$(iptables -L FORWARD -n 2>/dev/null | head -1 | grep -o "policy [A-Z]*" | awk '{print $2}')

if [[ "$INPUT_POLICY" == "DROP" ]]; then
    pass "INPUT policy is DROP (fail-shut)"
else
    fail "INPUT policy is $INPUT_POLICY (should be DROP)"
fi

if [[ "$OUTPUT_POLICY" == "DROP" ]]; then
    pass "OUTPUT policy is DROP (fail-shut)"
else
    fail "OUTPUT policy is $OUTPUT_POLICY (should be DROP)"
fi

if [[ "$FORWARD_POLICY" == "DROP" ]]; then
    pass "FORWARD policy is DROP (fail-shut)"
else
    fail "FORWARD policy is $FORWARD_POLICY (should be DROP)"
fi

# Check VPS endpoint rule exists
if [[ -n "$VPS_IP" && -n "$VPS_PORT" ]]; then
    if iptables -L OUTPUT -n | grep -q "$VPS_IP.*udp dpt:$VPS_PORT"; then
        pass "OUTPUT rule allows UDP to VPS"
    else
        fail "OUTPUT rule for VPS endpoint NOT found"
    fi
fi

# Check NAT on wg0 (need -v to see interface name)
if iptables -t nat -L POSTROUTING -v | grep -q "MASQUERADE.*wg0"; then
    pass "NAT masquerade on wg0"
else
    fail "NAT masquerade on wg0 NOT found"
fi
echo ""

# 9. Can ping VPS through tunnel
echo "=== VPS Tunnel Connectivity ==="
if ping -c 1 -W 3 10.100.0.1 &>/dev/null; then
    pass "Can ping VPS WireGuard IP (10.100.0.1)"
else
    fail "Cannot ping VPS WireGuard IP (10.100.0.1)"
fi
echo ""

# 10. External IP (through VPN)
echo "=== External IP (through VPN) ==="
EXTERNAL_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "FAILED")
if [[ "$EXTERNAL_IP" != "FAILED" && -n "$EXTERNAL_IP" ]]; then
    pass "Can reach internet through VPN"
    info "External IP: $EXTERNAL_IP"
    info "(This should be a NordVPN IP, not your home IP)"
else
    fail "Cannot reach internet - VPN tunnel may not be working"
fi
echo ""

# 11. DNS resolution
echo "=== DNS Resolution ==="
if nslookup google.com &>/dev/null; then
    pass "DNS resolution working"
else
    fail "DNS resolution NOT working"
fi
echo ""

# 12. Region service (if installed)
echo "=== Region Control Service ==="
if [[ -f /etc/systemd/system/gateway-region.service ]]; then
    if systemctl is-active --quiet gateway-region.service; then
        pass "Region control service is running"
        # Try to get status from API
        source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
        REGION_PORT="${REGION_PORT:-59420}"
        info "Region service port: $REGION_PORT"
        info "Access: https://192.168.50.1:$REGION_PORT"
    else
        fail "Region control service is NOT running"
    fi
else
    info "Region control service not installed (optional)"
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
