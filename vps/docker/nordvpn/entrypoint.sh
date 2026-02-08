#!/bin/bash
# NordVPN Container Entrypoint with WireGuard Passthrough
# Uses NordVPN's built-in kill switch, adds WireGuard passthrough after connection

set -euo pipefail

# Clean up any stale state from previous container runs
killall -9 nordvpnd 2>/dev/null || true
sleep 2
rm -f /run/nordvpn/nordvpnd.sock 2>/dev/null || true
rm -f /run/nordvpn/nordvpnd.pid 2>/dev/null || true
rm -f /var/run/nordvpnd.pid 2>/dev/null || true
pkill -9 -f nordvpnd 2>/dev/null || true
sleep 1

# Colors for logging
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Required environment variables
NORDVPN_TOKEN="${NORDVPN_TOKEN:?NORDVPN_TOKEN is required}"
NORDVPN_REGION="${NORDVPN_REGION:-us}"
NORDVPN_TECHNOLOGY="${NORDVPN_TECHNOLOGY:-nordlynx}"
NORDVPN_SERVER="${NORDVPN_SERVER:-}"
DNS_SERVERS="${DNS_SERVERS:-103.86.96.100,103.86.99.100}"
WG_PORT="${WG_PORT:-51820}"

# =============================================================================
# Start NordVPN daemon
# =============================================================================
log_info "Starting NordVPN daemon..."

mkdir -p /run/nordvpn
nordvpnd &

# Wait for daemon to be ready
sleep 5

for i in {1..30}; do
    if nordvpn status &>/dev/null; then
        log_info "NordVPN daemon is ready"
        break
    fi
    log_warn "Waiting for NordVPN daemon... ($i/30)"
    sleep 2
done

# Verify daemon is responding
if ! nordvpn status &>/dev/null; then
    log_error "NordVPN daemon failed to start"
    exit 1
fi

# =============================================================================
# Login to NordVPN
# =============================================================================
log_info "Logging in to NordVPN..."

if nordvpn account &>/dev/null; then
    log_info "Already logged in to NordVPN"
else
    LOGIN_OUTPUT=$(nordvpn login --token "$NORDVPN_TOKEN" 2>&1)
    if echo "$LOGIN_OUTPUT" | grep -qi "logged in\|Welcome"; then
        log_info "Login successful"
    else
        log_error "Failed to login to NordVPN: $LOGIN_OUTPUT"
        exit 1
    fi
fi

# =============================================================================
# Configure NordVPN Settings
# =============================================================================
log_info "Configuring NordVPN settings..."

nordvpn set technology "$NORDVPN_TECHNOLOGY" || true
nordvpn set killswitch on || true
nordvpn set firewall on || true
nordvpn set analytics off || true
nordvpn set dns $DNS_SERVERS || true
nordvpn set threatprotectionlite on || true

# =============================================================================
# Connect to VPN
# =============================================================================
log_info "Connecting to NordVPN..."

if [[ -n "$NORDVPN_SERVER" ]]; then
    log_info "Connecting to specific server: $NORDVPN_SERVER"
    nordvpn connect "$NORDVPN_SERVER"
else
    log_info "Connecting to region: $NORDVPN_REGION"
    nordvpn connect "$NORDVPN_REGION"
fi

# Wait for connection
for i in {1..60}; do
    if nordvpn status | grep -q "Status: Connected"; then
        log_info "VPN connected successfully!"
        break
    fi
    log_warn "Waiting for VPN connection... ($i/60)"
    sleep 2
done

# Verify connection
if ! nordvpn status | grep -q "Status: Connected"; then
    log_error "Failed to connect to VPN"
    nordvpn status
    exit 1
fi

# Show connection details
log_info "VPN Status:"
nordvpn status

CURRENT_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "Unable to determine")
log_info "Current external IP: $CURRENT_IP"

# =============================================================================
# Setup WireGuard passthrough AFTER VPN is connected
# NordVPN's kill-switch uses mangle table - we need to add exceptions
# =============================================================================
log_info "Setting up WireGuard passthrough rules..."

# Add exceptions in mangle table for WireGuard traffic
# NordVPN may have rules that DROP traffic - we insert at position 1 to take precedence
iptables -t mangle -I PREROUTING 1 -i eth0 -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
iptables -t mangle -I POSTROUTING 1 -p udp --sport "$WG_PORT" -j ACCEPT 2>/dev/null || true

# Add filter rules for WireGuard
iptables -I INPUT 1 -p udp --dport "$WG_PORT" -j ACCEPT 2>/dev/null || true
iptables -I OUTPUT 1 -p udp --sport "$WG_PORT" -j ACCEPT 2>/dev/null || true

# Policy routing: WireGuard responses go directly via eth0, not through VPN
ip rule add sport "$WG_PORT" table main priority 100 2>/dev/null || true

# Add MASQUERADE for WireGuard client traffic going through VPN
iptables -t nat -A POSTROUTING -o nordlynx -j MASQUERADE 2>/dev/null || true
iptables -t nat -A POSTROUTING -o tun0 -j MASQUERADE 2>/dev/null || true

log_info "WireGuard passthrough configured on port $WG_PORT"

# =============================================================================
# Setup rotation (if enabled)
# =============================================================================
ROTATION_INTERVAL="${ROTATION_INTERVAL:-3600}"

# Initialize current region file for persistence across rotation/changes
echo "$NORDVPN_REGION" > /var/lib/nordvpn/current_region

if [[ "$ROTATION_INTERVAL" -gt 0 ]]; then
    log_info "Setting up server rotation every ${ROTATION_INTERVAL} seconds..."

    cat > /usr/local/bin/rotate-server.sh << 'ROTATE_EOF'
#!/bin/bash
REGION=$(cat /var/lib/nordvpn/current_region 2>/dev/null || echo "us")
echo "[$(date)] Rotating VPN server within region: $REGION"
nordvpn disconnect
sleep 2
nordvpn connect "$REGION"
sleep 5
nordvpn status
NEW_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "Unknown")
echo "[$(date)] New IP: $NEW_IP"
ROTATE_EOF
    chmod +x /usr/local/bin/rotate-server.sh

    # Create change-region script for runtime region switching
    cat > /usr/local/bin/change-region.sh << 'CHANGE_EOF'
#!/bin/bash
NEW_REGION="${1:-}"
if [[ -z "$NEW_REGION" ]]; then
    echo "Usage: change-region.sh <region>"
    echo "Example: change-region.sh uk"
    exit 1
fi
echo "[$(date)] Changing region to: $NEW_REGION"
nordvpn disconnect
sleep 2
nordvpn connect "$NEW_REGION"
sleep 5
# Re-apply MASQUERADE for WireGuard client traffic (nordlynx interface may be recreated)
iptables -t nat -A POSTROUTING -o nordlynx -j MASQUERADE 2>/dev/null || true
# Persist for rotation script
echo "$NEW_REGION" > /var/lib/nordvpn/current_region
nordvpn status
NEW_IP=$(curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "Unknown")
echo "[$(date)] New IP: $NEW_IP"
CHANGE_EOF
    chmod +x /usr/local/bin/change-region.sh

    (
        while true; do
            sleep "$ROTATION_INTERVAL"
            /usr/local/bin/rotate-server.sh
        done
    ) &
fi

# =============================================================================
# Keep container running and monitor VPN
# =============================================================================
log_info "Container ready. Monitoring VPN connection..."

while true; do
    if ! nordvpn status | grep -q "Status: Connected"; then
        log_error "VPN disconnected! Attempting to reconnect..."

        if [[ -n "$NORDVPN_SERVER" ]]; then
            nordvpn connect "$NORDVPN_SERVER"
        else
            nordvpn connect "$NORDVPN_REGION"
        fi

        sleep 10
    fi
    sleep 30
done
