#!/bin/bash
#
# Raspberry Pi Gateway Install Script
# Sets up Pi 3B+ as a secure gateway with WiFi AP, Ethernet DHCP, and WireGuard tunnel
#
# All client traffic routes: Client -> Pi -> WireGuard -> VPS -> NordVPN -> Internet
# Fail-shut: If WireGuard fails, all client traffic is blocked (no IP leak)
#
# FRESH IMAGE SCENARIO:
#   1. Image Pi with Raspberry Pi Imager, configure initial WiFi for SSH access
#   2. SSH into Pi, clone/download this repo
#   3. Run this script - it will:
#      - Stop wpa_supplicant on wlan0 (breaking your SSH if over WiFi!)
#      - Convert wlan0 to Access Point mode
#      - Start WireGuard tunnel
#   4. Reconnect via ethernet OR connect to the new AP
#
# Usage:
#   ./install.sh --wg-config /path/to/peer.conf --ap-password "YourPassword123"
#
# Modes:
#   ethernet-upstream (default): eth0=upstream, wlan0=AP
#   usb-wifi: wlan0=upstream WiFi, USB adapter=AP, eth0=DHCP server
#             (auto-detects USB WiFi: wlan1 or wlx* interfaces)
#

set -euo pipefail

# =============================================================================
# Logging Configuration
# =============================================================================
LOG_FILE="/var/log/gateway-install.log"
STEP_COUNT=0
TOTAL_STEPS=13

# Ensure log directory exists
mkdir -p "$(dirname "$LOG_FILE")"

# Logging functions - output to both console and file
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_step() {
    STEP_COUNT=$((STEP_COUNT + 1))
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] [$STEP_COUNT/$TOTAL_STEPS] $*"
    echo "" | tee -a "$LOG_FILE"
    echo "==============================================================================" | tee -a "$LOG_FILE"
    echo "$msg" | tee -a "$LOG_FILE"
    echo "==============================================================================" | tee -a "$LOG_FILE"
}

log_info() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_warn() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] WARN: $*"
    echo "$msg" | tee -a "$LOG_FILE"
}

log_error() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $*"
    echo "$msg" | tee -a "$LOG_FILE" >&2
}

log_debug() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG: $*"
    echo "$msg" >> "$LOG_FILE"  # Debug only to file, not console
}

die() {
    log_error "$@"
    log_error "Installation failed. Check log at: $LOG_FILE"
    log_error "To retry: sudo $0 $*"
    exit 1
}

# Log command output for debugging
run_cmd() {
    local desc="$1"
    shift
    log_debug "Running: $*"
    if "$@" >> "$LOG_FILE" 2>&1; then
        log_debug "$desc: SUCCESS"
        return 0
    else
        local rc=$?
        log_error "$desc: FAILED (exit code $rc)"
        log_error "Command was: $*"
        return $rc
    fi
}

# Detect OS type and network manager (dhcpcd vs netplan)
detect_os() {
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case "$ID" in
            raspbian)
                OS_TYPE="raspios"
                NETWORK_MANAGER="dhcpcd"
                ;;
            debian)
                # Debian can use either dhcpcd or netplan
                if [[ -f /etc/dhcpcd.conf ]]; then
                    OS_TYPE="debian"
                    NETWORK_MANAGER="dhcpcd"
                else
                    OS_TYPE="debian"
                    NETWORK_MANAGER="netplan"
                fi
                ;;
            ubuntu)
                OS_TYPE="ubuntu"
                NETWORK_MANAGER="netplan"
                ;;
            *)
                log_warn "Unknown OS: $ID, assuming dhcpcd"
                OS_TYPE="unknown"
                NETWORK_MANAGER="dhcpcd"
                ;;
        esac
    else
        OS_TYPE="unknown"
        NETWORK_MANAGER="dhcpcd"
    fi

    log_info "Detected OS: $OS_TYPE ($PRETTY_NAME)"
    log_info "Network Manager: $NETWORK_MANAGER"
}

# =============================================================================
# Default Configuration
# =============================================================================
MODE="ethernet-upstream"
WG_CONFIG=""
AP_SSID="SecureGateway"
AP_PASSWORD=""
AP_CHANNEL="7"
UPSTREAM_SSID=""
UPSTREAM_PASSWORD=""
AP_NETWORK="192.168.50.0/24"
ETH_NETWORK="192.168.51.0/24"
COUNTRY="US"
SKIP_REBOOT="false"

# Region service configuration
REGION_KEY=""
REGION_PASSWORD=""
REGION_PORT="59420"
VPS_IP=""
SKIP_REGION_SERVICE="false"

# Derived values (set after parsing args)
AP_IP=""
ETH_IP=""
AP_IFACE=""
UPSTREAM_IFACE=""

# DNS servers (Cloudflare - queries go through WireGuard tunnel)
# Note: NordVPN DNS (103.86.96.100) can sinkhole some domains
DNS_SERVERS="1.1.1.1,1.0.0.1"

# =============================================================================
# Helper Functions
# =============================================================================

# Wait for apt/dpkg locks to be released
wait_for_apt() {
    local max_wait=300
    local waited=0

    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/cache/apt/archives/lock >/dev/null 2>&1; do
        if [ $waited -eq 0 ]; then
            log_info "Waiting for apt/dpkg locks to be released..."
        fi
        sleep 5
        waited=$((waited + 5))
        if [ $waited -ge $max_wait ]; then
            die "Timeout waiting for apt locks after ${max_wait}s"
        fi
    done

    if [ $waited -gt 0 ]; then
        log_info "Locks released after ${waited}s"
    fi
}

# Verify service started with retries
verify_service() {
    local service="$1"
    local max_attempts="${2:-10}"
    local attempt=1

    log_debug "Verifying service: $service"

    while [ $attempt -le $max_attempts ]; do
        if systemctl is-active --quiet "$service"; then
            log_info "Service $service is running"
            return 0
        fi
        log_debug "Waiting for $service to start (attempt $attempt/$max_attempts)..."
        sleep 2
        attempt=$((attempt + 1))
    done

    log_error "Service $service failed to start after $max_attempts attempts"
    log_error "Service status:"
    systemctl status "$service" --no-pager 2>&1 | tee -a "$LOG_FILE" || true
    journalctl -u "$service" -n 20 --no-pager 2>&1 | tee -a "$LOG_FILE" || true
    return 1
}

# Extract gateway IP from CIDR network (e.g., 192.168.50.0/24 -> 192.168.50.1)
get_gateway_ip() {
    local network="$1"
    echo "$network" | sed 's|\.[0-9]*/|.1/|' | cut -d'/' -f1
}

# Extract DHCP range from network (x.x.x.50 to x.x.x.200)
get_dhcp_range() {
    local network="$1"
    local base
    base=$(echo "$network" | sed 's|\.[0-9]*/.*||')
    echo "${base}.50,${base}.200"
}

# Detect USB WiFi adapter interface name
# Returns the first wireless interface that is NOT wlan0 (the built-in WiFi)
# Handles both traditional naming (wlan1) and Ubuntu predictable naming (wlx*)
detect_usb_wifi() {
    local iface
    # First try wlan1 (traditional naming on Raspberry Pi OS)
    if ip link show wlan1 &>/dev/null; then
        echo "wlan1"
        return 0
    fi
    # Then look for wlx* interfaces (Ubuntu 24.04 predictable naming based on MAC)
    for iface in /sys/class/net/wlx*; do
        if [[ -e "$iface" ]]; then
            basename "$iface"
            return 0
        fi
    done
    # Not found
    return 1
}

# Check current network state for debugging
log_network_state() {
    log_debug "=== Current Network State ==="
    log_debug "Interfaces:"
    ip -br addr 2>&1 | while read -r line; do log_debug "  $line"; done
    log_debug "Routes:"
    ip route 2>&1 | while read -r line; do log_debug "  $line"; done
    log_debug "WiFi:"
    iwconfig 2>&1 | grep -E "(wlan|ESSID|Mode)" | while read -r line; do log_debug "  $line"; done || true
    log_debug "=== End Network State ==="
}

usage() {
    cat << EOF
Raspberry Pi Gateway Install Script

Usage: $0 [OPTIONS]

Required:
  --wg-config <path>        WireGuard config file (peer.conf from VPS), or "-" for stdin
  --ap-password <pass>      WiFi Access Point password (min 8 characters)
  --ap-password-file <path> Read AP password from file (avoids shell escaping issues)

Mode (choose one):
  --mode ethernet-upstream  eth0=upstream DHCP client, wlan0=AP (default)
  --mode usb-wifi           wlan0=upstream WiFi, USB adapter=AP, eth0=DHCP server
                            (auto-detects USB WiFi: wlan1 or wlx* interfaces)

Access Point:
  --ap-ssid <name>          AP SSID (default: SecureGateway)
  --ap-channel <1-13>       WiFi channel (default: 7)

For usb-wifi mode:
  --upstream-ssid <ssid>    Upstream WiFi network name
  --upstream-password <pw>  Upstream WiFi password

Networks:
  --ap-network <CIDR>       AP client network (default: 192.168.50.0/24)
  --eth-network <CIDR>      Ethernet client network (default: 192.168.51.0/24)

Region Service (for remote region switching):
  --vps-ip <ip>             VPS IP address (required for region service)
  --region-key <path>       SSH key for region-changer user (from VPS)
  --region-password <pass>  Password for region control web interface
  --region-password-file <path>  Read region password from file (avoids shell escaping)
  --region-port <port>        Port for region control service (default: 59420)
  --skip-region-service     Skip region service installation

For usb-wifi mode (file options avoid shell escaping issues):
  --upstream-password-file <path>  Read upstream WiFi password from file

Other:
  --country <code>          WiFi regulatory domain (default: US)
  --skip-reboot             Don't reboot at end (for testing)
  --help                    Show this help

IMPORTANT for ethernet-upstream mode:
  If you're SSH'd in over WiFi (from Raspberry Pi Imager setup), you WILL lose
  connection when wlan0 switches to AP mode. Make sure you have:
  - Physical access to reconnect, OR
  - Ethernet connected (eth0 will remain DHCP client for upstream)

Examples:
  # Ethernet upstream (Pi gets internet via eth0, clients connect to WiFi AP)
  $0 --wg-config peer_gateway.conf --ap-password "MySecurePass123"

  # USB WiFi mode (Pi connects to home WiFi, USB adapter creates AP)
  $0 --mode usb-wifi --wg-config peer.conf --ap-password "MyPass123" \\
     --upstream-ssid "HomeWiFi" --upstream-password "HomePass"

EOF
    exit 0
}

# =============================================================================
# Argument Parsing
# =============================================================================

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --wg-config)
                WG_CONFIG="$2"
                shift 2
                ;;
            --mode)
                MODE="$2"
                if [[ "$MODE" != "ethernet-upstream" && "$MODE" != "usb-wifi" ]]; then
                    die "Invalid mode: $MODE (use 'ethernet-upstream' or 'usb-wifi')"
                fi
                shift 2
                ;;
            --ap-ssid)
                AP_SSID="$2"
                shift 2
                ;;
            --ap-password)
                AP_PASSWORD="$2"
                shift 2
                ;;
            --ap-password-file)
                if [[ -f "$2" ]]; then
                    AP_PASSWORD=$(cat "$2" | tr -d '\n')
                else
                    die "AP password file not found: $2"
                fi
                shift 2
                ;;
            --ap-channel)
                AP_CHANNEL="$2"
                shift 2
                ;;
            --upstream-ssid)
                UPSTREAM_SSID="$2"
                shift 2
                ;;
            --upstream-password)
                UPSTREAM_PASSWORD="$2"
                shift 2
                ;;
            --upstream-password-file)
                if [[ -f "$2" ]]; then
                    UPSTREAM_PASSWORD=$(cat "$2" | tr -d '\n')
                else
                    die "Upstream password file not found: $2"
                fi
                shift 2
                ;;
            --ap-network)
                AP_NETWORK="$2"
                shift 2
                ;;
            --eth-network)
                ETH_NETWORK="$2"
                shift 2
                ;;
            --country)
                COUNTRY="$2"
                shift 2
                ;;
            --skip-reboot)
                SKIP_REBOOT="true"
                shift
                ;;
            --vps-ip)
                VPS_IP="$2"
                shift 2
                ;;
            --region-key)
                REGION_KEY="$2"
                shift 2
                ;;
            --region-password)
                REGION_PASSWORD="$2"
                shift 2
                ;;
            --region-password-file)
                if [[ -f "$2" ]]; then
                    REGION_PASSWORD=$(cat "$2" | tr -d '\n')
                else
                    die "Region password file not found: $2"
                fi
                shift 2
                ;;
            --region-port)
                REGION_PORT="$2"
                shift 2
                ;;
            --skip-region-service)
                SKIP_REGION_SERVICE="true"
                shift
                ;;
            --help|-h)
                usage
                ;;
            *)
                die "Unknown option: $1"
                ;;
        esac
    done

    # Validate required arguments
    if [[ -z "$WG_CONFIG" ]]; then
        die "Missing required argument: --wg-config"
    fi

    if [[ -z "$AP_PASSWORD" ]]; then
        die "Missing required argument: --ap-password"
    fi

    if [[ ${#AP_PASSWORD} -lt 8 ]]; then
        die "AP password must be at least 8 characters"
    fi

    # Validate mode-specific requirements
    if [[ "$MODE" == "usb-wifi" ]]; then
        if [[ -z "$UPSTREAM_SSID" ]]; then
            die "usb-wifi mode requires --upstream-ssid"
        fi
        if [[ -z "$UPSTREAM_PASSWORD" ]]; then
            die "usb-wifi mode requires --upstream-password"
        fi
    fi

    # Set interface names based on mode
    if [[ "$MODE" == "ethernet-upstream" ]]; then
        AP_IFACE="wlan0"
        UPSTREAM_IFACE="eth0"
    else
        # Detect USB WiFi adapter (could be wlan1 or wlx* on Ubuntu)
        if ! AP_IFACE=$(detect_usb_wifi); then
            die "usb-wifi mode requires a USB WiFi adapter but none was found (no wlan1 or wlx* interface)"
        fi
        UPSTREAM_IFACE="wlan0"
        log_info "Detected USB WiFi adapter: $AP_IFACE"
    fi

    # Calculate IPs
    AP_IP=$(get_gateway_ip "$AP_NETWORK")
    ETH_IP=$(get_gateway_ip "$ETH_NETWORK")

    # Log configuration
    log_info "Configuration:"
    log_info "  Mode: $MODE"
    log_info "  AP Interface: $AP_IFACE"
    log_info "  Upstream Interface: $UPSTREAM_IFACE"
    log_info "  AP SSID: $AP_SSID"
    log_info "  AP IP: $AP_IP"
    log_info "  AP Network: $AP_NETWORK"
    if [[ "$MODE" == "usb-wifi" ]]; then
        log_info "  ETH IP: $ETH_IP"
        log_info "  ETH Network: $ETH_NETWORK"
        log_info "  Upstream SSID: $UPSTREAM_SSID"
    fi
}

# =============================================================================
# Pre-flight Checks
# =============================================================================

preflight_checks() {
    log_step "Running pre-flight checks..."

    # Check we're on a Raspberry Pi
    if [[ ! -f /proc/device-tree/model ]]; then
        log_warn "Cannot detect device model - may not be a Raspberry Pi"
    else
        local model
        model=$(cat /proc/device-tree/model | tr -d '\0')
        log_info "Device: $model"
    fi

    # Check OS
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        log_info "OS: $PRETTY_NAME"
    fi

    # Log current network state
    log_network_state

    # Check if wlan0 exists
    if ! ip link show wlan0 &>/dev/null; then
        die "wlan0 interface not found. Is WiFi enabled?"
    fi
    log_info "wlan0 interface found"

    # Check if eth0 exists
    if ! ip link show eth0 &>/dev/null; then
        log_warn "eth0 interface not found - ethernet may not be available"
    else
        log_info "eth0 interface found"
    fi

    # For usb-wifi mode, check for USB WiFi adapter (wlan1 or wlx*)
    if [[ "$MODE" == "usb-wifi" ]]; then
        local usb_wifi
        if ! usb_wifi=$(detect_usb_wifi); then
            die "usb-wifi mode requires a USB WiFi adapter but none was found (no wlan1 or wlx* interface)"
        fi
        log_info "USB WiFi adapter found: $usb_wifi"
    fi

    # Check WireGuard config exists/readable
    if [[ "$WG_CONFIG" != "-" ]]; then
        if [[ ! -f "$WG_CONFIG" ]]; then
            die "WireGuard config not found: $WG_CONFIG"
        fi
        if ! grep -qi "Endpoint" "$WG_CONFIG"; then
            die "WireGuard config missing Endpoint line: $WG_CONFIG"
        fi
        log_info "WireGuard config validated: $WG_CONFIG"
    fi

    # Check internet connectivity (needed for apt)
    log_info "Checking internet connectivity..."
    if ! ping -c 1 -W 5 8.8.8.8 &>/dev/null; then
        log_warn "Cannot ping 8.8.8.8 - internet may not be available"
        if ! ping -c 1 -W 5 1.1.1.1 &>/dev/null; then
            die "No internet connectivity. Cannot proceed with installation."
        fi
    fi
    log_info "Internet connectivity confirmed"

    # Warn about WiFi SSH
    if [[ "$MODE" == "ethernet-upstream" ]]; then
        local current_ip
        current_ip=$(hostname -I | awk '{print $1}')
        local wlan0_ip
        wlan0_ip=$(ip -4 addr show wlan0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")

        if [[ -n "$wlan0_ip" && "$current_ip" == "$wlan0_ip" ]]; then
            log_warn "============================================================"
            log_warn "WARNING: You appear to be connected via WiFi (wlan0)"
            log_warn "Current IP: $wlan0_ip"
            log_warn ""
            log_warn "When this script converts wlan0 to AP mode, your SSH"
            log_warn "connection WILL BE LOST!"
            log_warn ""
            log_warn "After installation completes:"
            log_warn "  1. Connect ethernet cable, OR"
            log_warn "  2. Connect to AP '$AP_SSID' and SSH to $AP_IP"
            log_warn "============================================================"
            sleep 3
        fi
    fi
}

# =============================================================================
# Installation Functions
# =============================================================================

install_packages() {
    log_step "Installing required packages..."

    wait_for_apt

    log_info "Updating package lists..."
    if ! apt-get update >> "$LOG_FILE" 2>&1; then
        log_warn "apt-get update had issues, continuing anyway..."
    fi

    wait_for_apt

    log_info "Installing packages: hostapd dnsmasq wireguard-tools iptables-persistent..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        hostapd \
        dnsmasq \
        wireguard-tools \
        iptables-persistent \
        netfilter-persistent \
        >> "$LOG_FILE" 2>&1 || die "Failed to install packages"

    log_info "Packages installed successfully"
}

disable_conflicting_services() {
    log_step "Disabling conflicting services..."

    # Stop wpa_supplicant for AP interface - this is what breaks the imager WiFi connection
    if [[ "$MODE" == "ethernet-upstream" ]]; then
        log_info "Stopping wpa_supplicant on wlan0 (required for AP mode)..."

        # This will kill your WiFi SSH connection if you're using it!
        systemctl stop wpa_supplicant@wlan0.service 2>/dev/null || true
        systemctl disable wpa_supplicant@wlan0.service 2>/dev/null || true

        # Also stop the default wpa_supplicant
        # Be careful - don't kill it entirely if we need wlan0 as client in usb-wifi mode
        killall wpa_supplicant 2>/dev/null || true

        # Remove the imager-created wpa_supplicant config that auto-connects
        if [[ -f /etc/wpa_supplicant/wpa_supplicant.conf ]]; then
            log_info "Backing up and removing imager wpa_supplicant.conf..."
            mv /etc/wpa_supplicant/wpa_supplicant.conf /etc/wpa_supplicant/wpa_supplicant.conf.backup-$(date +%s)
        fi
    fi

    # Stop services that might conflict during setup
    systemctl stop hostapd 2>/dev/null || true
    systemctl stop dnsmasq 2>/dev/null || true

    # Disable the default dnsmasq instance that conflicts
    if systemctl is-enabled dnsmasq &>/dev/null; then
        log_info "Disabling default dnsmasq (will enable our configured version)"
    fi

    log_info "Conflicting services handled"
}

configure_dhcpcd() {
    log_step "Configuring network interfaces (dhcpcd)..."

    local dhcpcd_conf="/etc/dhcpcd.conf"
    local marker="# === Gateway Configuration ==="
    local end_marker="# === End Gateway ==="

    # Backup original
    if [[ ! -f "${dhcpcd_conf}.original" ]]; then
        cp "$dhcpcd_conf" "${dhcpcd_conf}.original"
        log_info "Backed up original dhcpcd.conf"
    fi

    # Remove old gateway config if present (idempotent)
    if grep -q "$marker" "$dhcpcd_conf" 2>/dev/null; then
        log_info "Removing previous gateway configuration..."
        sed -i "/$marker/,/$end_marker/d" "$dhcpcd_conf"
    fi

    # Add new configuration
    log_info "Adding gateway network configuration..."
    cat >> "$dhcpcd_conf" << EOF

$marker
# Static IP for Access Point interface
interface $AP_IFACE
    static ip_address=${AP_IP}/24
    nohook wpa_supplicant

EOF

    if [[ "$MODE" == "usb-wifi" ]]; then
        cat >> "$dhcpcd_conf" << EOF
# Static IP for Ethernet (DHCP server for wired clients)
interface eth0
    static ip_address=${ETH_IP}/24
    nohook wpa_supplicant

EOF
    fi

    echo "$end_marker" >> "$dhcpcd_conf"

    log_info "dhcpcd configured"
    log_debug "dhcpcd.conf contents:"
    cat "$dhcpcd_conf" >> "$LOG_FILE"
}

configure_netplan() {
    log_step "Configuring network interfaces (netplan)..."

    # Backup existing netplan configs
    mkdir -p /etc/netplan/backup
    cp /etc/netplan/*.yaml /etc/netplan/backup/ 2>/dev/null || true
    log_info "Backed up existing netplan configs to /etc/netplan/backup/"

    # Create gateway netplan config based on mode
    log_info "Creating gateway netplan configuration..."

    if [[ "$MODE" == "usb-wifi" ]]; then
        # In usb-wifi mode:
        # - eth0 is a DHCP SERVER for wired clients (needs static IP)
        # - wlan0 is upstream WiFi CLIENT (DHCP from upstream router)
        # - USB WiFi adapter (wlan1/wlx*) is AP (static IP set manually later)
        cat > /etc/netplan/50-gateway.yaml << EOF
# Gateway network configuration (usb-wifi mode)
# Generated by install.sh at $(date)
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - ${ETH_IP}/24
      dhcp4: false
      dhcp6: false
      optional: true
  wifis:
    wlan0:
      dhcp4: true
      access-points:
        "$UPSTREAM_SSID":
          password: '$UPSTREAM_PASSWORD'
EOF
    else
        # In ethernet-upstream mode:
        # - eth0 is upstream (DHCP client)
        # - wlan0 is AP (static IP set manually later)
        cat > /etc/netplan/50-gateway.yaml << EOF
# Gateway network configuration (ethernet-upstream mode)
# Generated by install.sh at $(date)
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: true
      dhcp6: false
EOF
    fi

    # Set strict permissions (netplan requires 600 for files with WiFi credentials)
    chmod 600 /etc/netplan/50-gateway.yaml

    # Remove any existing wifi config that conflicts (e.g., from cloud-init)
    if [[ -f /etc/netplan/50-cloud-init.yaml ]]; then
        log_info "Removing conflicting cloud-init netplan config..."
        mv /etc/netplan/50-cloud-init.yaml /etc/netplan/backup/ 2>/dev/null || true
    fi

    # Permanently prevent cloud-init from regenerating netplan configs on reboot
    mkdir -p /etc/cloud/cloud.cfg.d
    cat > /etc/cloud/cloud.cfg.d/99-disable-network-config.cfg << 'CLOUDINIT'
network: {config: disabled}
CLOUDINIT
    log_info "Disabled cloud-init network management"

    # Apply netplan
    log_info "Applying netplan configuration..."
    netplan apply >> "$LOG_FILE" 2>&1 || log_warn "netplan apply had warnings"

    # Handle wpa_supplicant and AP interface setup based on mode
    if [[ "$MODE" == "ethernet-upstream" ]]; then
        log_info "Stopping wpa_supplicant for AP mode..."

        # Stop wpa_supplicant - netplan/systemd-networkd starts it for wifi client mode
        systemctl stop wpa_supplicant@wlan0 2>/dev/null || true
        systemctl stop wpa_supplicant 2>/dev/null || true
        killall wpa_supplicant 2>/dev/null || true

        # Disable wpa_supplicant for wlan0
        systemctl disable wpa_supplicant@wlan0 2>/dev/null || true

        # Set static IP on AP interface (hostapd needs this)
        log_info "Setting static IP on $AP_IFACE..."
        ip addr flush dev "$AP_IFACE" 2>/dev/null || true
        ip addr add "${AP_IP}/24" dev "$AP_IFACE"
        ip link set "$AP_IFACE" up
    elif [[ "$MODE" == "usb-wifi" ]]; then
        # For usb-wifi mode: Set static IP on USB WiFi adapter (AP interface)
        # wlan0 stays managed by netplan as upstream WiFi client
        log_info "Setting static IP on AP interface ($AP_IFACE)..."
        ip addr flush dev "$AP_IFACE" 2>/dev/null || true
        ip addr add "${AP_IP}/24" dev "$AP_IFACE"
        ip link set "$AP_IFACE" up
    fi

    log_info "netplan configured"
}

configure_wpa_supplicant() {
    log_step "Configuring wpa_supplicant..."

    if [[ "$MODE" != "usb-wifi" ]]; then
        log_info "Skipping wpa_supplicant (not needed for ethernet-upstream mode)"
        return 0
    fi

    # For netplan systems, WiFi credentials are embedded in netplan config
    # and systemd-networkd manages wpa_supplicant internally.
    # We only need explicit wpa_supplicant config for dhcpcd systems.
    if [[ "$NETWORK_MANAGER" == "netplan" ]]; then
        log_info "Netplan handles wpa_supplicant internally - skipping separate config"
        # Ensure the explicit wpa_supplicant service is disabled to avoid conflicts
        systemctl disable "wpa_supplicant@wlan0.service" 2>/dev/null || true
        systemctl stop "wpa_supplicant@wlan0.service" 2>/dev/null || true
        return 0
    fi

    # For dhcpcd systems, create wpa_supplicant config
    log_info "Configuring wpa_supplicant for upstream WiFi connection (dhcpcd mode)..."

    local wpa_conf="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"

    cat > "$wpa_conf" << EOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$COUNTRY

network={
    ssid="$UPSTREAM_SSID"
    psk="$UPSTREAM_PASSWORD"
    key_mgmt=WPA-PSK
}
EOF

    chmod 600 "$wpa_conf"

    # Enable wpa_supplicant for wlan0 (dhcpcd systems only)
    systemctl enable "wpa_supplicant@wlan0.service" 2>/dev/null || true

    log_info "wpa_supplicant configured for upstream WiFi: $UPSTREAM_SSID"
}

configure_hostapd() {
    log_step "Configuring hostapd (Access Point)..."

    log_info "Creating hostapd configuration..."
    # Use printf to safely write password with special characters (!, @, #, etc.)
    cat > /etc/hostapd/hostapd.conf << HOSTAPD_EOF
# Raspberry Pi Gateway Access Point
# Generated by install.sh at $(date)

# Interface and driver
interface=$AP_IFACE
driver=nl80211

# Network name and security
ssid=$AP_SSID
wpa=2
wpa_key_mgmt=WPA-PSK
wpa_pairwise=CCMP
rsn_pairwise=CCMP

# Wireless settings
hw_mode=g
channel=$AP_CHANNEL
country_code=$COUNTRY

# 802.11n support (Pi 3B+ supports it)
ieee80211n=1
wmm_enabled=1

# Other settings
auth_algs=1
ignore_broadcast_ssid=0

# Logging
logger_syslog=-1
logger_syslog_level=2
logger_stdout=-1
logger_stdout_level=2
HOSTAPD_EOF
    # Write password separately to handle special characters properly
    printf 'wpa_passphrase=%s\n' "$AP_PASSWORD" >> /etc/hostapd/hostapd.conf

    # Point hostapd to config file
    log_info "Configuring hostapd defaults..."
    cat > /etc/default/hostapd << EOF
DAEMON_CONF="/etc/hostapd/hostapd.conf"
EOF

    # Unmask and enable hostapd
    log_info "Enabling hostapd service..."
    systemctl unmask hostapd 2>/dev/null || true
    systemctl enable hostapd

    log_info "hostapd configured for SSID: $AP_SSID on channel $AP_CHANNEL"
}

configure_dnsmasq() {
    log_step "Configuring dnsmasq (DHCP/DNS)..."

    # Backup original config
    if [[ -f /etc/dnsmasq.conf && ! -f /etc/dnsmasq.conf.original ]]; then
        cp /etc/dnsmasq.conf /etc/dnsmasq.conf.original
        log_info "Backed up original dnsmasq.conf"
    fi

    local ap_range
    ap_range=$(get_dhcp_range "$AP_NETWORK")

    log_info "Creating dnsmasq configuration..."
    cat > /etc/dnsmasq.conf << EOF
# Raspberry Pi Gateway DHCP/DNS
# Generated by install.sh at $(date)

# Don't use /etc/resolv.conf - use our DNS servers
no-resolv

# DNS servers (Cloudflare - queries go through WireGuard tunnel)
server=1.1.1.1
server=1.0.0.1

# Bind dynamically - allows interfaces to appear after startup (e.g., eth0 with no cable)
bind-dynamic

# Interface for Access Point
interface=$AP_IFACE

# DHCP for Access Point clients
dhcp-range=interface:$AP_IFACE,$ap_range,255.255.255.0,24h
dhcp-option=interface:$AP_IFACE,option:router,$AP_IP
dhcp-option=interface:$AP_IFACE,option:dns-server,$AP_IP
EOF

    # Add ethernet DHCP if in usb-wifi mode
    if [[ "$MODE" == "usb-wifi" ]]; then
        local eth_range
        eth_range=$(get_dhcp_range "$ETH_NETWORK")

        cat >> /etc/dnsmasq.conf << EOF

# Interface for Ethernet clients
interface=eth0

# DHCP for Ethernet clients
dhcp-range=interface:eth0,$eth_range,255.255.255.0,24h
dhcp-option=interface:eth0,option:router,$ETH_IP
dhcp-option=interface:eth0,option:dns-server,$ETH_IP
EOF
    fi

    cat >> /etc/dnsmasq.conf << EOF

# Don't forward short names
domain-needed
bogus-priv

# Logging (enable for debugging)
#log-queries
#log-dhcp
EOF

    systemctl enable dnsmasq

    log_info "dnsmasq configured"
    log_info "  AP DHCP range: $ap_range"
    if [[ "$MODE" == "usb-wifi" ]]; then
        log_info "  ETH DHCP range: $(get_dhcp_range "$ETH_NETWORK")"
    fi
}

configure_wireguard() {
    log_step "Configuring WireGuard..."

    local wg_conf="/etc/wireguard/wg0.conf"

    # Ensure directory exists
    mkdir -p /etc/wireguard
    chmod 700 /etc/wireguard

    # Read WireGuard config
    if [[ "$WG_CONFIG" == "-" ]]; then
        log_info "Reading WireGuard config from stdin..."
        cat > "$wg_conf"
    elif [[ -f "$WG_CONFIG" ]]; then
        log_info "Copying WireGuard config from: $WG_CONFIG"
        cp "$WG_CONFIG" "$wg_conf"
    else
        die "WireGuard config file not found: $WG_CONFIG"
    fi

    chmod 600 "$wg_conf"

    # Extract and log endpoint info
    local endpoint
    endpoint=$(grep -i "^Endpoint" "$wg_conf" | head -1 | sed 's/.*= *//' | tr -d ' ')
    log_info "VPS Endpoint: $endpoint"

    # Enable WireGuard service
    systemctl enable wg-quick@wg0

    log_info "WireGuard configured"
}

# Add direct route to VPS endpoint to prevent WireGuard routing loops
# When wg-quick sets up AllowedIPs = 0.0.0.0/0, it creates policy routing
# that can accidentally route VPS-bound traffic through the tunnel itself
add_vps_route() {
    log_info "Adding direct route to VPS endpoint..."

    local wg_conf="/etc/wireguard/wg0.conf"
    local vps_endpoint vps_ip vps_port gateway

    # Extract endpoint from config
    vps_endpoint=$(grep -i "^Endpoint" "$wg_conf" | head -1 | sed 's/.*= *//' | tr -d ' ')
    vps_ip=$(echo "$vps_endpoint" | cut -d':' -f1)

    # Resolve hostname if needed
    if ! echo "$vps_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        log_info "Resolving VPS hostname: $vps_ip"
        local resolved_ip
        resolved_ip=$(getent hosts "$vps_ip" | awk '{print $1}' | head -1)
        if [[ -n "$resolved_ip" ]]; then
            vps_ip="$resolved_ip"
        else
            log_warn "Could not resolve VPS hostname, skipping direct route"
            return
        fi
    fi

    if [[ -z "$vps_ip" ]]; then
        log_warn "Could not determine VPS IP for direct route"
        return
    fi

    # Get default gateway
    gateway=$(ip route | grep "^default" | awk '{print $3}' | head -1)

    if [[ -z "$gateway" ]]; then
        log_warn "Could not determine default gateway, skipping direct route"
        return
    fi

    log_info "Adding direct route: $vps_ip via $gateway dev $UPSTREAM_IFACE"
    ip route add "$vps_ip/32" via "$gateway" dev "$UPSTREAM_IFACE" 2>/dev/null || \
        log_debug "Route may already exist"

    # Make route persistent based on network manager
    if [[ "$NETWORK_MANAGER" == "dhcpcd" ]]; then
        log_info "Creating dhcpcd hook for persistent VPS route..."
        cat > /lib/dhcpcd/dhcpcd-hooks/99-vps-route << HOOKEOF
# Add direct route to VPS endpoint when interface gets DHCP lease
# Generated by install.sh at $(date)
if [ "\$interface" = "$UPSTREAM_IFACE" ] && [ "\$reason" = "BOUND" ]; then
    ip route add $vps_ip/32 via \$new_routers dev $UPSTREAM_IFACE 2>/dev/null || true
fi
HOOKEOF
    else
        # For netplan/systemd-networkd
        log_info "Creating networkd-dispatcher hook for persistent VPS route..."
        mkdir -p /etc/networkd-dispatcher/routable.d
        cat > /etc/networkd-dispatcher/routable.d/99-vps-route << HOOKEOF
#!/bin/bash
# Add direct route to VPS endpoint when interface becomes routable
# Generated by install.sh at $(date)
# networkd-dispatcher passes IFACE or iface depending on version
INTERFACE="\${IFACE:-\${iface:-}}"
if [[ "\$INTERFACE" == "$UPSTREAM_IFACE" ]] || [[ -z "\$INTERFACE" ]]; then
    gateway=\$(ip route | grep "^default" | awk '{print \$3}' | head -1)
    if [[ -n "\$gateway" ]]; then
        ip route add $vps_ip/32 via "\$gateway" dev $UPSTREAM_IFACE 2>/dev/null || true
    fi
fi
HOOKEOF
        chmod +x /etc/networkd-dispatcher/routable.d/99-vps-route
    fi

    # Also add PreUp hook to WireGuard config as backup
    # This ensures the VPS route exists before WireGuard tries to connect
    log_info "Adding PreUp hook to WireGuard config..."
    local wg_conf="/etc/wireguard/wg0.conf"
    if [[ -f "$wg_conf" ]] && ! grep -q "PreUp.*$vps_ip" "$wg_conf"; then
        sed -i "/^\[Interface\]/a PreUp = gateway=\$(ip route | grep \"^default\" | awk '{print \$3}' | head -1); ip route add $vps_ip/32 via \$gateway dev $UPSTREAM_IFACE 2>/dev/null || true" "$wg_conf"
    fi

    log_info "VPS direct route configured"
}

# Extract VPS endpoint from WireGuard config for iptables
get_vps_endpoint() {
    local wg_conf="/etc/wireguard/wg0.conf"
    local endpoint

    endpoint=$(grep -i "^Endpoint" "$wg_conf" | head -1 | sed 's/.*= *//' | tr -d ' ')

    if [[ -z "$endpoint" ]]; then
        die "Could not find Endpoint in WireGuard config"
    fi

    echo "$endpoint"
}

configure_ip_forwarding() {
    log_step "Enabling IP forwarding and disabling IPv6..."

    cat > /etc/sysctl.d/99-gateway.conf << EOF
# Raspberry Pi Gateway - IP Forwarding and IPv6 Disable
# Generated by install.sh at $(date)

# Enable IPv4 forwarding for gateway
net.ipv4.ip_forward=1

# Disable IPv6 completely (reduces attack surface, prevents IP leaks)
net.ipv6.conf.all.disable_ipv6=1
net.ipv6.conf.default.disable_ipv6=1
net.ipv6.conf.lo.disable_ipv6=1
net.ipv6.conf.eth0.disable_ipv6=1
net.ipv6.conf.wlan0.disable_ipv6=1
EOF

    sysctl -p /etc/sysctl.d/99-gateway.conf >> "$LOG_FILE" 2>&1

    # Force remove any existing IPv6 addresses
    log_info "Removing any IPv6 addresses from interfaces..."
    ip -6 addr flush dev eth0 2>/dev/null || true
    ip -6 addr flush dev wlan0 2>/dev/null || true

    # Create systemd service to ensure IPv6 stays disabled after boot
    # This handles the race condition where sysctl runs before interfaces exist
    log_info "Creating systemd service to disable IPv6 at boot..."
    cat > /etc/systemd/system/disable-ipv6.service << 'EOF'
[Unit]
Description=Disable IPv6 on all interfaces
After=network-pre.target
Before=network.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for iface in $(ls /sys/class/net/); do sysctl -w net.ipv6.conf.$iface.disable_ipv6=1 2>/dev/null || true; ip -6 addr flush dev $iface 2>/dev/null || true; done'
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable disable-ipv6.service

    # Verify forwarding enabled
    local fwd
    fwd=$(cat /proc/sys/net/ipv4/ip_forward)
    if [[ "$fwd" != "1" ]]; then
        die "Failed to enable IP forwarding"
    fi

    log_info "IP forwarding enabled, IPv6 disabled"
}

create_network_service() {
    log_step "Creating gateway network service for boot resilience..."

    # Create directory for gateway configuration
    mkdir -p /opt/proxy-router/rpi

    # Get VPS IP from WireGuard config if not provided via --vps-ip
    local vps_ip_config="$VPS_IP"
    if [[ -z "$vps_ip_config" ]]; then
        vps_ip_config=$(get_vps_endpoint | cut -d':' -f1)
    fi

    # Create gateway configuration file
    log_info "Creating gateway configuration..."
    cat > /opt/proxy-router/rpi/gateway.conf << GWCONF
# Gateway configuration - generated by install.sh at $(date)
# This file is sourced by setup-network.sh at boot

MODE="$MODE"
AP_IFACE="$AP_IFACE"
AP_IP="$AP_IP"
AP_NETWORK="$AP_NETWORK"
ETH_IP="$ETH_IP"
ETH_NETWORK="$ETH_NETWORK"
UPSTREAM_IFACE="$UPSTREAM_IFACE"
VPS_IP="$vps_ip_config"
REGION_PORT="$REGION_PORT"
GWCONF
    chmod 644 /opt/proxy-router/rpi/gateway.conf

    # Create the network setup script
    log_info "Creating network setup script..."
    cat > /opt/proxy-router/rpi/setup-network.sh << 'NETSCRIPT'
#!/bin/bash
# Gateway network interface setup - runs at boot
# Handles both ethernet-upstream and usb-wifi modes
# Provides bulletproof network initialization

set -o pipefail

# Load configuration
if [[ ! -f /opt/proxy-router/rpi/gateway.conf ]]; then
    echo "ERROR: /opt/proxy-router/rpi/gateway.conf not found"
    exit 1
fi
source /opt/proxy-router/rpi/gateway.conf

LOG_FILE="/var/log/gateway-network.log"
MAX_WAIT=30

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" | tee -a "$LOG_FILE"
}

wait_for_interface() {
    local iface="$1"
    local waited=0
    while [[ $waited -lt $MAX_WAIT ]]; do
        if ip link show "$iface" &>/dev/null; then
            log "Interface $iface found"
            return 0
        fi
        sleep 1
        ((waited++))
    done
    log "WARNING: Interface $iface not found after ${MAX_WAIT}s"
    return 1
}

setup_interface_ip() {
    local iface="$1"
    local ip="$2"
    ip link set "$iface" up 2>/dev/null || true
    # Check if IP already assigned
    if ip addr show "$iface" 2>/dev/null | grep -q "$ip"; then
        log "Interface $iface already has IP $ip"
        return 0
    fi
    ip addr flush dev "$iface" 2>/dev/null || true
    ip addr add "${ip}/24" dev "$iface"
    log "Assigned IP $ip to $iface"
}

# ============ MAIN ============

log "========== Gateway Network Setup Starting =========="
log "Mode: $MODE"
log "AP Interface: $AP_IFACE"
log "Upstream Interface: $UPSTREAM_IFACE"

# --- Setup eth0 based on mode ---
if wait_for_interface eth0; then
    if [[ "$MODE" == "usb-wifi" ]]; then
        # USB WiFi mode: eth0 is DHCP server with static IP
        log "Setting eth0 static IP for DHCP server (USB WiFi mode)..."
        setup_interface_ip eth0 "$ETH_IP"

        # ALSO try DHCP as fallback for emergency SSH access
        # This adds a secondary IP if connected to a router
        log "Attempting DHCP on eth0 for fallback SSH access..."
        # Run in background so it doesn't block boot
        (sleep 5 && timeout 15 dhclient -nw -pf /run/dhclient.eth0.pid eth0 2>/dev/null) &
    else
        # Ethernet-upstream mode: eth0 gets DHCP from router
        log "Ensuring eth0 DHCP client (ethernet-upstream mode)..."
        # netplan should handle this, but ensure dhclient runs as backup
        if ! ip addr show eth0 2>/dev/null | grep -q "inet "; then
            log "No IP on eth0, running dhclient..."
            timeout 30 dhclient eth0 2>/dev/null || log "dhclient failed on eth0"
        else
            log "eth0 already has IP"
        fi
    fi
else
    log "WARNING: eth0 not found"
fi

# --- Setup AP interface ---
log "Setting up AP interface ($AP_IFACE)..."
if wait_for_interface "$AP_IFACE"; then
    setup_interface_ip "$AP_IFACE" "$AP_IP"
else
    log "ERROR: AP interface $AP_IFACE not available!"
    # Don't exit - let hostapd fail with a clear error
fi

# --- USB WiFi mode: Connect to upstream WiFi ---
if [[ "$MODE" == "usb-wifi" ]]; then
    log "Connecting to upstream WiFi (wlan0)..."

    # Ensure systemd-networkd is running (needed for netplan WiFi management)
    systemctl is-active --quiet systemd-networkd || systemctl start systemd-networkd

    # Apply netplan config
    if command -v netplan &>/dev/null; then
        netplan apply 2>&1 | tee -a "$LOG_FILE" || log "netplan apply had issues"
    fi

    # Wait for wlan0 to get IP (max 60 seconds)
    wlan_waited=0
    while [[ $wlan_waited -lt 60 ]]; do
        if ip addr show wlan0 2>/dev/null | grep -q "inet "; then
            log "wlan0 has IP: $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}')"
            break
        fi
        sleep 2
        ((wlan_waited+=2))
    done

    # Recovery: if first attempt failed, restart networkd and retry
    if [[ $wlan_waited -ge 60 ]]; then
        log "WARNING: wlan0 no IP in 60s - restarting systemd-networkd..."
        systemctl restart systemd-networkd
        sleep 5
        netplan apply 2>&1 | tee -a "$LOG_FILE" || true

        wlan_waited=0
        while [[ $wlan_waited -lt 30 ]]; do
            if ip addr show wlan0 2>/dev/null | grep -q "inet "; then
                log "wlan0 recovered: $(ip addr show wlan0 | grep 'inet ' | awk '{print $2}')"
                break
            fi
            sleep 2
            ((wlan_waited+=2))
        done
        [[ $wlan_waited -ge 30 ]] && log "ERROR: wlan0 still no IP after recovery attempt"
    fi
fi

# --- Ensure VPS route exists (needed before WireGuard) ---
if [[ -n "$VPS_IP" ]]; then
    log "Ensuring direct route to VPS ($VPS_IP)..."
    gw=$(ip route | grep "^default" | awk '{print $3}' | head -1)
    if [[ -n "$gw" ]]; then
        ip route add "$VPS_IP/32" via "$gw" dev "$UPSTREAM_IFACE" 2>/dev/null || true
        log "VPS route: $VPS_IP via $gw on $UPSTREAM_IFACE"
    else
        log "WARNING: No default gateway found for VPS route"
    fi
fi

log "========== Gateway Network Setup Complete =========="
exit 0
NETSCRIPT
    chmod 755 /opt/proxy-router/rpi/setup-network.sh

    # Create the systemd service
    log_info "Creating gateway-network.service..."
    cat > /etc/systemd/system/gateway-network.service << 'SVCFILE'
[Unit]
Description=Gateway Network Interface Setup
After=local-fs.target
After=systemd-networkd.service
After=sys-subsystem-net-devices-eth0.device
Wants=systemd-networkd.service
Before=hostapd.service
Before=dnsmasq.service
Before=wg-quick@wg0.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/opt/proxy-router/rpi/setup-network.sh
TimeoutStartSec=120

[Install]
WantedBy=multi-user.target
SVCFILE

    # Create service drop-ins for proper dependency ordering
    log_info "Creating service dependency overrides..."

    # hostapd depends on gateway-network
    mkdir -p /etc/systemd/system/hostapd.service.d
    cat > /etc/systemd/system/hostapd.service.d/gateway.conf << 'DROPINFILE'
[Unit]
After=gateway-network.service
Requires=gateway-network.service
DROPINFILE

    # dnsmasq depends on gateway-network and hostapd
    mkdir -p /etc/systemd/system/dnsmasq.service.d
    cat > /etc/systemd/system/dnsmasq.service.d/gateway.conf << 'DROPINFILE'
[Unit]
After=gateway-network.service
After=hostapd.service
Requires=gateway-network.service
DROPINFILE

    # wg-quick depends on gateway-network
    mkdir -p /etc/systemd/system/wg-quick@wg0.service.d
    cat > /etc/systemd/system/wg-quick@wg0.service.d/gateway.conf << 'DROPINFILE'
[Unit]
After=gateway-network.service
Wants=gateway-network.service
DROPINFILE

    # Reload systemd and enable the service
    systemctl daemon-reload
    systemctl enable gateway-network.service

    log_info "Gateway network service created and enabled"
}

configure_iptables() {
    log_step "Configuring iptables (fail-shut firewall)..."

    local vps_endpoint
    vps_endpoint=$(get_vps_endpoint)

    local vps_ip
    local vps_port

    # Parse endpoint (IP:PORT or HOST:PORT)
    vps_ip=$(echo "$vps_endpoint" | cut -d':' -f1)
    vps_port=$(echo "$vps_endpoint" | cut -d':' -f2)

    # Resolve hostname if needed
    if ! echo "$vps_ip" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$'; then
        log_info "Resolving VPS hostname: $vps_ip"
        local resolved_ip
        resolved_ip=$(getent hosts "$vps_ip" | awk '{print $1}' | head -1)
        if [[ -z "$resolved_ip" ]]; then
            die "Could not resolve VPS hostname: $vps_ip"
        fi
        vps_ip="$resolved_ip"
    fi

    log_info "VPS endpoint for firewall: $vps_ip:$vps_port"

    # Clear existing rules
    log_info "Clearing existing iptables rules..."
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X

    # ==========================================================================
    # DEFAULT POLICIES: DROP EVERYTHING (fail-shut)
    # ==========================================================================
    log_info "Setting default policies to DROP (fail-shut)..."
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP

    # ==========================================================================
    # INPUT: What can come INTO the Pi
    # ==========================================================================
    log_info "Configuring INPUT rules..."

    # Loopback
    iptables -A INPUT -i lo -j ACCEPT

    # Established connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # Allow from AP clients (for DHCP, DNS, SSH, etc)
    iptables -A INPUT -i "$AP_IFACE" -s "$AP_NETWORK" -j ACCEPT

    # Allow from WireGuard tunnel
    iptables -A INPUT -i wg0 -j ACCEPT

    # Allow DHCP requests on AP interface (before client has IP)
    iptables -A INPUT -i "$AP_IFACE" -p udp --dport 67 -j ACCEPT

    # Allow SSH on upstream interface for management
    # This allows you to SSH into the Pi from the upstream network
    iptables -A INPUT -i "$UPSTREAM_IFACE" -p tcp --dport 22 -j ACCEPT

    if [[ "$MODE" == "usb-wifi" ]]; then
        # Allow from Ethernet clients
        iptables -A INPUT -i eth0 -s "$ETH_NETWORK" -j ACCEPT
        iptables -A INPUT -i eth0 -p udp --dport 67 -j ACCEPT
    fi

    # ==========================================================================
    # OUTPUT: What can go OUT from the Pi
    # ==========================================================================
    log_info "Configuring OUTPUT rules..."

    # Loopback
    iptables -A OUTPUT -o lo -j ACCEPT

    # Established connections
    iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    # To AP clients
    iptables -A OUTPUT -o "$AP_IFACE" -d "$AP_NETWORK" -j ACCEPT

    # Through WireGuard tunnel (all traffic to VPN)
    iptables -A OUTPUT -o wg0 -j ACCEPT

    # CRITICAL: Only allow UDP to VPS WireGuard endpoint (nothing else!)
    iptables -A OUTPUT -o "$UPSTREAM_IFACE" -p udp -d "$vps_ip" --dport "$vps_port" -j ACCEPT

    # Allow DHCP client on upstream interface (to get IP from router)
    iptables -A OUTPUT -o "$UPSTREAM_IFACE" -p udp --dport 67 -j ACCEPT

    # Allow SSH responses on upstream interface (for management access)
    iptables -A OUTPUT -o "$UPSTREAM_IFACE" -p tcp --sport 22 -j ACCEPT

    if [[ "$MODE" == "usb-wifi" ]]; then
        # To Ethernet clients
        iptables -A OUTPUT -o eth0 -d "$ETH_NETWORK" -j ACCEPT
    fi

    # ==========================================================================
    # FORWARD: Client traffic routing (all through WireGuard)
    # ==========================================================================
    log_info "Configuring FORWARD rules..."

    # AP clients -> WireGuard only
    iptables -A FORWARD -i "$AP_IFACE" -o wg0 -s "$AP_NETWORK" -j ACCEPT
    iptables -A FORWARD -i wg0 -o "$AP_IFACE" -d "$AP_NETWORK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    if [[ "$MODE" == "usb-wifi" ]]; then
        # Ethernet clients -> WireGuard only
        iptables -A FORWARD -i eth0 -o wg0 -s "$ETH_NETWORK" -j ACCEPT
        iptables -A FORWARD -i wg0 -o eth0 -d "$ETH_NETWORK" -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
    fi

    # ==========================================================================
    # NAT: Masquerade through WireGuard
    # ==========================================================================
    log_info "Configuring NAT..."
    iptables -t nat -A POSTROUTING -o wg0 -j MASQUERADE

    # ==========================================================================
    # Save rules
    # ==========================================================================
    log_info "Saving iptables rules..."
    netfilter-persistent save >> "$LOG_FILE" 2>&1

    log_info "iptables configured with fail-shut rules"
    log_info "  - All traffic BLOCKED by default"
    log_info "  - Only WireGuard UDP to $vps_ip:$vps_port allowed"
    log_info "  - Client traffic forwarded ONLY through wg0"
}

install_management_script() {
    log_step "Installing management tools..."

    cat > /usr/local/bin/gateway-wifi << 'MGMTEOF'
#!/bin/bash
#
# Gateway WiFi Management Script
#

set -euo pipefail

usage() {
    cat << EOF
Gateway WiFi Management

Usage: gateway-wifi <command> [args]

Commands:
  status                    Show gateway status
  scan                      Scan for WiFi networks
  set-ap <ssid> <password>  Change Access Point SSID and password
  set-upstream <ssid> <pw>  Change upstream WiFi network (usb-wifi mode)
  restart                   Restart all gateway services
  logs [minutes]            Show recent logs (default: 10 minutes)
  test                      Test VPN connectivity

EOF
    exit 0
}

cmd_status() {
    echo "=== Gateway Status ==="
    echo

    echo "WireGuard:"
    if systemctl is-active --quiet wg-quick@wg0; then
        echo "  Status: CONNECTED"
        wg show wg0 2>/dev/null | grep -E "(endpoint|latest handshake|transfer)" | sed 's/^/  /'
    else
        echo "  Status: DISCONNECTED"
    fi
    echo

    echo "Access Point (hostapd):"
    if systemctl is-active --quiet hostapd; then
        echo "  Status: Running"
        grep -E "^(ssid|interface|channel)=" /etc/hostapd/hostapd.conf 2>/dev/null | sed 's/^/  /'
    else
        echo "  Status: STOPPED"
    fi
    echo

    echo "DHCP/DNS (dnsmasq):"
    if systemctl is-active --quiet dnsmasq; then
        echo "  Status: Running"
        echo "  Active leases:"
        if [[ -f /var/lib/misc/dnsmasq.leases ]]; then
            cat /var/lib/misc/dnsmasq.leases | awk '{print "    " $3 " (" $4 ") -> " $2}' || echo "    (none)"
        else
            echo "    (no lease file)"
        fi
    else
        echo "  Status: STOPPED"
    fi
    echo

    echo "Network Interfaces:"
    ip -br addr | grep -E "^(wlan|eth|wg)" | sed 's/^/  /'
    echo
}

cmd_scan() {
    echo "Scanning for WiFi networks..."
    iwlist wlan0 scan 2>/dev/null | grep -E "ESSID|Quality|Encryption" | sed 's/^[[:space:]]*//'
}

cmd_set_ap() {
    local ssid="${1:-}"
    local password="${2:-}"

    local hostapd_conf="/etc/hostapd/hostapd.conf"

    if [[ ! -f "$hostapd_conf" ]]; then
        echo "Error: hostapd.conf not found at $hostapd_conf"
        exit 1
    fi

    if [[ -z "$ssid" ]]; then
        echo "Usage: gateway-wifi set-ap <ssid> [password]"
        echo ""
        echo "If password is omitted, the current password is kept."
        echo ""
        echo "Current AP settings:"
        grep -E "^ssid=" "$hostapd_conf" 2>/dev/null
        echo "wpa_passphrase=[hidden]"
        exit 1
    fi

    # Validate password if provided
    if [[ -n "$password" && ${#password} -lt 8 ]]; then
        echo "Error: Password must be at least 8 characters"
        exit 1
    fi

    # Backup current config
    cp "$hostapd_conf" "${hostapd_conf}.backup-$(date +%Y%m%d-%H%M%S)"

    echo "Updating Access Point settings..."
    echo "  SSID: $ssid"

    # Update SSID
    sed -i "s/^ssid=.*/ssid=$ssid/" "$hostapd_conf"

    # Update password only if provided
    if [[ -n "$password" ]]; then
        echo "  Password: [updating]"
        # Remove old password line and add new one (handles special characters)
        sed -i '/^wpa_passphrase=/d' "$hostapd_conf"
        printf 'wpa_passphrase=%s\n' "$password" >> "$hostapd_conf"
    else
        echo "  Password: [unchanged]"
    fi

    echo ""
    echo "Restarting hostapd..."
    systemctl restart hostapd

    sleep 2

    if systemctl is-active --quiet hostapd; then
        echo ""
        echo "Success! Access Point updated."
        echo "  New SSID: $ssid"
        if [[ -n "$password" ]]; then
            echo "  Password: [updated]"
        else
            echo "  Password: [unchanged]"
        fi
        echo ""
        echo "Devices will need to reconnect to the new network."
    else
        echo ""
        echo "Warning: hostapd may have failed to restart."
        echo "Check status with: systemctl status hostapd"
        echo "A backup was saved at: ${hostapd_conf}.backup-*"
    fi
}

cmd_set_upstream() {
    local ssid="${1:-}"
    local password="${2:-}"

    if [[ -z "$ssid" || -z "$password" ]]; then
        echo "Usage: gateway-wifi set-upstream <ssid> <password>"
        exit 1
    fi

    # Check if this is usb-wifi mode via gateway.conf
    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    if [[ "${MODE:-}" != "usb-wifi" ]]; then
        echo "Error: This command is only for usb-wifi mode"
        exit 1
    fi

    echo "Updating upstream WiFi to: $ssid"

    if [[ -f /etc/netplan/50-gateway.yaml ]]; then
        # Netplan (Ubuntu 24.04): update YAML and apply
        local eth_ip="${ETH_IP:-192.168.51.1}"
        cat > /etc/netplan/50-gateway.yaml << NETPLANEOF
# Gateway network configuration (usb-wifi mode)
# Updated at $(date)
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - ${eth_ip}/24
      dhcp4: false
      dhcp6: false
      optional: true
  wifis:
    wlan0:
      dhcp4: true
      access-points:
        "$ssid":
          password: '$password'
NETPLANEOF
        chmod 600 /etc/netplan/50-gateway.yaml
        echo "Applying netplan configuration..."
        netplan apply 2>/dev/null || true
    elif [[ -f /etc/wpa_supplicant/wpa_supplicant-wlan0.conf ]]; then
        # dhcpcd / manual wpa_supplicant (Raspberry Pi OS)
        local wpa_conf="/etc/wpa_supplicant/wpa_supplicant-wlan0.conf"
        local country
        country=$(grep "^country=" "$wpa_conf" 2>/dev/null | cut -d= -f2 || echo "US")
        cat > "$wpa_conf" << WPAEOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$country

network={
    ssid="$ssid"
    psk="$password"
    key_mgmt=WPA-PSK
}
WPAEOF
        chmod 600 "$wpa_conf"
        echo "Restarting wpa_supplicant..."
        systemctl restart wpa_supplicant@wlan0
    else
        echo "Error: No supported network manager found"
        exit 1
    fi

    # Wait for connection
    echo "Waiting for connection..."
    local attempts=0
    while [[ $attempts -lt 10 ]]; do
        sleep 1
        if wpa_cli -i wlan0 status 2>/dev/null | grep -q "wpa_state=COMPLETED"; then
            local connected_ssid
            connected_ssid=$(wpa_cli -i wlan0 status 2>/dev/null | grep "^ssid=" | cut -d= -f2)
            echo "Connected to $connected_ssid"
            return
        fi
        attempts=$((attempts + 1))
    done
    echo "Warning: Connection may still be establishing. Check 'wpa_cli -i wlan0 status'"
}

cmd_restart() {
    echo "Restarting gateway services..."
    echo "  Restarting dhcpcd..."
    systemctl restart dhcpcd
    sleep 2
    echo "  Restarting hostapd..."
    systemctl restart hostapd
    sleep 1
    echo "  Restarting dnsmasq..."
    systemctl restart dnsmasq
    sleep 1
    echo "  Restarting WireGuard..."
    systemctl restart wg-quick@wg0
    sleep 2
    echo "Done. Run 'gateway-wifi status' to verify."
}

cmd_logs() {
    local minutes="${1:-10}"
    echo "=== Gateway Logs (last $minutes minutes) ==="
    journalctl -u hostapd -u dnsmasq -u wg-quick@wg0 --since "$minutes minutes ago" --no-pager
}

cmd_test() {
    echo "=== VPN Connectivity Test ==="
    echo

    echo "1. WireGuard status:"
    if wg show wg0 &>/dev/null; then
        echo "   OK - WireGuard interface is up"
        local handshake
        handshake=$(wg show wg0 latest-handshakes | awk '{print $2}')
        if [[ -n "$handshake" && "$handshake" != "0" ]]; then
            echo "   OK - Last handshake: $(date -d @$handshake 2>/dev/null || echo $handshake)"
        else
            echo "   WARN - No recent handshake"
        fi
    else
        echo "   FAIL - WireGuard interface not found"
    fi
    echo

    echo "2. External IP (through VPN):"
    local ext_ip
    if ext_ip=$(timeout 15 curl -s https://api.ipify.org 2>/dev/null); then
        echo "   External IP: $ext_ip"
        echo "   (This should be a NordVPN IP, not your home IP)"
    else
        echo "   FAIL - Could not reach external IP service"
    fi
    echo

    echo "3. DNS resolution (through VPN):"
    if timeout 5 nslookup google.com &>/dev/null; then
        echo "   OK - DNS working"
    else
        echo "   FAIL - DNS not working"
    fi
    echo
}

# Main
case "${1:-}" in
    status)
        cmd_status
        ;;
    scan)
        cmd_scan
        ;;
    set-ap)
        cmd_set_ap "${2:-}" "${3:-}"
        ;;
    set-upstream)
        cmd_set_upstream "${2:-}" "${3:-}"
        ;;
    restart)
        cmd_restart
        ;;
    logs)
        cmd_logs "${2:-10}"
        ;;
    test)
        cmd_test
        ;;
    *)
        usage
        ;;
esac
MGMTEOF

    chmod +x /usr/local/bin/gateway-wifi

    log_info "Management script installed: /usr/local/bin/gateway-wifi"
}

start_services() {
    log_step "Starting services..."

    # Reload systemd to pick up new service files
    systemctl daemon-reload

    # Start gateway-network service first (handles interface IPs)
    log_info "Starting gateway-network service..."
    if systemctl start gateway-network.service; then
        log_info "Gateway network service started"
    else
        log_warn "Gateway network service had issues, applying IPs manually..."
    fi

    # Apply network configuration based on network manager (backup for gateway-network)
    if [[ "$NETWORK_MANAGER" == "dhcpcd" ]]; then
        log_info "Restarting dhcpcd to apply static IPs..."
        systemctl restart dhcpcd
        sleep 3
    else
        log_info "Ensuring AP interface has static IP..."
        ip addr flush dev "$AP_IFACE" 2>/dev/null || true
        ip addr add "${AP_IP}/24" dev "$AP_IFACE" 2>/dev/null || true
        ip link set "$AP_IFACE" up
        sleep 2

        # For usb-wifi mode, ensure eth0 is up with static IP (dnsmasq needs this)
        if [[ "$MODE" == "usb-wifi" ]]; then
            log_info "Ensuring eth0 has static IP for DHCP server..."
            ip link set eth0 up 2>/dev/null || true
            ip addr flush dev eth0 2>/dev/null || true
            ip addr add "${ETH_IP}/24" dev eth0 2>/dev/null || true
            sleep 1
        fi
    fi

    # Verify AP interface has correct IP
    local ap_actual_ip
    ap_actual_ip=$(ip -4 addr show "$AP_IFACE" 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "")
    if [[ "$ap_actual_ip" != "$AP_IP" ]]; then
        log_warn "AP interface $AP_IFACE has IP $ap_actual_ip, expected $AP_IP"
        log_info "Attempting to set IP manually..."
        ip addr flush dev "$AP_IFACE" 2>/dev/null || true
        ip addr add "${AP_IP}/24" dev "$AP_IFACE" 2>/dev/null || true
    fi

    # Start hostapd
    log_info "Starting hostapd..."
    systemctl start hostapd
    if ! verify_service hostapd 15; then
        log_error "hostapd failed to start. Common issues:"
        log_error "  - Another process using wlan0"
        log_error "  - WiFi hardware not in correct mode"
        log_error "  - Invalid channel for country code"
        die "hostapd failed"
    fi

    # Start dnsmasq
    log_info "Starting dnsmasq..."
    systemctl start dnsmasq
    if ! verify_service dnsmasq 10; then
        log_error "dnsmasq failed to start"
        die "dnsmasq failed"
    fi

    # Start WireGuard
    log_info "Starting WireGuard..."
    systemctl start wg-quick@wg0
    if ! verify_service wg-quick@wg0 15; then
        log_error "WireGuard failed to start"
        die "WireGuard failed"
    fi

    # Verify WireGuard is actually connected
    sleep 3
    if wg show wg0 &>/dev/null; then
        log_info "WireGuard interface is up"
        local endpoint
        endpoint=$(wg show wg0 endpoints | awk '{print $2}')
        log_info "Connected to endpoint: $endpoint"
    else
        log_warn "WireGuard interface may not be fully connected"
    fi

    # Verify WireGuard policy routing is in place (critical for client forwarding)
    # wg-quick creates these rules for AllowedIPs = 0.0.0.0/0
    log_info "Verifying WireGuard policy routing..."
    if ! ip rule list | grep -q "not from all fwmark.*lookup"; then
        log_warn "WireGuard policy routing rules missing, bouncing WireGuard..."
        wg-quick down wg0 2>/dev/null || true
        sleep 2
        wg-quick up wg0
        sleep 2
        if ip rule list | grep -q "not from all fwmark.*lookup"; then
            log_info "WireGuard policy routing now active"
        else
            log_error "WireGuard policy routing still missing after bounce"
        fi
    else
        log_info "WireGuard policy routing is active"
    fi

    log_info "All services started successfully"
}

# =============================================================================
# Region Service Installation
# =============================================================================

install_region_service() {
    if [[ "$SKIP_REGION_SERVICE" == "true" ]]; then
        log_info "Skipping region service installation (--skip-region-service)"
        return 0
    fi

    # Check required parameters
    if [[ -z "$VPS_IP" ]]; then
        log_warn "VPS IP not provided (--vps-ip), skipping region service"
        return 0
    fi

    if [[ -z "$REGION_KEY" ]]; then
        log_warn "Region SSH key not provided (--region-key), skipping region service"
        return 0
    fi

    if [[ ! -f "$REGION_KEY" ]]; then
        log_error "Region SSH key not found: $REGION_KEY"
        return 1
    fi

    if [[ -z "$REGION_PASSWORD" ]]; then
        log_warn "Region password not provided (--region-password), skipping region service"
        return 0
    fi

    log_step "Installing region control service..."

    local REGION_DIR="/opt/proxy-router/rpi/region-service"
    local REGION_PORT="${REGION_PORT:-59420}"

    # Install socat and iw (needed for WiFi scanning) if not present
    wait_for_apt
    local install_pkgs=""
    command -v socat &>/dev/null || install_pkgs="socat"
    command -v iw &>/dev/null || install_pkgs="$install_pkgs iw"
    if [[ -n "$install_pkgs" ]]; then
        log_info "Installing$install_pkgs..."
        run_cmd "Install packages" apt-get install -y $install_pkgs
    fi

    # Create directory structure
    mkdir -p "$REGION_DIR"
    mkdir -p /opt/proxy-router/logs
    chmod 700 "$REGION_DIR"

    # Copy SSH key
    cp "$REGION_KEY" "$REGION_DIR/vps_key"
    chmod 600 "$REGION_DIR/vps_key"

    # Create VPS config
    cat > "$REGION_DIR/vps.conf" << VPSCONF
VPS_IP=$VPS_IP
VPS_PORT=32222
VPSCONF
    chmod 600 "$REGION_DIR/vps.conf"

    # Create password hash
    echo -n "$REGION_PASSWORD" | sha256sum | awk '{print $1}' > "$REGION_DIR/auth.conf"
    chmod 600 "$REGION_DIR/auth.conf"

    # Generate self-signed TLS certificate
    log_info "Generating TLS certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$REGION_DIR/server.key" \
        -out "$REGION_DIR/server.crt" \
        -days 3650 -nodes \
        -subj "/CN=gateway.local/O=ProxyRouter/C=US" \
        -addext "subjectAltName=DNS:gateway.local,IP:${AP_IP}" 2>/dev/null
    chmod 600 "$REGION_DIR/server.key"
    chmod 644 "$REGION_DIR/server.crt"

    # Create HTTP handler script
    cat > "$REGION_DIR/handler.sh" << 'HANDLER'
#!/bin/bash
# Region Service HTTP Handler
# Handles API requests for region switching

set -euo pipefail

REGION_DIR="/opt/proxy-router/rpi/region-service"
LOG_FILE="/opt/proxy-router/logs/region-service.log"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $*" >> "$LOG_FILE"
}

# Load VPS config
source "$REGION_DIR/vps.conf"

# Valid regions
VALID_REGIONS="us uk de nl ch se ca au jp sg fr it es pl ro hk br mx in za"

# Read HTTP request
read_request() {
    read -r REQUEST_METHOD REQUEST_URI HTTP_VERSION 2>/dev/null || true
    REQUEST_METHOD=$(echo "$REQUEST_METHOD" | tr -d '\r')
    REQUEST_URI=$(echo "$REQUEST_URI" | tr -d '\r')

    # Read headers
    CONTENT_LENGTH=0
    AUTH_HEADER=""
    while IFS= read -r line; do
        line=$(echo "$line" | tr -d '\r')
        [[ -z "$line" ]] && break
        if [[ "$line" == Content-Length:* ]]; then
            CONTENT_LENGTH="${line#Content-Length: }"
        elif [[ "$line" == Authorization:* ]]; then
            AUTH_HEADER="${line#Authorization: }"
        fi
    done

    # Read body if present
    REQUEST_BODY=""
    if [[ "$CONTENT_LENGTH" -gt 0 ]]; then
        read -r -n "$CONTENT_LENGTH" REQUEST_BODY 2>/dev/null || true
    fi
}

# Check authentication
check_auth() {
    if [[ -z "$AUTH_HEADER" ]]; then
        return 1
    fi

    # Extract base64 credentials from "Basic <base64>"
    local encoded="${AUTH_HEADER#Basic }"
    local decoded
    decoded=$(echo "$encoded" | base64 -d 2>/dev/null) || return 1

    local user="${decoded%%:*}"
    local pass="${decoded#*:}"

    if [[ "$user" != "admin" ]]; then
        return 1
    fi

    local hash
    hash=$(echo -n "$pass" | sha256sum | awk '{print $1}')
    local stored_hash
    stored_hash=$(cat "$REGION_DIR/auth.conf")

    [[ "$hash" == "$stored_hash" ]]
}

# Send HTTP response
send_response() {
    local status="$1"
    local content_type="$2"
    local body="$3"
    local extra_headers="${4:-}"

    printf "HTTP/1.1 %s\r\n" "$status"
    printf "Content-Type: %s\r\n" "$content_type"
    printf "Content-Length: %d\r\n" "${#body}"
    printf "Connection: close\r\n"
    printf "Access-Control-Allow-Origin: *\r\n"
    if [[ -n "$extra_headers" ]]; then
        printf "%s\r\n" "$extra_headers"
    fi
    printf "\r\n"
    printf "%s" "$body"
}

# SSH to VPS and run region-control command
vps_cmd() {
    local cmd="$1"
    shift
    ssh -p "$VPS_PORT" -i "$REGION_DIR/vps_key" \
        -o ConnectTimeout=15 \
        -o StrictHostKeyChecking=accept-new \
        -o BatchMode=yes \
        "region-changer@$VPS_IP" \
        "/opt/proxy-router/bin/region-control" "$cmd" "$@" 2>&1
}

# API: Get status
api_status() {
    local region ip connected timestamp

    region=$(vps_cmd region 2>/dev/null) || region="unknown"
    ip=$(vps_cmd ip 2>/dev/null) || ip="unknown"

    if [[ "$ip" != "unknown" && -n "$ip" ]]; then
        connected="true"
    else
        connected="false"
    fi

    timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    local port="${REGION_PORT:-59420}"

    printf '{"region":"%s","external_ip":"%s","vpn_connected":%s,"port":%s,"timestamp":"%s"}' \
        "$region" "$ip" "$connected" "$port" "$timestamp"
}

# API: List regions
api_regions() {
    cat << 'REGIONS'
{"regions":[
{"code":"us","name":"United States"},
{"code":"uk","name":"United Kingdom"},
{"code":"de","name":"Germany"},
{"code":"nl","name":"Netherlands"},
{"code":"ch","name":"Switzerland"},
{"code":"se","name":"Sweden"},
{"code":"ca","name":"Canada"},
{"code":"au","name":"Australia"},
{"code":"jp","name":"Japan"},
{"code":"sg","name":"Singapore"},
{"code":"fr","name":"France"},
{"code":"it","name":"Italy"},
{"code":"es","name":"Spain"},
{"code":"pl","name":"Poland"},
{"code":"ro","name":"Romania"},
{"code":"hk","name":"Hong Kong"},
{"code":"br","name":"Brazil"},
{"code":"mx","name":"Mexico"},
{"code":"in","name":"India"},
{"code":"za","name":"South Africa"}
]}
REGIONS
}

# API: Change region
api_change_region() {
    local body="$1"

    # Extract region from JSON (simple parsing without jq)
    local region
    region=$(echo "$body" | grep -oE '"region"\s*:\s*"[^"]+"' | grep -oE '"[^"]+"\s*$' | tr -d '"' | tr -d ' ')

    if [[ -z "$region" ]]; then
        echo '{"success":false,"error":"Missing region parameter"}'
        return
    fi

    # Validate region
    if ! echo "$VALID_REGIONS" | grep -qw "$region"; then
        printf '{"success":false,"error":"Invalid region: %s"}' "$region"
        return
    fi

    log "Changing region to: $region"

    # Get previous region
    local prev_region
    prev_region=$(vps_cmd region 2>/dev/null) || prev_region="unknown"

    # Execute region change (this blocks until complete)
    local output
    if output=$(vps_cmd change "$region" 2>&1); then
        # Wait for connection to stabilize
        sleep 3

        # Get new IP
        local new_ip
        new_ip=$(vps_cmd ip 2>/dev/null) || new_ip="unknown"

        log "Region changed: $prev_region -> $region, new IP: $new_ip"
        printf '{"success":true,"previous_region":"%s","new_region":"%s","new_ip":"%s"}' \
            "$prev_region" "$region" "$new_ip"
    else
        log "Region change failed: $output"
        printf '{"success":false,"error":"Region change failed: %s"}' "$output"
    fi
}

# API: Get WiFi status (usb-wifi mode only)
api_wifi_status() {
    # Check if this is usb-wifi mode via gateway.conf
    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    if [[ "${MODE:-}" != "usb-wifi" ]]; then
        echo '{"available":false,"error":"WiFi management only available in usb-wifi mode"}'
        return
    fi

    local ssid connected signal
    ssid=$(wpa_cli -i wlan0 status 2>/dev/null | grep "^ssid=" | cut -d= -f2 || echo "")

    if [[ -n "$ssid" ]]; then
        connected="true"
        # Get signal strength
        signal=$(iw dev wlan0 link 2>/dev/null | grep "signal:" | awk '{print $2}' || echo "unknown")
    else
        connected="false"
        signal="0"
    fi

    printf '{"available":true,"connected":%s,"ssid":"%s","signal":"%s"}' "$connected" "$ssid" "$signal"
}

# API: Scan WiFi networks (usb-wifi mode only)
api_wifi_scan() {
    # Check if this is usb-wifi mode via gateway.conf
    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    if [[ "${MODE:-}" != "usb-wifi" ]]; then
        echo '{"available":false,"error":"WiFi scanning only available in usb-wifi mode"}'
        return
    fi

    log "Scanning for WiFi networks..."

    # Trigger a scan
    iw dev wlan0 scan trigger 2>/dev/null || true
    sleep 2

    # Get scan results - parse SSID and signal strength
    local networks=""
    local first=true

    while IFS= read -r line; do
        local ssid signal
        ssid=$(echo "$line" | cut -f1)
        signal=$(echo "$line" | cut -f2)

        # Skip empty SSIDs
        [[ -z "$ssid" ]] && continue

        # Escape quotes in SSID
        ssid=$(echo "$ssid" | sed 's/"/\\"/g')

        if [[ "$first" == "true" ]]; then
            first=false
        else
            networks="$networks,"
        fi
        networks="$networks{\"ssid\":\"$ssid\",\"signal\":\"$signal\"}"
    done < <(iw dev wlan0 scan dump 2>/dev/null | awk '
        /^BSS / { signal="" }
        /signal:/ { signal=$2 }
        /SSID:/ {
            ssid=$0;
            sub(/.*SSID: /, "", ssid);
            if (ssid != "" && signal != "") print ssid "\t" signal
        }
    ' | sort -t$'\t' -k2 -nr | head -20)

    echo "{\"available\":true,\"networks\":[$networks]}"
}

# API: Connect to WiFi network (usb-wifi mode only)
api_wifi_connect() {
    local body="$1"

    # Check if this is usb-wifi mode via gateway.conf
    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    if [[ "${MODE:-}" != "usb-wifi" ]]; then
        echo '{"success":false,"error":"WiFi management only available in usb-wifi mode"}'
        return
    fi

    # Extract SSID and password from JSON
    local ssid password
    ssid=$(echo "$body" | grep -oE '"ssid"\s*:\s*"[^"]*"' | sed 's/.*:.*"\([^"]*\)"/\1/')
    password=$(echo "$body" | grep -oE '"password"\s*:\s*"[^"]*"' | sed 's/.*:.*"\([^"]*\)"/\1/')

    if [[ -z "$ssid" ]]; then
        echo '{"success":false,"error":"Missing ssid parameter"}'
        return
    fi

    if [[ -z "$password" ]]; then
        echo '{"success":false,"error":"Missing password parameter"}'
        return
    fi

    log "Connecting to WiFi network: $ssid"

    # Determine which network manager is in use and apply config
    if [[ -f /etc/netplan/50-gateway.yaml ]]; then
        # Netplan (Ubuntu 24.04): update netplan YAML and apply
        local eth_ip="${ETH_IP:-192.168.51.1}"
        cat > /etc/netplan/50-gateway.yaml << NETPLANEOF
# Gateway network configuration (usb-wifi mode)
# Updated at $(date)
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      addresses:
        - ${eth_ip}/24
      dhcp4: false
      dhcp6: false
      optional: true
  wifis:
    wlan0:
      dhcp4: true
      access-points:
        "$ssid":
          password: '$password'
NETPLANEOF
        chmod 600 /etc/netplan/50-gateway.yaml
        netplan apply 2>/dev/null || true
    elif [[ -f /etc/wpa_supplicant/wpa_supplicant-wlan0.conf ]]; then
        # dhcpcd / manual wpa_supplicant (Raspberry Pi OS)
        local country
        country=$(grep "^country=" /etc/wpa_supplicant/wpa_supplicant-wlan0.conf 2>/dev/null | cut -d= -f2 || echo "US")
        cat > /etc/wpa_supplicant/wpa_supplicant-wlan0.conf << WPAEOF
ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
update_config=1
country=$country

network={
    ssid="$ssid"
    psk="$password"
    key_mgmt=WPA-PSK
}
WPAEOF
        chmod 600 /etc/wpa_supplicant/wpa_supplicant-wlan0.conf
        systemctl restart wpa_supplicant@wlan0 2>/dev/null || true
    else
        echo '{"success":false,"error":"No supported network manager found"}'
        return
    fi

    # Wait for connection (works with both netplan and wpa_supplicant)
    local attempts=0
    local max_attempts=20
    while [[ $attempts -lt $max_attempts ]]; do
        sleep 1
        if wpa_cli -i wlan0 status 2>/dev/null | grep -q "wpa_state=COMPLETED"; then
            local new_ip
            new_ip=$(ip -4 addr show wlan0 2>/dev/null | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || echo "acquiring...")
            log "Connected to WiFi: $ssid"
            printf '{"success":true,"ssid":"%s","ip":"%s"}' "$ssid" "$new_ip"
            return
        fi
        attempts=$((attempts + 1))
    done

    log "Failed to connect to WiFi: $ssid"
    echo '{"success":false,"error":"Connection timed out. Check password and try again."}'
}

# API: Change service port
api_change_port() {
    local body="$1"
    local new_port
    new_port=$(echo "$body" | grep -oE '"port"\s*:\s*[0-9]+' | grep -oE '[0-9]+')

    if [[ -z "$new_port" ]]; then
        echo '{"success":false,"error":"Missing port parameter"}'
        return
    fi

    if [[ "$new_port" -lt 1024 || "$new_port" -gt 65535 ]]; then
        echo '{"success":false,"error":"Port must be between 1024-65535"}'
        return
    fi

    source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
    local old_port="${REGION_PORT:-59420}"

    if [[ "$new_port" == "$old_port" ]]; then
        echo '{"success":false,"error":"Already using that port"}'
        return
    fi

    log "Changing port from $old_port to $new_port"

    # Fork background process to do the actual port change after response is sent
    (
        sleep 2

        # Update systemd service file
        sed -i "s/openssl-listen:$old_port/openssl-listen:$new_port/" \
            /opt/proxy-router/rpi/region-service/gateway-region.service

        # Update iptables: swap old port for new
        source /opt/proxy-router/rpi/gateway.conf 2>/dev/null
        local ap_iface="${AP_IFACE:-wlan1}"
        local ap_network="${AP_NETWORK:-192.168.50.0/24}"

        iptables -D INPUT -i "$ap_iface" -s "$ap_network" -p tcp --dport "$old_port" -j ACCEPT 2>/dev/null
        iptables -D OUTPUT -o "$ap_iface" -d "$ap_network" -p tcp --sport "$old_port" -j ACCEPT 2>/dev/null
        iptables -D INPUT -i "$ap_iface" -p tcp --dport "$old_port" -m state --state NEW \
            -m recent --set --name REGION_LIMIT 2>/dev/null
        iptables -D INPUT -i "$ap_iface" -p tcp --dport "$old_port" -m state --state NEW \
            -m recent --update --seconds 60 --hitcount 10 --name REGION_LIMIT -j DROP 2>/dev/null

        iptables -A INPUT -i "$ap_iface" -s "$ap_network" -p tcp --dport "$new_port" -j ACCEPT
        iptables -A OUTPUT -o "$ap_iface" -d "$ap_network" -p tcp --sport "$new_port" -j ACCEPT
        iptables -A INPUT -i "$ap_iface" -p tcp --dport "$new_port" -m state --state NEW \
            -m recent --set --name REGION_LIMIT
        iptables -A INPUT -i "$ap_iface" -p tcp --dport "$new_port" -m state --state NEW \
            -m recent --update --seconds 60 --hitcount 10 --name REGION_LIMIT -j DROP

        iptables-save > /etc/iptables/rules.v4

        # Update gateway.conf
        sed -i "s/REGION_PORT=\"$old_port\"/REGION_PORT=\"$new_port\"/" /opt/proxy-router/rpi/gateway.conf

        # Restart service on new port
        systemctl daemon-reload
        systemctl restart gateway-region

        log "Port changed from $old_port to $new_port"
    ) &>/dev/null &

    printf '{"success":true,"old_port":%s,"new_port":%s}' "$old_port" "$new_port"
}

# Serve web UI
serve_ui() {
    cat "$REGION_DIR/index.html"
}

# Main request handler
main() {
    read_request

    log "Request: $REQUEST_METHOD $REQUEST_URI from client"

    # Check authentication for all requests except OPTIONS
    if [[ "$REQUEST_METHOD" != "OPTIONS" ]]; then
        if ! check_auth; then
            log "Auth failed for $REQUEST_URI"
            send_response "401 Unauthorized" "application/json" '{"error":"Unauthorized"}' 'WWW-Authenticate: Basic realm="Gateway Region Control"'
            return
        fi
    fi

    # Route requests
    case "$REQUEST_URI" in
        /|/index.html)
            send_response "200 OK" "text/html; charset=utf-8" "$(serve_ui)"
            ;;
        /api/status)
            send_response "200 OK" "application/json" "$(api_status)"
            ;;
        /api/regions)
            send_response "200 OK" "application/json" "$(api_regions)"
            ;;
        /api/region)
            if [[ "$REQUEST_METHOD" == "POST" ]]; then
                send_response "200 OK" "application/json" "$(api_change_region "$REQUEST_BODY")"
            else
                send_response "405 Method Not Allowed" "application/json" '{"error":"Use POST"}'
            fi
            ;;
        /api/wifi/status)
            send_response "200 OK" "application/json" "$(api_wifi_status)"
            ;;
        /api/wifi/scan)
            send_response "200 OK" "application/json" "$(api_wifi_scan)"
            ;;
        /api/wifi/connect)
            if [[ "$REQUEST_METHOD" == "POST" ]]; then
                send_response "200 OK" "application/json" "$(api_wifi_connect "$REQUEST_BODY")"
            else
                send_response "405 Method Not Allowed" "application/json" '{"error":"Use POST"}'
            fi
            ;;
        /api/settings/port)
            if [[ "$REQUEST_METHOD" == "POST" ]]; then
                send_response "200 OK" "application/json" "$(api_change_port "$REQUEST_BODY")"
            else
                send_response "405 Method Not Allowed" "application/json" '{"error":"Use POST"}'
            fi
            ;;
        *)
            send_response "404 Not Found" "application/json" '{"error":"Not found"}'
            ;;
    esac
}

main
HANDLER
    chmod +x "$REGION_DIR/handler.sh"

    # Create web UI
    cat > "$REGION_DIR/index.html" << 'WEBUI'
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Gateway Region Control</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: #0f0f1a;
            color: #e0e0e0;
            min-height: 100vh;
            padding: 20px;
        }
        .container { max-width: 500px; margin: 0 auto; }
        h1 {
            text-align: center;
            margin-bottom: 30px;
            color: #fff;
            font-size: 1.5em;
        }
        .card {
            background: #1a1a2e;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 20px;
            border: 1px solid #2a2a4a;
        }
        .card h2 {
            font-size: 0.9em;
            color: #888;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
        }
        .status-row {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px 0;
            border-bottom: 1px solid #2a2a4a;
        }
        .status-row:last-child { border-bottom: none; }
        .status-label { color: #888; }
        .status-value { font-weight: 600; color: #fff; }
        .status-value.connected { color: #4ade80; }
        .status-value.disconnected { color: #f87171; }
        select {
            width: 100%;
            padding: 12px;
            font-size: 16px;
            border-radius: 8px;
            border: 1px solid #3a3a5a;
            background: #0f0f1a;
            color: #fff;
            margin-bottom: 15px;
            cursor: pointer;
        }
        select:focus { outline: none; border-color: #6366f1; }
        button {
            width: 100%;
            padding: 14px;
            font-size: 16px;
            font-weight: 600;
            border: none;
            border-radius: 8px;
            cursor: pointer;
            transition: all 0.2s;
        }
        button.primary {
            background: #6366f1;
            color: #fff;
        }
        button.primary:hover { background: #4f46e5; }
        button.primary:disabled {
            background: #3a3a5a;
            cursor: not-allowed;
        }
        .feedback {
            margin-top: 15px;
            padding: 12px;
            border-radius: 8px;
            text-align: center;
            display: none;
        }
        .feedback.success {
            background: rgba(74, 222, 128, 0.1);
            border: 1px solid #4ade80;
            color: #4ade80;
            display: block;
        }
        .feedback.error {
            background: rgba(248, 113, 113, 0.1);
            border: 1px solid #f87171;
            color: #f87171;
            display: block;
        }
        .feedback.loading {
            background: rgba(99, 102, 241, 0.1);
            border: 1px solid #6366f1;
            color: #6366f1;
            display: block;
        }
        .refresh-btn {
            background: transparent;
            border: 1px solid #3a3a5a;
            color: #888;
            padding: 8px 16px;
            font-size: 14px;
            width: auto;
        }
        .refresh-btn:hover { border-color: #6366f1; color: #6366f1; }
        .header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
        }
        .hidden { display: none !important; }
        input[type="password"] {
            width: 100%;
            padding: 12px;
            font-size: 16px;
            border-radius: 8px;
            border: 1px solid #3a3a5a;
            background: #0f0f1a;
            color: #fff;
            margin-bottom: 15px;
        }
        input[type="password"]:focus { outline: none; border-color: #6366f1; }
        input[type="number"] {
            padding: 12px;
            font-size: 16px;
            border-radius: 8px;
            border: 1px solid #3a3a5a;
            background: #0f0f1a;
            color: #fff;
        }
        input[type="number"]:focus { outline: none; border-color: #6366f1; }
        .wifi-status {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-bottom: 15px;
            padding: 10px;
            background: #0f0f1a;
            border-radius: 8px;
        }
        .wifi-status .dot {
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #f87171;
        }
        .wifi-status .dot.connected { background: #4ade80; }
        .wifi-status .ssid { color: #fff; font-weight: 500; }
        .wifi-status .signal { color: #888; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🌐 Gateway Region Control</h1>

        <div class="card">
            <div class="header">
                <h2>Current Status</h2>
                <button class="refresh-btn" onclick="refreshStatus()">↻ Refresh</button>
            </div>
            <div class="status-row">
                <span class="status-label">Region</span>
                <span class="status-value" id="current-region">Loading...</span>
            </div>
            <div class="status-row">
                <span class="status-label">External IP</span>
                <span class="status-value" id="current-ip">Loading...</span>
            </div>
            <div class="status-row">
                <span class="status-label">VPN Status</span>
                <span class="status-value" id="vpn-status">Loading...</span>
            </div>
        </div>

        <div class="card">
            <h2>Change Region</h2>
            <select id="region-select">
                <option value="">Select a region...</option>
            </select>
            <button class="primary" id="change-btn" onclick="changeRegion()">
                Change Region
            </button>
            <div class="feedback" id="feedback"></div>
        </div>

        <div class="card hidden" id="wifi-card">
            <div class="header">
                <h2>Upstream WiFi</h2>
                <button class="refresh-btn" onclick="scanWifi()">↻ Scan</button>
            </div>
            <div class="wifi-status" id="wifi-status">
                <span class="dot" id="wifi-dot"></span>
                <span class="ssid" id="wifi-ssid">Checking...</span>
                <span class="signal" id="wifi-signal"></span>
            </div>
            <select id="wifi-select">
                <option value="">Select a network...</option>
            </select>
            <input type="password" id="wifi-password" placeholder="WiFi Password">
            <button class="primary" id="wifi-connect-btn" onclick="connectWifi()">
                Connect
            </button>
            <div class="feedback" id="wifi-feedback"></div>
        </div>

        <div class="card">
            <h2>Settings</h2>
            <div class="status-row">
                <span class="status-label">Service Port</span>
                <span class="status-value" id="current-port">Loading...</span>
            </div>
            <div style="display:flex;gap:8px;align-items:center;margin-top:15px">
                <input type="number" id="port-input" placeholder="New port (1024-65535)"
                       min="1024" max="65535" style="flex:1">
                <button class="primary" id="port-btn" onclick="changePort()"
                        style="white-space:nowrap;width:auto;padding:12px 20px">Change Port</button>
            </div>
            <div class="feedback" id="port-feedback"></div>
        </div>
    </div>

    <script>
        const regionNames = {
            us: 'United States', uk: 'United Kingdom', de: 'Germany',
            nl: 'Netherlands', ch: 'Switzerland', se: 'Sweden',
            ca: 'Canada', au: 'Australia', jp: 'Japan', sg: 'Singapore',
            fr: 'France', it: 'Italy', es: 'Spain', pl: 'Poland',
            ro: 'Romania', hk: 'Hong Kong', br: 'Brazil', mx: 'Mexico',
            in: 'India', za: 'South Africa'
        };

        async function fetchAPI(endpoint, options = {}) {
            const response = await fetch(endpoint, {
                ...options,
                headers: { 'Content-Type': 'application/json', ...options.headers }
            });
            return response.json();
        }

        async function refreshStatus() {
            try {
                const data = await fetchAPI('/api/status');
                document.getElementById('current-region').textContent =
                    regionNames[data.region] || data.region || 'Unknown';
                document.getElementById('current-ip').textContent =
                    data.external_ip || 'Unknown';
                const statusEl = document.getElementById('vpn-status');
                if (data.vpn_connected) {
                    statusEl.textContent = 'Connected';
                    statusEl.className = 'status-value connected';
                } else {
                    statusEl.textContent = 'Disconnected';
                    statusEl.className = 'status-value disconnected';
                }
                document.getElementById('current-port').textContent = data.port || 'Unknown';
            } catch (e) {
                console.error('Status fetch failed:', e);
            }
        }

        async function loadRegions() {
            try {
                const data = await fetchAPI('/api/regions');
                const select = document.getElementById('region-select');
                data.regions.forEach(r => {
                    const opt = document.createElement('option');
                    opt.value = r.code;
                    opt.textContent = r.name;
                    select.appendChild(opt);
                });
            } catch (e) {
                console.error('Regions fetch failed:', e);
            }
        }

        async function changeRegion() {
            const select = document.getElementById('region-select');
            const region = select.value;
            const feedback = document.getElementById('feedback');
            const btn = document.getElementById('change-btn');

            if (!region) {
                feedback.textContent = 'Please select a region';
                feedback.className = 'feedback error';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Changing...';
            feedback.textContent = 'Connecting to ' + regionNames[region] + '... This may take 15-20 seconds.';
            feedback.className = 'feedback loading';

            try {
                const data = await fetchAPI('/api/region', {
                    method: 'POST',
                    body: JSON.stringify({ region })
                });

                if (data.success) {
                    feedback.textContent = 'Changed to ' + regionNames[region] + '. New IP: ' + data.new_ip;
                    feedback.className = 'feedback success';
                    setTimeout(refreshStatus, 1000);
                } else {
                    feedback.textContent = data.error || 'Failed to change region';
                    feedback.className = 'feedback error';
                }
            } catch (e) {
                feedback.textContent = 'Request failed: ' + e.message;
                feedback.className = 'feedback error';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Change Region';
            }
        }

        // WiFi Functions
        async function checkWifiAvailable() {
            try {
                const data = await fetchAPI('/api/wifi/status');
                if (data.available) {
                    document.getElementById('wifi-card').classList.remove('hidden');
                    updateWifiStatus(data);
                    scanWifi();
                }
            } catch (e) {
                console.error('WiFi status check failed:', e);
            }
        }

        function updateWifiStatus(data) {
            const dot = document.getElementById('wifi-dot');
            const ssid = document.getElementById('wifi-ssid');
            const signal = document.getElementById('wifi-signal');

            if (data.connected) {
                dot.classList.add('connected');
                ssid.textContent = data.ssid || 'Connected';
                signal.textContent = data.signal ? data.signal + ' dBm' : '';
            } else {
                dot.classList.remove('connected');
                ssid.textContent = 'Not connected';
                signal.textContent = '';
            }
        }

        async function scanWifi() {
            const select = document.getElementById('wifi-select');
            select.innerHTML = '<option value="">Scanning...</option>';
            select.disabled = true;

            try {
                const data = await fetchAPI('/api/wifi/scan');
                select.innerHTML = '<option value="">Select a network...</option>';

                if (data.networks && data.networks.length > 0) {
                    // Remove duplicates and sort by signal
                    const seen = new Set();
                    data.networks.forEach(n => {
                        if (n.ssid && !seen.has(n.ssid)) {
                            seen.add(n.ssid);
                            const opt = document.createElement('option');
                            opt.value = n.ssid;
                            opt.textContent = n.ssid + ' (' + n.signal + ' dBm)';
                            select.appendChild(opt);
                        }
                    });
                }
            } catch (e) {
                select.innerHTML = '<option value="">Scan failed</option>';
                console.error('WiFi scan failed:', e);
            } finally {
                select.disabled = false;
            }
        }

        async function connectWifi() {
            const select = document.getElementById('wifi-select');
            const password = document.getElementById('wifi-password');
            const feedback = document.getElementById('wifi-feedback');
            const btn = document.getElementById('wifi-connect-btn');

            const ssid = select.value;
            if (!ssid) {
                feedback.textContent = 'Please select a network';
                feedback.className = 'feedback error';
                return;
            }

            if (!password.value) {
                feedback.textContent = 'Please enter the WiFi password';
                feedback.className = 'feedback error';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Connecting...';
            feedback.textContent = 'Connecting to ' + ssid + '...';
            feedback.className = 'feedback loading';

            try {
                const data = await fetchAPI('/api/wifi/connect', {
                    method: 'POST',
                    body: JSON.stringify({ ssid: ssid, password: password.value })
                });

                if (data.success) {
                    feedback.textContent = 'Connected to ' + ssid;
                    feedback.className = 'feedback success';
                    password.value = '';
                    // Refresh WiFi status
                    setTimeout(async () => {
                        const status = await fetchAPI('/api/wifi/status');
                        updateWifiStatus(status);
                    }, 2000);
                } else {
                    feedback.textContent = data.error || 'Connection failed';
                    feedback.className = 'feedback error';
                }
            } catch (e) {
                feedback.textContent = 'Request failed: ' + e.message;
                feedback.className = 'feedback error';
            } finally {
                btn.disabled = false;
                btn.textContent = 'Connect';
            }
        }

        async function changePort() {
            const input = document.getElementById('port-input');
            const port = parseInt(input.value);
            const feedback = document.getElementById('port-feedback');
            const btn = document.getElementById('port-btn');

            if (!port || port < 1024 || port > 65535) {
                feedback.textContent = 'Port must be between 1024-65535';
                feedback.className = 'feedback error';
                return;
            }

            btn.disabled = true;
            btn.textContent = 'Changing...';
            feedback.textContent = 'Switching to port ' + port + '...';
            feedback.className = 'feedback loading';

            try {
                const data = await fetchAPI('/api/settings/port', {
                    method: 'POST',
                    body: JSON.stringify({ port: port })
                });

                if (data.success) {
                    feedback.textContent = 'Port changed to ' + data.new_port + '. Redirecting...';
                    feedback.className = 'feedback success';
                    setTimeout(function() {
                        window.location.href = 'https://' + window.location.hostname + ':' + data.new_port;
                    }, 5000);
                } else {
                    feedback.textContent = data.error || 'Failed to change port';
                    feedback.className = 'feedback error';
                    btn.disabled = false;
                    btn.textContent = 'Change Port';
                }
            } catch (e) {
                feedback.textContent = 'Connection error';
                feedback.className = 'feedback error';
                btn.disabled = false;
                btn.textContent = 'Change Port';
            }
        }

        // Initialize
        refreshStatus();
        loadRegions();
        checkWifiAvailable();
        setInterval(refreshStatus, 60000);
    </script>
</body>
</html>
WEBUI

    # Create systemd service
    cat > "$REGION_DIR/gateway-region.service" << SVCFILE
[Unit]
Description=Gateway Region Control Service
After=network.target wg-quick@wg0.service

[Service]
Type=simple
WorkingDirectory=$REGION_DIR
ExecStart=/usr/bin/socat openssl-listen:$REGION_PORT,cert=$REGION_DIR/server.crt,key=$REGION_DIR/server.key,verify=0,fork,reuseaddr EXEC:$REGION_DIR/handler.sh
Restart=always
RestartSec=5
StandardOutput=append:/opt/proxy-router/logs/region-service.log
StandardError=append:/opt/proxy-router/logs/region-service.log

[Install]
WantedBy=multi-user.target
SVCFILE

    # Symlink service file
    ln -sf "$REGION_DIR/gateway-region.service" /etc/systemd/system/gateway-region.service

    # Add iptables rules for region service (only from AP network)
    log_info "Adding iptables rules for region service..."
    iptables -A INPUT -i "$AP_IFACE" -s "$AP_NETWORK" -p tcp --dport "$REGION_PORT" -j ACCEPT
    iptables -A OUTPUT -o "$AP_IFACE" -d "$AP_NETWORK" -p tcp --sport "$REGION_PORT" -j ACCEPT

    # Add iptables rules for SSH to VPS (required for region control)
    log_info "Adding iptables rules for SSH to VPS..."
    iptables -A OUTPUT -o "$UPSTREAM_IFACE" -p tcp -d "$VPS_IP" --dport 32222 -j ACCEPT
    iptables -A INPUT -i "$UPSTREAM_IFACE" -p tcp -s "$VPS_IP" --sport 32222 -j ACCEPT

    # Rate limiting (10 connections per minute per IP)
    iptables -A INPUT -i "$AP_IFACE" -p tcp --dport "$REGION_PORT" -m state --state NEW \
        -m recent --set --name REGION_LIMIT
    iptables -A INPUT -i "$AP_IFACE" -p tcp --dport "$REGION_PORT" -m state --state NEW \
        -m recent --update --seconds 60 --hitcount 10 --name REGION_LIMIT -j DROP

    # Save iptables rules
    iptables-save > /etc/iptables/rules.v4

    # Enable and start service
    systemctl daemon-reload
    systemctl enable gateway-region
    systemctl start gateway-region

    # Verify service started
    sleep 2
    if systemctl is-active --quiet gateway-region; then
        log_info "Region service started on port $REGION_PORT"
    else
        log_error "Region service failed to start"
        journalctl -u gateway-region -n 10 --no-pager | tee -a "$LOG_FILE"
    fi

    # Test SSH connectivity to VPS
    log_info "Testing SSH connectivity to VPS..."
    if ssh -p 32222 -i "$REGION_DIR/vps_key" \
        -o ConnectTimeout=10 \
        -o StrictHostKeyChecking=accept-new \
        -o BatchMode=yes \
        "region-changer@$VPS_IP" \
        "/opt/proxy-router/bin/region-control" region &>/dev/null; then
        log_info "SSH to VPS region-changer successful"
    else
        log_warn "Could not connect to VPS region-changer - check key and VPS setup"
    fi
}

print_summary() {
    local vps_endpoint
    vps_endpoint=$(get_vps_endpoint)

    echo ""
    echo "=============================================================================="
    echo "  Raspberry Pi Gateway Installation Complete"
    echo "=============================================================================="
    echo ""
    echo "Mode: $MODE"
    echo ""
    echo "Access Point:"
    echo "  SSID: $AP_SSID"
    echo "  Password: [hidden - see install command]"
    echo "  Interface: $AP_IFACE"
    echo "  Gateway IP: $AP_IP"
    echo "  Network: $AP_NETWORK"
    echo ""

    if [[ "$MODE" == "usb-wifi" ]]; then
        echo "Ethernet DHCP Server:"
        echo "  Interface: eth0"
        echo "  Gateway IP: $ETH_IP"
        echo "  Network: $ETH_NETWORK"
        echo ""
        echo "Upstream WiFi:"
        echo "  SSID: $UPSTREAM_SSID"
        echo ""
    else
        echo "Upstream: eth0 (DHCP client - connect to router)"
        echo ""
    fi

    echo "WireGuard VPN:"
    echo "  Endpoint: $vps_endpoint"
    echo ""

    if [[ -n "$VPS_IP" && -n "$REGION_KEY" && "$SKIP_REGION_SERVICE" != "true" ]]; then
        echo "Region Control Service:"
        echo "  Web UI: https://$AP_IP:$REGION_PORT"
        echo "  User: admin"
        echo "  Password: [hidden - see install command]"
        echo ""
        echo "  curl example:"
        echo "    curl -sk -u admin:pass https://$AP_IP:$REGION_PORT/api/status"
        echo ""
    fi

    echo "Management Commands:"
    echo "  gateway-wifi status  - Show status of all services"
    echo "  gateway-wifi test    - Test VPN connectivity"
    echo "  gateway-wifi restart - Restart all services"
    echo "  gateway-wifi logs    - View recent logs"
    echo ""
    echo "=============================================================================="
    echo "  Next Steps"
    echo "=============================================================================="
    echo ""
    echo "1. Connect a device to WiFi network '$AP_SSID'"
    echo ""
    echo "2. Verify VPN is working:"
    echo "   curl https://api.ipify.org"
    echo "   (Should show NordVPN IP, NOT your home IP)"
    echo ""
    echo "3. Test fail-shut (on this Pi):"
    echo "   sudo wg-quick down wg0"
    echo "   (Client should LOSE connectivity - not leak real IP)"
    echo "   sudo wg-quick up wg0"
    echo "   (Connectivity restored)"
    echo ""
    echo "Installation log: $LOG_FILE"
    echo ""
}

# =============================================================================
# Main
# =============================================================================

main() {
    # Start logging
    echo "" >> "$LOG_FILE"
    echo "=============================================================================" >> "$LOG_FILE"
    echo "Gateway Install Started: $(date)" >> "$LOG_FILE"
    echo "Command: $0 $*" >> "$LOG_FILE"
    echo "=============================================================================" >> "$LOG_FILE"

    if [[ $EUID -ne 0 ]]; then
        die "This script must be run as root (use sudo)"
    fi

    parse_args "$@"

    # Detect OS and network manager type
    detect_os

    log "Starting Raspberry Pi Gateway installation..."
    log "Log file: $LOG_FILE"

    preflight_checks
    install_packages
    disable_conflicting_services

    # Configure network based on detected network manager
    if [[ "$NETWORK_MANAGER" == "netplan" ]]; then
        configure_netplan
    else
        configure_dhcpcd
    fi

    configure_wpa_supplicant
    configure_hostapd
    configure_dnsmasq
    configure_wireguard

    # Add direct route to VPS to prevent routing loops
    add_vps_route

    configure_ip_forwarding
    create_network_service
    configure_iptables
    install_management_script
    start_services

    # Install region service if configured
    install_region_service

    print_summary

    # Log completion
    log "Installation completed successfully at $(date)"

    if [[ "$SKIP_REBOOT" != "true" ]]; then
        echo ""
        echo "A reboot is recommended to ensure all services start correctly."
        echo "Reboot now? [y/N] "
        read -r response
        if [[ "$response" =~ ^[Yy]$ ]]; then
            log "Rebooting..."
            reboot
        else
            log "Skipping reboot. Run 'sudo reboot' when ready."
        fi
    fi
}

main "$@"
