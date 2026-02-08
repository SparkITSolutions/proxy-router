#!/bin/bash
# VPS Install Script - Self-contained, Fully Automated
# One-liner bootstrap for proxy router VPS node
#
# Usage (interactive):
#   curl -sSL https://raw.githubusercontent.com/SparkITSolutions/proxy-router/main/vps/install.sh | sudo bash
#
# Usage (fully automated):
#   curl -sSL ... | sudo bash -s -- --token YOUR_TOKEN --region uk --ssh-port 32222
#
# CLI Options:
#   --token, -t       NordVPN token (required for non-interactive)
#   --region, -r      VPN region (default: us)
#   --ssh-port        SSH port (default: 32222)
#   --wg-port         WireGuard port (default: 51820)

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step() { echo -e "${BLUE}[STEP]${NC} $1"; }

# =============================================================================
# Parse CLI Arguments
# =============================================================================
NORDVPN_TOKEN="${NORDVPN_TOKEN:-}"
NORDVPN_REGION="${NORDVPN_REGION:-us}"
SSH_PORT="${SSH_PORT:-32222}"
WG_PORT="${WG_PORT:-51820}"

while [[ $# -gt 0 ]]; do
    case $1 in
        --token|-t)
            NORDVPN_TOKEN="$2"
            shift 2
            ;;
        --region|-r)
            NORDVPN_REGION="$2"
            shift 2
            ;;
        --ssh-port)
            SSH_PORT="$2"
            shift 2
            ;;
        --wg-port)
            WG_PORT="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --token, -t TOKEN    NordVPN access token (required)"
            echo "  --region, -r REGION  VPN region (default: us)"
            echo "  --ssh-port PORT      SSH port (default: 32222)"
            echo "  --wg-port PORT       WireGuard port (default: 51820)"
            echo ""
            echo "Example:"
            echo "  $0 --token abc123 --region uk --ssh-port 32222"
            exit 0
            ;;
        *)
            log_error "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

echo ""
echo "=============================================="
echo "  Proxy Router VPS Node Installation"
echo "=============================================="
echo ""

# =============================================================================
# Wait for dpkg lock (handles unattended-upgrades, etc.)
# =============================================================================
wait_for_apt() {
    local max_wait=300  # 5 minutes max
    local waited=0

    while fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || \
          fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || \
          fuser /var/lib/dpkg/lock >/dev/null 2>&1; do
        if [[ $waited -eq 0 ]]; then
            log_info "Waiting for apt/dpkg lock (another process is running)..."
        fi
        sleep 5
        waited=$((waited + 5))
        if [[ $waited -ge $max_wait ]]; then
            log_error "Timed out waiting for apt lock after ${max_wait}s"
            exit 1
        fi
    done

    if [[ $waited -gt 0 ]]; then
        log_info "Lock released after ${waited}s"
    fi
}

# =============================================================================
# Step 1: Gather Configuration
# =============================================================================
log_step "Gathering configuration..."

# NordVPN Token - prompt only if not provided
if [[ -z "$NORDVPN_TOKEN" ]]; then
    echo "Get your NordVPN token from: https://my.nordaccount.com/dashboard/nordvpn/access-tokens/"
    read -p "Enter NordVPN token: " NORDVPN_TOKEN
fi

if [[ -z "$NORDVPN_TOKEN" ]]; then
    log_error "NordVPN token is required. Use --token or set NORDVPN_TOKEN env var"
    exit 1
fi

echo ""
log_info "Configuration:"
echo "  NordVPN Region: $NORDVPN_REGION"
echo "  SSH Port: $SSH_PORT"
echo "  WireGuard Port: $WG_PORT"
echo ""

# =============================================================================
# Step 2: System Updates & Dependencies
# =============================================================================
log_step "Installing dependencies..."

wait_for_apt
apt-get update -qq

wait_for_apt
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    curl wget gnupg ca-certificates \
    fail2ban ufw \
    wireguard-tools

# =============================================================================
# Step 3: Basic Hardening (SSH port change with safety measures)
# =============================================================================
log_step "Applying basic hardening..."

# SAFETY: Change SSH port FIRST, before touching firewall
# This ensures we don't lock ourselves out

change_ssh_port() {
    local target_port="$1"

    # Check if already listening on target port
    if ss -tlnp | grep -q ":${target_port} "; then
        log_info "SSH already listening on port $target_port"
        return 0
    fi

    log_info "Changing SSH to port $target_port..."

    # Update sshd_config
    if grep -q "^Port " /etc/ssh/sshd_config; then
        sed -i "s/^Port .*/Port $target_port/" /etc/ssh/sshd_config
    elif grep -q "^#Port " /etc/ssh/sshd_config; then
        sed -i "s/^#Port .*/Port $target_port/" /etc/ssh/sshd_config
    else
        echo "Port $target_port" >> /etc/ssh/sshd_config
    fi

    # Handle Ubuntu 22.04+ socket activation
    if systemctl is-active ssh.socket &>/dev/null; then
        log_info "Configuring SSH socket for port change..."

        # Create override for ssh.socket to use new port on BOTH IPv4 and IPv6
        mkdir -p /etc/systemd/system/ssh.socket.d
        cat > /etc/systemd/system/ssh.socket.d/override.conf << SOCKETEOF
[Socket]
ListenStream=
ListenStream=0.0.0.0:$target_port
ListenStream=[::]:$target_port
SOCKETEOF

        # Reload and restart
        systemctl daemon-reload
        systemctl restart ssh.socket
        sleep 3
    else
        # Traditional service restart
        systemctl restart sshd 2>/dev/null || systemctl restart ssh
        sleep 2
    fi

    # Verify with retries
    local retries=5
    for i in $(seq 1 $retries); do
        if ss -tlnp | grep -q ":${target_port} "; then
            log_info "SSH now listening on port $target_port"
            return 0
        fi
        log_warn "Waiting for SSH to start on port $target_port... ($i/$retries)"
        sleep 2
    done

    log_error "CRITICAL: SSH failed to start on port $target_port"
    log_error "Current SSH status:"
    ss -tlnp | grep ssh || true
    systemctl status ssh.socket 2>/dev/null || systemctl status sshd 2>/dev/null || systemctl status ssh 2>/dev/null || true
    return 1
}

# Change SSH port FIRST
if ! change_ssh_port "$SSH_PORT"; then
    log_error "SSH port change failed - aborting to prevent lockout"
    log_error "SSH is still available on its current port"
    exit 1
fi

# SAFETY: Verify we can still see SSH listening before touching firewall
if ! ss -tlnp | grep -q ":${SSH_PORT} "; then
    log_error "CRITICAL: Cannot verify SSH on port $SSH_PORT - aborting"
    exit 1
fi

log_info "SSH verified on port $SSH_PORT - now configuring firewall"

# Configure UFW - add rules BEFORE enabling
# SAFETY: Also allow port 22 temporarily in case something goes wrong
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp comment 'SSH-fallback'
ufw allow "$SSH_PORT"/tcp comment 'SSH'
ufw allow "$WG_PORT"/udp comment 'WireGuard'

# Enable UFW
ufw --force enable

# Verify UFW is allowing our SSH port
if ufw status | grep -q "$SSH_PORT/tcp"; then
    log_info "UFW configured - port $SSH_PORT is allowed"
else
    log_error "UFW may not have the SSH rule - adding again"
    ufw allow "$SSH_PORT"/tcp
fi

# Configure fail2ban (after SSH port is confirmed working)
cat > /etc/fail2ban/jail.local << EOF
[sshd]
enabled = true
port = $SSH_PORT
maxretry = 3
bantime = 3600
EOF
systemctl enable fail2ban
systemctl restart fail2ban

log_info "SSH on port $SSH_PORT, fail2ban and UFW configured"
log_warn "Port 22 is also open as fallback - remove later with: ufw delete allow 22/tcp"

# =============================================================================
# Step 4: Install Docker
# =============================================================================
log_step "Installing Docker..."

if ! command -v docker &>/dev/null; then
    wait_for_apt
    curl -fsSL https://get.docker.com | sh
    systemctl enable docker
    systemctl start docker
fi

if ! docker compose version &>/dev/null; then
    wait_for_apt
    apt-get install -y -qq docker-compose-plugin
fi

log_info "Docker installed"

# =============================================================================
# Step 5: Create Directory Structure
# =============================================================================
log_step "Setting up proxy-router..."

INSTALL_DIR="/opt/proxy-router"
mkdir -p "$INSTALL_DIR"/{vps/docker/nordvpn,config/wireguard,keys}
cd "$INSTALL_DIR"

# =============================================================================
# Step 6: Generate WireGuard Keys
# =============================================================================
log_step "Generating WireGuard keys..."

# Only generate if not already present
if [[ ! -f keys/server_private.key ]]; then
    wg genkey | tee keys/server_private.key | wg pubkey > keys/server_public.key
    wg genkey | tee keys/client_private.key | wg pubkey > keys/client_public.key
    wg genpsk > keys/preshared.key
    chmod 600 keys/*.key
fi

SERVER_PRIVATE=$(cat keys/server_private.key)
SERVER_PUBLIC=$(cat keys/server_public.key)
CLIENT_PRIVATE=$(cat keys/client_private.key)
CLIENT_PUBLIC=$(cat keys/client_public.key)
PRESHARED=$(cat keys/preshared.key)

# Get public IP
VPS_PUBLIC_IP=$(curl -s --max-time 10 https://api.ipify.org || hostname -I | awk '{print $1}')

log_info "Keys generated, VPS IP: $VPS_PUBLIC_IP"

# =============================================================================
# Step 7: Create NordVPN Dockerfile
# =============================================================================
log_step "Creating Docker configuration..."

cat > vps/docker/nordvpn/Dockerfile << 'DOCKERFILE'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies first (wireguard-tools needed for wg command to set fwmark)
RUN apt-get update && apt-get install -y \
    curl ca-certificates gnupg iptables iproute2 iputils-ping procps wget \
    wireguard-tools \
    && rm -rf /var/lib/apt/lists/*

# Install NordVPN using their official install script approach
RUN sh -c 'wget -qO - https://repo.nordvpn.com/gpg/nordvpn_public.asc | gpg --dearmor -o /etc/apt/keyrings/nordvpn.gpg' \
    && echo "deb [signed-by=/etc/apt/keyrings/nordvpn.gpg] https://repo.nordvpn.com/deb/nordvpn/debian stable main" > /etc/apt/sources.list.d/nordvpn.list \
    && apt-get update \
    && apt-get install -y nordvpn \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

HEALTHCHECK --interval=30s --timeout=10s --start-period=90s --retries=3 \
    CMD nordvpn status | grep -q "Status: Connected" || exit 1

ENTRYPOINT ["/entrypoint.sh"]
DOCKERFILE

cat > vps/docker/nordvpn/entrypoint.sh << 'ENTRYPOINT'
#!/bin/bash
set -e

# Apply kill switch FIRST
iptables -P OUTPUT DROP
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
# Allow Docker networks
iptables -A INPUT -s 172.16.0.0/12 -j ACCEPT
iptables -A OUTPUT -d 172.16.0.0/12 -j ACCEPT
iptables -A INPUT -s 10.0.0.0/8 -j ACCEPT
iptables -A OUTPUT -d 10.0.0.0/8 -j ACCEPT
# Allow NordVPN connection setup
iptables -A OUTPUT -p udp --dport 1194 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT
iptables -A OUTPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT

# ============================================================================
# FIX: 2026-01-15 - WireGuard tunnel connectivity fixes
# Problem: NordVPN kill-switch blocks WireGuard traffic in multiple ways:
#   1. INPUT/OUTPUT filter rules block UDP 51820
#   2. Mangle PREROUTING drops incoming eth0 traffic without connmark 0xe1f1
#   3. Mangle POSTROUTING drops outgoing eth0 traffic without connmark 0xe1f1
#   4. Policy routing (table 205) sends WG responses through nordlynx instead of eth0
#   5. No NAT for WireGuard client traffic going out nordlynx
# ============================================================================
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -p udp --sport 51820 -j ACCEPT
# ============================================================================
# END FIX: 2026-01-15 - filter table rules
# ============================================================================

echo "[INFO] Kill switch applied"

# Start NordVPN daemon
mkdir -p /run/nordvpn
nordvpnd &
sleep 5

# Wait for daemon
for i in {1..30}; do
    nordvpn status &>/dev/null && break
    echo "[INFO] Waiting for NordVPN daemon... ($i/30)"
    sleep 2
done

# Login
echo "[INFO] Logging in..."
nordvpn login --token "$NORDVPN_TOKEN"

# Configure
nordvpn set technology "${NORDVPN_TECHNOLOGY:-nordlynx}"
nordvpn set killswitch on
nordvpn set dns 103.86.96.100 103.86.99.100

# Connect
echo "[INFO] Connecting to ${NORDVPN_REGION:-us}..."
nordvpn connect "${NORDVPN_REGION:-us}"

# Wait for connection
for i in {1..60}; do
    if nordvpn status | grep -q "Status: Connected"; then
        echo "[INFO] Connected!"
        nordvpn status
        break
    fi
    sleep 2
done

# Tighten firewall - only allow VPN interface
iptables -D OUTPUT -p udp --dport 1194 -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -p tcp --dport 443 -j ACCEPT 2>/dev/null || true
iptables -D OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null || true
iptables -A OUTPUT -o nordlynx -j ACCEPT
iptables -A OUTPUT -o tun0 -j ACCEPT
iptables -A INPUT -i nordlynx -j ACCEPT
iptables -A INPUT -i tun0 -j ACCEPT

# ============================================================================
# FIX: 2026-01-15 - WireGuard tunnel connectivity fixes (mangle + NAT + fwmark)
# These rules must be applied AFTER NordVPN connects because nordvpn overwrites
# iptables rules during connection setup
# ============================================================================
echo "[INFO] Applying WireGuard mangle table fixes..."
# Bypass NordVPN's mangle rules that DROP non-connmarked traffic on eth0
iptables -t mangle -I PREROUTING -i eth0 -p udp --dport 51820 -j ACCEPT
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 51820 -j ACCEPT

# NAT for WireGuard clients going out through NordVPN tunnel
iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -o nordlynx -j MASQUERADE

# Set WireGuard fwmark to 0xe1f1 to use main routing table (direct eth0)
# instead of table 205 (nordlynx). This makes WG responses go directly to clients.
echo "[INFO] Waiting for WireGuard interface..."
for i in {1..20}; do
    if wg show wg0 &>/dev/null; then
        wg set wg0 fwmark 0xe1f1
        echo "[INFO] WireGuard fwmark set to 0xe1f1"
        break
    fi
    sleep 3
done
# ============================================================================
# END FIX: 2026-01-15 - mangle + NAT + fwmark rules
# ============================================================================

echo "[INFO] VPN IP: $(curl -s --max-time 10 https://api.ipify.org)"

# Create change-region.sh script for region switching
cat > /usr/local/bin/change-region.sh << 'REGIONSCRIPT'
#!/bin/bash
set -euo pipefail
REGION="$1"

# Map short codes to NordVPN country names
case "$REGION" in
    us) NORDVPN_COUNTRY="United_States" ;;
    uk) NORDVPN_COUNTRY="United_Kingdom" ;;
    de) NORDVPN_COUNTRY="Germany" ;;
    nl) NORDVPN_COUNTRY="Netherlands" ;;
    ch) NORDVPN_COUNTRY="Switzerland" ;;
    se) NORDVPN_COUNTRY="Sweden" ;;
    ca) NORDVPN_COUNTRY="Canada" ;;
    au) NORDVPN_COUNTRY="Australia" ;;
    jp) NORDVPN_COUNTRY="Japan" ;;
    sg) NORDVPN_COUNTRY="Singapore" ;;
    fr) NORDVPN_COUNTRY="France" ;;
    it) NORDVPN_COUNTRY="Italy" ;;
    es) NORDVPN_COUNTRY="Spain" ;;
    pl) NORDVPN_COUNTRY="Poland" ;;
    ro) NORDVPN_COUNTRY="Romania" ;;
    hk) NORDVPN_COUNTRY="Hong_Kong" ;;
    br) NORDVPN_COUNTRY="Brazil" ;;
    mx) NORDVPN_COUNTRY="Mexico" ;;
    in) NORDVPN_COUNTRY="India" ;;
    za) NORDVPN_COUNTRY="South_Africa" ;;
    *)
        echo "Invalid region: $REGION" >&2
        echo "Valid regions: us uk de nl ch se ca au jp sg fr it es pl ro hk br mx in za" >&2
        exit 1
        ;;
esac

nordvpn disconnect
sleep 2
nordvpn connect "$NORDVPN_COUNTRY"
sleep 3
wg set wg0 fwmark 0xe1f1 2>/dev/null || true
nordvpn status
REGIONSCRIPT
chmod +x /usr/local/bin/change-region.sh
echo "[INFO] Region change script installed"

# Keep running and reconnect if needed
while true; do
    if ! nordvpn status | grep -q "Status: Connected"; then
        echo "[WARN] Disconnected, reconnecting..."
        nordvpn connect "${NORDVPN_REGION:-us}"
    fi
    # Re-apply WireGuard fwmark in case it was reset
    wg set wg0 fwmark 0xe1f1 2>/dev/null || true
    sleep 30
done
ENTRYPOINT
chmod +x vps/docker/nordvpn/entrypoint.sh

# =============================================================================
# Step 8: Create docker-compose.yml
# =============================================================================
cat > vps/docker-compose.yml << COMPOSE
services:
  nordvpn:
    build: ./docker/nordvpn
    container_name: nordvpn
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
    devices:
      - /dev/net/tun:/dev/net/tun
    sysctls:
      - net.ipv4.conf.all.src_valid_mark=1
      - net.ipv4.ip_forward=1
    environment:
      - NORDVPN_TOKEN=${NORDVPN_TOKEN}
      - NORDVPN_REGION=${NORDVPN_REGION}
    volumes:
      - nordvpn_data:/var/lib/nordvpn
    ports:
      - "${WG_PORT}:51820/udp"

  wireguard:
    image: linuxserver/wireguard:latest
    container_name: wireguard
    restart: unless-stopped
    cap_add:
      - NET_ADMIN
      - SYS_MODULE
    environment:
      - PUID=1000
      - PGID=1000
      - SERVERURL=${VPS_PUBLIC_IP}
      - SERVERPORT=51820
      - PEERS=client
      - PEERDNS=103.86.96.100
      - INTERNAL_SUBNET=10.100.0.0
      - ALLOWEDIPS=0.0.0.0/0
    volumes:
      - ./config/wireguard:/config
      - /lib/modules:/lib/modules:ro
    network_mode: "service:nordvpn"
    depends_on:
      nordvpn:
        condition: service_healthy

  tor:
    image: dockurr/tor:latest
    container_name: tor
    restart: unless-stopped
    network_mode: "service:nordvpn"
    depends_on:
      nordvpn:
        condition: service_healthy

volumes:
  nordvpn_data:
COMPOSE

# =============================================================================
# Step 9: Create .env file
# =============================================================================
cat > vps/.env << ENV
NORDVPN_TOKEN=${NORDVPN_TOKEN}
NORDVPN_REGION=${NORDVPN_REGION}
VPS_PUBLIC_IP=${VPS_PUBLIC_IP}
WG_PORT=${WG_PORT}
ENV

# =============================================================================
# Step 10: Start services
# =============================================================================
log_step "Starting services..."

cd "$INSTALL_DIR/vps"
docker compose up -d --build

log_info "Waiting for NordVPN to connect (this takes ~60-90 seconds)..."
sleep 30

# Check status
for i in {1..12}; do
    if docker exec nordvpn nordvpn status 2>/dev/null | grep -q "Connected"; then
        log_info "NordVPN connected!"
        break
    fi
    echo "  Waiting... ($i/12)"
    sleep 10
done

# Wait for WireGuard configs to generate
sleep 10

# =============================================================================
# Step 11: Generate client config
# =============================================================================
log_step "Generating client configuration..."

# The linuxserver/wireguard image generates peer configs automatically
CLIENT_CONFIG_DIR="$INSTALL_DIR/vps/config/wireguard/peer_client"

if [[ -f "$CLIENT_CONFIG_DIR/peer_client.conf" ]]; then
    cp "$CLIENT_CONFIG_DIR/peer_client.conf" "$INSTALL_DIR/keys/client.conf"

    # Fix linuxserver/wireguard generated config - add missing /32 CIDR and PersistentKeepalive
    # The linuxserver image omits the CIDR notation and keepalive, which breaks wg-quick
    sed -i 's|^Address = \([0-9.]*\)$|Address = \1/32|' "$INSTALL_DIR/keys/client.conf"

    # Remove ListenPort from client config (not needed, causes port conflicts)
    sed -i '/^ListenPort/d' "$INSTALL_DIR/keys/client.conf"

    # Add PersistentKeepalive if not present (needed for NAT traversal)
    if ! grep -q "PersistentKeepalive" "$INSTALL_DIR/keys/client.conf"; then
        echo "PersistentKeepalive = 25" >> "$INSTALL_DIR/keys/client.conf"
    fi

    log_info "Client config post-processed (added /32 CIDR and PersistentKeepalive)"
else
    # Generate manually if not created
    cat > "$INSTALL_DIR/keys/client.conf" << CLIENTCONF
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = 10.100.0.2/32
DNS = 103.86.96.100

[Peer]
PublicKey = $SERVER_PUBLIC
PresharedKey = $PRESHARED
Endpoint = $VPS_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
CLIENTCONF
fi

# =============================================================================
# Step 12: Setup Region Control (SSH-based region switching for RPI)
# =============================================================================
log_step "Setting up region control..."

setup_region_control() {
    local REGION_USER="region-changer"
    local REGION_HOME="$INSTALL_DIR/region-changer"
    local REGION_KEY="$INSTALL_DIR/keys/region-changer"

    # Create restricted user with home in /opt/proxy-router
    if ! id "$REGION_USER" &>/dev/null; then
        useradd -r -s /bin/bash -d "$REGION_HOME" -M "$REGION_USER"
        log_info "Created user: $REGION_USER"
    fi

    # Create user home and .ssh
    mkdir -p "$REGION_HOME/.ssh"
    chmod 700 "$REGION_HOME"
    chmod 700 "$REGION_HOME/.ssh"

    # Generate SSH keypair if not exists
    if [[ ! -f "$REGION_KEY" ]]; then
        ssh-keygen -t ed25519 -f "$REGION_KEY" -N "" -C "region-changer@proxy-router"
        log_info "Generated region-changer SSH key"
    fi

    # Install public key
    cat "${REGION_KEY}.pub" > "$REGION_HOME/.ssh/authorized_keys"
    chmod 600 "$REGION_HOME/.ssh/authorized_keys"
    chown -R "$REGION_USER:$REGION_USER" "$REGION_HOME"

    # Create bin directory
    mkdir -p "$INSTALL_DIR/bin"

    # Create wrapper script
    cat > "$INSTALL_DIR/bin/region-control" << 'REGIONCTL'
#!/bin/bash
# Region Control - Restricted command wrapper for region-changer user
# Usage: region-control {status|region|ip|change <region>}

set -euo pipefail

VALID_REGIONS="us uk de nl ch se ca au jp sg fr it es pl ro hk br mx in za"

case "${1:-}" in
    status)
        sudo /usr/bin/docker exec nordvpn nordvpn status
        ;;
    region)
        # Get region from nordvpn status command
        COUNTRY=$(sudo /usr/bin/docker exec nordvpn nordvpn status 2>/dev/null | grep -i 'Country:' | awk -F': ' '{print $2}' | tr '[:upper:]' '[:lower:]')
        case "$COUNTRY" in
            "united states") echo "us" ;;
            "united kingdom") echo "uk" ;;
            "germany") echo "de" ;;
            "netherlands") echo "nl" ;;
            "switzerland") echo "ch" ;;
            "sweden") echo "se" ;;
            "canada") echo "ca" ;;
            "australia") echo "au" ;;
            "japan") echo "jp" ;;
            "singapore") echo "sg" ;;
            "france") echo "fr" ;;
            "italy") echo "it" ;;
            "spain") echo "es" ;;
            "poland") echo "pl" ;;
            "romania") echo "ro" ;;
            "hong kong") echo "hk" ;;
            "brazil") echo "br" ;;
            "mexico") echo "mx" ;;
            "india") echo "in" ;;
            "south africa") echo "za" ;;
            *) echo "unknown" ;;
        esac
        ;;
    ip)
        sudo /usr/bin/docker exec nordvpn curl -s --max-time 10 https://api.ipify.org 2>/dev/null || echo "unknown"
        ;;
    change)
        REGION="${2:-}"
        if [[ -z "$REGION" ]]; then
            echo "Usage: region-control change <region>" >&2
            echo "Valid regions: $VALID_REGIONS" >&2
            exit 1
        fi
        if ! echo "$VALID_REGIONS" | grep -qw "$REGION"; then
            echo "Invalid region: $REGION" >&2
            echo "Valid regions: $VALID_REGIONS" >&2
            exit 1
        fi
        echo "Changing region to: $REGION"
        sudo /usr/bin/docker exec nordvpn /usr/local/bin/change-region.sh "$REGION"
        ;;
    *)
        echo "Usage: region-control {status|region|ip|change <region>}" >&2
        echo "Valid regions: $VALID_REGIONS" >&2
        exit 1
        ;;
esac
REGIONCTL
    chmod +x "$INSTALL_DIR/bin/region-control"

    # Create etc directory for sudoers
    mkdir -p "$INSTALL_DIR/etc"

    # Create sudoers file (allow only specific docker commands)
    cat > "$INSTALL_DIR/etc/sudoers-region-changer" << SUDOERS
# Region-changer: Allow specific docker exec commands for region switching
# Installed by proxy-router VPS installer
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn /usr/local/bin/change-region.sh *
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn cat /var/lib/nordvpn/current_region
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn curl -s --max-time 10 https\://api.ipify.org
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn nordvpn status
SUDOERS
    chmod 440 "$INSTALL_DIR/etc/sudoers-region-changer"

    # Symlink to /etc/sudoers.d/
    ln -sf "$INSTALL_DIR/etc/sudoers-region-changer" /etc/sudoers.d/region-changer

    # Validate sudoers syntax
    if visudo -c -f "$INSTALL_DIR/etc/sudoers-region-changer" &>/dev/null; then
        log_info "Sudoers config validated"
    else
        log_error "Sudoers config has syntax errors!"
        rm -f /etc/sudoers.d/region-changer
        return 1
    fi

    log_info "Region control configured"
    log_info "Private key for RPI: $REGION_KEY"
}

setup_region_control

# =============================================================================
# Output
# =============================================================================
echo ""
echo "=============================================="
echo "  Installation Complete!"
echo "=============================================="
echo ""
echo "VPS: $VPS_PUBLIC_IP"
echo "SSH: ssh -p $SSH_PORT root@$VPS_PUBLIC_IP"
echo "WireGuard: UDP port $WG_PORT"
echo ""
echo "=============================================="
echo "  Client WireGuard Config"
echo "=============================================="
echo ""
echo "Copy this to your Gateway VM or GL.iNet router:"
echo ""
cat "$INSTALL_DIR/keys/client.conf"
echo ""
echo "=============================================="
echo ""
echo "Config file saved to: $INSTALL_DIR/keys/client.conf"
echo ""
echo "=============================================="
echo "  Region Control (for RPI)"
echo "=============================================="
echo ""
echo "Copy this SSH key to your RPI for region switching:"
echo "  scp -P $SSH_PORT root@$VPS_PUBLIC_IP:$INSTALL_DIR/keys/region-changer /tmp/"
echo ""
echo "Test from any machine with the key:"
echo "  ssh -p $SSH_PORT -i region-changer region-changer@$VPS_PUBLIC_IP $INSTALL_DIR/bin/region-control status"
echo ""
echo "=============================================="
echo ""
echo "Commands:"
echo "  docker exec nordvpn nordvpn status    # Check VPN"
echo "  docker compose -f $INSTALL_DIR/vps/docker-compose.yml logs -f  # View logs"
echo "  $INSTALL_DIR/bin/region-control change uk  # Change region"
echo ""
log_warn "SSH is now on port $SSH_PORT!"
