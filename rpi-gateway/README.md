# Raspberry Pi Gateway

Transforms a Raspberry Pi (3B+ or 4) into a secure gateway that routes all client traffic through a WireGuard tunnel to your VPS, then through NordVPN.

Supports both **Ubuntu 24.04** (netplan) and **Raspberry Pi OS** (dhcpcd).

## Traffic Flow

```
Client Device ──► Pi WiFi AP ──► WireGuard ──► VPS ──► NordVPN ──► Internet
                  (wlan0)         (wg0)               (nordlynx)
```

## Features

- **WiFi Access Point**: Clients connect to Pi's WiFi network
- **Ethernet DHCP** (usb-wifi mode): Wired clients get DHCP from Pi
- **Fail-Shut Firewall**: If WireGuard fails, ALL traffic is blocked (no IP leaks)
- **Idempotent**: Safe to run multiple times
- **Comprehensive Logging**: All actions logged to `/var/log/gateway-install.log`

## Fresh Image Setup (Recommended Workflow)

### Step 1: Image the SD Card

Use Raspberry Pi Imager with these settings:

1. **OS**: Raspberry Pi OS Lite (64-bit recommended, 32-bit works)
2. **Settings** (gear icon):
   - Set hostname: `gateway`
   - Enable SSH with password authentication
   - Set username/password
   - Configure wireless LAN (your home WiFi for initial setup)
   - Set locale/timezone

### Step 2: First Boot & SSH In

```bash
# Find Pi on network (replace with your network)
nmap -sn 192.168.1.0/24 | grep -i raspberry

# Or use hostname
ssh pi@gateway.local

# Or check router's DHCP leases
```

### Step 3: Get the Install Script

```bash
# Option A: Clone repo
git clone https://github.com/SparkITSolutions/proxy-router.git
cd proxy-router/rpi-gateway

# Option B: Download just the script
curl -O https://raw.githubusercontent.com/SparkITSolutions/proxy-router/main/rpi-gateway/install.sh
chmod +x install.sh
```

### Step 4: Copy WireGuard Config from VPS

On your VPS, the WireGuard client config is at:
```
/opt/proxy-router/keys/client.conf
```

Copy it to the Pi:
```bash
# From your local machine (use port 32222 for VPS SSH!)
scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/client.conf ./peer_gateway.conf
scp peer_gateway.conf USER@RPI_IP:~/
```

### Step 5: Run Install

**Important**: If using ethernet-upstream mode (default), connect an ethernet cable BEFORE running, as WiFi will be converted to AP mode.

```bash
sudo ./install.sh \
  --wg-config ~/peer_gateway.conf \
  --ap-password "YourSecurePassword123" \
  --ap-ssid "SecureNet"
```

After install:
- Your SSH connection (if over WiFi) will be lost
- Connect via ethernet OR connect to the new AP and SSH to `192.168.50.1`

## Modes

### Mode A: `ethernet-upstream` (Default)

Pi gets internet via Ethernet, creates WiFi AP for clients.

```
┌─────────────────────────────────────────┐
│     Raspberry Pi 3B+ Gateway            │
│                                         │
│  eth0: DHCP client ──► Upstream router  │
│                                         │
│  wlan0: Access Point                    │◄── WiFi Clients
│         SSID: "SecureGateway"           │
│                                         │
│  wg0: WireGuard tunnel ──► VPS          │
└─────────────────────────────────────────┘
```

Best for: Fixed installations where Pi is plugged into router.

### Mode B: `usb-wifi`

Pi connects to upstream WiFi, USB WiFi adapter creates AP, Ethernet serves wired clients.

```
┌─────────────────────────────────────────┐
│     Raspberry Pi 3B+ Gateway            │
│                                         │
│  wlan0: WiFi client ──► Upstream WiFi   │
│                                         │
│  wlan1: Access Point (USB adapter)      │◄── WiFi Clients
│         SSID: "SecureGateway"           │
│                                         │
│  eth0: DHCP Server                      │◄── Wired Clients
│        192.168.51.0/24                  │
│                                         │
│  wg0: WireGuard tunnel ──► VPS          │
└─────────────────────────────────────────┘
```

Best for: Portable setups, hotel rooms, traveling.

## CLI Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--wg-config <path>` | Yes | - | WireGuard config file (or `-` for stdin) |
| `--ap-password <pass>` | Yes | - | WiFi AP password (min 8 chars) |
| `--mode <mode>` | No | ethernet-upstream | `ethernet-upstream` or `usb-wifi` |
| `--ap-ssid <name>` | No | SecureGateway | WiFi network name |
| `--ap-channel <1-13>` | No | 7 | WiFi channel |
| `--ap-network <CIDR>` | No | 192.168.50.0/24 | AP client network |
| `--eth-network <CIDR>` | No | 192.168.51.0/24 | Ethernet client network |
| `--upstream-ssid <ssid>` | usb-wifi | - | Upstream WiFi name |
| `--upstream-password <pw>` | usb-wifi | - | Upstream WiFi password |
| `--country <code>` | No | US | WiFi regulatory domain |
| `--skip-reboot` | No | false | Don't prompt for reboot |
| `--vps-ip <ip>` | No | - | VPS IP (for region service) |
| `--region-key <path>` | No | - | SSH key for region-changer user |
| `--region-password <pass>` | No | - | Password for region web UI |
| `--skip-region-service` | No | false | Skip region service installation |

## Management Commands

After installation, use the `gateway-wifi` command:

```bash
# Show status of all services
gateway-wifi status

# Test VPN connectivity
gateway-wifi test

# Scan for WiFi networks
gateway-wifi scan

# Change AP SSID and/or password
sudo gateway-wifi set-ap "NewSSID"              # Change SSID only, keep password
sudo gateway-wifi set-ap "NewSSID" "NewPass123" # Change both

# Change upstream WiFi (usb-wifi mode only)
gateway-wifi set-upstream "NewNetwork" "NewPassword"

# Restart all gateway services
gateway-wifi restart

# View recent logs
gateway-wifi logs
gateway-wifi logs 30  # Last 30 minutes
```

## Verification

### 1. Check Gateway Status

```bash
gateway-wifi status
```

Expected output:
```
=== Gateway Status ===

WireGuard:
  Status: CONNECTED
  endpoint: 1.2.3.4:51820
  latest handshake: 5 seconds ago
  transfer: 1.5 MiB received, 200 KiB sent

Access Point (hostapd):
  Status: Running
  ssid=SecureGateway
  interface=wlan0
  channel=7

DHCP/DNS (dnsmasq):
  Status: Running
  Active leases:
    192.168.50.50 (iPhone) -> aa:bb:cc:dd:ee:ff
```

### 2. Verify IP from Client

Connect a device to the AP, then:

```bash
curl https://api.ipify.org
# Should show NordVPN IP, NOT your home IP
```

### 3. Test Fail-Shut (Critical!)

On the Pi:
```bash
sudo wg-quick down wg0
```

From client:
```bash
curl https://api.ipify.org
# Should TIMEOUT/FAIL (not show home IP)
```

This confirms the fail-shut is working - no traffic leaks when VPN is down.

Restore:
```bash
sudo wg-quick up wg0
```

## Troubleshooting

### Check the Install Log

```bash
sudo cat /var/log/gateway-install.log
```

### WiFi AP not starting

```bash
# Check hostapd status
systemctl status hostapd
journalctl -u hostapd -n 50

# Common fixes:
# 1. wpa_supplicant still running
sudo killall wpa_supplicant
sudo systemctl restart hostapd

# 2. Wrong country code (check channel is valid)
# Channels 12-14 only valid in some countries

# 3. Driver issues
iw list  # Check supported modes
```

### Clients not getting DHCP

```bash
# Check dnsmasq
systemctl status dnsmasq
journalctl -u dnsmasq -n 50

# Verify interface has IP
ip addr show wlan0
# Should show 192.168.50.1/24

# View leases
cat /var/lib/misc/dnsmasq.leases
```

### WireGuard not connecting

```bash
# Check WireGuard
wg show
systemctl status wg-quick@wg0
journalctl -u wg-quick@wg0 -n 50

# Verify endpoint is reachable from Pi
ping <VPS_IP>

# Check the config
sudo cat /etc/wireguard/wg0.conf
```

### No internet through VPN

```bash
# Verify VPN is up
wg show wg0

# Check IP forwarding
cat /proc/sys/net/ipv4/ip_forward  # Should be 1

# Check iptables
sudo iptables -L -n -v
sudo iptables -t nat -L -n -v

# Test DNS
nslookup google.com
```

### SSH connection lost during install

This is expected in ethernet-upstream mode! Reconnect via:
1. Ethernet (if connected) - same IP as before
2. Connect to AP "SecureGateway" and SSH to 192.168.50.1

## Security Notes

1. **Fail-Shut Design**: All traffic is blocked by default. Only WireGuard UDP to VPS is allowed out.

2. **DNS**: All DNS queries go through Cloudflare (1.1.1.1, 1.0.0.1) via the VPN tunnel.

3. **No IPv6**: IPv6 is disabled to prevent leaks.

4. **iptables Policies**: INPUT, OUTPUT, and FORWARD all default to DROP.

5. **Minimal Attack Surface**: Only necessary ports open, no extra services.

## Files Created/Modified

| Path | Purpose |
|------|---------|
| `/etc/hostapd/hostapd.conf` | Access Point configuration |
| `/etc/dnsmasq.conf` | DHCP/DNS configuration |
| `/etc/wireguard/wg0.conf` | WireGuard tunnel config |
| `/etc/dhcpcd.conf` | Network interface config |
| `/etc/sysctl.d/99-gateway.conf` | IP forwarding settings |
| `/etc/iptables/rules.v4` | Firewall rules |
| `/usr/local/bin/gateway-wifi` | Management script |
| `/var/log/gateway-install.log` | Installation log |

## Re-running the Install

The script is idempotent. If you need to change settings:

```bash
sudo ./install.sh \
  --wg-config ~/peer_gateway.conf \
  --ap-password "NewPassword" \
  --ap-ssid "NewSSID" \
  --ap-channel 11
```

This will:
- Preserve backups of original configs
- Remove previous gateway settings
- Apply new configuration
- Restart all services

## Changing VPN Region

### Method 1: Region Control Web UI (Recommended)

If you installed with region service enabled, use the web interface from any device on the WiFi:

1. Open `https://192.168.50.1:59420` in your browser
2. Accept the self-signed certificate warning
3. Login with username `admin` and your `--region-password`
4. Select a region and click "Change Region"

Or use curl:
```bash
# Check status
curl -sk -u admin:YOURPASS https://192.168.50.1:59420/api/status

# Change region
curl -sk -u admin:YOURPASS -X POST -d '{"region":"uk"}' https://192.168.50.1:59420/api/region
```

### Method 2: SSH to VPS (Direct)

```bash
ssh -p 32222 root@VPS_IP "docker exec nordvpn nordvpn disconnect && docker exec nordvpn nordvpn connect uk"
```

Available regions: `us`, `uk`, `de`, `nl`, `ch`, `se`, `ca`, `au`, `jp`, `sg`, `fr`, `it`, `es`, `pl`, `ro`, `hk`, `br`, `mx`, `in`, `za`

The RPI will automatically use the new exit IP. Client connections continue working seamlessly.

## Region Control Service

The region control service provides a secure web interface and API for changing the VPN region without SSH access.

### Setup

1. **During VPS install**, a restricted `region-changer` SSH user is automatically created
2. **Copy the key to RPI**:
   ```bash
   scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/region-changer /tmp/region-key
   ```
3. **Include during RPI install**:
   ```bash
   sudo ./install.sh \
     --wg-config ~/peer_gateway.conf \
     --ap-password "WiFiPass" \
     --vps-ip VPS_IP \
     --region-key /tmp/region-key \
     --region-password "WebUIPass"
   ```

### Security

- Only accessible from the AP network (192.168.50.0/24)
- TLS encrypted (self-signed certificate)
- HTTP Basic Auth with SHA-256 hashed password
- Rate limited: 10 requests/minute per IP
- VPS user can ONLY execute whitelisted docker commands

### Files

| Path | Purpose |
|------|---------|
| `/opt/proxy-router/rpi/region-service/handler.sh` | HTTP request handler |
| `/opt/proxy-router/rpi/region-service/index.html` | Web UI |
| `/opt/proxy-router/rpi/region-service/vps_key` | SSH key for VPS |
| `/opt/proxy-router/rpi/region-service/auth.conf` | Password hash |
| `/opt/proxy-router/logs/region-service.log` | Service logs |

## FAQ

### How do I change the WiFi network name or password after setup?

Use the `gateway-wifi set-ap` command:

```bash
# Change SSID only (keeps existing password)
sudo gateway-wifi set-ap "MyNewNetwork"

# Change both SSID and password
sudo gateway-wifi set-ap "MyNewNetwork" "MyNewPassword123"

# View current settings
gateway-wifi set-ap
```

The command automatically backs up the hostapd config before making changes. Connected devices will need to reconnect to the new network.
