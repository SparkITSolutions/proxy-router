# Quickstart

## Prerequisites

- **VPS**: Fresh Ubuntu 24.04 with public IP
- **RPI**: Raspberry Pi 3B+/4 with Ubuntu 24.04
- **Connection**: Ethernet OR USB WiFi adapter (for wireless-only mode)
- **NordVPN Token**: From https://my.nordaccount.com/dashboard/nordvpn/access-tokens/

## Initial RPI Setup with Raspberry Pi Imager

Use Raspberry Pi Imager to flash Ubuntu 24.04 Server with WiFi and SSH pre-configured:

1. Download [Raspberry Pi Imager](https://www.raspberrypi.com/software/)
2. Select **Ubuntu Server 24.04 LTS (64-bit)** as the OS
3. Click the **gear icon (⚙️)** or press `Ctrl+Shift+X` to open settings
4. Configure:
   - **Hostname**: e.g., `gateway`
   - **Username/Password**: e.g., `ubuntu` / `changeme`
   - **WiFi SSID and Password**: Your network credentials
   - **Enable SSH**: Check this box
5. Flash to SD card and boot the Pi

The RPi will automatically connect to WiFi and be accessible via SSH. If you are using a secondary wireless NIC it's best to let it boot once and run the default apt update before plugging the secondary NIC in. If you are using the wired NIC as the upstream interface, don't bother configuring the wifi SSID / password in RPI imager.

Find its IP from your router or use `ping gateway.local`.

## 1. VPS Setup

```bash
# Copy install script to VPS (fresh VPS uses port 22)
scp vps/install.sh root@VPS_IP:/tmp/

# SSH to VPS and run installer
ssh root@VPS_IP
chmod +x /tmp/install.sh
/tmp/install.sh --token 'YOUR_NORDVPN_TOKEN' --region us --ssh-port 32222
```

The installer will:
- Change SSH to port 32222
- Configure fail2ban
- Install Docker and configure firewall
- Start NordVPN + WireGuard + Tor containers
- Generate WireGuard client config

**After install, SSH uses port 32222**: `ssh -p 32222 root@VPS_IP`

## 2. Verify VPS

```bash
# Copy health check to VPS and run it
scp -P 32222 vps/health-check.sh root@VPS_IP:/tmp/
ssh -p 32222 root@VPS_IP "chmod +x /tmp/health-check.sh && /tmp/health-check.sh"
```

All checks should pass.

## 3. RPI Gateway Setup (Ethernet)

Use this mode when your RPI is connected via ethernet cable.

```bash
# Get WireGuard client config from VPS
scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/client.conf /tmp/peer_gateway.conf

# Get region-changer SSH key for region control service (optional but recommended)
scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/region-changer /tmp/region-key

# Copy files to RPI
scp /tmp/peer_gateway.conf USER@RPI_IP:/tmp/
scp /tmp/region-key USER@RPI_IP:/tmp/
scp rpi-gateway/install.sh USER@RPI_IP:/tmp/

# SSH to RPI and run installer
ssh USER@RPI_IP
sudo chmod +x /tmp/install.sh
sudo /tmp/install.sh \
  --wg-config /tmp/peer_gateway.conf \
  --ap-ssid "SecureGateway" \
  --ap-password "YourPassword" \
  --mode ethernet-upstream \
  --vps-ip VPS_IP \
  --region-key /tmp/region-key \
  --region-password "RegionUIPassword"
```

Replace `USER` with your RPI username (e.g., `ubuntu`, `pi`, or custom).

**Note:** The `--vps-ip`, `--region-key`, and `--region-password` options enable the region control web UI. Omit them for a basic setup without region control.

## 3b. RPI Gateway Setup (USB WiFi / Wireless-Only)

Use this mode when:
- You don't have ethernet access to your Pi
- You want a portable setup (hotel rooms, traveling)
- Your Pi is already on a WiFi network and has a USB WiFi adapter

**Requirements:**
- Raspberry Pi connected to a WiFi network (your current network)
- USB WiFi adapter plugged in (this becomes the AP for your devices)

**WARNING:** During installation, your SSH connection **WILL BE LOST** when the Pi reconfigures networking. The Pi will:
1. Configure the USB adapter as an Access Point
2. Configure built-in WiFi as the upstream connection
3. You must reconnect to the new AP to regain SSH access

```bash
# Get WireGuard client config from VPS
scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/client.conf /tmp/peer_gateway.conf

# Get region-changer SSH key (optional but recommended)
scp -P 32222 root@VPS_IP:/opt/proxy-router/keys/region-changer /tmp/region-key

# Copy files to RPI (via current network)
scp /tmp/peer_gateway.conf USER@RPI_IP:/tmp/
scp /tmp/region-key USER@RPI_IP:/tmp/
scp rpi-gateway/install.sh USER@RPI_IP:/tmp/

# SSH to RPI
ssh USER@RPI_IP
sudo chmod +x /tmp/install.sh

# Run installer with USB WiFi mode
sudo /tmp/install.sh \
  --wg-config /tmp/peer_gateway.conf \
  --ap-ssid "SecureGateway" \
  --ap-password "YourAPPassword" \
  --mode usb-wifi \
  --upstream-ssid "YourCurrentWiFi" \
  --upstream-password "YourCurrentWiFiPassword" \
  --vps-ip VPS_IP \
  --region-key /tmp/region-key \
  --region-password "RegionUIPassword"
```

Replace:
- `USER` with your RPI username (e.g., `ubuntu`, `pi`, or custom)
- `RPI_IP` with your Pi's current IP on the network
- `YourCurrentWiFi` with the WiFi network your Pi is currently connected to
- `YourCurrentWiFiPassword` with that WiFi's password

**After Installation:**
1. Your SSH connection will drop
2. Look for the new WiFi network: `SecureGateway` (or your `--ap-ssid`)
3. Connect to it with the password you set (`--ap-password`)
4. SSH to the Pi at its new IP: `ssh USER@192.168.50.1`

**Note:** For passwords with special characters (`!@#$%`), use file-based options:
```bash
echo 'MyP@ssword!123' > /tmp/ap_pass.txt
echo 'UpstreamP@ss!' > /tmp/upstream_pass.txt
sudo /tmp/install.sh ... --ap-password-file /tmp/ap_pass.txt --upstream-password-file /tmp/upstream_pass.txt ...
rm -f /tmp/ap_pass.txt /tmp/upstream_pass.txt
```

**Changing Upstream WiFi Later:**

In USB WiFi mode, you can change the upstream WiFi network via the web UI:
1. Connect to the RPI's AP
2. Open `https://192.168.50.1:59420`
3. Use the "Upstream WiFi" section to scan and connect to a new network

## 4. Verify RPI

```bash
scp rpi-gateway/health-check.sh USER@RPI_IP:/tmp/
ssh USER@RPI_IP "sudo chmod +x /tmp/health-check.sh && sudo /tmp/health-check.sh"
```

All checks should pass.

## 5. Test End-to-End

1. Connect a device to the WiFi AP (SSID you configured)
2. Visit https://whatismyip.com
3. Should show a NordVPN IP, **not** your home IP

## Change Region

### Via Web UI (Recommended)

If you installed with region service enabled:
1. Connect to the RPI WiFi
2. Open `https://192.168.50.1:59420`
3. Login with `admin` and your region password
4. Select a region and click "Change Region"

### Via curl API

```bash
curl -sk -u admin:YOURPASSWORD -X POST -d '{"region":"uk"}' https://192.168.50.1:59420/api/region
```

### Via SSH to VPS (Direct)

To permanently change the VPN region (persists across container restarts):

```bash
# SSH to VPS
ssh -p 32222 root@VPS_IP

# Update the .env file with new region
sed -i 's/NORDVPN_REGION=.*/NORDVPN_REGION=uk/' /opt/proxy-router/vps/.env

# Apply the change
docker exec nordvpn nordvpn disconnect && docker exec nordvpn nordvpn connect uk

# Verify
docker exec nordvpn nordvpn status
```

**Quick temporary change** (reverts on container restart):
```bash
ssh -p 32222 root@VPS_IP "docker exec nordvpn nordvpn disconnect && docker exec nordvpn nordvpn connect uk"
```

Available regions: `us`, `uk`, `de`, `nl`, `ch`, `se`, `ca`, `au`, `jp`, `sg`, `fr`, `it`, `es`, `pl`, `ro`, `hk`, `br`, `mx`, `in`, `za`

## Troubleshooting

See [README.md](README.md#troubleshooting) for detailed troubleshooting instructions.
