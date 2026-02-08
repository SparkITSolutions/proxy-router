# Proxy Router End-to-End Testing Instructions

This document provides step-by-step instructions for setting up and validating the proxy router system. Follow these instructions exactly.

## Connection Information

**Before starting, you will be provided:**
- VPS SSH connection details (IP, port, key/credentials)
- RPI SSH connection details (IP, user, password)
- NordVPN access token
- WiFi AP SSID and password to use

## Architecture Overview

```
                                                        ┌─────────────────────────────────────────┐
                                                        │              VPS (Docker)               │
┌──────────┐    WiFi     ┌──────────┐   WireGuard      │  ┌─────────┐    ┌─────────┐            │    ┌──────────┐
│  Client  │ ─────────►  │   RPI    │ ────────────────►│  │   WG    │───►│ NordVPN │ ──────────►│───►│ Internet │
│  Device  │  (WiFi AP)  │ Gateway  │   UDP 51820      │  │ Server  │    │ Tunnel  │            │    │          │
└──────────┘             └──────────┘                  │  └─────────┘    └─────────┘            │    └──────────┘
   phone/                     │                        └─────────────────────────────────────────┘
   laptop              Fail-shut iptables
                       (blocks if tunnel down)
```

**Traffic Flow:**
1. Client device (phone/laptop) connects to RPI WiFi access point
2. Client gets DHCP IP (192.168.50.x range)
3. RPI forces ALL client traffic through WireGuard tunnel (fail-shut iptables)
4. Traffic arrives at VPS WireGuard server (inside nordvpn container network)
5. VPS routes traffic through NordVPN tunnel to internet
6. Response follows reverse path

**Fail-shut Design:**
- If WireGuard tunnel fails, ALL client traffic is blocked (no IP leak)
- If NordVPN disconnects, VPS blocks all outbound (container kill-switch)

---

## Prerequisites

### Hardware
- **VPS**: Fresh Ubuntu 24.04 with public IP, UDP 51820 reachable from internet
- **RPI**: Raspberry Pi 3B+/4 with Ubuntu 24.04, ethernet connection to internet

### Credentials Required
- NordVPN access token from: https://my.nordaccount.com/dashboard/nordvpn/access-tokens/
- SSH access to VPS (details provided at test start)
- SSH access to RPI (details provided at test start)
- WiFi AP password (provided at test start)

---

## Part 1: VPS Setup

### Step 1.1: SSH to Fresh VPS

Use the VPS SSH connection details provided at the start of the test.

### Step 1.2: Copy and Run Install Script

Copy `vps/install.sh` from the local repo to the VPS and execute it with:
- `--token '<NORDVPN_TOKEN>'` - The NordVPN access token
- `--region us` - VPN region (or as specified)
- `--ssh-port 32222` - New SSH port

The script will:
1. Change SSH port to 32222
2. Configure UFW firewall (allows 22, 32222, 51820/udp)
3. Install Docker
4. Create NordVPN container with kill-switch
5. Create WireGuard server container (shares nordvpn network namespace)
6. Generate WireGuard client config
7. Apply iptables fixes for WireGuard connectivity (2026-01-15 fixes)

### Step 1.3: Verify VPS Setup

Reconnect to VPS on the new SSH port (32222).

Run the health check by copying `vps/health-check.sh` from the local repo to the VPS and executing it.

**Expected result:** All checks should pass.

### Step 1.4: Retrieve Client Config

On the VPS, read the generated WireGuard client config:
```bash
cat /opt/proxy-router/keys/client.conf
```

Save this config - you need it for the RPI setup.

---

## Part 2: RPI Gateway Setup

### Step 2.1: Prepare RPI

1. Flash Ubuntu 24.04 Server for Raspberry Pi
2. Connect RPI to router via ethernet
3. SSH into RPI

### Step 2.2: Transfer Files to RPI

From your local machine:
```bash
# Copy client config from VPS
scp -P 32222 root@<VPS_IP>:/opt/proxy-router/keys/client.conf /tmp/peer_gateway.conf

# Copy to RPI
scp /tmp/peer_gateway.conf <user>@<RPI_IP>:/tmp/
scp rpi-gateway/install.sh <user>@<RPI_IP>:/tmp/
```

### Step 2.2b: Copy Region Control Key (Optional but Recommended)

To enable the region control web UI, copy the region-changer SSH key from VPS:
```bash
# From local machine
scp -P 32222 root@<VPS_IP>:/opt/proxy-router/keys/region-changer /tmp/region-key
scp /tmp/region-key <user>@<RPI_IP>:/tmp/
```

### Step 2.3: Run RPI Install Script

SSH to RPI and run:
```bash
sudo chmod +x /tmp/install.sh

# For passwords with special characters (!@# etc), use files to avoid shell escaping:
echo 'YourWiFiPassword123!@#' > /tmp/ap_password.txt
echo 'YourRegionPassword!@#' > /tmp/region_password.txt

sudo /tmp/install.sh \
    --wg-config /tmp/peer_gateway.conf \
    --ap-ssid "SecureGateway" \
    --ap-password-file /tmp/ap_password.txt \
    --mode ethernet-upstream \
    --vps-ip <VPS_IP> \
    --region-key /tmp/region-key \
    --region-password-file /tmp/region_password.txt \
    --skip-reboot

# Clean up password files
rm -f /tmp/ap_password.txt /tmp/region_password.txt
```

**Alternative:** If your passwords have no special characters, use `--ap-password` and `--region-password` directly:
```bash
sudo /tmp/install.sh \
    --wg-config /tmp/peer_gateway.conf \
    --ap-ssid "SecureGateway" \
    --ap-password "SimplePassword123" \
    --mode ethernet-upstream \
    --vps-ip <VPS_IP> \
    --region-key /tmp/region-key \
    --region-password "RegionPass123" \
    --skip-reboot
```

**Note:** The `--vps-ip`, `--region-key`, and `--region-password` options are for the region control service. Omit them to skip region service installation.

**WARNING:** If connected via WiFi, your connection WILL DROP when wlan0 becomes an AP. Reconnect via:
- Ethernet to same IP, OR
- Connect to new WiFi AP and SSH to 192.168.50.1

### Step 2.3b: Alternative - USB WiFi Mode

For portable setups where the RPI connects to an existing WiFi network (as a client) while creating its own AP on a USB WiFi adapter:

```bash
# Requires a USB WiFi adapter (will be detected as wlan1 or wlx*)
# wlan0 = upstream WiFi client (connects to existing network)
# USB adapter = Access Point (creates new network)

# Create password files
echo 'YourAPPassword!@#' > /tmp/ap_password.txt
echo 'YourRegionPassword!@#' > /tmp/region_password.txt
echo 'YourUpstreamWiFiPassword!@#' > /tmp/upstream_password.txt

sudo /tmp/install.sh \
    --wg-config /tmp/peer_gateway.conf \
    --mode usb-wifi \
    --ap-ssid "SecureGateway" \
    --ap-password-file /tmp/ap_password.txt \
    --upstream-ssid "ExistingWiFiNetwork" \
    --upstream-password-file /tmp/upstream_password.txt \
    --vps-ip <VPS_IP> \
    --region-key /tmp/region-key \
    --region-password-file /tmp/region_password.txt \
    --skip-reboot

# Clean up password files
rm -f /tmp/ap_password.txt /tmp/region_password.txt /tmp/upstream_password.txt
```

**USB WiFi Mode Architecture:**
```
┌─────────────────────────────────────────┐
│     Raspberry Pi Gateway                │
│                                         │
│  wlan0 (built-in) ──► Upstream WiFi     │ (connects to your existing network)
│                                         │
│  wlan1/wlx* (USB)  ◄── WiFi Clients     │ (creates the AP)
│                                         │
│  eth0 ◄── Wired Clients                 │ (optional DHCP server)
│                                         │
│  wg0 ──► VPS WireGuard tunnel           │
└─────────────────────────────────────────┘
```

**Requirements for USB WiFi mode:**
- USB WiFi adapter that supports AP mode
- `--upstream-ssid` and `--upstream-password` (or `--upstream-password-file`) are required

### Step 2.4: Verify RPI Setup

Copy the health check script to the RPI and run it:
```bash
# From local machine
scp rpi-gateway/health-check.sh <user>@<RPI_IP>:/tmp/

# On RPI
sudo chmod +x /tmp/health-check.sh
sudo /tmp/health-check.sh
```

**Expected result:** All checks should pass.

---

## Part 3: End-to-End Validation

### Test 1: Tunnel Connectivity

From RPI:
```bash
# Should show handshake and transfer data
sudo wg show wg0

# Should succeed with ~50-100ms latency
ping -c 3 10.100.0.1
```

### Test 2: VPN Exit IP

From RPI:
```bash
curl https://api.ipify.org
```

**Expected:** Returns a NordVPN IP address (NOT your home IP).

Compare with VPS:
```bash
ssh -p 32222 root@<VPS_IP> "docker exec nordvpn curl -s https://api.ipify.org"
```

**Expected:** Same IP as RPI external IP.

### Test 3: Fail-Shut Verification

On RPI, stop WireGuard:
```bash
sudo wg-quick down wg0
```

Try to reach internet:
```bash
curl --max-time 5 https://api.ipify.org
```

**Expected:** Connection TIMES OUT (not your home IP!). This proves fail-shut is working.

Restore:
```bash
sudo wg-quick up wg0
```

### Test 4: Client Device Test

1. Connect a phone/laptop to WiFi AP (SSID configured in Step 2.3)
2. On client, visit https://whatismyip.com
3. **Expected:** Shows NordVPN IP, not home IP

### Test 5: Tor Access

From RPI (or any device on the WiFi AP):
```bash
curl -s --socks5-hostname 10.100.0.1:9050 https://check.torproject.org/api/ip
```

**Expected:** `{"IsTor":true,"IP":"<some-tor-exit-ip>"}`

To test .onion access:
```bash
curl -s --socks5-hostname 10.100.0.1:9050 https://duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion/ | head -20
```

**Expected:** HTML content from DuckDuckGo's .onion site.

**For browser testing:** Configure SOCKS5 proxy to `10.100.0.1:9050` with "Proxy DNS" enabled, then visit `https://check.torproject.org`.

### Test 6: Region Control Service (if installed)

**Test 6a: Web UI**

1. Connect a device to the WiFi AP
2. Open `https://192.168.50.1:59420` in a browser
3. Accept the self-signed certificate warning
4. Login with username `admin` and the password from `--region-password`
5. **Expected:** Dashboard shows current region and external IP

**Test 6b: API Status**

From RPI or any device on WiFi:
```bash
curl -sk -u admin:<REGION_PASSWORD> https://192.168.50.1:59420/api/status
```

**Expected:** JSON with region, IP, and connection status:
```json
{"region":"us","external_ip":"185.x.x.x","vpn_connected":true,"timestamp":"..."}
```

**Test 6c: Region Change**

```bash
# Change to UK
curl -sk -u admin:<REGION_PASSWORD> -X POST -d '{"region":"uk"}' https://192.168.50.1:59420/api/region
```

**Expected:**
- Response shows `"success":true` with new IP
- Takes 15-20 seconds (blocking call)
- External IP changes after completion

**Test 6d: Verify Region Change**

```bash
curl https://api.ipify.org
```

**Expected:** IP is different from before and corresponds to UK region.

**Test 6e: Security Verification**

From a machine NOT on the AP network (e.g., from your local machine or another network), try:
```bash
curl -sk -u admin:<REGION_PASSWORD> https://<RPI_UPSTREAM_IP>:59420/api/status
```

**Expected:** Connection refused or timeout (service only accessible from AP network 192.168.50.0/24).

**Note:** Testing via `localhost` on the RPI itself will succeed because the iptables loopback ACCEPT rule matches before the AP-specific restriction. This is expected — localhost access is not a security concern since it requires being on the Pi already.

---

## Health Check Scripts

### VPS Health Check (`vps/health-check.sh`)

Validates:
- Docker containers running (nordvpn, wireguard, tor)
- NordVPN connected
- External IP reachable through VPN
- WireGuard interface exists and listening
- WireGuard fwmark set to 0xe1f1
- UFW allows UDP 51820
- iptables filter table: INPUT/OUTPUT rules for UDP 51820
- iptables mangle table: PREROUTING/POSTROUTING bypass rules
- NAT masquerade for WireGuard clients on nordlynx
- Client config exists

### RPI Health Check (`rpi-gateway/health-check.sh`)

Validates:
- Services running (hostapd, dnsmasq, wg-quick@wg0)
- WiFi AP config exists
- WireGuard interface exists
- WireGuard handshake recent (< 180s)
- VPS direct route exists (prevents routing loop)
- **WireGuard policy routing rules exist** (critical for client forwarding)
- **WireGuard routing table has wg0 default route**
- IPv4 forwarding enabled
- IPv6 disabled
- iptables policies DROP (fail-shut)
- iptables VPS endpoint rule exists
- NAT masquerade on wg0
- Can ping VPS tunnel IP (10.100.0.1)
- External IP reachable (shows NordVPN IP)
- DNS resolution working
- **Region service running** (if installed)

**Note:** If the policy routing checks fail, client devices won't be able to reach the internet even though the RPI itself can. Fix by restarting WireGuard: `sudo wg-quick down wg0 && sudo wg-quick up wg0`

---

## Troubleshooting

### VPS Issues

#### NordVPN not connected
```bash
docker logs nordvpn
docker exec nordvpn nordvpn status
```

#### WireGuard handshake never completes on client

**Check 1:** Verify iptables rules in nordvpn container:
```bash
docker exec nordvpn iptables -L INPUT -n | grep 51820
docker exec nordvpn iptables -L OUTPUT -n | grep 51820
docker exec nordvpn iptables -t mangle -L PREROUTING -n | head -5
docker exec nordvpn iptables -t mangle -L POSTROUTING -n | head -5
```

**Fix if missing:**
```bash
docker exec nordvpn iptables -A INPUT -p udp --dport 51820 -j ACCEPT
docker exec nordvpn iptables -A OUTPUT -p udp --sport 51820 -j ACCEPT
docker exec nordvpn iptables -t mangle -I PREROUTING -i eth0 -p udp --dport 51820 -j ACCEPT
docker exec nordvpn iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 51820 -j ACCEPT
```

**Check 2:** Verify WireGuard fwmark:
```bash
docker exec wireguard wg show wg0
```

Should show `fwmark: 0xe1f1`. If not:
```bash
docker exec nordvpn wg set wg0 fwmark 0xe1f1
```

#### RPI tunnel works but can't reach internet

**Check NAT rule:**
```bash
docker exec nordvpn iptables -t nat -L POSTROUTING -n
```

Should show MASQUERADE for 10.100.0.0/24 on nordlynx. If not:
```bash
docker exec nordvpn iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -o nordlynx -j MASQUERADE
```

### RPI Issues

#### No WireGuard handshake
```bash
# Check if packets are being sent
sudo tcpdump -i eth0 -n 'udp port 51820' -c 5

# Check VPS route exists
ip route | grep <VPS_IP>
```

#### hostapd not starting
```bash
journalctl -u hostapd -n 50
```

Common issues:
- wpa_supplicant still running on wlan0: `sudo systemctl stop wpa_supplicant`
- Invalid channel for country code

#### External IP shows home IP (VPN leak!)

**This is critical!** Check:
1. WireGuard handshake exists: `sudo wg show wg0`
2. iptables policies are DROP: `sudo iptables -L -n | head -10`
3. Default route goes through wg0: `ip route`

---

## Known Issues Fixed (2026-01-15, updated 2026-01-24)

### Issue 1: NordVPN kill-switch blocks WireGuard

**Root Cause:** NordVPN's kill-switch sets iptables INPUT/OUTPUT policy to DROP and only allows traffic through nordlynx/tun0 interfaces. WireGuard UDP 51820 traffic on eth0 is blocked.

**Fix:** Added to entrypoint.sh:
```bash
iptables -A INPUT -p udp --dport 51820 -j ACCEPT
iptables -A OUTPUT -p udp --sport 51820 -j ACCEPT
```

### Issue 2: NordVPN mangle table drops WireGuard

**Root Cause:** NordVPN uses mangle table PREROUTING/POSTROUTING to DROP all eth0 traffic without connmark 0xe1f1.

**Fix:** Added to entrypoint.sh (after NordVPN connects):
```bash
iptables -t mangle -I PREROUTING -i eth0 -p udp --dport 51820 -j ACCEPT
iptables -t mangle -I POSTROUTING -o eth0 -p udp --sport 51820 -j ACCEPT
```

### Issue 3: WireGuard responses routed through NordVPN

**Root Cause:** NordVPN policy routing rule `not from all fwmark 0xe1f1 lookup 205` sends all unmarked traffic through table 205 (nordlynx). WireGuard responses go to NordVPN instead of directly to clients.

**Fix:** Set WireGuard fwmark to 0xe1f1:
```bash
wg set wg0 fwmark 0xe1f1
```

### Issue 4: No NAT for WireGuard client traffic

**Root Cause:** WireGuard client traffic (10.100.0.0/24) going out nordlynx wasn't NAT'd.

**Fix:** Added to entrypoint.sh:
```bash
iptables -t nat -A POSTROUTING -s 10.100.0.0/24 -o nordlynx -j MASQUERADE
```

### Issue 5: VPS sudoers URL colon not escaped

**Root Cause:** The VPS install.sh creates a sudoers file with `https://api.ipify.org` but colons in sudoers files have special meaning and must be escaped.

**Fix:** Changed line in vps/install.sh from:
```
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn curl -s --max-time 10 https://api.ipify.org
```
To:
```
$REGION_USER ALL=(root) NOPASSWD: /usr/bin/docker exec nordvpn curl -s --max-time 10 https\://api.ipify.org
```

### Issue 6: RPI region service iptables subnet format error

**Root Cause:** The RPI install.sh used `${AP_NETWORK%/*}.0/24` to construct the subnet, but `AP_NETWORK` is already `192.168.50.0/24`, resulting in `192.168.50.0.0/24` (invalid).

**Fix:** Changed line in rpi-gateway/install.sh from:
```bash
iptables -A INPUT -i "$AP_IFACE" -s "${AP_NETWORK%/*}.0/24" -p tcp --dport "$REGION_PORT" -j ACCEPT
```
To:
```bash
iptables -A INPUT -i "$AP_IFACE" -s "$AP_NETWORK" -p tcp --dport "$REGION_PORT" -j ACCEPT
```

Also added missing OUTPUT rule for region service responses.

### Issue 7: RPI region service missing WWW-Authenticate header

**Root Cause:** The region service handler returned a 401 response without the `WWW-Authenticate` header, so browsers didn't know to show a login dialog.

**Fix:** Modified `send_response` function to accept extra headers, and added `WWW-Authenticate: Basic realm="Gateway Region Control"` to the 401 response. Also fixed unbound variable error by using `${4:-}` for the optional parameter.

### Issue 8: VPS missing change-region.sh script in container

**Root Cause:** The VPS install.sh referenced `/usr/local/bin/change-region.sh` inside the NordVPN container but never created it.

**Fix:** Added script creation to the entrypoint.sh that runs inside the container.

### Issue 9: RPI missing iptables rules for SSH to VPS

**Root Cause:** The RPI fail-shut firewall only allowed UDP to VPS port 51820, but the region service needs TCP to VPS port 32222 for SSH commands.

**Fix:** Added iptables OUTPUT and INPUT rules for TCP to VPS:32222 in the region service setup.

### Issue 10: Region detection returned "unknown"

**Root Cause:** The region-control script tried to read `/var/lib/nordvpn/current_region` which doesn't exist. NordVPN doesn't create this file.

**Fix:** Changed region detection to parse the country from `nordvpn status` output and map it to region codes.

### Issue 11: Shell escaping corrupts passwords with special characters

**Root Cause:** Bash history expansion interprets `!` in double-quoted strings. Running `--ap-password "worldtraveler123!@#"` could result in the password becoming `worldtraveler123\!@#` due to shell escaping.

**Symptoms:**
- WiFi password doesn't work as expected
- Password contains backslashes that weren't intended

**Fix:** Added `--ap-password-file`, `--region-password-file`, and `--upstream-password-file` options to read passwords from files, avoiding shell interpretation entirely.

**Usage:**
```bash
# Create password file with exact content
echo 'MyPassword123!@#' > /tmp/password.txt

# Use file instead of inline password
sudo ./install.sh --ap-password-file /tmp/password.txt ...

# Clean up
rm -f /tmp/password.txt
```

### Issue 12: USB WiFi mode eth0 not configured on Ubuntu (netplan)

**Root Cause:** In USB WiFi mode on Ubuntu 24.04, the `configure_netplan()` function configured eth0 with `dhcp4: true`, but eth0 should have a static IP (192.168.51.1) because it serves as a DHCP server for wired clients. The `configure_dhcpcd()` function handled this correctly for Raspberry Pi OS, but netplan didn't.

**Symptoms:**
- dnsmasq fails to start with "unknown interface eth0" error
- eth0 has no IP address assigned

**Fix:** Updated `configure_netplan()` to check the mode and configure eth0 with a static IP in usb-wifi mode. Also added eth0 initialization in `start_services()` before dnsmasq starts.

### Issue 13: Region change fails with "server does not exist"

**Root Cause:** The `change-region.sh` script inside the NordVPN container passed short region codes (e.g., "uk") directly to `nordvpn connect`, but NordVPN expects full country names (e.g., "United_Kingdom").

**Symptoms:**
- Region change returns error "The specified server does not exist"
- API returns `{"success":false,"error":"..."}`

**Fix:** Added a case statement in `change-region.sh` to map short codes to NordVPN country names:
```bash
case "$REGION" in
    us) NORDVPN_COUNTRY="United_States" ;;
    uk) NORDVPN_COUNTRY="United_Kingdom" ;;
    # ... other mappings
esac
nordvpn connect "$NORDVPN_COUNTRY"
```

### Issue 14: change-region.sh dollar signs escaped in single-quoted heredoc

**Root Cause:** The `change-region.sh` script is generated inside the NordVPN entrypoint.sh, which itself is inside a single-quoted heredoc (`<< 'ENTRYPOINT'`). The inner heredoc for change-region.sh also uses a single-quoted delimiter (`<< 'REGIONSCRIPT'`). Because single-quoted heredocs prevent variable expansion, the `\$` escapes were written literally to the file as `\$` instead of `$`. This meant `REGION="\$1"` set REGION to the literal string `$1` instead of the first argument.

**Symptoms:**
- Region change returns error "Invalid region: $REGION"
- The literal string `$REGION` appears in the error instead of the actual region code passed

**Fix:** Removed all backslash escapes before `$` in the change-region.sh section of `vps/install.sh` (lines 468-508). Since both the outer and inner heredocs use single-quoted delimiters (no expansion), `$` signs are written literally without needing escapes.

### Issue 15: WiFi management unavailable on Ubuntu/netplan (usb-wifi mode)

**Root Cause:** The region service API functions (`api_wifi_status`, `api_wifi_scan`, `api_wifi_connect`) and the `gateway-wifi set-upstream` CLI command checked for `/etc/wpa_supplicant/wpa_supplicant-wlan0.conf` to detect USB WiFi mode. On Ubuntu 24.04 with netplan, this file is never created — netplan manages wpa_supplicant internally via `/run/netplan/wpa-wlan0.conf`. The mode IS `usb-wifi` per `gateway.conf`, but the API returned `{"available":false}`.

**Symptoms:**
- Web UI "Upstream WiFi" section hidden (not shown)
- API returns `{"available":false,"error":"WiFi management only available in usb-wifi mode"}`
- `gateway-wifi set-upstream` returns "Error: This command is only for usb-wifi mode"

**Fix:** Three changes in `rpi-gateway/install.sh`:
1. Changed mode detection in all WiFi API functions and CLI to read `MODE` from `/opt/proxy-router/rpi/gateway.conf` instead of checking for the wpa_supplicant config file
2. Added netplan backend support in `api_wifi_connect()` and `cmd_set_upstream()` — on netplan systems, updates `/etc/netplan/50-gateway.yaml` and runs `netplan apply`; on dhcpcd systems, keeps the original wpa_supplicant approach
3. Added `iw` package to the region service installation for WiFi scanning support

### Issue 16: WiFi and services not surviving reboot (usb-wifi mode)

**Root Cause:** Multiple interacting issues prevented the RPI from fully booting after a reboot in usb-wifi mode:

1. **YAML password escaping** — Netplan YAML used double-quoted passwords (`password: "pass!word"`). In YAML double-quoted scalars, `\` is an escape character, and `!` can cause issues with some parsers. This led to "Invalid YAML: found unknown escape character" errors.
2. **Missing chmod 600** — `configure_netplan()` created `/etc/netplan/50-gateway.yaml` but didn't set permissions to 600. Netplan requires 600 for files containing WiFi credentials and refuses to apply them otherwise.
3. **cloud-init not disabled** — The install script moved `50-cloud-init.yaml` to backup, but didn't disable cloud-init's network management. On reboot, cloud-init could regenerate conflicting netplan configs.
4. **Incorrect systemd service ordering** — `gateway-network.service` had `DefaultDependencies=no` and `Before=network.target`, causing it to race ahead of `systemd-networkd.service`. The `netplan apply` in `setup-network.sh` would execute before networkd was ready to manage WiFi.
5. **No WiFi recovery logic** — If `netplan apply` failed or wlan0 didn't get an IP, `setup-network.sh` logged a warning but had no retry mechanism.
6. **dnsmasq failed with `bind-interfaces`** — dnsmasq was configured with `bind-interfaces` which requires ALL listed interfaces to be present at startup. When eth0 had no carrier (no cable), dnsmasq couldn't bind to it and refused to start entirely.

**Symptoms:**
- After reboot, wlan0 has no IP address (WiFi not connected)
- `netplan apply` fails with YAML errors
- WireGuard service fails (depends on wlan0 being up for VPS route)
- dnsmasq fails (can't bind to eth0 with no carrier)
- WiFi scan returns no results in web UI

**Fix:** Six changes in `rpi-gateway/install.sh`:
1. Changed YAML password quoting from double quotes to single quotes in all 3 netplan YAML generators (`configure_netplan()`, `api_wifi_connect()`, `cmd_set_upstream()`)
2. Added `chmod 600 /etc/netplan/50-gateway.yaml` after initial creation in `configure_netplan()`
3. Added cloud-init network disable: creates `/etc/cloud/cloud.cfg.d/99-disable-network-config.cfg` with `network: {config: disabled}`
4. Fixed `gateway-network.service` ordering: removed `DefaultDependencies=no` and `Before=network.target`, added `After=systemd-networkd.service` and `Wants=systemd-networkd.service`
5. Added WiFi recovery logic in `setup-network.sh`: ensures systemd-networkd is running, retries `netplan apply` with networkd restart if wlan0 doesn't get IP within 60s
6. Changed dnsmasq from `bind-interfaces` to `bind-dynamic` so it tolerates interfaces that aren't ready at startup
7. Added `optional: true` to eth0 in netplan YAML (all 3 generators) so systemd-networkd doesn't wait for carrier

---

## Success Criteria

A successful end-to-end test means:

1. **VPS health check passes** - All containers running, NordVPN connected, iptables correct
2. **RPI health check passes** - All services running, tunnel established, fail-shut active
3. **Tunnel works** - RPI can ping 10.100.0.1 through WireGuard
4. **VPN exit works** - RPI external IP is NordVPN IP, not home IP
5. **Fail-shut works** - Stopping WireGuard blocks ALL traffic, no IP leak
6. **Client works** - Device on WiFi AP shows NordVPN IP
7. **Tor works** - SOCKS5 proxy at 10.100.0.1:9050 returns `{"IsTor":true,...}`
8. **Region service works** (if installed) - Web UI accessible, can change regions via API

Criteria 1-7 are required for basic deployment. Criterion 8 is required if region service was installed.
