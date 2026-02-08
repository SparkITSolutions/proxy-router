# Tests

Code validation tests for proxy-router scripts.

## Running Tests

```bash
# Run all tests
./tests/test-vps-scripts.sh && ./tests/test-rpi-scripts.sh

# Run individually
./tests/test-vps-scripts.sh
./tests/test-rpi-scripts.sh
```

Tests exit 0 on success, non-zero on failure.

## What's Tested

### VPS Scripts (`test-vps-scripts.sh`)

| Test | Description |
|------|-------------|
| Bash syntax | Validates entrypoint.sh and change-region.sh |
| change-region.sh | Verifies entrypoint creates the script |
| rotate-server.sh | Verifies entrypoint creates rotation script |
| Kill switch | Verifies NordVPN kill switch is enabled |
| docker-compose.yml | Validates YAML syntax (requires Docker) |
| .env.example | Checks required variables present |
| WireGuard passthrough | Verifies iptables rules for WG traffic |
| ShellCheck | Lints for common issues (if installed) |

### RPI Scripts (`test-rpi-scripts.sh`)

| Test | Description |
|------|-------------|
| Bash syntax | Validates install.sh |
| WireGuard setup | Verifies WG configuration code |
| hostapd setup | Verifies AP configuration code |
| dnsmasq setup | Verifies DHCP/DNS configuration code |
| Fail-shut firewall | Verifies iptables DROP policy |
| IPv6 disabled | Verifies IPv6 disable logic |
| gateway-wifi | Verifies management command creation |
| CLI arguments | Verifies --wg-config, --ap-password |
| ShellCheck | Lints for common issues (if installed) |

## Optional: Install ShellCheck

For more thorough linting:

```bash
# macOS
brew install shellcheck

# Ubuntu/Debian
apt install shellcheck
```
