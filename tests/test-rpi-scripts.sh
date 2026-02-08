#!/bin/bash
# RPI Script Validation Tests
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
test_pass() { echo "✓ $1"; PASS=$((PASS + 1)); }
test_fail() { echo "✗ $1"; FAIL=$((FAIL + 1)); }

echo "=== RPI Script Tests ==="
echo ""

# Test 1: Bash syntax
if bash -n rpi-gateway/install.sh 2>/dev/null; then
    test_pass "install.sh syntax valid"
else
    test_fail "install.sh syntax error"
fi

# Test 2: Has WireGuard setup
if grep -q "setup_wireguard\|wg-quick\|wireguard" rpi-gateway/install.sh; then
    test_pass "install.sh has WireGuard setup"
else
    test_fail "install.sh missing WireGuard setup"
fi

# Test 3: Has hostapd setup
if grep -q "hostapd" rpi-gateway/install.sh; then
    test_pass "install.sh has hostapd setup"
else
    test_fail "install.sh missing hostapd setup"
fi

# Test 4: Has dnsmasq setup
if grep -q "dnsmasq" rpi-gateway/install.sh; then
    test_pass "install.sh has dnsmasq setup"
else
    test_fail "install.sh missing dnsmasq setup"
fi

# Test 5: Has fail-shut iptables (DROP policy)
if grep -q "iptables.*DROP\|policy DROP\|-P.*DROP" rpi-gateway/install.sh; then
    test_pass "install.sh has fail-shut firewall rules"
else
    test_fail "install.sh missing fail-shut firewall rules"
fi

# Test 6: Disables IPv6
if grep -q "disable_ipv6\|ipv6.*disable" rpi-gateway/install.sh; then
    test_pass "install.sh disables IPv6"
else
    test_fail "install.sh missing IPv6 disable"
fi

# Test 7: Creates gateway-wifi command
if grep -q "gateway-wifi" rpi-gateway/install.sh; then
    test_pass "install.sh creates gateway-wifi command"
else
    test_fail "install.sh missing gateway-wifi creation"
fi

# Test 8: Has --wg-config argument
if grep -q "\-\-wg-config" rpi-gateway/install.sh; then
    test_pass "install.sh accepts --wg-config argument"
else
    test_fail "install.sh missing --wg-config argument"
fi

# Test 9: Has --ap-password argument
if grep -q "\-\-ap-password" rpi-gateway/install.sh; then
    test_pass "install.sh accepts --ap-password argument"
else
    test_fail "install.sh missing --ap-password argument"
fi

# Test 10: ShellCheck (if available)
if command -v shellcheck &>/dev/null; then
    if shellcheck -S warning rpi-gateway/install.sh 2>/dev/null; then
        test_pass "ShellCheck passed"
    else
        test_fail "ShellCheck found issues"
    fi
else
    echo "- Skipping ShellCheck (not installed)"
fi

echo ""
echo "=== Results: $PASS passed, $FAIL failed ==="
[[ $FAIL -eq 0 ]]
