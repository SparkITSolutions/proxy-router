#!/bin/bash
# VPS Script Validation Tests
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0; FAIL=0
test_pass() { echo "✓ $1"; PASS=$((PASS + 1)); }
test_fail() { echo "✗ $1"; FAIL=$((FAIL + 1)); }

echo "=== VPS Script Tests ==="
echo ""

# Test 1: Bash syntax - entrypoint.sh
if bash -n vps/docker/nordvpn/entrypoint.sh 2>/dev/null; then
    test_pass "entrypoint.sh syntax valid"
else
    test_fail "entrypoint.sh syntax error"
fi

# Test 2: Bash syntax - change-region.sh
if bash -n vps/change-region.sh 2>/dev/null; then
    test_pass "change-region.sh syntax valid"
else
    test_fail "change-region.sh syntax error"
fi

# Test 3: entrypoint.sh creates change-region script
if grep -q "change-region.sh" vps/docker/nordvpn/entrypoint.sh; then
    test_pass "entrypoint.sh creates change-region.sh"
else
    test_fail "entrypoint.sh missing change-region.sh creation"
fi

# Test 4: entrypoint.sh creates rotation script
if grep -q "rotate-server.sh" vps/docker/nordvpn/entrypoint.sh; then
    test_pass "entrypoint.sh creates rotate-server.sh"
else
    test_fail "entrypoint.sh missing rotate-server.sh creation"
fi

# Test 5: entrypoint.sh has kill switch
if grep -q "killswitch" vps/docker/nordvpn/entrypoint.sh; then
    test_pass "entrypoint.sh enables kill switch"
else
    test_fail "entrypoint.sh missing kill switch"
fi

# Test 6: docker-compose.yml valid YAML
if command -v docker &>/dev/null; then
    if docker compose -f vps/docker-compose.yml config &>/dev/null; then
        test_pass "docker-compose.yml valid"
    else
        test_fail "docker-compose.yml invalid"
    fi
else
    echo "- Skipping docker-compose validation (docker not installed)"
fi

# Test 7: .env.example has required vars
if grep -q "NORDVPN_TOKEN" vps/.env.example && \
   grep -q "WG_PORT" vps/.env.example; then
    test_pass ".env.example has required variables"
else
    test_fail ".env.example missing required variables"
fi

# Test 8: WireGuard passthrough in entrypoint
if grep -q "udp.*dport.*WG_PORT" vps/docker/nordvpn/entrypoint.sh || \
   grep -q "51820" vps/docker/nordvpn/entrypoint.sh; then
    test_pass "entrypoint.sh has WireGuard passthrough"
else
    test_fail "entrypoint.sh missing WireGuard passthrough"
fi

# Test 9: ShellCheck (if available)
if command -v shellcheck &>/dev/null; then
    if shellcheck -S warning vps/docker/nordvpn/entrypoint.sh vps/change-region.sh 2>/dev/null; then
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
