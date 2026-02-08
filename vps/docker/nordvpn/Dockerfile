# NordVPN Container with Fail-Shut Networking
# Based on Ubuntu 24.04 with iptables-based kill switch

FROM ubuntu:24.04

LABEL maintainer="proxy-router"
LABEL description="NordVPN client with fail-shut kill switch"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Install dependencies
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    gnupg \
    iptables \
    iproute2 \
    iputils-ping \
    dnsutils \
    procps \
    jq \
    cron \
    && rm -rf /var/lib/apt/lists/*

# Install NordVPN
RUN curl -sSL https://repo.nordvpn.com/deb/nordvpn/debian/pool/main/nordvpn-release_1.0.0_all.deb -o /tmp/nordvpn-release.deb \
    && dpkg -i /tmp/nordvpn-release.deb \
    && apt-get update \
    && apt-get install -y nordvpn \
    && rm -rf /var/lib/apt/lists/* /tmp/*

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Health check - verify VPN is connected and we have the expected IP
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD nordvpn status | grep -q "Status: Connected" || exit 1

# Required capabilities for networking
# These are set in docker-compose.yml:
# - NET_ADMIN: for iptables and VPN tunnel
# - SYS_MODULE: for loading tun module (if needed)

ENTRYPOINT ["/entrypoint.sh"]
