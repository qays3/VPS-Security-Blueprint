#!/usr/bin/env bash
set -euo pipefail

log_info "Updating system packages..."
apt update && apt upgrade -y

log_info "Installing essential packages..."
apt install -y curl wget git unzip ca-certificates lsb-release apt-transport-https \
    gnupg build-essential sudo ufw fail2ban htop iftop iproute2 jq iptables-persistent \
    netfilter-persistent