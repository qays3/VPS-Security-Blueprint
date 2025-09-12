#!/usr/bin/env bash
# File: app/01_packages.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Updating system packages..."
apt update && apt upgrade -y

log_info "Installing essential packages..."
apt install -y curl wget git unzip ca-certificates lsb-release apt-transport-https \
    gnupg build-essential sudo ufw fail2ban htop iftop iproute2 jq iptables-persistent \
    netfilter-persistent