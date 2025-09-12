#!/usr/bin/env bash
# File: app/05_network_detection.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Detecting primary network interface..."

PRIMARY_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
[ -z "$PRIMARY_IFACE" ] && PRIMARY_IFACE="eth0"

echo "export PRIMARY_IFACE='$PRIMARY_IFACE'" > /tmp/vps_network_vars.sh

log_info "Using primary interface: $PRIMARY_IFACE"