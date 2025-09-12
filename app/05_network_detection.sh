#!/usr/bin/env bash
set -euo pipefail

log_info "Detecting primary network interface..."

PRIMARY_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
[ -z "$PRIMARY_IFACE" ] && PRIMARY_IFACE="eth0"

export PRIMARY_IFACE

log_info "Using primary interface: $PRIMARY_IFACE"