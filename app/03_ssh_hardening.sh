#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"
[ -f /tmp/vps_setup_vars.sh ] && source /tmp/vps_setup_vars.sh
USERNAME="${USERNAME:-unknown}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"
cp -a "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config.bak"

sed -i '/^#*PermitRootLogin/d' "$SSHD_CONFIG"
sed -i '/^#*PasswordAuthentication/d' "$SSHD_CONFIG"
sed -i '/^#*MaxAuthTries/d' "$SSHD_CONFIG"
sed -i '/^#*ClientAliveInterval/d' "$SSHD_CONFIG"
sed -i '/^#*ClientAliveCountMax/d' "$SSHD_CONFIG"
sed -i '/^#*Protocol/d' "$SSHD_CONFIG"
sed -i '/^#*X11Forwarding/d' "$SSHD_CONFIG"
sed -i '/^#*AllowUsers/d' "$SSHD_CONFIG"

cat >> "$SSHD_CONFIG" <<EOF

PermitRootLogin no
PasswordAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
Protocol 2
X11Forwarding no
UsePAM yes
AllowUsers $USERNAME
EOF

if sshd -t; then
    systemctl reload sshd || systemctl restart ssh || true
    log_info "SSH configuration updated successfully - root login disabled, only $USERNAME allowed"
else
    log_error "SSH configuration test failed, reverting changes"
    cp "${BACKUP_DIR}/sshd_config.bak" "$SSHD_CONFIG"
fi