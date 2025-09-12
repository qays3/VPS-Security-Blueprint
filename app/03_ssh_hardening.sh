#!/usr/bin/env bash
# File: app/03_ssh_hardening.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Hardening SSH configuration..."

SSHD_CONFIG="/etc/ssh/sshd_config"
cp -a "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config.bak"

sed -i -E 's/^\s*PermitRootLogin\s+.*/PermitRootLogin no/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*PasswordAuthentication\s+.*/PasswordAuthentication yes/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*MaxAuthTries\s+.*/MaxAuthTries 3/' "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveInterval\s+.*/ClientAliveInterval 300/' "$SSHD_CONFIG" || echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveCountMax\s+.*/ClientAliveCountMax 2/' "$SSHD_CONFIG" || echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"

if sshd -t; then
    systemctl reload sshd || systemctl restart ssh || true
    log_info "SSH configuration updated successfully"
else
    log_error "SSH configuration test failed, reverting changes"
    cp "${BACKUP_DIR}/sshd_config.bak" "$SSHD_CONFIG"
fi