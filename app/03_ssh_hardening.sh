#!/usr/bin/env bash
set -euo pipefail

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