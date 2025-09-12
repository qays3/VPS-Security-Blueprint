#!/usr/bin/env bash
set -euo pipefail

log_info "Installing and configuring Snort..."

apt install -y snort

SNORT_CONF="/etc/snort/snort.debian.conf"
if [ -f "$SNORT_CONF" ]; then
  cp -a "$SNORT_CONF" "${BACKUP_DIR}/snort.debian.conf.bak"
  sed -i "s/^INTERFACE=.*/INTERFACE=${PRIMARY_IFACE}/" "$SNORT_CONF" || echo "INTERFACE=${PRIMARY_IFACE}" >> "$SNORT_CONF"
else
  echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
fi

cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/bin/snort -A fast -b -d -D -i ${PRIMARY_IFACE} -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort
ExecStop=/bin/kill -9 \$MAINPID

[Install]
WantedBy=multi-user.target
EOF

systemctl enable snort || log_warn "Failed to enable Snort"
systemctl start snort || log_warn "Failed to start Snort"
log_info "Snort installation completed"