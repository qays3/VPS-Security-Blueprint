#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing and configuring Snort..."

apt install -y snort

groupadd -f snort
useradd -r -g snort -d /var/log/snort -s /bin/false snort 2>/dev/null || true

mkdir -p /var/log/snort
chown -R snort:snort /var/log/snort

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
ExecStop=/bin/kill \$MAINPID
Restart=always
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable snort
systemctl start snort
sleep 3

if systemctl is-active --quiet snort; then
    log_info "Snort started successfully"
else
    log_warn "Snort failed to start, checking configuration..."
    systemctl status snort --no-pager
    journalctl -u snort --lines=10 --no-pager
fi

log_info "Snort installation completed"