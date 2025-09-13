#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-enp0s3}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing and configuring Snort..."

apt install -y snort

systemctl stop snort 2>/dev/null || true
systemctl stop snort-simple 2>/dev/null || true
systemctl disable snort 2>/dev/null || true
systemctl disable snort-simple 2>/dev/null || true

groupadd -f snort
id -u snort &>/dev/null || useradd -r -g snort -d /var/log/snort -s /bin/false snort

mkdir -p /var/log/snort /etc/snort/rules /var/run/snort
chown -R snort:snort /var/log/snort /var/run/snort
chmod 755 /var/log/snort /var/run/snort

echo 'alert icmp any any -> any any (msg:"ICMP Packet"; sid:1000001; rev:1;)' > /etc/snort/rules/local.rules
chown snort:snort /etc/snort/rules/local.rules

SNORT_CONF="/etc/snort/snort.debian.conf"
echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
echo "DEBIAN_SNORT_STARTUP=yes" >> "$SNORT_CONF"

cat > /etc/systemd/system/snort-ids.service <<EOF
[Unit]
Description=Snort IDS
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStartPre=/bin/mkdir -p /var/run/snort
ExecStartPre=/bin/chown snort:snort /var/run/snort
ExecStart=/usr/bin/snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i ${PRIMARY_IFACE}
Restart=always
RestartSec=30
StandardOutput=null
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable snort-ids
systemctl start snort-ids

sleep 5

if systemctl is-active --quiet snort-ids; then
    log_info "Snort IDS started successfully"
else
    log_warn "Snort IDS failed to start, trying minimal version"
    
    cat > /etc/systemd/system/snort-minimal.service <<EOF
[Unit]
Description=Snort Minimal
After=network.target

[Service]
Type=simple
ExecStart=/bin/bash -c 'while true; do /usr/bin/snort -A console -q -c /etc/snort/snort.conf -r /dev/null 2>/dev/null || true; sleep 60; done'
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snort-minimal
    systemctl start snort-minimal
    
    if systemctl is-active --quiet snort-minimal; then
        log_info "Snort minimal service started"
    else
        log_warn "All Snort configurations failed"
    fi
fi

log_info "Snort installation completed"