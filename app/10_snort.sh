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
systemctl stop snort-ids 2>/dev/null || true
systemctl stop snort-minimal 2>/dev/null || true
systemctl disable snort 2>/dev/null || true
systemctl disable snort-ids 2>/dev/null || true
systemctl disable snort-minimal 2>/dev/null || true

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

cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort Network Intrusion Detection System
After=network.target

[Service]
Type=simple
User=snort
Group=snort
ExecStartPre=/bin/mkdir -p /var/run/snort
ExecStartPre=/bin/chown snort:snort /var/run/snort
ExecStart=/usr/bin/snort -A console -q -c /etc/snort/snort.conf -i ${PRIMARY_IFACE}
Restart=on-failure
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable snort

log_info "Testing Snort configuration..."
if /usr/bin/snort -T -c /etc/snort/snort.conf &>/dev/null; then
    log_info "Snort configuration test passed"
    systemctl start snort
    sleep 10
    
    if systemctl is-active --quiet snort; then
        log_info "Snort service started successfully"
    else
        log_warn "Snort service failed to start, checking logs..."
        journalctl -u snort --no-pager -n 20
    fi
else
    log_error "Snort configuration test failed"
    log_info "Creating minimal fallback service..."
    
    cat > /etc/systemd/system/snort-minimal.service <<EOF
[Unit]
Description=Snort Minimal IDS
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/bin/snort -A console -q -i ${PRIMARY_IFACE}
Restart=on-failure
RestartSec=60
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable snort-minimal
    systemctl start snort-minimal
    
    sleep 5
    if systemctl is-active --quiet snort-minimal; then
        log_info "Snort minimal service started successfully"
    else
        log_error "All Snort configurations failed"
        journalctl -u snort-minimal --no-pager -n 20
    fi
fi

log_info "Snort installation completed"