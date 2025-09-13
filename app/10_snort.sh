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

systemctl stop snort 2>/dev/null || true
systemctl disable snort 2>/dev/null || true

groupadd -f snort
id -u snort &>/dev/null || useradd -r -g snort -d /var/log/snort -s /bin/false snort

mkdir -p /var/log/snort /etc/snort/rules /var/run/snort
chown -R snort:snort /var/log/snort /var/run/snort
chown -R root:snort /etc/snort
chmod 755 /var/log/snort /var/run/snort
chmod -R 640 /etc/snort/snort.conf 2>/dev/null || true

SNORT_CONF="/etc/snort/snort.debian.conf"
if [ -f "$SNORT_CONF" ]; then
  cp -a "$SNORT_CONF" "${BACKUP_DIR}/snort.debian.conf.bak"
  sed -i "s/^INTERFACE=.*/INTERFACE=${PRIMARY_IFACE}/" "$SNORT_CONF"
else
  echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
fi

cat > /etc/snort/rules/local.rules <<'EOF'
alert icmp any any -> any any (msg:"ICMP Packet"; sid:1000001; rev:1;)
alert tcp any any -> any 22 (msg:"SSH Connection"; sid:1000002; rev:1;)
EOF

chown root:snort /etc/snort/rules/local.rules
chmod 640 /etc/snort/rules/local.rules

cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/run/snort
ExecStartPre=/bin/chown snort:snort /var/run/snort
ExecStart=/usr/bin/snort -q -D -c /etc/snort/snort.conf -i ${PRIMARY_IFACE}
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

if [ -f /etc/snort/snort.conf ]; then
    log_info "Testing Snort configuration..."
    if snort -T -c /etc/snort/snort.conf >/dev/null 2>&1; then
        log_info "Snort configuration test passed"
        systemctl enable snort
        systemctl start snort
        sleep 5
        if systemctl is-active --quiet snort; then
            log_info "Snort started successfully"
        else
            log_warn "Snort failed to start, creating lightweight version"
            cat > /etc/systemd/system/snort-simple.service <<EOF
[Unit]
Description=Snort Simple Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/snort -A console -q -c /etc/snort/snort.conf -i ${PRIMARY_IFACE}
Restart=always
RestartSec=60
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
EOF
            systemctl daemon-reload
            systemctl enable snort-simple
            systemctl start snort-simple || log_warn "Simple snort also failed"
        fi
    else
        log_warn "Snort configuration test failed, skipping service start"
    fi
else
    log_warn "Snort configuration file not found, creating minimal setup"
    echo "# Minimal Snort configuration" > /etc/snort/snort.conf
fi

log_info "Snort installation completed"