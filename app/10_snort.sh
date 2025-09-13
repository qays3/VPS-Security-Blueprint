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

mkdir -p /var/log/snort /etc/snort/rules
chown -R snort:snort /var/log/snort
chown -R snort:snort /etc/snort/rules
chmod 755 /var/log/snort
chmod 755 /etc/snort/rules

SNORT_CONF="/etc/snort/snort.debian.conf"
if [ -f "$SNORT_CONF" ]; then
  cp -a "$SNORT_CONF" "${BACKUP_DIR}/snort.debian.conf.bak"
  sed -i "s/^INTERFACE=.*/INTERFACE=${PRIMARY_IFACE}/" "$SNORT_CONF" || echo "INTERFACE=${PRIMARY_IFACE}" >> "$SNORT_CONF"
else
  echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
fi

if [ -f /etc/snort/snort.conf ]; then
    cp -a /etc/snort/snort.conf "${BACKUP_DIR}/snort.conf.bak"
    sed -i "s|var RULE_PATH.*|var RULE_PATH /etc/snort/rules|" /etc/snort/snort.conf
    sed -i "s|var SO_RULE_PATH.*|var SO_RULE_PATH /etc/snort/so_rules|" /etc/snort/snort.conf
    sed -i "s|var PREPROC_RULE_PATH.*|var PREPROC_RULE_PATH /etc/snort/preproc_rules|" /etc/snort/snort.conf
    sed -i "s|var WHITE_LIST_PATH.*|var WHITE_LIST_PATH /etc/snort/rules|" /etc/snort/snort.conf
    sed -i "s|var BLACK_LIST_PATH.*|var BLACK_LIST_PATH /etc/snort/rules|" /etc/snort/snort.conf
fi

touch /etc/snort/rules/local.rules /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules
chown snort:snort /etc/snort/rules/*.rules

cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=forking
ExecStartPre=/bin/mkdir -p /var/log/snort
ExecStartPre=/bin/chown snort:snort /var/log/snort
ExecStart=/usr/bin/snort -A fast -b -d -D -i ${PRIMARY_IFACE} -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort --pid-path=/var/run/snort.pid
ExecStop=/bin/kill -TERM \$MAINPID
PIDFile=/var/run/snort.pid
Restart=on-failure
RestartSec=10
User=root
Group=root

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable snort

if snort -T -c /etc/snort/snort.conf -i ${PRIMARY_IFACE} >/dev/null 2>&1; then
    systemctl start snort
    sleep 5
    if systemctl is-active --quiet snort; then
        log_info "Snort started successfully"
    else
        log_warn "Snort service not active, trying alternative approach"
        cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStartPre=/bin/mkdir -p /var/log/snort
ExecStartPre=/bin/chown snort:snort /var/log/snort
ExecStart=/usr/bin/snort -A console -q -i ${PRIMARY_IFACE} -c /etc/snort/snort.conf
Restart=always
RestartSec=10
User=root

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl start snort
        sleep 3
        if systemctl is-active --quiet snort; then
            log_info "Snort started with console mode"
        else
            log_warn "Snort still failing, disabling for now"
            systemctl disable snort
        fi
    fi
else
    log_warn "Snort configuration test failed, creating minimal config"
    echo 'alert icmp any any -> any any (msg:"ICMP test"; sid:1000001; rev:1;)' > /etc/snort/rules/local.rules
    systemctl start snort || log_warn "Snort failed to start even with minimal config"
fi

log_info "Snort installation completed"