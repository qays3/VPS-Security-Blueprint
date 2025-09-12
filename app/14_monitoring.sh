#!/usr/bin/env bash
# File: app/14_monitoring.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up monitoring dashboard..."

cat > /usr/local/bin/security-status.sh <<EOF
#!/bin/bash

echo "=== VPS Security Status ==="
echo "Date: \$(date)"
echo "Interface: ${PRIMARY_IFACE}"
echo

echo "=== Service Status ==="
systemctl is-active --quiet suricata && echo "✓ Suricata: ACTIVE" || echo "✗ Suricata: INACTIVE"
systemctl is-active --quiet snort && echo "✓ Snort: ACTIVE" || echo "✗ Snort: INACTIVE"
systemctl is-active --quiet fail2ban && echo "✓ Fail2ban: ACTIVE" || echo "✗ Fail2ban: INACTIVE"
systemctl is-active --quiet nginx && echo "✓ Nginx: ACTIVE" || echo "✗ Nginx: INACTIVE"
systemctl is-active --quiet wazuh-manager && echo "✓ Wazuh Manager: ACTIVE" || echo "✗ Wazuh Manager: INACTIVE"
systemctl is-active --quiet wazuh-agent && echo "✓ Wazuh Agent: ACTIVE" || echo "✗ Wazuh Agent: INACTIVE"
echo

echo "=== Current Banned IPs ==="
iptables -L INPUT -n | grep DROP | awk '{print \$4}' | grep -E '^[0-9]+\\.' | head -20 || echo "No banned IPs found"
echo

echo "=== Fail2ban Status ==="
fail2ban-client status 2>/dev/null || echo "Fail2ban not responding"
echo

echo "=== Recent Suricata Alerts (Last 10) ==="
if [ -f /var/log/suricata/fast.log ]; then
    tail -n 10 /var/log/suricata/fast.log 2>/dev/null
else
    echo "No Suricata logs found"
fi
echo

echo "=== Recent Security Events ==="
if [ -f /var/log/security-sync.log ]; then
    tail -n 10 /var/log/security-sync.log
else
    echo "No security sync logs found"
fi
echo

echo "=== System Resources ==="
echo "CPU Usage: \$(top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | awk -F'%' '{print \$1}' || echo 'N/A')"
echo "Memory Usage: \$(free -m | awk 'NR==2{printf \"%.2f%%\", \$3*100/\$2 }')"
echo "Disk Usage: \$(df -h / | awk 'NR==2 {print \$5}')"
echo "Load Average: \$(uptime | awk -F'load average:' '{print \$2}')"
EOF

chmod 755 /usr/local/bin/security-status.sh

cat > /etc/logrotate.d/security-logs <<'EOF'
/var/log/security-sync.log
/var/log/wazuh-blocks.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

log_info "Monitoring dashboard configured"