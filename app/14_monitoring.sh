#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up enhanced monitoring dashboard..."

cat > /usr/local/bin/security-status.sh << 'EOF'
#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${YELLOW}[WARN]${NC} Some checks require root privileges"
        echo -e "${YELLOW}[WARN]${NC} Run with sudo for complete information"
        echo ""
    fi
}

check_root

echo -e "${CYAN}=========================================="
echo -e "     VPS SECURITY STATUS DASHBOARD"
echo -e "==========================================${NC}"
echo -e "Date: $(date)"
echo -e "Hostname: $(hostname)"
echo -e "Primary Interface: PRIMARY_IFACE_PLACEHOLDER"
echo -e "Public IP: $(curl -s ipinfo.io/ip 2>/dev/null || echo 'Unable to detect')"
echo ""

echo -e "${BLUE}=== CORE SERVICES STATUS ===${NC}"

if systemctl is-active --quiet suricata 2>/dev/null; then
    echo -e "✓ suricata: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ suricata: ${RED}INACTIVE${NC}"
fi

if systemctl is-active --quiet snort 2>/dev/null || systemctl is-active --quiet snort-alt 2>/dev/null || systemctl is-active --quiet snort-ids 2>/dev/null || systemctl is-active --quiet snort-minimal 2>/dev/null; then
    echo -e "✓ snort: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ snort: ${RED}INACTIVE${NC}"
fi

if systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo -e "✓ fail2ban: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ fail2ban: ${RED}INACTIVE${NC}"
fi

if systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "✓ nginx: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ nginx: ${RED}INACTIVE${NC}"
fi

if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    echo -e "✓ wazuh-manager: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ wazuh-manager: ${RED}INACTIVE${NC}"
fi

if systemctl is-active --quiet ssh 2>/dev/null; then
    echo -e "✓ ssh: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ ssh: ${RED}INACTIVE${NC}"
fi

if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo -e "✓ ufw: ${GREEN}ACTIVE${NC}"
else
    echo -e "✗ ufw: ${RED}INACTIVE${NC}"
fi
echo ""

echo -e "${BLUE}=== FIREWALL STATUS ===${NC}"
if command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
    echo -e "✓ UFW Firewall: ${GREEN}ACTIVE${NC}"
    echo "Active Rules:"
    ufw status numbered 2>/dev/null | grep -E "^\[.*\]" | head -10
else
    echo -e "✗ UFW Firewall: ${RED}INACTIVE${NC}"
fi
echo ""

echo -e "${BLUE}=== LISTENING PORTS ===${NC}"
echo "Port    Service    State"
echo "------------------------"
if command -v ss >/dev/null; then
    ss -tuln 2>/dev/null | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -n | uniq | while read port; do
        if [ ! -z "$port" ] && [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" != "0" ]; then
            service_name=$(ss -tuln 2>/dev/null | grep ":$port " | head -1 | awk '{print $1}')
            echo -e "$port\t${service_name}\t${GREEN}OPEN${NC}"
        fi
    done
fi
echo ""

echo -e "${BLUE}=== IDS/IPS STATUS ===${NC}"
if systemctl is-active --quiet suricata 2>/dev/null; then
    echo -e "✓ Suricata IPS: ${GREEN}RUNNING${NC}"
    if [ -f /var/log/suricata/eve.json ]; then
        alerts=$(tail -100 /var/log/suricata/eve.json 2>/dev/null | grep '"event_type":"alert"' | wc -l)
        echo "  Recent alerts: $alerts"
    fi
    if [ -f /var/log/suricata/stats.log ]; then
        pkts=$(tail -5 /var/log/suricata/stats.log 2>/dev/null | grep -o 'capture.kernel_packets":[0-9]*' | tail -1 | cut -d: -f2)
        echo "  Packets processed: ${pkts:-0}"
    fi
else
    echo -e "✗ Suricata IPS: ${RED}STOPPED${NC}"
fi

if systemctl is-active --quiet snort 2>/dev/null || systemctl is-active --quiet snort-alt 2>/dev/null || systemctl is-active --quiet snort-ids 2>/dev/null || systemctl is-active --quiet snort-minimal 2>/dev/null; then
    echo -e "✓ Snort IDS: ${GREEN}RUNNING${NC}"
else
    echo -e "✗ Snort IDS: ${RED}STOPPED${NC}"
fi
echo ""

echo -e "${BLUE}=== WAF STATUS ===${NC}"
if systemctl is-active --quiet nginx 2>/dev/null; then
    echo -e "✓ Nginx + ModSecurity: ${GREEN}ACTIVE${NC}"
    if [ -f /var/log/nginx/modsec_audit.log ]; then
        blocked=$(grep -c "Access denied" /var/log/nginx/modsec_audit.log 2>/dev/null || echo "0")
        echo "  Total blocked requests: $blocked"
    fi
    if [ -f /var/log/nginx/access.log ]; then
        today_requests=$(grep "$(date '+%d/%b/%Y')" /var/log/nginx/access.log 2>/dev/null | wc -l)
        echo "  Today's requests: $today_requests"
        http_errors=$(grep "$(date '+%d/%b/%Y')" /var/log/nginx/access.log 2>/dev/null | grep -c ' 4[0-9][0-9] \|5[0-9][0-9] ' || echo "0")
        echo "  HTTP errors today: $http_errors"
    fi
else
    echo -e "✗ Nginx + ModSecurity: ${RED}INACTIVE${NC}"
fi
echo ""

echo -e "${BLUE}=== BLOCKED IPS ===${NC}"
if [[ $EUID -eq 0 ]]; then
    blocked_count=$(iptables -L INPUT -n 2>/dev/null | grep -c DROP || echo "0")
    echo "Total blocked IPs: $blocked_count"
    if [ $blocked_count -gt 0 ]; then
        echo "Recent blocks:"
        iptables -L INPUT -n 2>/dev/null | grep DROP | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -10
    fi
else
    echo "Run as root to view blocked IPs"
fi
echo ""

echo -e "${BLUE}=== FAIL2BAN STATUS ===${NC}"
if systemctl is-active --quiet fail2ban 2>/dev/null; then
    echo -e "✓ Fail2ban: ${GREEN}RUNNING${NC}"
    if command -v fail2ban-client >/dev/null; then
        fail2ban-client status 2>/dev/null | grep "Jail list:" | sed 's/.*Jail list:/Active jails:/' || echo "Status check failed"
        echo ""
        fail2ban-client status sshd 2>/dev/null | grep "Currently banned:" || echo "SSH jail: No current bans"
    fi
else
    echo -e "✗ Fail2ban: ${RED}NOT RUNNING${NC}"
fi
echo ""

echo -e "${BLUE}=== LOG MONITORING ===${NC}"
if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
    echo -e "✓ Wazuh Manager: ${GREEN}RUNNING${NC}"
    if [ -f /var/ossec/logs/alerts/alerts.log ]; then
        recent_alerts=$(tail -50 /var/ossec/logs/alerts/alerts.log 2>/dev/null | grep "$(date '+%Y %b %d')" | wc -l)
        echo "  Today's alerts: $recent_alerts"
    fi
    if [ -f /var/ossec/logs/ossec.log ]; then
        echo "  Manager status: Active"
    fi
else
    echo -e "✗ Wazuh Manager: ${RED}NOT RUNNING${NC}"
fi
echo ""

echo -e "${BLUE}=== SYSTEM RESOURCES ===${NC}"
cpu_usage=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' || echo "N/A")
memory_usage=$(free 2>/dev/null | awk 'NR==2{printf "%.1f%%", $3*100/$2 }' || echo "N/A")
disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}' || echo "N/A")
load_avg=$(uptime 2>/dev/null | awk -F'load average:' '{print $2}' || echo " N/A")

echo "CPU Usage: ${cpu_usage}%"
echo "Memory Usage: ${memory_usage}"
echo "Disk Usage: ${disk_usage}"
echo "Load Average:${load_avg}"

if command -v iostat >/dev/null; then
    io_wait=$(iostat -c 1 1 2>/dev/null | tail -1 | awk '{print $4}' || echo "N/A")
    echo "IO Wait: ${io_wait}%"
fi
echo ""

echo -e "${BLUE}=== RECENT SECURITY EVENTS ===${NC}"
echo "SSH Failed Logins (Last 24h):"
if command -v journalctl >/dev/null; then
    journalctl --since "24 hours ago" -u ssh 2>/dev/null | grep "Failed password" | tail -5 | awk '{print $1, $2, $3, $(NF-3), $(NF-1)}' || echo "No recent failed SSH attempts"
else
    grep "Failed password" /var/log/auth.log 2>/dev/null | tail -5 || echo "No recent failed SSH attempts"
fi
echo ""

if [ -f /var/log/suricata/fast.log ]; then
    echo "Recent Suricata Alerts:"
    tail -5 /var/log/suricata/fast.log 2>/dev/null | awk '{print $1, $2, $6, $7, $8}' || echo "No recent Suricata alerts"
else
    echo "No Suricata logs found"
fi
echo ""

echo -e "${BLUE}=== NETWORK CONNECTIONS ===${NC}"
if command -v ss >/dev/null; then
    echo "Active connections by state:"
    ss -s 2>/dev/null | grep -E "(TCP|UDP):" || echo "Connection stats unavailable"
    echo ""
    echo "Top external connections:"
    ss -tuln 2>/dev/null | grep ESTAB | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -5 || echo "No established connections"
fi
echo ""

echo -e "${BLUE}=== SECURITY SCORE ===${NC}"
score=0
systemctl is-active --quiet suricata 2>/dev/null && score=$((score + 20))
systemctl is-active --quiet fail2ban 2>/dev/null && score=$((score + 20))
systemctl is-active --quiet nginx 2>/dev/null && score=$((score + 15))
systemctl is-active --quiet wazuh-manager 2>/dev/null && score=$((score + 15))
command -v ufw >/dev/null && ufw status 2>/dev/null | grep -q "Status: active" && score=$((score + 15))
[[ $EUID -eq 0 ]] && iptables -L 2>/dev/null | grep -q "DROP" && score=$((score + 10))
(systemctl is-active --quiet snort 2>/dev/null || systemctl is-active --quiet snort-alt 2>/dev/null || systemctl is-active --quiet snort-ids 2>/dev/null || systemctl is-active --quiet snort-minimal 2>/dev/null) && score=$((score + 5))

if [ $score -ge 90 ]; then
    echo -e "Security Score: ${GREEN}$score/100 - EXCELLENT${NC}"
elif [ $score -ge 70 ]; then
    echo -e "Security Score: ${YELLOW}$score/100 - GOOD${NC}"
else
    echo -e "Security Score: ${RED}$score/100 - NEEDS IMPROVEMENT${NC}"
fi

echo ""
echo -e "${CYAN}==========================================${NC}"
echo -e "Report generated: $(date)"
echo -e "For full functionality, run: sudo $0"
echo -e "${CYAN}==========================================${NC}"
EOF

sed -i "s/PRIMARY_IFACE_PLACEHOLDER/${PRIMARY_IFACE}/g" /usr/local/bin/security-status.sh

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

/var/log/suricata/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    postrotate
        systemctl reload suricata >/dev/null 2>&1 || true
    endscript
}
EOF

log_info "Enhanced monitoring dashboard configured"