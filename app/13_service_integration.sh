#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up enhanced service integration..."

cat > /var/ossec/etc/rules/local_rules.xml <<'EOF'
<group name="local,syslog,">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>fail2ban.actions</match>
    <regex>Ban (\S+)</regex>
    <description>Fail2ban banned IP address: $(regex)</description>
    <group>authentication_failed,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>1002</if_sid>
    <match>suricata</match>
    <regex>ATTACK|MALWARE|TROJAN|EXPLOIT</regex>
    <description>Suricata detected attack: $(regex)</description>
    <group>ids,intrusion_attempt,</group>
  </rule>

  <rule id="100003" level="10">
    <if_sid>1002</if_sid>
    <match>ModSecurity</match>
    <regex>Access denied</regex>
    <description>ModSecurity blocked web attack</description>
    <group>web,attack,</group>
  </rule>

  <rule id="100004" level="15">
    <if_sid>100001,100002,100003</if_sid>
    <frequency>3</frequency>
    <timeframe>300</timeframe>
    <description>Multiple security alerts from same source</description>
    <group>multiple_attacks,</group>
  </rule>

  <rule id="100005" level="8">
    <if_sid>1002</if_sid>
    <match>nginx</match>
    <regex>rate.limiting</regex>
    <description>Nginx rate limiting triggered</description>
    <group>web,dos_attack,</group>
  </rule>
</group>
EOF

cat > /var/ossec/active-response/bin/firewall-drop.sh <<'EOF'
#!/bin/bash
ACTION=$1
USER=$2
IP=$3

LOG_FILE="/var/log/wazuh-blocks.log"

case "$ACTION" in
  add)
    if ! iptables -L INPUT -n | grep -q "$IP"; then
        /usr/sbin/iptables -I INPUT -s $IP -j DROP
        echo "$(date) - Wazuh blocked IP: $IP" >> "$LOG_FILE"
    fi
    /usr/sbin/fail2ban-client set sshd banip $IP 2>/dev/null || true
    ;;
  delete)
    /usr/sbin/iptables -D INPUT -s $IP -j DROP 2>/dev/null || true
    /usr/sbin/fail2ban-client set sshd unbanip $IP 2>/dev/null || true
    echo "$(date) - Wazuh unblocked IP: $IP" >> "$LOG_FILE"
    ;;
esac
EOF

chmod 755 /var/ossec/active-response/bin/firewall-drop.sh

cat > /usr/local/bin/security-sync.sh <<'EOF'
#!/bin/bash

BANNED_IPS_FILE="/tmp/banned_ips.txt"
LOG_FILE="/var/log/security-sync.log"

log_event() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $1" >> "$LOG_FILE"
}

validate_ip() {
    local ip=$1
    if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
        IFS='.' read -ra ADDR <<< "$ip"
        for i in "${ADDR[@]}"; do
            if [[ $i -gt 255 ]]; then
                return 1
            fi
        done
        if [[ ! "$ip" =~ ^(127\.|0\.) ]]; then
            return 0
        fi
    fi
    return 1
}

extract_and_ban() {
    > "$BANNED_IPS_FILE"
    
    if [ -f "/var/log/suricata/fast.log" ]; then
        tail -n 100 "/var/log/suricata/fast.log" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "/var/ossec/logs/alerts/alerts.log" ]; then
        tail -n 100 "/var/ossec/logs/alerts/alerts.log" 2>/dev/null | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "/var/log/nginx/access.log" ]; then
        tail -n 100 "/var/log/nginx/access.log" 2>/dev/null | grep -E "(40[0-9]|50[0-9])" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "/var/log/fail2ban.log" ]; then
        tail -n 50 "/var/log/fail2ban.log" 2>/dev/null | grep "Ban " | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "$BANNED_IPS_FILE" ] && [ -s "$BANNED_IPS_FILE" ]; then
        sort -u "$BANNED_IPS_FILE" > "/tmp/unique_banned_ips.txt"
        
        while IFS= read -r ip; do
            if validate_ip "$ip"; then
                if ! iptables -L INPUT -n 2>/dev/null | grep -q "$ip"; then
                    if iptables -I INPUT -s "$ip" -j DROP 2>/dev/null; then
                        log_event "Auto-banned IP: $ip"
                        fail2ban-client set sshd banip "$ip" 2>/dev/null || true
                    fi
                fi
            fi
        done < "/tmp/unique_banned_ips.txt"
        
        rm -f "$BANNED_IPS_FILE" "/tmp/unique_banned_ips.txt"
    fi
}

extract_and_ban
EOF

chmod 755 /usr/local/bin/security-sync.sh

cat > /etc/cron.d/security-health <<'EOF'
*/5 * * * * root /usr/local/bin/security-sync.sh >/dev/null 2>&1
0 2 * * * root find /var/log/security-sync.log -mtime +7 -delete 2>/dev/null || true
*/10 * * * * root systemctl is-active --quiet suricata || systemctl restart suricata >/dev/null 2>&1
*/10 * * * * root systemctl is-active --quiet fail2ban || systemctl restart fail2ban >/dev/null 2>&1
*/10 * * * * root systemctl is-active --quiet nginx || systemctl restart nginx >/dev/null 2>&1
*/10 * * * * root systemctl is-active --quiet wazuh-manager || systemctl restart wazuh-manager >/dev/null 2>&1
EOF

mkdir -p /var/log
touch /var/log/security-sync.log /var/log/wazuh-blocks.log
chmod 644 /var/log/security-sync.log /var/log/wazuh-blocks.log

log_info "Enhanced service integration configured with auto-recovery"