#!/usr/bin/env bash
set -euo pipefail

log_info "Setting up service integration..."

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
</group>
EOF

cat > /var/ossec/active-response/bin/firewall-drop.sh <<'EOF'
#!/bin/bash
ACTION=$1
USER=$2
IP=$3

case "$ACTION" in
  add)
    /usr/sbin/iptables -I INPUT -s $IP -j DROP
    /usr/sbin/fail2ban-client set sshd banip $IP 2>/dev/null || true
    echo "$(date) - Blocked IP: $IP" >> /var/log/wazuh-blocks.log
    ;;
  delete)
    /usr/sbin/iptables -D INPUT -s $IP -j DROP 2>/dev/null || true
    /usr/sbin/fail2ban-client set sshd unbanip $IP 2>/dev/null || true
    echo "$(date) - Unblocked IP: $IP" >> /var/log/wazuh-blocks.log
    ;;
esac
EOF

chmod 755 /var/ossec/active-response/bin/firewall-drop.sh

cat > /usr/local/bin/security-sync.sh <<'EOF'
#!/bin/bash

BANNED_IPS_FILE="/tmp/banned_ips.txt"
WAZUH_LOG="/var/ossec/logs/alerts/alerts.log"
SURICATA_LOG="/var/log/suricata/fast.log"

extract_and_ban() {
    if [ -f "$SURICATA_LOG" ]; then
        tail -n 100 "$SURICATA_LOG" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "$WAZUH_LOG" ]; then
        tail -n 100 "$WAZUH_LOG" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    if [ -f "$BANNED_IPS_FILE" ]; then
        sort -u "$BANNED_IPS_FILE" > /tmp/unique_banned_ips.txt
        
        while read -r ip; do
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                if [[ ! "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|127\.) ]]; then
                    if ! iptables -L INPUT -n | grep -q "$ip"; then
                        iptables -I INPUT -s "$ip" -j DROP
                        echo "$(date) - Auto-banned IP: $ip" >> /var/log/security-sync.log
                        fail2ban-client set sshd banip "$ip" 2>/dev/null || true
                    fi
                fi
            fi
        done < /tmp/unique_banned_ips.txt
        
        rm -f "$BANNED_IPS_FILE" /tmp/unique_banned_ips.txt
    fi
}

extract_and_ban
EOF

chmod 755 /usr/local/bin/security-sync.sh

echo "*/5 * * * * root /usr/local/bin/security-sync.sh" >> /etc/crontab

log_info "Service integration configured"