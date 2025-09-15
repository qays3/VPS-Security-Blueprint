#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

INTERNAL_IP=$(ip route get 8.8.8.8 | grep -oP 'src \K\S+' | head -1)
if [[ -z "$INTERNAL_IP" ]]; then
    INTERNAL_IP=$(hostname -I | awk '{print $1}')
fi

if [[ -z "$INTERNAL_IP" ]]; then
    echo "Available IP addresses:"
    ip addr show | grep -E "inet.*global" | awk '{print $2}' | cut -d/ -f1
    echo ""
    read -p "Enter your VM's internal IP address: " INTERNAL_IP
fi

log_info "Using internal IP: $INTERNAL_IP"

apt update
apt install -y curl gnupg dos2unix libxml2-utils apt-transport-https lsb-release jq

systemctl stop wazuh-manager 2>/dev/null || true
systemctl stop wazuh-indexer 2>/dev/null || true
systemctl stop wazuh-dashboard 2>/dev/null || true
systemctl disable wazuh-manager 2>/dev/null || true
systemctl disable wazuh-indexer 2>/dev/null || true
systemctl disable wazuh-dashboard 2>/dev/null || true

apt remove --purge wazuh-manager wazuh-indexer wazuh-dashboard -y 2>/dev/null || true
apt autoremove -y 2>/dev/null || true

rm -rf /var/ossec /var/lib/wazuh-indexer /etc/wazuh-indexer

groupadd ossec 2>/dev/null || true
useradd -r -g ossec -d /var/ossec -s /sbin/nologin ossec 2>/dev/null || true
groupadd wazuh-indexer 2>/dev/null || true
useradd -r -g wazuh-indexer -d /usr/share/wazuh-indexer -s /sbin/nologin wazuh-indexer 2>/dev/null || true

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" > /etc/apt/sources.list.d/wazuh.list
apt update

DEBIAN_FRONTEND=noninteractive apt install -y wazuh-indexer

mkdir -p /etc/wazuh-indexer/certs

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/wazuh-indexer/certs/indexer-key.pem \
    -out /etc/wazuh-indexer/certs/indexer.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=$INTERNAL_IP"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/wazuh-indexer/certs/admin-key.pem \
    -out /etc/wazuh-indexer/certs/admin.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=admin"

openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout /etc/wazuh-indexer/certs/root-ca-key.pem \
    -out /etc/wazuh-indexer/certs/root-ca.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=root-ca"

chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
chmod 600 /etc/wazuh-indexer/certs/*.pem

cat > /etc/wazuh-indexer/opensearch.yml <<EOF
cluster.name: wazuh-cluster
node.name: wazuh-indexer
path.data: /var/lib/wazuh-indexer
path.logs: /var/log/wazuh-indexer

network.host: ["127.0.0.1"]
http.port: 9200
transport.port: 9300

discovery.type: single-node
cluster.initial_master_nodes: ["wazuh-indexer"]

plugins.security.disabled: true

bootstrap.memory_lock: false
EOF

cat > /etc/wazuh-indexer/jvm.options <<EOF
-Xms512m
-Xmx512m
-XX:+UseG1GC
-XX:MaxGCPauseMillis=200
EOF

systemctl enable wazuh-indexer
systemctl start wazuh-indexer

sleep 15

TIMEOUT=60
COUNTER=0
while ! curl -s http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1; do
    if [ $COUNTER -ge $TIMEOUT ]; then
        log_error "Wazuh indexer failed to start within $TIMEOUT seconds"
        exit 1
    fi
    sleep 2
    COUNTER=$((COUNTER + 2))
    log_info "Waiting for indexer to start... ($COUNTER/$TIMEOUT)"
done

log_info "Wazuh indexer is running"

DEBIAN_FRONTEND=noninteractive apt install -y wazuh-manager

mkdir -p /var/ossec/etc/rules /var/ossec/logs/alerts /var/ossec/active-response/bin

cat > /var/ossec/etc/ossec.conf <<EOF
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <hostname>wazuh-server</hostname>
  </global>

  <rules>
    <include>rules_config.xml</include>
    <include>pam_rules.xml</include>
    <include>sshd_rules.xml</include>
    <include>syslog_rules.xml</include>
    <include>web_rules.xml</include>
    <include>web_appsec_rules.xml</include>
    <include>apache_rules.xml</include>
    <include>nginx_rules.xml</include>
    <include>ids_rules.xml</include>
    <include>firewall_rules.xml</include>
    <include>attack_rules.xml</include>
    <include>local_rules.xml</include>
  </rules>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories>/etc,/usr/bin,/usr/sbin</directories>
    <directories>/bin,/sbin</directories>
  </syscheck>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
  </rootcheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/suricata/fast.log</location>
  </localfile>

  <indexer>
    <enabled>yes</enabled>
    <hosts>
      <host>http://127.0.0.1:9200</host>
    </hosts>
  </indexer>

  <active-response>
    <disabled>no</disabled>
  </active-response>

</ossec_config>
EOF

cat > /var/ossec/etc/rules/local_rules.xml <<EOF
<group name="local,syslog,">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>fail2ban.actions</match>
    <regex>Ban (\S+)</regex>
    <description>Fail2ban banned IP address: \$(regex)</description>
    <group>authentication_failed,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>1002</if_sid>
    <match>suricata</match>
    <regex>ATTACK|MALWARE|TROJAN|EXPLOIT</regex>
    <description>Suricata detected attack: \$(regex)</description>
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

  <rule id="100006" level="7">
    <if_sid>5716</if_sid>
    <srcip>!10.0.0.0/8,!172.16.0.0/12,!192.168.0.0/16</srcip>
    <description>SSH login from external IP</description>
    <group>authentication_success,external_access,</group>
  </rule>

  <rule id="100007" level="12">
    <if_sid>31101</if_sid>
    <description>High number of connections from single IP</description>
    <group>network,dos_attack,</group>
  </rule>
</group>
EOF

chown -R ossec:ossec /var/ossec
chmod -R 750 /var/ossec/etc
chmod 644 /var/ossec/etc/ossec.conf
chmod 644 /var/ossec/etc/rules/local_rules.xml

systemctl enable wazuh-manager
systemctl start wazuh-manager

sleep 10

cat > /usr/local/bin/wazuh <<EOF
#!/bin/bash

WAZUH_INDEXER="http://127.0.0.1:9200"

show_help() {
    echo "Wazuh Query Tool"
    echo ""
    echo "Usage: wazuh [OPTION]"
    echo ""
    echo "Options:"
    echo "  -h, --help              Show this help"
    echo "  -s, --status            Show cluster status"
    echo "  -i, --indices           List all indices"
    echo "  -a, --alerts [N]        Show last N alerts (default: 10)"
    echo "  -f, --failed-logins     Show failed login attempts"
    echo "  -w, --web-attacks       Show web attacks"
    echo "  -n, --network-events    Show network events"
    echo ""
    echo "Examples:"
    echo "  wazuh --alerts 20       # Show last 20 alerts"
    echo "  wazuh --failed-logins   # Show SSH failures"
    echo "  wazuh --web-attacks     # Show web attack attempts"
}

ALERT_COUNT="10"

while [[ \$# -gt 0 ]]; do
    case \$1 in
        -h|--help)
            show_help
            exit 0
            ;;
        -s|--status)
            echo "Wazuh Indexer Cluster Status:"
            curl -s \$WAZUH_INDEXER/_cluster/health?pretty
            exit 0
            ;;
        -i|--indices)
            echo "Available Indices:"
            curl -s \$WAZUH_INDEXER/_cat/indices?v
            exit 0
            ;;
        -a|--alerts)
            if [[ \$2 =~ ^[0-9]+\$ ]]; then
                ALERT_COUNT="\$2"
                shift
            fi
            shift
            ;;
        -f|--failed-logins)
            echo "Recent Failed Login Attempts:"
            curl -s -X GET "\$WAZUH_INDEXER/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d '{
              "size": 20,
              "sort": [{"@timestamp": {"order": "desc"}}],
              "query": {
                "bool": {
                  "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"wildcard": {"rule.description": "*sshd*"}}
                  ]
                }
              }
            }' 2>/dev/null | jq -r '.hits.hits[]._source | "\(.timestamp // .@timestamp) \(.data.srcip // "N/A") \(.rule.description)"' 2>/dev/null || echo "No data available"
            exit 0
            ;;
        -w|--web-attacks)
            echo "Recent Web Attacks:"
            curl -s -X GET "\$WAZUH_INDEXER/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d '{
              "size": 20,
              "sort": [{"@timestamp": {"order": "desc"}}],
              "query": {
                "bool": {
                  "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"terms": {"rule.groups": ["web", "attack", "modsecurity"]}}
                  ]
                }
              }
            }' 2>/dev/null | jq -r '.hits.hits[]._source | "\(.timestamp // .@timestamp) \(.data.srcip // "N/A") \(.rule.description)"' 2>/dev/null || echo "No data available"
            exit 0
            ;;
        -n|--network-events)
            echo "Recent Network Events:"
            curl -s -X GET "\$WAZUH_INDEXER/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d '{
              "size": 20,
              "sort": [{"@timestamp": {"order": "desc"}}],
              "query": {
                "bool": {
                  "must": [
                    {"range": {"@timestamp": {"gte": "now-24h"}}},
                    {"terms": {"rule.groups": ["ids", "network", "intrusion_attempt"]}}
                  ]
                }
              }
            }' 2>/dev/null | jq -r '.hits.hits[]._source | "\(.timestamp // .@timestamp) \(.data.srcip // "N/A") \(.rule.description)"' 2>/dev/null || echo "No data available"
            exit 0
            ;;
        *)
            echo "Unknown option: \$1"
            show_help
            exit 1
            ;;
    esac
done

echo "Recent Wazuh Alerts (Last \$ALERT_COUNT):"
curl -s -X GET "\$WAZUH_INDEXER/wazuh-alerts-*/_search?pretty" -H 'Content-Type: application/json' -d '{
  "size": '"\$ALERT_COUNT"',
  "sort": [{"@timestamp": {"order": "desc"}}],
  "query": {
    "range": {
      "@timestamp": {
        "gte": "now-24h"
      }
    }
  }
}' 2>/dev/null | jq -r '.hits.hits[]._source | "\(.timestamp // .@timestamp) Level:\(.rule.level) \(.rule.description) Source:\(.data.srcip // "localhost")"' 2>/dev/null || echo "No recent alerts found"
EOF

chmod 755 /usr/local/bin/wazuh

sleep 5

cat > /root/WAZUH_INFO.txt <<EOF
Wazuh Indexer URL: http://127.0.0.1:9200
No authentication required (simplified setup)

Usage:
wazuh --help
wazuh --alerts 20
wazuh --failed-logins
wazuh --web-attacks
wazuh --network-events
EOF

if systemctl is-active --quiet wazuh-indexer; then
    log_info "Wazuh Indexer is running"
else
    log_error "Wazuh Indexer failed to start"
    systemctl status wazuh-indexer --no-pager
fi

if systemctl is-active --quiet wazuh-manager; then
    log_info "Wazuh Manager is running"
else
    log_error "Wazuh Manager failed to start"
    systemctl status wazuh-manager --no-pager
fi

log_info "Installation completed"
log_info "Wazuh Indexer URL: http://127.0.0.1:9200"
log_info "Use: wazuh --help"