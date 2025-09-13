#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing dependencies..."
apt update
apt install -y curl gnupg dos2unix libxml2-utils apt-transport-https lsb-release

log_info "Installing and configuring Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
mkdir -p /etc/apt/sources.list.d
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | tee /etc/apt/sources.list.d/wazuh.list >/dev/null

apt update
apt install -y wazuh-manager || true

systemctl daemon-reload
systemctl stop wazuh-manager || true

mkdir -p "$BACKUP_DIR"
cp -a /var/ossec/etc/ossec.conf "${BACKUP_DIR}/ossec.conf.bak" 2>/dev/null || true

rm -f /var/ossec/etc/ossec.conf

cat > /var/ossec/etc/ossec.conf <<'WAZUHEOF'
<?xml version="1.0" encoding="UTF-8"?>
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <memory_size>64</memory_size>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <logging>
    <log_format>plain</log_format>
  </logging>

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

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <rule_exclude>0215-policy_rules.xml</rule_exclude>
    <list>etc/lists/audit-keys</list>
    <list>etc/lists/amazon/aws-eventnames</list>
    <list>etc/lists/security-eventchannel</list>
  </ruleset>
</ossec_config>
WAZUHEOF

mkdir -p /var/ossec/logs/alerts /var/ossec/queue/alerts /var/ossec/queue/diff /var/ossec/queue/rids /var/ossec/stats /var/ossec/var/run /var/ossec/etc/rules

cat > /var/ossec/etc/rules/local_rules.xml <<'RULESEOF'
<?xml version="1.0" encoding="UTF-8"?>
<group name="local,">
  <rule id="100001" level="5">
    <decoded_as>ssh</decoded_as>
    <match>Failed password|Failed publickey|authentication failure</match>
    <description>SSH authentication failure</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100002" level="10">
    <if_sid>100001</if_sid>
    <frequency>5</frequency>
    <timeframe>300</timeframe>
    <description>SSH brute force attack detected</description>
    <group>authentication_failures,attack,</group>
  </rule>
</group>
RULESEOF

groupadd ossec 2>/dev/null || true
useradd -r -s /bin/false -d /var/ossec -g ossec ossec 2>/dev/null || true

chown -R ossec:ossec /var/ossec/logs /var/ossec/queue /var/ossec/stats /var/ossec/var 2>/dev/null || true
chown -R root:ossec /var/ossec/etc 2>/dev/null || true
chmod -R 550 /var/ossec/etc 2>/dev/null || true
chmod 440 /var/ossec/etc/ossec.conf 2>/dev/null || true
chmod 440 /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true

if xmllint --noout /var/ossec/etc/ossec.conf 2>/dev/null; then
    log_info "Wazuh XML configuration is valid"
    
    systemctl enable wazuh-manager || true
    systemctl start wazuh-manager || true
    sleep 10
    
    if systemctl is-active --quiet wazuh-manager; then
        log_info "Wazuh manager installed and running successfully"
    else
        log_warn "Wazuh manager startup failed after XML fix"
        journalctl -u wazuh-manager --lines=5 --no-pager
    fi
else
    log_error "XML configuration is still invalid"
    xmllint --noout /var/ossec/etc/ossec.conf
fi

log_info "Wazuh installation completed"