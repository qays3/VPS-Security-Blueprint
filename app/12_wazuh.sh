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

log_info "Installing dependencies..."
apt update
apt install -y curl gnupg dos2unix libxml2-utils apt-transport-https lsb-release

log_info "Installing and configuring Wazuh..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
mkdir -p /etc/apt/sources.list.d
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | tee /etc/apt/sources.list.d/wazuh.list >/dev/null

apt update
apt install -y wazuh-manager

systemctl daemon-reload
systemctl stop wazuh-manager 2>/dev/null || true

mkdir -p "$BACKUP_DIR"
cp -a /var/ossec/etc/ossec.conf "${BACKUP_DIR}/ossec.conf.bak" 2>/dev/null || true

cat > /var/ossec/etc/ossec.conf <<'WAZUHEOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <memory_size>128</memory_size>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
    <white_list>10.0.0.0/8</white_list>
    <white_list>172.16.0.0/12</white_list>
    <white_list>192.168.0.0/16</white_list>
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
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <list>etc/lists/audit-keys</list>
  </ruleset>
</ossec_config>
WAZUHEOF

mkdir -p /var/ossec/logs/alerts /var/ossec/queue/alerts /var/ossec/queue/diff /var/ossec/queue/rids /var/ossec/stats /var/ossec/var/run /var/ossec/etc/rules

cat > /var/ossec/etc/rules/local_rules.xml <<'RULESEOF'
<group name="local,">
  <rule id="100001" level="5">
    <decoded_as>ssh</decoded_as>
    <match>Failed password|Failed publickey|authentication failure</match>
    <description>SSH authentication failure</description>
    <group>authentication_failed,</group>
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
useradd -r -s /bin/false -d /var/ossec -g ossec ossecm 2>/dev/null || true
useradd -r -s /bin/false -d /var/ossec -g ossec ossecr 2>/dev/null || true

chown -R ossec:ossec /var/ossec/logs /var/ossec/queue /var/ossec/stats /var/ossec/var 2>/dev/null || true
chown -R root:ossec /var/ossec/etc 2>/dev/null || true
chmod -R 550 /var/ossec/etc 2>/dev/null || true
chmod 440 /var/ossec/etc/ossec.conf 2>/dev/null || true
chmod 440 /var/ossec/etc/rules/local_rules.xml 2>/dev/null || true

systemctl enable wazuh-manager
systemctl start wazuh-manager
sleep 15

if systemctl is-active --quiet wazuh-manager; then
    log_info "Wazuh manager installed and running successfully"
else
    log_warn "Wazuh manager startup failed, checking basic functionality"
    systemctl status wazuh-manager --no-pager --lines=3
fi

log_info "Wazuh installation completed"