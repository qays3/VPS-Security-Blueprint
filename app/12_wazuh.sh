#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing and configuring Wazuh..."

curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
chmod 644 /usr/share/keyrings/wazuh.gpg
mkdir -p /etc/apt/sources.list.d
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" | tee /etc/apt/sources.list.d/wazuh.list >/dev/null
apt update
apt install -y wazuh-manager dos2unix

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager
sleep 10

if [ ! -d "/var/ossec/etc/rules" ]; then
    log_error "Wazuh rules directory not found after installation"
    exit 1
fi

mkdir -p "$BACKUP_DIR"
cp -a /var/ossec/etc/ossec.conf "${BACKUP_DIR}/ossec.conf.bak" || true

cat > /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>
  <alerts>
    <log_alert_level>3</log_alert_level>
  </alerts>
  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/suricata/fast.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/security-sync.log</location>
  </localfile>
</ossec_config>
EOF

dos2unix /var/ossec/etc/ossec.conf

mkdir -p /var/ossec/logs/alerts
mkdir -p /var/log

chown -R ossec:ossec /var/ossec/logs/
chmod 755 /var/ossec/logs/alerts/

systemctl restart wazuh-manager

if systemctl is-active --quiet wazuh-manager; then
    log_info "Wazuh manager installed and running successfully"
else
    log_error "Wazuh manager failed to start"
    systemctl status wazuh-manager
fi

log_info "Wazuh installation completed"
