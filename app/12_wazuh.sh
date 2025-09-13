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
systemctl enable wazuh-manager
systemctl stop wazuh-manager || true

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
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <syscheck>
    <disabled>yes</disabled>
  </syscheck>

  <rootcheck>
    <disabled>yes</disabled>
  </rootcheck>
</ossec_config>
WAZUHEOF

dos2unix /var/ossec/etc/ossec.conf
xmllint --noout /var/ossec/etc/ossec.conf || { log_error "XML validation failed"; exit 1; }

mkdir -p /var/ossec/logs/alerts /var/ossec/queue/alerts /var/ossec/queue/diff /var/ossec/queue/rids /var/ossec/stats /var/ossec/var/run

chown -R ossec:ossec /var/ossec/logs /var/ossec/queue /var/ossec/stats /var/ossec/var
chown -R root:ossec /var/ossec/etc
chmod -R 550 /var/ossec/etc
chmod 440 /var/ossec/etc/ossec.conf

systemctl start wazuh-manager

if systemctl is-active --quiet wazuh-manager; then
    log_info "Wazuh manager installed and running successfully"
else
    log_error "Wazuh manager failed to start"
    systemctl status wazuh-manager
    journalctl -xeu wazuh-manager.service
fi

log_info "Wazuh installation completed"