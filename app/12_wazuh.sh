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

# Completely remove and recreate the configuration
rm -f /var/ossec/etc/ossec.conf

cat > /var/ossec/etc/ossec.conf << 'WAZUHEOF'
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
</ossec_config>
WAZUHEOF

# Verify the file was created correctly
if [ ! -f /var/ossec/etc/ossec.conf ]; then
    log_error "Failed to create ossec.conf"
    exit 1
fi

# Check file size
file_size=$(wc -c < /var/ossec/etc/ossec.conf)
if [ "$file_size" -lt 100 ]; then
    log_error "Configuration file is too small, something went wrong"
    cat /var/ossec/etc/ossec.conf
    exit 1
fi

# Convert line endings and validate
dos2unix /var/ossec/etc/ossec.conf 2>/dev/null || true

# Test XML validity
if ! xmllint --noout /var/ossec/etc/ossec.conf 2>/dev/null; then
    log_error "XML validation failed"
    log_error "File contents:"
    cat /var/ossec/etc/ossec.conf
    exit 1
fi

# Set up directories and permissions
mkdir -p /var/ossec/logs/alerts /var/ossec/queue/alerts /var/ossec/queue/diff /var/ossec/queue/rids /var/ossec/stats /var/ossec/var/run /var/ossec/etc/rules

# Create a minimal local rules file
cat > /var/ossec/etc/rules/local_rules.xml << 'RULESEOF'
<group name="local,">
</group>
RULESEOF

chown -R ossec:ossec /var/ossec/logs /var/ossec/queue /var/ossec/stats /var/ossec/var
chown -R root:ossec /var/ossec/etc
chmod -R 550 /var/ossec/etc
chmod 440 /var/ossec/etc/ossec.conf
chmod 440 /var/ossec/etc/rules/local_rules.xml

# Test the configuration before starting
log_info "Testing Wazuh configuration..."
if /var/ossec/bin/wazuh-control start 2>/dev/null; then
    sleep 2
    /var/ossec/bin/wazuh-control stop
    log_info "Configuration test passed"
else
    log_error "Wazuh control test failed"
    exit 1
fi

# Start the service
log_info "Starting Wazuh manager..."
systemctl start wazuh-manager

# Wait and check if it started successfully
sleep 5
if systemctl is-active --quiet wazuh-manager; then
    log_info "Wazuh manager installed and running successfully"
else
    log_error "Wazuh manager failed to start"
    systemctl status wazuh-manager --no-pager -l
    journalctl -u wazuh-manager --no-pager -l | tail -20
    exit 1
fi

log_info "Wazuh installation completed successfully"