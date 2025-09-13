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

log_info "Cleaning up previous Wazuh installation..."
systemctl stop wazuh-manager 2>/dev/null || true
systemctl stop wazuh-dashboard 2>/dev/null || true
systemctl stop wazuh-indexer 2>/dev/null || true
rm -f /tmp/wazuh-install-files.tar
rm -f /tmp/wazuh-passwords.txt

log_info "Setting up Wazuh all-in-one installation..."
cd /tmp

curl -sO https://packages.wazuh.com/4.12/wazuh-install.sh
curl -sO https://packages.wazuh.com/4.12/config.yml

PUBLIC_IP=$(curl -s ipinfo.io/ip 2>/dev/null || echo "127.0.0.1")
INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7; exit}' 2>/dev/null || echo "127.0.0.1")

cat > config.yml <<EOF
nodes:
  indexer:
    - name: node-1
      ip: "${INTERNAL_IP}"
  server:
    - name: wazuh-1
      ip: "${INTERNAL_IP}"
  dashboard:
    - name: dashboard
      ip: "${INTERNAL_IP}"
EOF

log_info "Generating configuration files..."
bash wazuh-install.sh --generate-config-files || {
    log_error "Failed to generate config files"
    exit 1
}

log_info "Installing Wazuh all-in-one with overwrite (this may take 10-15 minutes)..."
timeout 1200 bash wazuh-install.sh --all-in-one --overwrite || {
    log_error "All-in-one installation failed"
    exit 1
}

sleep 20

log_info "Configuring UFW for Wazuh..."
ufw allow 1515/tcp >/dev/null 2>&1 || true
ufw allow 1514/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 9200/tcp >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

log_info "Checking Wazuh services status..."
services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
active_services=0

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        log_info "✓ $service is running"
        active_services=$((active_services + 1))
    else
        log_warn "✗ $service is not running"
        systemctl status "$service" --no-pager --lines=2 || true
    fi
done

if [ $active_services -eq 3 ]; then
    log_info "Wazuh installation completed successfully with all 3 services running"
    
    if [ -f /tmp/wazuh-passwords.txt ]; then
        log_info "Web interface credentials saved to /tmp/wazuh-passwords.txt"
        cat /tmp/wazuh-passwords.txt
    fi
    
    log_info "Wazuh dashboard should be accessible at: https://${PUBLIC_IP}:443"
    log_info "Default username: admin"
elif [ $active_services -gt 0 ]; then
    log_warn "Wazuh partially installed with $active_services/3 services running"
else
    log_error "Wazuh installation failed - no services are running"
    log_info "Check installation logs at: /var/log/wazuh-install.log"
    exit 1
fi

cd - >/dev/null

log_info "Wazuh installation completed"