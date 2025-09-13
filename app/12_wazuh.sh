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

log_info "Setting up Wazuh all-in-one installation..."
cd /tmp

systemctl stop wazuh-manager 2>/dev/null || true
systemctl stop wazuh-dashboard 2>/dev/null || true
systemctl stop wazuh-indexer 2>/dev/null || true

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
    log_warn "Config generation failed, continuing with installation"
}

log_info "Installing Wazuh all-in-one (this may take 5-10 minutes)..."
export WAZUH_INSTALL_TYPE="all-in-one"
timeout 900 bash wazuh-install.sh --all-in-one || {
    log_warn "All-in-one installation failed or timed out, trying manual installation"
    
    log_info "Attempting manual Wazuh installation..."
    bash wazuh-install.sh --wazuh-indexer node-1 || true
    sleep 10
    bash wazuh-install.sh --start-cluster || true
    sleep 10
    bash wazuh-install.sh --wazuh-server wazuh-1 || true
    sleep 10
    bash wazuh-install.sh --wazuh-dashboard dashboard || true
}

sleep 15

log_info "Configuring UFW for Wazuh..."
ufw allow 1515/tcp >/dev/null 2>&1 || true
ufw allow 1514/tcp >/dev/null 2>&1 || true
ufw allow 443/tcp >/dev/null 2>&1 || true
ufw allow 9200/tcp >/dev/null 2>&1 || true
ufw reload >/dev/null 2>&1 || true

log_info "Starting and enabling Wazuh services..."
services=("wazuh-indexer" "wazuh-manager" "wazuh-dashboard")
for service in "${services[@]}"; do
    systemctl enable "$service" 2>/dev/null || true
    systemctl start "$service" 2>/dev/null || true
done

sleep 10

log_info "Checking Wazuh services status..."
active_services=0

for service in "${services[@]}"; do
    if systemctl is-active --quiet "$service" 2>/dev/null; then
        log_info "✓ $service is running"
        active_services=$((active_services + 1))
    else
        log_warn "✗ $service is not running, attempting to start..."
        systemctl restart "$service" 2>/dev/null || true
        sleep 10
        if systemctl is-active --quiet "$service" 2>/dev/null; then
            log_info "✓ $service started successfully"
            active_services=$((active_services + 1))
        else
            log_warn "✗ $service failed to start"
            systemctl status "$service" --no-pager --lines=3 || true
        fi
    fi
done

if [ $active_services -ge 1 ]; then
    log_info "Wazuh installation completed with $active_services/3 services running"
    
    if [ -f /tmp/wazuh-install-files.tar ]; then
        log_info "Installation files saved to /tmp/wazuh-install-files.tar"
        
        if [ -f /tmp/wazuh-passwords.txt ]; then
            log_info "Web interface credentials saved to /tmp/wazuh-passwords.txt"
        fi
    fi
    
    if systemctl is-active --quiet wazuh-dashboard 2>/dev/null; then
        log_info "Wazuh dashboard should be accessible at: https://${PUBLIC_IP}:443"
        log_info "Default credentials: admin / admin (check /tmp/wazuh-passwords.txt for generated passwords)"
    fi
    
    if systemctl is-active --quiet wazuh-manager 2>/dev/null; then
        log_info "Wazuh manager is running and monitoring logs"
    fi
else
    log_warn "Wazuh installation completed but no services are running properly"
    log_info "Check installation logs at: /var/log/wazuh-install.log"
fi

cd - >/dev/null

log_info "Wazuh installation completed"