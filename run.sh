#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

TIMESTAMP=$(date +%F_%T)
BACKUP_DIR="/root/sec-backups-${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
APP_DIR="$SCRIPT_DIR/app"

if [ ! -d "$APP_DIR" ]; then
    log_error "App directory not found: $APP_DIR"
    exit 1
fi

export TIMESTAMP BACKUP_DIR PRIMARY_IFACE USERNAME PASSWORD
export -f log_info log_warn log_error

log_info "Making all scripts executable..."
find "$APP_DIR" -name "*.sh" -exec chmod +x {} \;

log_info "Starting security setup..."

"$APP_DIR/01_packages.sh"

"$APP_DIR/02_user_setup.sh"
[ -f /tmp/vps_setup_vars.sh ] && source /tmp/vps_setup_vars.sh

"$APP_DIR/03_ssh_hardening.sh"

"$APP_DIR/04_kernel_hardening.sh"

"$APP_DIR/05_network_detection.sh"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh

"$APP_DIR/06_ddos_protection.sh"

"$APP_DIR/07_ufw_firewall.sh"

"$APP_DIR/08_fail2ban.sh"

"$APP_DIR/09_suricata.sh"

"$APP_DIR/10_snort.sh"

"$APP_DIR/11_nginx_modsecurity.sh"

"$APP_DIR/12_wazuh.sh"

"$APP_DIR/13_service_integration.sh"

"$APP_DIR/14_monitoring.sh"

"$APP_DIR/15_final_setup.sh"

log_info "Security setup completed successfully!"
log_info "Run '/usr/local/bin/security-status.sh' to check system status."