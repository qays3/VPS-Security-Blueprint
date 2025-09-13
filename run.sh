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

log_info "Starting 01_packages"
"$APP_DIR/01_packages.sh"

log_info "Starting 02_user_setup"
"$APP_DIR/02_user_setup.sh"
[ -f /tmp/vps_setup_vars.sh ] && source /tmp/vps_setup_vars.sh

log_info "Starting 03_ssh_hardening"
"$APP_DIR/03_ssh_hardening.sh"

log_info "Starting 04_kernel_hardening"
"$APP_DIR/04_kernel_hardening.sh"

log_info "Starting 05_network_detection"
"$APP_DIR/05_network_detection.sh"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh

log_info "Starting 06_ddos_protection"
"$APP_DIR/06_ddos_protection.sh"

log_info "Starting 07_ufw_firewall"
"$APP_DIR/07_ufw_firewall.sh"

log_info "Starting 08_fail2ban"
"$APP_DIR/08_fail2ban.sh"

log_info "Starting 09_suricata"
"$APP_DIR/09_suricata.sh"

log_info "Starting 10_snort"
"$APP_DIR/10_snort.sh"

log_info "Starting 11_nginx_modsecurity"
if ! "$APP_DIR/11_nginx_modsecurity.sh"; then
    log_error "Nginx ModSecurity installation failed, but continuing..."
fi

log_info "Starting 12_wazuh"
if ! "$APP_DIR/12_wazuh.sh"; then
    log_error "Wazuh installation failed, but continuing..."
fi

log_info "Starting 13_service_integration"
"$APP_DIR/13_service_integration.sh"

log_info "Starting 14_monitoring"
"$APP_DIR/14_monitoring.sh"

log_info "Starting 15_final_setup"
"$APP_DIR/15_final_setup.sh"

log_info "Security setup completed successfully!"
log_info "Run '/usr/local/bin/security-status.sh' to check system status."