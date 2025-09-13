#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

show_help() {
    echo "VPS Security Blueprint Setup Script"
    echo ""
    echo "Usage: sudo $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -s, --start NUM    Start from step NUM (1-15)"
    echo "  -h, --help         Show this help message"
    echo ""
    echo "Steps:"
    echo "  01 - Package installation"
    echo "  02 - User setup"
    echo "  03 - SSH hardening"
    echo "  04 - Kernel hardening"
    echo "  05 - Network detection"
    echo "  06 - DDoS protection"
    echo "  07 - UFW firewall"
    echo "  08 - Fail2ban"
    echo "  09 - Suricata IPS"
    echo "  10 - Snort IDS"
    echo "  11 - Nginx + ModSecurity"
    echo "  12 - Wazuh SIEM"
    echo "  13 - Service integration"
    echo "  14 - Monitoring setup"
    echo "  15 - Final configuration"
    echo ""
    echo "Example: sudo $0 -s 10  (starts from step 10)"
    exit 0
}

if [[ $EUID -ne 0 ]]; then
    echo "Error: You must run this script as sudo"
    echo "Usage: sudo $0"
    exit 1
fi

START_STEP=1

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--start)
            START_STEP="$2"
            if ! [[ "$START_STEP" =~ ^[0-9]+$ ]] || [ "$START_STEP" -lt 1 ] || [ "$START_STEP" -gt 15 ]; then
                echo "Error: Start step must be between 1 and 15"
                exit 1
            fi
            shift 2
            ;;
        -h|--help)
            show_help
            ;;
        *)
            echo "Unknown option: $1"
            show_help
            ;;
    esac
done

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

if [ "$START_STEP" -le 1 ]; then
    log_info "Starting 01_packages"
    "$APP_DIR/01_packages.sh"
fi

if [ "$START_STEP" -le 2 ]; then
    log_info "Starting 02_user_setup"
    "$APP_DIR/02_user_setup.sh"
    [ -f /tmp/vps_setup_vars.sh ] && source /tmp/vps_setup_vars.sh
else
    [ -f /tmp/vps_setup_vars.sh ] && source /tmp/vps_setup_vars.sh
fi

if [ "$START_STEP" -le 3 ]; then
    log_info "Starting 03_ssh_hardening"
    "$APP_DIR/03_ssh_hardening.sh"
fi

if [ "$START_STEP" -le 4 ]; then
    log_info "Starting 04_kernel_hardening"
    "$APP_DIR/04_kernel_hardening.sh"
fi

if [ "$START_STEP" -le 5 ]; then
    log_info "Starting 05_network_detection"
    "$APP_DIR/05_network_detection.sh"
    [ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
else
    [ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
fi

if [ "$START_STEP" -le 6 ]; then
    log_info "Starting 06_ddos_protection"
    "$APP_DIR/06_ddos_protection.sh"
fi

if [ "$START_STEP" -le 7 ]; then
    log_info "Starting 07_ufw_firewall"
    "$APP_DIR/07_ufw_firewall.sh"
fi

if [ "$START_STEP" -le 8 ]; then
    log_info "Starting 08_fail2ban"
    "$APP_DIR/08_fail2ban.sh"
fi

if [ "$START_STEP" -le 9 ]; then
    log_info "Starting 09_suricata"
    "$APP_DIR/09_suricata.sh"
fi

if [ "$START_STEP" -le 10 ]; then
    log_info "Starting 10_snort"
    "$APP_DIR/10_snort.sh"
fi

if [ "$START_STEP" -le 11 ]; then
    log_info "Starting 11_nginx_modsecurity"
    if ! "$APP_DIR/11_nginx_modsecurity.sh"; then
        log_error "Nginx ModSecurity installation failed, but continuing..."
    fi
fi

if [ "$START_STEP" -le 12 ]; then
    log_info "Starting 12_wazuh"
    if ! "$APP_DIR/12_wazuh.sh"; then
        log_error "Wazuh installation failed, but continuing..."
    fi
fi

if [ "$START_STEP" -le 13 ]; then
    log_info "Starting 13_service_integration"
    "$APP_DIR/13_service_integration.sh"
fi

if [ "$START_STEP" -le 14 ]; then
    log_info "Starting 14_monitoring"
    "$APP_DIR/14_monitoring.sh"
fi

if [ "$START_STEP" -le 15 ]; then
    log_info "Starting 15_final_setup"
    "$APP_DIR/15_final_setup.sh"
fi

log_info "Security setup completed successfully!"
log_info "Run '/usr/local/bin/security-status.sh' to check system status."