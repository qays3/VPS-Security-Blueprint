#!/bin/bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

show_banner() {
    clear
    echo -e "${RED}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${RED}║            ${YELLOW}SECURITY STACK REMOVAL${RED}             ║${NC}"
    echo -e "${RED}║         ${YELLOW}Complete System Cleanup${RED}            ║${NC}"
    echo -e "${RED}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${YELLOW}WARNING: This will completely remove all security components${NC}"
    echo -e "${YELLOW}and restore the system to its original state.${NC}"
    echo ""
    echo -e "${RED}This action CANNOT be undone!${NC}"
    echo ""
}

confirm_removal() {
    echo -e "${BLUE}Components to be removed:${NC}"
    echo "• Wazuh Manager & Indexer"
    echo "• Suricata IDS/IPS"
    echo "• Snort IDS"
    echo "• Nginx + ModSecurity"
    echo "• Fail2ban"
    echo "• UFW firewall rules"
    echo "• Custom iptables rules"
    echo "• SSH hardening settings"
    echo "• Kernel security settings"
    echo "• All security scripts and tools"
    echo "• Custom user accounts (optional)"
    echo ""
    echo -e "${RED}Do you want to proceed with complete removal?${NC}"
    echo "Type 'REMOVE' to continue or anything else to cancel:"
    read -r confirmation
    
    if [ "$confirmation" != "REMOVE" ]; then
        echo -e "${GREEN}Operation cancelled.${NC}"
        exit 0
    fi
}

create_backup() {
    BACKUP_DIR="/root/removal_backup_$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    log_info "Creating backup before removal..."
    
    cp -r /etc/ssh "$BACKUP_DIR/" 2>/dev/null || true
    cp /etc/sysctl.conf "$BACKUP_DIR/" 2>/dev/null || true
    iptables-save > "$BACKUP_DIR/iptables_backup.txt" 2>/dev/null || true
    ufw status verbose > "$BACKUP_DIR/ufw_backup.txt" 2>/dev/null || true
    
    echo "Backup created at: $BACKUP_DIR"
}

stop_all_services() {
    log_info "Stopping all security services..."
    
    systemctl stop wazuh-manager 2>/dev/null || true
    systemctl stop wazuh-indexer 2>/dev/null || true
    systemctl stop wazuh-dashboard 2>/dev/null || true
    systemctl stop suricata 2>/dev/null || true
    systemctl stop snort 2>/dev/null || true
    systemctl stop snort-alt 2>/dev/null || true
    systemctl stop snort-ids 2>/dev/null || true
    systemctl stop snort-minimal 2>/dev/null || true
    systemctl stop nginx 2>/dev/null || true
    systemctl stop fail2ban 2>/dev/null || true
    
    systemctl disable wazuh-manager 2>/dev/null || true
    systemctl disable wazuh-indexer 2>/dev/null || true
    systemctl disable wazuh-dashboard 2>/dev/null || true
    systemctl disable suricata 2>/dev/null || true
    systemctl disable snort 2>/dev/null || true
    systemctl disable snort-alt 2>/dev/null || true
    systemctl disable snort-ids 2>/dev/null || true
    systemctl disable snort-minimal 2>/dev/null || true
    systemctl disable nginx 2>/dev/null || true
    systemctl disable fail2ban 2>/dev/null || true
}

remove_packages() {
    log_info "Removing security packages..."
    
    apt remove --purge -y wazuh-manager wazuh-indexer wazuh-dashboard 2>/dev/null || true
    apt remove --purge -y suricata suricata-update 2>/dev/null || true
    apt remove --purge -y snort 2>/dev/null || true
    apt remove --purge -y nginx nginx-common nginx-core 2>/dev/null || true
    apt remove --purge -y libmodsecurity3 libmodsecurity-dev 2>/dev/null || true
    apt remove --purge -y fail2ban 2>/dev/null || true
    apt remove --purge -y ufw 2>/dev/null || true
    apt remove --purge -y iptables-persistent netfilter-persistent 2>/dev/null || true
    
    apt autoremove -y 2>/dev/null || true
    apt autoclean 2>/dev/null || true
}

remove_repositories() {
    log_info "Removing security repositories..."
    
    rm -f /etc/apt/sources.list.d/wazuh.list
    rm -f /usr/share/keyrings/wazuh.gpg
    
    apt update -qq 2>/dev/null || true
}

clean_directories() {
    log_info "Removing security directories and files..."
    
    rm -rf /var/ossec
    rm -rf /var/lib/wazuh-indexer
    rm -rf /etc/wazuh-indexer
    rm -rf /etc/suricata
    rm -rf /var/lib/suricata
    rm -rf /var/log/suricata
    rm -rf /etc/snort
    rm -rf /var/log/snort
    rm -rf /var/run/snort
    rm -rf /etc/nginx
    rm -rf /var/www/html
    rm -rf /var/log/nginx
    rm -rf /etc/fail2ban
    rm -rf /var/log/fail2ban.log
    
    rm -f /var/log/security-sync.log
    rm -f /var/log/wazuh-blocks.log
}

remove_users_groups() {
    log_info "Removing security users and groups..."
    
    userdel -r ossec 2>/dev/null || true
    userdel -r wazuh-indexer 2>/dev/null || true
    userdel -r suricata 2>/dev/null || true
    userdel -r snort 2>/dev/null || true
    userdel -r www-data 2>/dev/null || true
    
    groupdel ossec 2>/dev/null || true
    groupdel wazuh-indexer 2>/dev/null || true
    groupdel suricata 2>/dev/null || true
    groupdel snort 2>/dev/null || true
    groupdel www-data 2>/dev/null || true
}

remove_custom_scripts() {
    log_info "Removing custom security scripts..."
    
    rm -f /usr/local/bin/security-status.sh
    rm -f /usr/local/bin/security-sync.sh
    rm -f /usr/local/bin/SecureVista.sh
    rm -f /usr/local/bin/wazuh
    
    rm -f /etc/systemd/system/snort.service
    rm -f /etc/systemd/system/snort-alt.service
    
    systemctl daemon-reload
}

remove_cron_jobs() {
    log_info "Removing security cron jobs..."
    
    rm -f /etc/cron.d/security-health
    
    crontab -l 2>/dev/null | grep -v security-sync | crontab - 2>/dev/null || true
}

reset_firewall() {
    log_info "Resetting firewall to default state..."
    
    iptables -F
    iptables -X
    iptables -t nat -F
    iptables -t nat -X
    iptables -t mangle -F
    iptables -t mangle -X
    iptables -P INPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P OUTPUT ACCEPT
    
    ip6tables -F 2>/dev/null || true
    ip6tables -X 2>/dev/null || true
    ip6tables -P INPUT ACCEPT 2>/dev/null || true
    ip6tables -P FORWARD ACCEPT 2>/dev/null || true
    ip6tables -P OUTPUT ACCEPT 2>/dev/null || true
    
    if command -v netfilter-persistent >/dev/null; then
        netfilter-persistent save 2>/dev/null || true
    fi
}

restore_ssh_config() {
    log_info "Restoring SSH to default configuration..."
    
    cat > /etc/ssh/sshd_config <<'EOF'
Include /etc/ssh/sshd_config.d/*.conf

Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

SyslogFacility AUTH
LogLevel INFO

LoginGraceTime 2m
PermitRootLogin prohibit-password
StrictModes yes
MaxAuthTries 6
MaxSessions 10

PubkeyAuthentication yes
AuthorizedKeysFile	.ssh/authorized_keys .ssh/authorized_keys2

PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

UsePAM yes

X11Forwarding yes
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes

AcceptEnv LANG LC_*

Subsystem	sftp	/usr/lib/openssh/sftp-server
EOF
    
    systemctl restart ssh || systemctl restart sshd || true
    
    log_warn "SSH root login is disabled by default. You can enable it by changing 'PermitRootLogin' to 'yes'"
}

restore_kernel_settings() {
    log_info "Restoring kernel settings to defaults..."
    
    cp /etc/sysctl.conf /etc/sysctl.conf.backup.$(date +%Y%m%d_%H%M%S) 2>/dev/null || true
    
    grep -v "# VPS Security Hardening" /etc/sysctl.conf > /tmp/sysctl_clean.conf 2>/dev/null || echo "" > /tmp/sysctl_clean.conf
    
    sed -i '/^net\.ipv4\.conf\.all\.rp_filter/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.default\.rp_filter/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.icmp_echo_ignore_broadcasts/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.all\.accept_source_route/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.default\.accept_source_route/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_syncookies/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_max_syn_backlog/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_fin_timeout/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_keepalive_time/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.all\.accept_redirects/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.default\.accept_redirects/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.conf\.all\.log_martians/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.ip_local_port_range/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_max_tw_buckets/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_tw_reuse/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_rmem/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_wmem/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.core\.rmem_max/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.core\.wmem_max/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.core\.netdev_max_backlog/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_congestion_control/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.core\.default_qdisc/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_slow_start_after_idle/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_mtu_probing/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_timestamps/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_sack/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_fack/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_window_scaling/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_adv_win_scale/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_moderate_rcvbuf/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_rfc1337/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_max_orphans/d' /tmp/sysctl_clean.conf
    sed -i '/^net\.ipv4\.tcp_orphan_retries/d' /tmp/sysctl_clean.conf
    
    mv /tmp/sysctl_clean.conf /etc/sysctl.conf
    sysctl -p 2>/dev/null || true
}

clean_logs() {
    log_info "Cleaning security-related logs..."
    
    rm -rf /var/log/suricata*
    rm -rf /var/log/snort*
    rm -rf /var/log/nginx*
    rm -rf /var/log/fail2ban*
    rm -rf /var/log/security-*
    rm -rf /var/log/wazuh-*
    
    rm -f /etc/logrotate.d/security-logs
    
    journalctl --vacuum-time=1d 2>/dev/null || true
}

remove_limits() {
    log_info "Removing security-related system limits..."
    
    sed -i '/wazuh-indexer/d' /etc/security/limits.conf
    sed -i '/ossec/d' /etc/security/limits.conf
    sed -i '/suricata/d' /etc/security/limits.conf
    sed -i '/snort/d' /etc/security/limits.conf
}

remove_custom_user() {
    echo ""
    echo -e "${BLUE}Custom User Removal${NC}"
    echo "Do you want to remove the custom user created during setup?"
    echo "This will also remove their home directory and files."
    echo ""
    read -p "Enter username to remove (or press Enter to skip): " custom_user
    
    if [ -n "$custom_user" ]; then
        if id "$custom_user" &>/dev/null; then
            echo -e "${RED}WARNING: This will permanently delete user '$custom_user' and all their files!${NC}"
            read -p "Type 'DELETE' to confirm removal: " delete_confirm
            
            if [ "$delete_confirm" = "DELETE" ]; then
                userdel -r "$custom_user" 2>/dev/null || true
                log_info "User '$custom_user' removed"
            else
                log_info "User removal cancelled"
            fi
        else
            log_warn "User '$custom_user' does not exist"
        fi
    fi
}

clean_temp_files() {
    log_info "Cleaning temporary files..."
    
    rm -f /tmp/vps_setup_vars.sh
    rm -f /tmp/vps_network_vars.sh
    rm -f /tmp/banned_ips.txt
    rm -f /tmp/unique_banned_ips.txt
    rm -f /tmp/sysctl_clean.conf
    
    find /tmp -name "*security*" -type f -delete 2>/dev/null || true
    find /tmp -name "*wazuh*" -type f -delete 2>/dev/null || true
    find /tmp -name "*suricata*" -type f -delete 2>/dev/null || true
}

remove_documentation() {
    log_info "Removing security documentation..."
    
    rm -f /root/SECURITY_README_*.txt
    rm -f /root/WAZUH_CONNECTION_INFO.txt
    rm -f /root/WAZUH_INFO.txt
    
    find /root -name "sec-backups-*" -type d -exec rm -rf {} + 2>/dev/null || true
    find /root -name "securevista_backup_*" -type f -delete 2>/dev/null || true
    find /root -name "securevista_config_*" -type f -delete 2>/dev/null || true
    find /root -name "system_snapshots" -type d -exec rm -rf {} + 2>/dev/null || true
}

install_basic_security() {
    log_info "Installing basic security packages..."
    
    apt update -qq
    apt install -y ufw
    
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    ufw allow 22/tcp
    ufw --force enable
    
    log_info "Basic UFW firewall configured (SSH access only)"
}

final_cleanup() {
    log_info "Performing final system cleanup..."
    
    apt update -qq 2>/dev/null || true
    apt autoremove -y 2>/dev/null || true
    apt autoclean 2>/dev/null || true
    
    systemctl daemon-reload
    
    find /var/cache -name "*wazuh*" -delete 2>/dev/null || true
    find /var/cache -name "*suricata*" -delete 2>/dev/null || true
    find /var/cache -name "*nginx*" -delete 2>/dev/null || true
    
    ldconfig 2>/dev/null || true
}

show_summary() {
    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║            ${YELLOW}REMOVAL COMPLETED${GREEN}                ║${NC}"
    echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${BLUE}Summary of changes:${NC}"
    echo "• All security services removed and disabled"
    echo "• Security packages uninstalled"
    echo "• Firewall rules reset to basic configuration"
    echo "• SSH configuration restored to defaults"
    echo "• Kernel settings restored"
    echo "• Custom scripts and tools removed"
    echo "• Security users and groups removed"
    echo "• Logs and temporary files cleaned"
    echo ""
    echo -e "${YELLOW}Current security status:${NC}"
    echo "• UFW firewall: $(ufw status | head -1)"
    echo "• SSH service: $(systemctl is-active ssh 2>/dev/null || echo 'inactive')"
    echo "• Root SSH login: disabled (default)"
    echo ""
    echo -e "${GREEN}System has been restored to a clean state.${NC}"
    echo -e "${YELLOW}Backup created at: $BACKUP_DIR${NC}"
    echo ""
    echo -e "${RED}Remember to:${NC}"
    echo "• Review SSH access before closing this session"
    echo "• Configure basic security measures as needed"
    echo "• Take a system snapshot if this is a VM"
    echo ""
}

main() {
    show_banner
    confirm_removal
    create_backup
    
    echo -e "${YELLOW}Starting removal process...${NC}"
    echo ""
    
    stop_all_services
    remove_packages
    remove_repositories
    clean_directories
    remove_users_groups
    remove_custom_scripts
    remove_cron_jobs
    reset_firewall
    restore_ssh_config
    restore_kernel_settings
    clean_logs
    remove_limits
    clean_temp_files
    remove_documentation
    remove_custom_user
    install_basic_security
    final_cleanup
    
    show_summary
}

main "$@"