#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: SecureVista requires root privileges${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

show_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              ${PURPLE}SecureVista v1.0${CYAN}               ║${NC}"
    echo -e "${CYAN}║         ${YELLOW}VPS Security Management Tool${CYAN}        ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
}

show_menu() {
    echo -e "${BLUE}┌─ Main Menu ─────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} 1. System Status & Monitoring              ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 2. Service Management                      ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 3. IP Management (Block/Unblock)           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 4. Port Management                         ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 5. Network Traffic Monitoring              ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 6. Log Viewer                              ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 7. File Integrity Monitoring              ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 8. Firewall Rules Management              ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 9. Backup & Restore                       ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 0. Exit                                    ${BLUE}│${NC}"
    echo -e "${BLUE}└─────────────────────────────────────────────┘${NC}"
    echo ""
}

system_status() {
    clear
    show_banner
    echo -e "${YELLOW}=== System Status & Monitoring ===${NC}"
    echo ""
    
    services=(
        "suricata:Suricata IPS"
        "snort:Snort IDS" 
        "snort-alt:Snort Alternative"
        "fail2ban:Fail2ban"
        "nginx:Nginx"
        "wazuh-manager:Wazuh Manager"
        "ssh:SSH Service"
    )
    
    echo -e "${CYAN}Service Status:${NC}"
    for service in "${services[@]}"; do
        name=$(echo $service | cut -d: -f1)
        desc=$(echo $service | cut -d: -f2)
        if systemctl is-active --quiet $name 2>/dev/null; then
            echo -e "  ${GREEN}✓${NC} $desc: ${GREEN}RUNNING${NC}"
        else
            echo -e "  ${RED}✗${NC} $desc: ${RED}STOPPED${NC}"
        fi
    done
    
    echo ""
    echo -e "${CYAN}Firewall Status:${NC}"
    if ufw status 2>/dev/null | grep -q "Status: active"; then
        echo -e "  ${GREEN}✓${NC} UFW Firewall: ${GREEN}ACTIVE${NC}"
    else
        echo -e "  ${RED}✗${NC} UFW Firewall: ${RED}INACTIVE${NC}"
    fi
    
    echo ""
    echo -e "${CYAN}System Resources:${NC}"
    cpu_usage=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}' || echo "N/A")
    memory_usage=$(free 2>/dev/null | awk 'NR==2{printf "%.1f%%", $3*100/$2 }' || echo "N/A")
    disk_usage=$(df -h / 2>/dev/null | awk 'NR==2 {print $5}' || echo "N/A")
    echo -e "  CPU Usage: ${cpu_usage}%"
    echo -e "  Memory Usage: ${memory_usage}"
    echo -e "  Disk Usage: ${disk_usage}"
    
    echo ""
    echo -e "${CYAN}Recent Blocked IPs (Last 10):${NC}"
    iptables -L INPUT -n 2>/dev/null | grep DROP | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | head -10 | while read ip; do
        echo -e "  ${RED}●${NC} $ip"
    done
    
    echo ""
    echo -e "${CYAN}Active Network Connections:${NC}"
    ss -s 2>/dev/null | grep -E "(TCP|UDP):" || echo "  Connection stats unavailable"
    
    echo ""
    read -p "Press Enter to continue..."
}

service_management() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Service Management ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} Start Service"
        echo -e "${BLUE}2.${NC} Stop Service"
        echo -e "${BLUE}3.${NC} Restart Service"
        echo -e "${BLUE}4.${NC} Check Service Status"
        echo -e "${BLUE}5.${NC} Enable Service (Auto-start)"
        echo -e "${BLUE}6.${NC} Disable Service"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1|2|3|4|5|6)
                echo ""
                echo -e "${CYAN}Available Services:${NC}"
                echo -e "${BLUE}1.${NC} suricata (IPS)"
                echo -e "${BLUE}2.${NC} snort (IDS)"
                echo -e "${BLUE}3.${NC} fail2ban (IP Banning)"
                echo -e "${BLUE}4.${NC} nginx (Web Server)"
                echo -e "${BLUE}5.${NC} wazuh-manager (SIEM)"
                echo -e "${BLUE}6.${NC} ssh (SSH Service)"
                echo ""
                read -p "Select service: " svc_choice
                
                case $svc_choice in
                    1) service="suricata" ;;
                    2) service="snort" ;;
                    3) service="fail2ban" ;;
                    4) service="nginx" ;;
                    5) service="wazuh-manager" ;;
                    6) service="ssh" ;;
                    *) echo -e "${RED}Invalid selection${NC}"; continue ;;
                esac
                
                case $choice in
                    1) systemctl start $service && echo -e "${GREEN}Service started${NC}" || echo -e "${RED}Failed to start${NC}" ;;
                    2) systemctl stop $service && echo -e "${GREEN}Service stopped${NC}" || echo -e "${RED}Failed to stop${NC}" ;;
                    3) systemctl restart $service && echo -e "${GREEN}Service restarted${NC}" || echo -e "${RED}Failed to restart${NC}" ;;
                    4) systemctl status $service --no-pager ;;
                    5) systemctl enable $service && echo -e "${GREEN}Service enabled${NC}" || echo -e "${RED}Failed to enable${NC}" ;;
                    6) systemctl disable $service && echo -e "${GREEN}Service disabled${NC}" || echo -e "${RED}Failed to disable${NC}" ;;
                esac
                echo ""
                read -p "Press Enter to continue..."
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
    done
}

ip_management() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== IP Management ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} View Blocked IPs"
        echo -e "${BLUE}2.${NC} Block IP Address"
        echo -e "${BLUE}3.${NC} Unblock IP Address"
        echo -e "${BLUE}4.${NC} View Fail2ban Status"
        echo -e "${BLUE}5.${NC} View Recent Failed Logins"
        echo -e "${BLUE}6.${NC} Clear All Blocks (Dangerous)"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Blocked IPs in iptables:${NC}"
                iptables -L INPUT -n --line-numbers | grep DROP | while read line; do
                    echo -e "  ${RED}●${NC} $line"
                done
                echo ""
                echo -e "${CYAN}Fail2ban banned IPs:${NC}"
                fail2ban-client status sshd 2>/dev/null | grep "Banned IP list:" || echo "  No banned IPs"
                ;;
            2)
                echo ""
                read -p "Enter IP address to block: " ip
                if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    iptables -I INPUT -s $ip -j DROP
                    fail2ban-client set sshd banip $ip 2>/dev/null || true
                    echo -e "${GREEN}IP $ip blocked successfully${NC}"
                else
                    echo -e "${RED}Invalid IP address format${NC}"
                fi
                ;;
            3)
                echo ""
                read -p "Enter IP address to unblock: " ip
                if [[ $ip =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                    iptables -D INPUT -s $ip -j DROP 2>/dev/null || true
                    fail2ban-client set sshd unbanip $ip 2>/dev/null || true
                    echo -e "${GREEN}IP $ip unblocked successfully${NC}"
                else
                    echo -e "${RED}Invalid IP address format${NC}"
                fi
                ;;
            4)
                echo ""
                fail2ban-client status
                ;;
            5)
                echo ""
                echo -e "${CYAN}Recent Failed SSH Logins:${NC}"
                journalctl --since "24 hours ago" -u ssh 2>/dev/null | grep "Failed password" | tail -10 | awk '{print $1, $2, $3, $(NF-3), $(NF-1)}' || grep "Failed password" /var/log/auth.log 2>/dev/null | tail -10
                ;;
            6)
                echo ""
                echo -e "${RED}WARNING: This will remove ALL IP blocks!${NC}"
                read -p "Are you sure? (yes/no): " confirm
                if [ "$confirm" = "yes" ]; then
                    iptables -F INPUT
                    fail2ban-client unban --all 2>/dev/null || true
                    echo -e "${GREEN}All blocks cleared${NC}"
                else
                    echo -e "${YELLOW}Operation cancelled${NC}"
                fi
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

port_management() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Port Management ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} View Open Ports"
        echo -e "${BLUE}2.${NC} Open Port (with security rules)"
        echo -e "${BLUE}3.${NC} Close Port"
        echo -e "${BLUE}4.${NC} View UFW Rules"
        echo -e "${BLUE}5.${NC} Quick Service Ports"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Currently Open Ports:${NC}"
                ss -tuln | awk 'NR>1 {print $5}' | sed 's/.*://' | sort -n | uniq | while read port; do
                    if [ ! -z "$port" ] && [[ "$port" =~ ^[0-9]+$ ]] && [ "$port" != "0" ]; then
                        service_name=$(ss -tuln | grep ":$port " | head -1 | awk '{print $1}')
                        echo -e "  ${GREEN}●${NC} Port $port ($service_name)"
                    fi
                done
                echo ""
                echo -e "${CYAN}UFW Rules:${NC}"
                ufw status numbered
                ;;
            2)
                echo ""
                echo -e "${CYAN}Common Service Ports:${NC}"
                echo -e "${BLUE}1.${NC} HTTP (80/tcp)"
                echo -e "${BLUE}2.${NC} HTTPS (443/tcp)"
                echo -e "${BLUE}3.${NC} FTP (21/tcp)"
                echo -e "${BLUE}4.${NC} FTPS (990/tcp)"
                echo -e "${BLUE}5.${NC} MySQL (3306/tcp)"
                echo -e "${BLUE}6.${NC} PostgreSQL (5432/tcp)"
                echo -e "${BLUE}7.${NC} MongoDB (27017/tcp)"
                echo -e "${BLUE}8.${NC} Custom Port"
                echo ""
                read -p "Select option or enter custom port: " port_choice
                
                case $port_choice in
                    1) port=80; protocol="tcp"; service="HTTP" ;;
                    2) port=443; protocol="tcp"; service="HTTPS" ;;
                    3) port=21; protocol="tcp"; service="FTP" ;;
                    4) port=990; protocol="tcp"; service="FTPS" ;;
                    5) port=3306; protocol="tcp"; service="MySQL" ;;
                    6) port=5432; protocol="tcp"; service="PostgreSQL" ;;
                    7) port=27017; protocol="tcp"; service="MongoDB" ;;
                    8)
                        read -p "Enter port number: " port
                        read -p "Enter protocol (tcp/udp): " protocol
                        service="Custom"
                        ;;
                    *)
                        if [[ $port_choice =~ ^[0-9]+$ ]] && [ $port_choice -ge 1 ] && [ $port_choice -le 65535 ]; then
                            port=$port_choice
                            protocol="tcp"
                            service="Custom"
                        else
                            echo -e "${RED}Invalid selection${NC}"
                            continue
                        fi
                        ;;
                esac
                
                echo ""
                echo -e "${YELLOW}Opening port $port/$protocol for $service...${NC}"
                
                ufw allow $port/$protocol
                
                if [ "$port" = "21" ]; then
                    ufw allow 20/tcp
                    echo -e "${GREEN}FTP data port (20) also opened${NC}"
                elif [ "$port" = "3306" ]; then
                    iptables -A INPUT -p tcp --dport 3306 -m state --state NEW -m limit --limit 5/min --limit-burst 10 -j ACCEPT
                    echo -e "${GREEN}MySQL rate limiting applied${NC}"
                elif [ "$port" = "5432" ]; then
                    iptables -A INPUT -p tcp --dport 5432 -m state --state NEW -m limit --limit 5/min --limit-burst 10 -j ACCEPT
                    echo -e "${GREEN}PostgreSQL rate limiting applied${NC}"
                fi
                
                echo -e "${GREEN}Port $port/$protocol opened with security rules${NC}"
                ;;
            3)
                echo ""
                read -p "Enter port number to close: " port
                read -p "Enter protocol (tcp/udp): " protocol
                if [[ $port =~ ^[0-9]+$ ]] && [ $port -ge 1 ] && [ $port -le 65535 ]; then
                    ufw delete allow $port/$protocol
                    echo -e "${GREEN}Port $port/$protocol closed${NC}"
                else
                    echo -e "${RED}Invalid port number${NC}"
                fi
                ;;
            4)
                echo ""
                ufw status verbose
                ;;
            5)
                echo ""
                echo -e "${CYAN}Quick Service Port Management:${NC}"
                echo -e "${BLUE}1.${NC} Enable Web Services (80,443)"
                echo -e "${BLUE}2.${NC} Enable Database Access (3306,5432)"
                echo -e "${BLUE}3.${NC} Enable File Transfer (21,22,990)"
                echo -e "${BLUE}4.${NC} Enable Monitoring (9090,3000)"
                echo ""
                read -p "Select option: " quick_choice
                
                case $quick_choice in
                    1)
                        ufw allow 80/tcp
                        ufw allow 443/tcp
                        echo -e "${GREEN}Web services enabled${NC}"
                        ;;
                    2)
                        ufw allow 3306/tcp
                        ufw allow 5432/tcp
                        iptables -A INPUT -p tcp --dport 3306 -m state --state NEW -m limit --limit 5/min --limit-burst 10 -j ACCEPT
                        iptables -A INPUT -p tcp --dport 5432 -m state --state NEW -m limit --limit 5/min --limit-burst 10 -j ACCEPT
                        echo -e "${GREEN}Database access enabled with rate limiting${NC}"
                        ;;
                    3)
                        ufw allow 21/tcp
                        ufw allow 20/tcp
                        ufw allow 22/tcp
                        ufw allow 990/tcp
                        echo -e "${GREEN}File transfer services enabled${NC}"
                        ;;
                    4)
                        ufw allow 9090/tcp
                        ufw allow 3000/tcp
                        echo -e "${GREEN}Monitoring services enabled${NC}"
                        ;;
                    *) echo -e "${RED}Invalid option${NC}" ;;
                esac
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

network_traffic() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Network Traffic Monitoring ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} Real-time Network Connections"
        echo -e "${BLUE}2.${NC} Bandwidth Usage by Interface"
        echo -e "${BLUE}3.${NC} Top Network Processes"
        echo -e "${BLUE}4.${NC} Connection Statistics"
        echo -e "${BLUE}5.${NC} Suricata Live Alerts"
        echo -e "${BLUE}6.${NC} Network Interface Status"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Real-time Network Connections (Press Ctrl+C to stop):${NC}"
                watch -n 2 'ss -tuln | head -20'
                ;;
            2)
                echo ""
                echo -e "${CYAN}Bandwidth Usage:${NC}"
                if command -v iftop >/dev/null; then
                    iftop -t -s 10
                else
                    echo -e "${YELLOW}iftop not installed, showing interface statistics:${NC}"
                    cat /proc/net/dev
                fi
                ;;
            3)
                echo ""
                echo -e "${CYAN}Top Network Processes:${NC}"
                if command -v nethogs >/dev/null; then
                    nethogs -d 5
                else
                    echo -e "${YELLOW}nethogs not installed, showing process network connections:${NC}"
                    lsof -i | head -20
                fi
                ;;
            4)
                echo ""
                echo -e "${CYAN}Connection Statistics:${NC}"
                ss -s
                echo ""
                echo -e "${CYAN}Protocol Statistics:${NC}"
                cat /proc/net/snmp | grep -E "Tcp:|Udp:|Ip:"
                ;;
            5)
                echo ""
                echo -e "${CYAN}Suricata Live Alerts (Press Ctrl+C to stop):${NC}"
                if [ -f /var/log/suricata/fast.log ]; then
                    tail -f /var/log/suricata/fast.log
                else
                    echo -e "${RED}Suricata log file not found${NC}"
                fi
                ;;
            6)
                echo ""
                echo -e "${CYAN}Network Interface Status:${NC}"
                ip addr show
                echo ""
                echo -e "${CYAN}Routing Table:${NC}"
                ip route show
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

log_viewer() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Log Viewer ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} Wazuh Alerts"
        echo -e "${BLUE}2.${NC} Suricata IDS Logs"
        echo -e "${BLUE}3.${NC} Fail2ban Logs"
        echo -e "${BLUE}4.${NC} Nginx Access Logs"
        echo -e "${BLUE}5.${NC} Nginx Error Logs"
        echo -e "${BLUE}6.${NC} SSH Authentication Logs"
        echo -e "${BLUE}7.${NC} System Logs"
        echo -e "${BLUE}8.${NC} ModSecurity WAF Logs"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Wazuh Alerts (Last 50 lines):${NC}"
                if [ -f /var/ossec/logs/alerts/alerts.log ]; then
                    tail -50 /var/ossec/logs/alerts/alerts.log | grep --color=always -E "Alert|ERROR|WARNING|CRITICAL"
                else
                    echo -e "${RED}Wazuh alerts log not found${NC}"
                fi
                ;;
            2)
                echo ""
                echo -e "${CYAN}Suricata IDS Alerts (Last 30 lines):${NC}"
                if [ -f /var/log/suricata/fast.log ]; then
                    tail -30 /var/log/suricata/fast.log | grep --color=always -E "ATTACK|MALWARE|TROJAN|EXPLOIT"
                else
                    echo -e "${RED}Suricata log not found${NC}"
                fi
                ;;
            3)
                echo ""
                echo -e "${CYAN}Fail2ban Activity (Last 30 lines):${NC}"
                if [ -f /var/log/fail2ban.log ]; then
                    tail -30 /var/log/fail2ban.log | grep --color=always -E "Ban|Unban|Found"
                else
                    echo -e "${RED}Fail2ban log not found${NC}"
                fi
                ;;
            4)
                echo ""
                echo -e "${CYAN}Nginx Access Log (Last 20 lines):${NC}"
                if [ -f /var/log/nginx/access.log ]; then
                    tail -20 /var/log/nginx/access.log
                else
                    echo -e "${RED}Nginx access log not found${NC}"
                fi
                ;;
            5)
                echo ""
                echo -e "${CYAN}Nginx Error Log (Last 20 lines):${NC}"
                if [ -f /var/log/nginx/error.log ]; then
                    tail -20 /var/log/nginx/error.log | grep --color=always -E "error|warning|critical"
                else
                    echo -e "${RED}Nginx error log not found${NC}"
                fi
                ;;
            6)
                echo ""
                echo -e "${CYAN}SSH Authentication Logs (Last 20 lines):${NC}"
                journalctl -u ssh --no-pager -n 20 | grep --color=always -E "Failed|Accepted|Invalid"
                ;;
            7)
                echo ""
                echo -e "${CYAN}System Messages (Last 20 lines):${NC}"
                tail -20 /var/log/syslog | grep --color=always -E "error|warning|critical|fail"
                ;;
            8)
                echo ""
                echo -e "${CYAN}ModSecurity WAF Logs (Last 10 entries):${NC}"
                if [ -f /var/log/nginx/modsec_audit.log ]; then
                    tail -10 /var/log/nginx/modsec_audit.log | grep --color=always -E "Access denied|blocked"
                else
                    echo -e "${RED}ModSecurity audit log not found${NC}"
                fi
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

file_integrity() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== File Integrity Monitoring ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} Run Wazuh File Integrity Check"
        echo -e "${BLUE}2.${NC} View Recent File Changes"
        echo -e "${BLUE}3.${NC} Add Directory to Monitor"
        echo -e "${BLUE}4.${NC} Remove Directory from Monitor"
        echo -e "${BLUE}5.${NC} Check System File Permissions"
        echo -e "${BLUE}6.${NC} Create System Snapshot"
        echo -e "${BLUE}7.${NC} Compare with Snapshot"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Running Wazuh File Integrity Check...${NC}"
                if [ -f /var/ossec/bin/agent_control ]; then
                    /var/ossec/bin/agent_control -r -a
                    echo -e "${GREEN}File integrity check initiated${NC}"
                else
                    echo -e "${RED}Wazuh agent control not found${NC}"
                fi
                ;;
            2)
                echo ""
                echo -e "${CYAN}Recent File Changes (Last 24 hours):${NC}"
                find /etc /usr/bin /usr/sbin /bin /sbin -type f -mtime -1 2>/dev/null | head -20
                echo ""
                echo -e "${CYAN}Wazuh FIM Alerts:${NC}"
                if [ -f /var/ossec/logs/alerts/alerts.log ]; then
                    grep "syscheck" /var/ossec/logs/alerts/alerts.log | tail -10
                fi
                ;;
            3)
                echo ""
                read -p "Enter directory path to monitor: " dir_path
                if [ -d "$dir_path" ]; then
                    if grep -q "$dir_path" /var/ossec/etc/ossec.conf; then
                        echo -e "${YELLOW}Directory already being monitored${NC}"
                    else
                        cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
                        sed -i "/<\/syscheck>/i\\    <directories>$dir_path</directories>" /var/ossec/etc/ossec.conf
                        systemctl restart wazuh-manager
                        echo -e "${GREEN}Directory added to monitoring${NC}"
                    fi
                else
                    echo -e "${RED}Directory does not exist${NC}"
                fi
                ;;
            4)
                echo ""
                echo -e "${CYAN}Currently monitored directories:${NC}"
                grep "<directories>" /var/ossec/etc/ossec.conf | sed 's/<[^>]*>//g' | sed 's/^[ \t]*//'
                echo ""
                read -p "Enter directory path to remove: " dir_path
                if grep -q "$dir_path" /var/ossec/etc/ossec.conf; then
                    cp /var/ossec/etc/ossec.conf /var/ossec/etc/ossec.conf.bak
                    sed -i "/<directories>$dir_path<\/directories>/d" /var/ossec/etc/ossec.conf
                    systemctl restart wazuh-manager
                    echo -e "${GREEN}Directory removed from monitoring${NC}"
                else
                    echo -e "${RED}Directory not found in monitoring list${NC}"
                fi
                ;;
            5)
                echo ""
                echo -e "${CYAN}Checking System File Permissions...${NC}"
                echo -e "${YELLOW}SUID/SGID Files:${NC}"
                find / -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | head -10
                echo ""
                echo -e "${YELLOW}World-writable Files:${NC}"
                find / -type f -perm -002 2>/dev/null | head -10
                echo ""
                echo -e "${YELLOW}Files with No Owner:${NC}"
                find / -nouser -o -nogroup 2>/dev/null | head -10
                ;;
            6)
                echo ""
                timestamp=$(date +%Y%m%d_%H%M%S)
                snapshot_dir="/root/system_snapshots"
                mkdir -p "$snapshot_dir"
                echo -e "${CYAN}Creating system snapshot...${NC}"
                
                find /etc -type f -exec md5sum {} \; > "$snapshot_dir/etc_snapshot_$timestamp.md5" 2>/dev/null
                find /usr/bin -type f -exec md5sum {} \; > "$snapshot_dir/bin_snapshot_$timestamp.md5" 2>/dev/null
                find /usr/sbin -type f -exec md5sum {} \; > "$snapshot_dir/sbin_snapshot_$timestamp.md5" 2>/dev/null
                dpkg -l > "$snapshot_dir/packages_$timestamp.txt"
                
                echo -e "${GREEN}System snapshot created: $snapshot_dir/snapshot_$timestamp${NC}"
                echo -e "${CYAN}Files created:${NC}"
                echo -e "  etc_snapshot_$timestamp.md5"
                echo -e "  bin_snapshot_$timestamp.md5"
                echo -e "  sbin_snapshot_$timestamp.md5"
                echo -e "  packages_$timestamp.txt"
                ;;
            7)
                echo ""
                snapshot_dir="/root/system_snapshots"
                if [ ! -d "$snapshot_dir" ]; then
                    echo -e "${RED}No snapshots found. Create a snapshot first.${NC}"
                    continue
                fi
                
                echo -e "${CYAN}Available snapshots:${NC}"
                ls -1 "$snapshot_dir"/*_*.md5 2>/dev/null | sed 's/.*_//' | sed 's/.md5//' | sort -u | nl
                echo ""
                read -p "Enter snapshot timestamp (YYYYMMDD_HHMMSS): " timestamp
                
                if [ -f "$snapshot_dir/etc_snapshot_$timestamp.md5" ]; then
                    echo -e "${CYAN}Comparing current system with snapshot $timestamp...${NC}"
                    
                    echo -e "${YELLOW}Changes in /etc:${NC}"
                    find /etc -type f -exec md5sum {} \; 2>/dev/null > /tmp/current_etc.md5
                    diff "$snapshot_dir/etc_snapshot_$timestamp.md5" /tmp/current_etc.md5 | grep "^>" | head -10
                    
                    echo -e "${YELLOW}Changes in /usr/bin:${NC}"
                    find /usr/bin -type f -exec md5sum {} \; 2>/dev/null > /tmp/current_bin.md5
                    diff "$snapshot_dir/bin_snapshot_$timestamp.md5" /tmp/current_bin.md5 | grep "^>" | head -10
                    
                    rm -f /tmp/current_*.md5
                    echo -e "${GREEN}Comparison complete${NC}"
                else
                    echo -e "${RED}Snapshot not found${NC}"
                fi
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

firewall_rules() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Firewall Rules Management ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} View Current UFW Rules"
        echo -e "${BLUE}2.${NC} View iptables Rules"
        echo -e "${BLUE}3.${NC} Add Custom UFW Rule"
        echo -e "${BLUE}4.${NC} Delete UFW Rule"
        echo -e "${BLUE}5.${NC} Reset UFW to Default"
        echo -e "${BLUE}6.${NC} Enable/Disable UFW"
        echo -e "${BLUE}7.${NC} Advanced iptables Rules"
        echo -e "${BLUE}8.${NC} DDoS Protection Rules"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                echo -e "${CYAN}Current UFW Rules:${NC}"
                ufw status verbose
                ;;
            2)
                echo ""
                echo -e "${CYAN}Current iptables Rules:${NC}"
                iptables -L -n --line-numbers
                ;;
            3)
                echo ""
                echo -e "${CYAN}Add Custom UFW Rule${NC}"
                echo -e "${BLUE}1.${NC} Allow specific IP"
                echo -e "${BLUE}2.${NC} Allow IP range"
                echo -e "${BLUE}3.${NC} Allow from specific IP to port"
                echo -e "${BLUE}4.${NC} Allow specific application"
                echo -e "${BLUE}5.${NC} Custom rule"
                echo ""
                read -p "Select rule type: " rule_type
                
                case $rule_type in
                    1)
                        read -p "Enter IP address: " ip
                        ufw allow from $ip
                        echo -e "${GREEN}Rule added: Allow from $ip${NC}"
                        ;;
                    2)
                        read -p "Enter IP range (e.g., 192.168.1.0/24): " range
                        ufw allow from $range
                        echo -e "${GREEN}Rule added: Allow from $range${NC}"
                        ;;
                    3)
                        read -p "Enter IP address: " ip
                        read -p "Enter port: " port
                        ufw allow from $ip to any port $port
                        echo -e "${GREEN}Rule added: Allow $ip to port $port${NC}"
                        ;;
                    4)
                        echo -e "${CYAN}Common applications:${NC}"
                        ufw app list
                        echo ""
                        read -p "Enter application name: " app
                        ufw allow "$app"
                        echo -e "${GREEN}Rule added: Allow $app${NC}"
                        ;;
                    5)
                        read -p "Enter custom UFW rule (e.g., 'allow 80/tcp'): " custom_rule
                        ufw $custom_rule
                        echo -e "${GREEN}Custom rule applied${NC}"
                        ;;
                esac
                ;;
            4)
                echo ""
                echo -e "${CYAN}Current UFW Rules:${NC}"
                ufw status numbered
                echo ""
                read -p "Enter rule number to delete: " rule_num
                if [[ $rule_num =~ ^[0-9]+$ ]]; then
                    ufw delete $rule_num
                    echo -e "${GREEN}Rule deleted${NC}"
                else
                    echo -e "${RED}Invalid rule number${NC}"
                fi
                ;;
            5)
                echo ""
                echo -e "${RED}WARNING: This will reset all UFW rules to default!${NC}"
                read -p "Are you sure? (yes/no): " confirm
                if [ "$confirm" = "yes" ]; then
                    ufw --force reset
                    ufw default deny incoming
                    ufw default allow outgoing
                    ufw allow 22/tcp
                    ufw limit 22/tcp
                    echo -e "${GREEN}UFW reset to secure defaults${NC}"
                else
                    echo -e "${YELLOW}Operation cancelled${NC}"
                fi
                ;;
            6)
                echo ""
                if ufw status | grep -q "Status: active"; then
                    echo -e "${YELLOW}UFW is currently ACTIVE${NC}"
                    read -p "Disable UFW? (yes/no): " confirm
                    if [ "$confirm" = "yes" ]; then
                        ufw disable
                        echo -e "${RED}UFW disabled${NC}"
                    fi
                else
                    echo -e "${YELLOW}UFW is currently INACTIVE${NC}"
                    read -p "Enable UFW? (yes/no): " confirm
                    if [ "$confirm" = "yes" ]; then
                        ufw enable
                        echo -e "${GREEN}UFW enabled${NC}"
                    fi
                fi
                ;;
            7)
                echo ""
                echo -e "${CYAN}Advanced iptables Rules${NC}"
                echo -e "${BLUE}1.${NC} Block specific IP"
                echo -e "${BLUE}2.${NC} Block IP range"
                echo -e "${BLUE}3.${NC} Rate limit connections"
                echo -e "${BLUE}4.${NC} Block specific country (GeoIP)"
                echo -e "${BLUE}5.${NC} Custom iptables rule"
                echo ""
                read -p "Select option: " adv_choice
                
                case $adv_choice in
                    1)
                        read -p "Enter IP to block: " ip
                        iptables -I INPUT -s $ip -j DROP
                        echo -e "${GREEN}IP $ip blocked${NC}"
                        ;;
                    2)
                        read -p "Enter IP range to block (e.g., 192.168.1.0/24): " range
                        iptables -I INPUT -s $range -j DROP
                        echo -e "${GREEN}IP range $range blocked${NC}"
                        ;;
                    3)
                        read -p "Enter port to rate limit: " port
                        read -p "Enter rate (e.g., 10/min): " rate
                        iptables -A INPUT -p tcp --dport $port -m state --state NEW -m limit --limit $rate -j ACCEPT
                        echo -e "${GREEN}Rate limiting applied to port $port${NC}"
                        ;;
                    4)
                        echo -e "${YELLOW}GeoIP blocking requires additional setup${NC}"
                        read -p "Enter country code to block (e.g., CN, RU): " country
                        echo -e "${YELLOW}Manual GeoIP setup required for country blocking${NC}"
                        ;;
                    5)
                        read -p "Enter custom iptables rule: " custom_rule
                        iptables $custom_rule
                        echo -e "${GREEN}Custom iptables rule applied${NC}"
                        ;;
                esac
                ;;
            8)
                echo ""
                echo -e "${CYAN}DDoS Protection Rules${NC}"
                echo -e "${BLUE}1.${NC} Enable SYN flood protection"
                echo -e "${BLUE}2.${NC} Enable connection limiting"
                echo -e "${BLUE}3.${NC} Enable ICMP rate limiting"
                echo -e "${BLUE}4.${NC} Enable all DDoS protections"
                echo ""
                read -p "Select option: " ddos_choice
                
                case $ddos_choice in
                    1)
                        iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
                        iptables -A INPUT -p tcp --syn -j DROP
                        echo -e "${GREEN}SYN flood protection enabled${NC}"
                        ;;
                    2)
                        iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/min --limit-burst 50 -j ACCEPT
                        echo -e "${GREEN}Connection limiting enabled${NC}"
                        ;;
                    3)
                        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT
                        echo -e "${GREEN}ICMP rate limiting enabled${NC}"
                        ;;
                    4)
                        iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
                        iptables -A INPUT -p tcp --syn -j DROP
                        iptables -A INPUT -p tcp -m state --state NEW -m limit --limit 50/min --limit-burst 50 -j ACCEPT
                        iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT
                        echo -e "${GREEN}All DDoS protections enabled${NC}"
                        ;;
                esac
                echo -e "${YELLOW}Remember to save iptables rules with: netfilter-persistent save${NC}"
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

backup_restore() {
    while true; do
        clear
        show_banner
        echo -e "${YELLOW}=== Backup & Restore ===${NC}"
        echo ""
        echo -e "${BLUE}1.${NC} Create Full Security Backup"
        echo -e "${BLUE}2.${NC} Restore from Backup"
        echo -e "${BLUE}3.${NC} View Available Backups"
        echo -e "${BLUE}4.${NC} Delete Old Backups"
        echo -e "${BLUE}5.${NC} Export Configuration"
        echo -e "${BLUE}6.${NC} Import Configuration"
        echo -e "${BLUE}0.${NC} Back to Main Menu"
        echo ""
        read -p "Select option: " choice
        
        case $choice in
            1)
                echo ""
                timestamp=$(date +%Y%m%d_%H%M%S)
                backup_dir="/root/securevista_backups/backup_$timestamp"
                mkdir -p "$backup_dir"
                
                echo -e "${CYAN}Creating full security backup...${NC}"
                
                cp -r /etc/ufw "$backup_dir/" 2>/dev/null || true
                cp -r /etc/fail2ban "$backup_dir/" 2>/dev/null || true
                cp -r /etc/suricata "$backup_dir/" 2>/dev/null || true
                cp -r /etc/nginx "$backup_dir/" 2>/dev/null || true
                cp -r /var/ossec/etc "$backup_dir/wazuh_etc" 2>/dev/null || true
                cp /etc/ssh/sshd_config "$backup_dir/" 2>/dev/null || true
                cp /etc/sysctl.conf "$backup_dir/" 2>/dev/null || true
                
                iptables-save > "$backup_dir/iptables_rules.txt"
                ufw status verbose > "$backup_dir/ufw_status.txt"
                dpkg -l > "$backup_dir/installed_packages.txt"
                
                tar czf "/root/securevista_backup_$timestamp.tar.gz" -C /root/securevista_backups "backup_$timestamp"
                rm -rf "$backup_dir"
                
                echo -e "${GREEN}Backup created: /root/securevista_backup_$timestamp.tar.gz${NC}"
                ;;
            2)
                echo ""
                echo -e "${CYAN}Available backups:${NC}"
                ls -la /root/securevista_backup_*.tar.gz 2>/dev/null | awk '{print $9}' | nl
                echo ""
                read -p "Enter backup filename: " backup_file
                
                if [ -f "$backup_file" ]; then
                    echo -e "${RED}WARNING: This will overwrite current configuration!${NC}"
                    read -p "Continue? (yes/no): " confirm
                    if [ "$confirm" = "yes" ]; then
                        tar xzf "$backup_file" -C /tmp/
                        
                        systemctl stop ufw fail2ban suricata nginx wazuh-manager
                        
                        cp -r /tmp/backup_*/ufw/* /etc/ufw/ 2>/dev/null || true
                        cp -r /tmp/backup_*/fail2ban/* /etc/fail2ban/ 2>/dev/null || true
                        cp -r /tmp/backup_*/suricata/* /etc/suricata/ 2>/dev/null || true
                        cp -r /tmp/backup_*/nginx/* /etc/nginx/ 2>/dev/null || true
                        cp -r /tmp/backup_*/wazuh_etc/* /var/ossec/etc/ 2>/dev/null || true
                        
                        systemctl start ufw fail2ban suricata nginx wazuh-manager
                        
                        echo -e "${GREEN}Configuration restored${NC}"
                    fi
                else
                    echo -e "${RED}Backup file not found${NC}"
                fi
                ;;
            3)
                echo ""
                echo -e "${CYAN}Available Backups:${NC}"
                ls -lh /root/securevista_backup_*.tar.gz 2>/dev/null || echo -e "${YELLOW}No backups found${NC}"
                ;;
            4)
                echo ""
                echo -e "${CYAN}Backups older than 30 days:${NC}"
                find /root -name "securevista_backup_*.tar.gz" -mtime +30 2>/dev/null
                echo ""
                read -p "Delete old backups? (yes/no): " confirm
                if [ "$confirm" = "yes" ]; then
                    find /root -name "securevista_backup_*.tar.gz" -mtime +30 -delete 2>/dev/null
                    echo -e "${GREEN}Old backups deleted${NC}"
                fi
                ;;
            5)
                echo ""
                timestamp=$(date +%Y%m%d_%H%M%S)
                config_file="/root/securevista_config_$timestamp.txt"
                
                echo -e "${CYAN}Exporting configuration to $config_file...${NC}"
                
                echo "# SecureVista Configuration Export - $timestamp" > "$config_file"
                echo "# UFW Rules" >> "$config_file"
                ufw status verbose >> "$config_file"
                echo -e "\n# iptables Rules" >> "$config_file"
                iptables-save >> "$config_file"
                echo -e "\n# Fail2ban Status" >> "$config_file"
                fail2ban-client status >> "$config_file"
                
                echo -e "${GREEN}Configuration exported to $config_file${NC}"
                ;;
            6)
                echo ""
                read -p "Enter configuration file path: " config_file
                if [ -f "$config_file" ]; then
                    echo -e "${CYAN}Configuration file found. Manual import required.${NC}"
                    echo -e "${YELLOW}Please review the file and manually apply settings.${NC}"
                    less "$config_file"
                else
                    echo -e "${RED}Configuration file not found${NC}"
                fi
                ;;
            0) break ;;
            *) echo -e "${RED}Invalid option${NC}"; sleep 1 ;;
        esac
        echo ""
        read -p "Press Enter to continue..."
    done
}

main_loop() {
    while true; do
        show_banner
        show_menu
        read -p "Select option [0-9]: " choice
        
        case $choice in
            1) system_status ;;
            2) service_management ;;
            3) ip_management ;;
            4) port_management ;;
            5) network_traffic ;;
            6) log_viewer ;;
            7) file_integrity ;;
            8) firewall_rules ;;
            9) backup_restore ;;
            0) 
                echo -e "${GREEN}Thank you for using SecureVista!${NC}"
                exit 0 
                ;;
            *) 
                echo -e "${RED}Invalid option. Please select 0-9.${NC}"
                sleep 1 
                ;;
        esac
    done
}

main_loop