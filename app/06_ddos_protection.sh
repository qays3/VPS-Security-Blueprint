#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up advanced DDoS protection..."

iptables -N DDOS_PROTECTION 2>/dev/null || iptables -F DDOS_PROTECTION
iptables -N RATE_LIMIT 2>/dev/null || iptables -F RATE_LIMIT
iptables -N CONN_LIMIT 2>/dev/null || iptables -F CONN_LIMIT

echo 'net.core.rmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_default = 262144' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.netdev_max_backlog = 30000' >> /etc/sysctl.conf
echo 'net.core.netdev_budget = 600' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 10240 87380 12582912' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 10240 87380 12582912' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_max_syn_backlog = 8192' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_syncookies = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_syn_retries = 2' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_synack_retries = 2' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_max_orphans = 65536' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_fin_timeout = 10' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_time = 120' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_probes = 3' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_keepalive_intvl = 10' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_retries2 = 5' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_no_metrics_save = 1' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_moderate_rcvbuf = 1' >> /etc/sysctl.conf
echo 'net.ipv4.route.flush = 1' >> /etc/sysctl.conf
echo 'net.ipv4.ip_local_port_range = 1024 65535' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rfc1337 = 1' >> /etc/sysctl.conf
echo 'net.ipv4.ip_forward = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.mc_forwarding = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.accept_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.send_redirects = 0' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.rp_filter = 1' >> /etc/sysctl.conf
echo 'net.ipv4.conf.all.log_martians = 1' >> /etc/sysctl.conf
echo 'net.ipv4.icmp_echo_ignore_broadcasts = 1' >> /etc/sysctl.conf
echo 'net.ipv4.icmp_ignore_bogus_error_responses = 1' >> /etc/sysctl.conf
echo 'net.ipv4.icmp_echo_ignore_all = 0' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_timestamps = 0' >> /etc/sysctl.conf

sysctl -p

iptables -A DDOS_PROTECTION -m state --state INVALID -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags FIN,ACK FIN -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ALL ALL -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ALL NONE -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
iptables -A DDOS_PROTECTION -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP
iptables -A DDOS_PROTECTION -f -j DROP
iptables -A DDOS_PROTECTION -m ttl --ttl-lt 64 -j DROP

iptables -A CONN_LIMIT -p tcp --syn -m connlimit --connlimit-above 15 --connlimit-mask 32 -j REJECT --reject-with tcp-reset
iptables -A CONN_LIMIT -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m limit --limit 1/s --limit-burst 2 -j ACCEPT

iptables -A RATE_LIMIT -p tcp --dport 80 -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name http_rate_limit -j DROP
iptables -A RATE_LIMIT -p tcp --dport 443 -m hashlimit --hashlimit-above 25/sec --hashlimit-burst 50 --hashlimit-mode srcip --hashlimit-name https_rate_limit -j DROP
iptables -A RATE_LIMIT -p tcp --dport 22 -m hashlimit --hashlimit-above 4/min --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name ssh_rate_limit -j DROP
iptables -A RATE_LIMIT -p tcp --syn -m hashlimit --hashlimit-above 15/sec --hashlimit-burst 30 --hashlimit-mode srcip --hashlimit-name syn_flood -j DROP
iptables -A RATE_LIMIT -p icmp -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name icmp_flood -j DROP
iptables -A RATE_LIMIT -p udp -m hashlimit --hashlimit-above 20/sec --hashlimit-burst 40 --hashlimit-mode srcip --hashlimit-name udp_flood -j DROP
iptables -A RATE_LIMIT -p udp --dport 53 -m hashlimit --hashlimit-above 5/sec --hashlimit-burst 10 --hashlimit-mode srcip --hashlimit-name dns_rate_limit -j DROP
iptables -A RATE_LIMIT -p udp --dport 123 -m hashlimit --hashlimit-above 2/sec --hashlimit-burst 5 --hashlimit-mode srcip --hashlimit-name ntp_rate_limit -j DROP
iptables -A RATE_LIMIT -p udp --dport 161 -j DROP

iptables -A DDOS_PROTECTION -p tcp --dport 23 -j DROP
iptables -A DDOS_PROTECTION -p tcp --dport 135 -j DROP
iptables -A DDOS_PROTECTION -p tcp --dport 445 -j DROP
iptables -A DDOS_PROTECTION -p tcp --dport 1433 -j DROP
iptables -A DDOS_PROTECTION -p tcp --dport 3389 -j DROP
iptables -A DDOS_PROTECTION -p udp --dport 1900 -j DROP
iptables -A DDOS_PROTECTION -p udp --dport 5353 -j DROP

iptables -A DDOS_PROTECTION -p tcp -m length --length 1000:65535 -m hashlimit --hashlimit-above 10/sec --hashlimit-burst 20 --hashlimit-mode srcip --hashlimit-name large_packets -j DROP

iptables -A DDOS_PROTECTION -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --set --name slowloris
iptables -A DDOS_PROTECTION -p tcp --dport 80 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 --name slowloris -j DROP
iptables -A DDOS_PROTECTION -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --set --name slowloris_ssl
iptables -A DDOS_PROTECTION -p tcp --dport 443 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 10 --name slowloris_ssl -j DROP

iptables -A DDOS_PROTECTION -p tcp --tcp-flags SYN,ACK,FIN,RST RST -m hashlimit --hashlimit-above 1/sec --hashlimit-burst 2 --hashlimit-mode srcip --hashlimit-name port_scan -j DROP

iptables -I INPUT 1 -j DDOS_PROTECTION
iptables -I INPUT 2 -j CONN_LIMIT  
iptables -I INPUT 3 -j RATE_LIMIT
iptables -I INPUT 1 -m state --state RELATED,ESTABLISHED -j ACCEPT
iptables -I INPUT 1 -i lo -j ACCEPT

cat > /usr/local/bin/emergency-whitelist <<'EOF'
#!/bin/bash
if [ "$#" -ne 1 ]; then
    echo "Usage: $0 <IP_ADDRESS>"
    exit 1
fi
IP=$1
iptables -I INPUT 1 -s $IP -j ACCEPT
echo "IP $IP added to emergency whitelist"
EOF
chmod +x /usr/local/bin/emergency-whitelist

netfilter-persistent save

cat > /etc/fail2ban/jail.d/ddos.conf <<'EOF'
[ddos]
enabled = true
port = http,https
filter = ddos
logpath = /var/log/nginx/access.log
maxretry = 20
findtime = 60
bantime = 3600
action = iptables[name=ddos, port=http, protocol=tcp]

[slowloris]
enabled = true
port = http,https
filter = slowloris
logpath = /var/log/nginx/access.log
maxretry = 5
findtime = 300
bantime = 7200
action = iptables[name=slowloris, port=http, protocol=tcp]

[nginx-botsearch]
enabled = true
port = http,https
filter = nginx-botsearch
logpath = /var/log/nginx/access.log
maxretry = 2
bantime = 86400
action = iptables[name=nginx-botsearch, port=http, protocol=tcp]
EOF

cat > /etc/fail2ban/filter.d/ddos.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*HTTP.*" (200|404) .*$
ignoreregex = 
EOF

cat > /etc/fail2ban/filter.d/slowloris.conf <<'EOF'
[Definition]
failregex = ^<HOST> .*"GET.*HTTP/1\.[01]" 408 .*$
            ^<HOST> .*"GET.*HTTP/1\.[01]" 400 .*$
ignoreregex =
EOF

cat > /etc/fail2ban/filter.d/nginx-botsearch.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*"(GET|POST).*(bot|spider|crawler|scraper|harvest|extract|scan|php|admin|wp-|phpmyadmin).*" .*$
ignoreregex =
EOF

systemctl restart fail2ban

cat > /usr/local/bin/ddos-monitor <<'EOF'
#!/bin/bash

echo "=== DDoS Protection Status ==="
echo "Active connections: $(ss -s | grep estab | awk '{print $2}')"
echo "SYN_RECV connections: $(ss -s | grep -o 'syn-recv [0-9]*' | awk '{print $2}')"
echo "Dropped packets: $(cat /proc/net/netstat | grep -o 'ListenDrops [0-9]*' | awk '{print $2}')"
echo "Current iptables packet counters:"
iptables -L DDOS_PROTECTION -v -n | head -20
echo ""
echo "Top 10 connecting IPs:"
ss -tn | awk 'NR>1 {print $4}' | cut -d: -f1 | sort | uniq -c | sort -nr | head -10
echo ""
echo "Recent fail2ban actions:"
tail -20 /var/log/fail2ban.log | grep Ban
EOF
chmod +x /usr/local/bin/ddos-monitor

log_info "Advanced DDoS protection configured"
log_info "Monitor with: ddos-monitor"
log_info "Emergency whitelist: emergency-whitelist <IP>"