#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up Cloudflare DDoS protection integration..."

read -p "Enter your domain name (e.g., example.com): " DOMAIN
read -p "Enter your server's real IP address: " SERVER_IP

cat > /etc/nginx/conf.d/cloudflare.conf <<EOF
set_real_ip_from 173.245.48.0/20;
set_real_ip_from 103.21.244.0/22;
set_real_ip_from 103.22.200.0/22;
set_real_ip_from 103.31.4.0/22;
set_real_ip_from 141.101.64.0/18;
set_real_ip_from 108.162.192.0/18;
set_real_ip_from 190.93.240.0/20;
set_real_ip_from 188.114.96.0/20;
set_real_ip_from 197.234.240.0/22;
set_real_ip_from 198.41.128.0/17;
set_real_ip_from 162.158.0.0/15;
set_real_ip_from 104.16.0.0/13;
set_real_ip_from 104.24.0.0/14;
set_real_ip_from 172.64.0.0/13;
set_real_ip_from 131.0.72.0/22;
set_real_ip_from 2400:cb00::/32;
set_real_ip_from 2606:4700::/32;
set_real_ip_from 2803:f800::/32;
set_real_ip_from 2405:b500::/32;
set_real_ip_from 2405:8100::/32;
set_real_ip_from 2a06:98c0::/29;
set_real_ip_from 2c0f:f248::/32;

real_ip_header CF-Connecting-IP;
real_ip_recursive on;
EOF

iptables -N CLOUDFLARE_ONLY 2>/dev/null || iptables -F CLOUDFLARE_ONLY

iptables -A CLOUDFLARE_ONLY -s 173.245.48.0/20 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 103.21.244.0/22 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 103.22.200.0/22 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 103.31.4.0/22 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 141.101.64.0/18 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 108.162.192.0/18 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 190.93.240.0/20 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 188.114.96.0/20 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 197.234.240.0/22 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 198.41.128.0/17 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 162.158.0.0/15 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 104.16.0.0/13 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 104.24.0.0/14 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 172.64.0.0/13 -j ACCEPT
iptables -A CLOUDFLARE_ONLY -s 131.0.72.0/22 -j ACCEPT

iptables -A CLOUDFLARE_ONLY -j DROP

iptables -I INPUT -p tcp --dport 80 -j CLOUDFLARE_ONLY
iptables -I INPUT -p tcp --dport 443 -j CLOUDFLARE_ONLY

cat > /etc/nginx/sites-available/cloudflare-protected <<EOF
server {
    listen 80;
    server_name $DOMAIN www.$DOMAIN;
    
    if (\$http_cf_ray = "") {
        return 444;
    }
    
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header CF-Connecting-IP \$http_cf_connecting_ip;
        proxy_set_header CF-Ray \$http_cf_ray;
        proxy_set_header CF-Visitor \$http_cf_visitor;
    }
    
    location /health {
        access_log off;
        return 200 "healthy\n";
        add_header Content-Type text/plain;
    }
    
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg)$ {
        expires 1y;
        add_header Cache-Control "public, immutable";
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host \$host;
    }
}

server {
    listen 8080;
    server_name $DOMAIN www.$DOMAIN;
    root /var/www/html;
    index index.html index.htm;
    
    access_log /var/log/nginx/backend_access.log;
    error_log /var/log/nginx/backend_error.log;
    
    location / {
        try_files \$uri \$uri/ =404;
    }
}
EOF

ln -sf /etc/nginx/sites-available/cloudflare-protected /etc/nginx/sites-enabled/

cat > /usr/local/bin/cloudflare-setup <<'EOF'
#!/bin/bash

echo "=== Cloudflare Setup Instructions ==="
echo ""
echo "1. Sign up for Cloudflare (free): https://cloudflare.com"
echo "2. Add your domain to Cloudflare"
echo "3. Change your domain's nameservers to Cloudflare's"
echo "4. In Cloudflare dashboard:"
echo "   - Go to Security > DDoS"
echo "   - Enable 'I'm Under Attack Mode' for maximum protection"
echo "   - Go to Security > WAF"
echo "   - Enable Web Application Firewall"
echo "   - Go to Security > Bots"
echo "   - Enable Bot Fight Mode"
echo "   - Go to Speed > Optimization"
echo "   - Enable Auto Minify for JS, CSS, HTML"
echo "   - Go to Caching > Configuration"
echo "   - Set Browser Cache TTL to 1 year"
echo "   - Go to SSL/TLS > Overview"
echo "   - Set encryption mode to 'Full (strict)'"
echo ""
echo "5. DNS Settings:"
echo "   A record: @ -> $SERVER_IP (proxied/orange cloud)"
echo "   A record: www -> $SERVER_IP (proxied/orange cloud)"
echo ""
echo "6. Page Rules (create these in order):"
echo "   1. *$DOMAIN/admin* -> Security Level: High, Cache Level: Bypass"
echo "   2. *$DOMAIN/*.php* -> Security Level: High, Cache Level: Bypass"
echo "   3. *$DOMAIN/* -> Security Level: Medium, Cache Level: Standard"
echo ""
echo "7. Firewall Rules:"
echo "   - Block countries: Create rule to block high-risk countries"
echo "   - Rate limiting: 10 requests per 10 seconds per IP"
echo "   - Challenge bad bots: (http.user_agent contains \"bot\" and not cf.verified_bot_category in {\"Search Engine\"})"
echo ""
echo "Your server will only accept traffic from Cloudflare IPs!"
EOF

chmod +x /usr/local/bin/cloudflare-setup

cat > /usr/local/bin/cf-threat-intel <<'EOF'
#!/bin/bash

echo "=== Cloudflare Threat Intelligence ==="
echo "Recent threats blocked:"
echo ""

if [ -f /var/log/nginx/access.log ]; then
    echo "Top blocked IPs (non-Cloudflare traffic):"
    grep -v "CF-Ray" /var/log/nginx/access.log | awk '{print $1}' | sort | uniq -c | sort -nr | head -10
    echo ""
    
    echo "Recent 444 responses (blocked non-CF traffic):"
    grep " 444 " /var/log/nginx/access.log | tail -10
    echo ""
fi

echo "Cloudflare headers in recent requests:"
grep "CF-Ray" /var/log/nginx/access.log | tail -5 | awk '{print $1, $7, $9}'
EOF

chmod +x /usr/local/bin/cf-threat-intel

cat > /etc/fail2ban/filter.d/cloudflare-bypass.conf <<'EOF'
[Definition]
failregex = ^<HOST> -.*" (444|403) .*$
ignoreregex =
EOF

cat > /etc/fail2ban/jail.d/cloudflare.conf <<'EOF'
[cloudflare-bypass]
enabled = true
port = http,https
filter = cloudflare-bypass
logpath = /var/log/nginx/access.log
maxretry = 3
findtime = 300
bantime = 86400
action = iptables[name=cloudflare-bypass, port=http, protocol=tcp]
EOF

ufw allow from 173.245.48.0/20 to any port 80
ufw allow from 103.21.244.0/22 to any port 80
ufw allow from 103.22.200.0/22 to any port 80
ufw allow from 103.31.4.0/22 to any port 80
ufw allow from 141.101.64.0/18 to any port 80
ufw allow from 108.162.192.0/18 to any port 80
ufw allow from 190.93.240.0/20 to any port 80
ufw allow from 188.114.96.0/20 to any port 80
ufw allow from 197.234.240.0/22 to any port 80
ufw allow from 198.41.128.0/17 to any port 80
ufw allow from 162.158.0.0/15 to any port 80
ufw allow from 104.16.0.0/13 to any port 80
ufw allow from 104.24.0.0/14 to any port 80
ufw allow from 172.64.0.0/13 to any port 80
ufw allow from 131.0.72.0/22 to any port 80

ufw allow from 173.245.48.0/20 to any port 443
ufw allow from 103.21.244.0/22 to any port 443
ufw allow from 103.22.200.0/22 to any port 443
ufw allow from 103.31.4.0/22 to any port 443
ufw allow from 141.101.64.0/18 to any port 443
ufw allow from 108.162.192.0/18 to any port 443
ufw allow from 190.93.240.0/20 to any port 443
ufw allow from 188.114.96.0/20 to any port 443
ufw allow from 197.234.240.0/22 to any port 443
ufw allow from 198.41.128.0/17 to any port 443
ufw allow from 162.158.0.0/15 to any port 443
ufw allow from 104.16.0.0/13 to any port 443
ufw allow from 104.24.0.0/14 to any port 443
ufw allow from 172.64.0.0/13 to any port 443
ufw allow from 131.0.72.0/22 to any port 443

nginx -t && systemctl reload nginx
systemctl restart fail2ban
netfilter-persistent save

cat > /root/CLOUDFLARE_SETUP.txt <<EOF
=== Cloudflare Protection Configured ===

Your server is now configured to ONLY accept traffic from Cloudflare.
Direct IP access is blocked - all traffic must go through Cloudflare.

Next steps:
1. Run: cloudflare-setup
2. Follow the instructions to configure Cloudflare dashboard
3. Update your DNS to point to Cloudflare
4. Enable SSL/TLS and security features

Monitoring:
- Check threats: cf-threat-intel
- Monitor logs: tail -f /var/log/nginx/access.log
- Cloudflare analytics: Check your Cloudflare dashboard

Domain: $DOMAIN
Backend server: http://127.0.0.1:8080
Cloudflare proxy: Port 80/443

IMPORTANT: Your site will be down until you complete Cloudflare setup!
EOF

log_info "Cloudflare protection configured"
log_info "Run 'cloudflare-setup' for next steps"
log_info "Your server now ONLY accepts Cloudflare traffic"