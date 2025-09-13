#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing Nginx with ModSecurity..."

apt update
apt install -y nginx libmodsecurity3 libmodsecurity-dev build-essential libpcre3-dev zlib1g-dev libssl-dev git

mkdir -p "${BACKUP_DIR}"
mkdir -p /etc/nginx/modsec /var/log/nginx

systemctl stop nginx 2>/dev/null || true

if [ ! -f /usr/lib/nginx/modules/ngx_http_modsecurity_module.so ]; then
    log_info "Compiling ModSecurity Nginx module..."
    cd /tmp
    
    NGINX_VERSION=$(nginx -v 2>&1 | grep -oP 'nginx/\K[0-9.]+')
    
    rm -rf nginx-$NGINX_VERSION modsecurity-nginx
    
    wget -q http://nginx.org/download/nginx-$NGINX_VERSION.tar.gz
    tar xzf nginx-$NGINX_VERSION.tar.gz
    
    git clone --depth 1 https://github.com/SpiderLabs/ModSecurity-nginx.git modsecurity-nginx
    
    cd nginx-$NGINX_VERSION
    
    NGINX_MODULES_PATH="/usr/lib/nginx/modules"
    mkdir -p "$NGINX_MODULES_PATH"
    
    ./configure --with-compat --add-dynamic-module=../modsecurity-nginx
    make modules
    
    cp objs/ngx_http_modsecurity_module.so "$NGINX_MODULES_PATH/"
    
    cd /tmp
    rm -rf nginx-$NGINX_VERSION* modsecurity-nginx
    
    log_info "ModSecurity Nginx module compiled successfully"
else
    log_info "ModSecurity module already exists"
fi

cat > /etc/nginx/modsec/modsecurity.conf <<'EOF'
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml application/json
SecResponseBodyLimit 524288
SecResponseBodyLimitAction ProcessPartial
SecTmpDir /tmp/
SecDataDir /tmp/
SecAuditEngine RelevantOnly
SecAuditLogRelevantStatus "^(?:5|4(?!04))"
SecAuditLogParts ABIJDEFHZ
SecAuditLogType Serial
SecAuditLog /var/log/nginx/modsec_audit.log
SecArgumentSeparator &
SecCookieFormat 0
SecStatusEngine On
SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
EOF

if ! [ -d /etc/nginx/modsec/crs ]; then
    log_info "Downloading OWASP Core Rule Set..."
    git clone --depth 1 https://github.com/coreruleset/coreruleset /etc/nginx/modsec/crs
    cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf
    log_info "OWASP CRS installed"
fi

cat > /etc/nginx/modsec/main.conf <<'EOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs/crs-setup.conf
Include /etc/nginx/modsec/crs/rules/*.conf
EOF

NGINX_CONF="/etc/nginx/nginx.conf"
cp -a "$NGINX_CONF" "${BACKUP_DIR}/nginx.conf.bak" 2>/dev/null || true

cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

load_module /usr/lib/nginx/modules/ngx_http_modsecurity_module.so;

events {
    worker_connections 1024;
    use epoll;
    multi_accept on;
}

http {
    sendfile on;
    tcp_nopush on;
    tcp_nodelay on;
    keepalive_timeout 65;
    types_hash_max_size 2048;
    client_max_body_size 10M;
    server_tokens off;
    
    limit_req_zone $binary_remote_addr zone=loginlimit:10m rate=1r/s;
    limit_req_zone $binary_remote_addr zone=generallimit:10m rate=10r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    limit_req_status 429;
    limit_conn_status 429;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for" '
                    'rt=$request_time uct="$upstream_connect_time" '
                    'uht="$upstream_header_time" urt="$upstream_response_time"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log warn;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

cp -a /etc/nginx/sites-available/default "${BACKUP_DIR}/default.bak" 2>/dev/null || true

cat > /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    server_name _;

    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

    limit_req zone=generallimit burst=20 nodelay;
    limit_conn conn_limit_per_ip 20;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline';" always;

    location / {
        try_files $uri $uri/ =404;
        
        location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
            expires 1y;
            add_header Cache-Control "public, immutable";
        }
    }

    location /login {
        limit_req zone=loginlimit burst=5 nodelay;
        try_files $uri $uri/ =404;
    }

    location ~* \.(asp|aspx|jsp|cgi|php)$ {
        return 444;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~ /(admin|wp-admin|administrator|phpmyadmin|pma|mysql|db) {
        deny all;
        return 444;
    }

    location ~* "(union.*select|insert.*into|delete.*from|drop.*table)" {
        return 444;
    }

    location ~* "(script.*>|<.*script|javascript:|vbscript:|onload|onerror)" {
        return 444;
    }

    location ~* "\.\./|\.\.\"" {
        return 444;
    }

    location ~* "\x00" {
        return 444;
    }

    location /nginx_status {
        stub_status on;
        access_log off;
        allow 127.0.0.1;
        deny all;
    }

    error_page 404 /404.html;
    error_page 500 502 503 504 /50x.html;
    
    location = /404.html {
        internal;
    }
    
    location = /50x.html {
        root /var/www/html;
        internal;
    }
}
EOF

cat > /var/www/html/index.html <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Secure Server</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 600px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
        h1 { color: #2c3e50; text-align: center; }
        .status { background: #27ae60; color: white; padding: 15px; border-radius: 5px; text-align: center; margin: 20px 0; }
        .info { background: #ecf0f1; padding: 15px; border-radius: 5px; margin: 10px 0; }
    </style>
</head>
<body>
    <div class="container">
        <h1>Security Systems Active</h1>
        <div class="status">
            <strong>Server Status: PROTECTED</strong>
        </div>
        <div class="info">
            <strong>Active Security Features:</strong><br>
            • Web Application Firewall (ModSecurity)<br>
            • Intrusion Detection/Prevention System<br>
            • DDoS Protection<br>
            • Rate Limiting<br>
            • Automated Threat Response
        </div>
        <div class="info">
            <strong>Server Time:</strong> <span id="time"></span>
        </div>
    </div>
    <script>
        function updateTime() {
            document.getElementById('time').innerHTML = new Date().toLocaleString();
        }
        updateTime();
        setInterval(updateTime, 1000);
    </script>
</body>
</html>
EOF

chown -R www-data:www-data /var/www/html
chmod 755 /var/www/html
chmod 644 /var/www/html/index.html
chown -R root:root /etc/nginx/modsec
chmod -R 644 /etc/nginx/modsec/*.conf

nginx -t
systemctl enable nginx
systemctl start nginx

log_info "Nginx with ModSecurity configured and started successfully"