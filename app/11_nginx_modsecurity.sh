#!/usr/bin/env bash
# File: app/11_nginx_modsecurity.sh
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

apt install -y nginx libnginx-mod-security
mkdir -p /etc/nginx/modsec

cat > /etc/nginx/modsec/modsecurity.conf <<'EOF'
SecRuleEngine On
SecRequestBodyAccess On
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecResponseBodyAccess On
SecResponseBodyMimeType text/plain text/html text/xml
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

if [ ! -d /etc/nginx/modsec/crs ]; then
    if command -v git >/dev/null 2>&1; then
        git clone --depth 1 https://github.com/coreruleset/coreruleset /etc/nginx/modsec/crs
        cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf
    else
        log_warn "Git not available, creating basic rule set..."
        mkdir -p /etc/nginx/modsec/crs/rules
        echo "# Basic CRS placeholder" > /etc/nginx/modsec/crs/crs-setup.conf
    fi
fi

cat > /etc/nginx/modsec/main.conf <<'EOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs/crs-setup.conf
Include /etc/nginx/modsec/crs/rules/*.conf
EOF

NGINX_CONF="/etc/nginx/nginx.conf"
cp -a "$NGINX_CONF" "${BACKUP_DIR}/nginx.conf.bak"

cat > /etc/nginx/nginx.conf <<'EOF'
user www-data;
worker_processes auto;
pid /run/nginx.pid;
include /etc/nginx/modules-enabled/*.conf;

events {
    worker_connections 768;
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
    
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    limit_req_status 503;
    limit_conn_status 503;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

cat > /etc/nginx/sites-available/default <<EOF
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    server_name _;

${MODSEC_CONFIG}

    limit_req zone=one burst=5 nodelay;
    limit_conn conn_limit_per_ip 10;

    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    location / {
        try_files \$uri \$uri/ =404;
    }

    location ~* \.(asp|aspx|jsp|cgi|php)\$ {
        return 404;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    location ~* "(union.*select|insert.*into|delete.*from|drop.*table)" {
        return 444;
    }

    location ~* "(script.*>|<.*script|javascript:|vbscript:)" {
        return 444;
    }

    location ~* "\.\./|\.\.\\\"" {
        return 444;
    }

    location ~* "\x00" {
        return 444;
    }
}
EOF

if nginx -t; then
    systemctl reload nginx
    log_info "Nginx with ModSecurity configured successfully"
else
    log_error "Nginx configuration test failed"
fi