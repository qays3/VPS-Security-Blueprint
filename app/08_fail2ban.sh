#!/usr/bin/env bash
# File: app/08_fail2ban.sh
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Configuring Fail2ban with cross-service IP sharing..."

cp -a /etc/fail2ban/jail.conf "${BACKUP_DIR}/jail.conf.bak" || true

cat > /etc/fail2ban/action.d/wazuh-ban.conf <<'EOF'
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = echo "<86>$(date --rfc-3339=seconds) fail2ban banned IP <ip>" >> /var/ossec/logs/alerts/alerts.log 2>/dev/null || true
actionunban = echo "<86>$(date --rfc-3339=seconds) fail2ban unbanned IP <ip>" >> /var/ossec/logs/alerts/alerts.log 2>/dev/null || true
EOF

cat > /etc/fail2ban/jail.local <<'EOF'
[DEFAULT]
bantime = 7200
findtime = 600
maxretry = 3
backend = systemd
banaction = ufw
action = %(action_mwl)s
         wazuh-ban

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[nginx-http-auth]
enabled = true
filter = nginx-http-auth
logpath = /var/log/nginx/error.log
maxretry = 3

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 6

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-nohome]
enabled = true
port = http,https
filter = nginx-nohome
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noproxy]
enabled = true
port = http,https
filter = nginx-noproxy
logpath = /var/log/nginx/access.log
maxretry = 2

[suricata]
enabled = true
filter = suricata
logpath = /var/log/suricata/fast.log
maxretry = 1
bantime = 86400
EOF

cat > /etc/fail2ban/filter.d/suricata.conf <<'EOF'
[Definition]
failregex = ^\S+\s+\[\*\*\] \[.+\] .* \[Classification: .+\] \[Priority: .+\] \{.+\} <HOST>:\d+ ->
ignoreregex =
EOF

systemctl enable fail2ban
systemctl restart fail2ban
sleep 3
if systemctl is-active --quiet fail2ban; then
    log_info "Fail2ban configured and running successfully"
else
    log_error "Fail2ban failed to start, checking status..."
    systemctl status fail2ban --no-pager -l
fi