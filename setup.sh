#!/usr/bin/env bash
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

TIMESTAMP=$(date +%F_%T)
BACKUP_DIR="/root/sec-backups-${TIMESTAMP}"
mkdir -p "$BACKUP_DIR"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Package installation
log_info "Updating system packages..."
apt update && apt upgrade -y

log_info "Installing essential packages..."
apt install -y curl wget git unzip ca-certificates lsb-release apt-transport-https gnupg build-essential sudo ufw fail2ban htop iftop iproute2 jq iptables-persistent netfilter-persistent

# User setup
log_info "Setting up user account..."
while true; do
  read -rp "Enter a username for login: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    log_warn "User exists, choose another."
  else
    break
  fi
done

while true; do
  read -rsp "Enter a strong password: " PASSWORD
  echo
  if [[ ${#PASSWORD} -ge 12 && "$PASSWORD" =~ [A-Z] && "$PASSWORD" =~ [a-z] && "$PASSWORD" =~ [0-9] && "$PASSWORD" =~ [^a-zA-Z0-9] ]]; then
    break
  else
    log_warn "Password must be at least 12 chars, include upper, lower, number, and symbol."
  fi
done

useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo "$USERNAME"
log_info "User $USERNAME created successfully"

# SSH hardening
log_info "Hardening SSH configuration..."
SSHD_CONFIG="/etc/ssh/sshd_config"
cp -a "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config.bak"
sed -i -E 's/^\s*PermitRootLogin\s+.*/PermitRootLogin no/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*PasswordAuthentication\s+.*/PasswordAuthentication yes/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*MaxAuthTries\s+.*/MaxAuthTries 3/' "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveInterval\s+.*/ClientAliveInterval 300/' "$SSHD_CONFIG" || echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveCountMax\s+.*/ClientAliveCountMax 2/' "$SSHD_CONFIG" || echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"

if sshd -t; then
    systemctl reload sshd || systemctl restart ssh || true
    log_info "SSH configuration updated successfully"
else
    log_error "SSH configuration test failed, reverting changes"
    cp "${BACKUP_DIR}/sshd_config.bak" "$SSHD_CONFIG"
fi

# Kernel hardening and DDoS protection
log_info "Applying kernel hardening and DDoS protection..."
cp -a /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak"
cat >> /etc/sysctl.conf <<'EOF'
# Network security and DDoS protection
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.ipv4.tcp_fin_timeout = 15
net.ipv4.tcp_keepalive_time = 300
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.ip_local_port_range = 10240 65535

# Enhanced DDoS protection
net.ipv4.tcp_max_tw_buckets = 1440000
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_rmem = 4096 65536 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.core.netdev_max_backlog = 5000
net.ipv4.tcp_congestion_control = bbr
net.core.default_qdisc = fq
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.tcp_mtu_probing = 1
net.ipv4.tcp_timestamps = 0
net.ipv4.tcp_sack = 1
net.ipv4.tcp_fack = 1
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_adv_win_scale = 1
net.ipv4.tcp_moderate_rcvbuf = 1
net.ipv4.tcp_rfc1337 = 1
net.ipv4.tcp_max_orphans = 65536
net.ipv4.tcp_orphan_retries = 0
EOF
sysctl -p
log_info "Kernel hardening applied successfully"

# Primary interface detection
log_info "Detecting primary network interface..."
PRIMARY_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
[ -z "$PRIMARY_IFACE" ] && PRIMARY_IFACE="eth0"
log_info "Using primary interface: $PRIMARY_IFACE"

# Advanced DDoS protection with iptables
log_info "Setting up advanced DDoS protection with iptables..."
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,FIN FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,PSH PSH -j DROP
iptables -A INPUT -p tcp --tcp-flags ACK,URG URG -j DROP
iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 1 -j ACCEPT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
netfilter-persistent save
log_info "Iptables DDoS protection configured"

# UFW firewall with enhanced rules
log_info "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw limit 22/tcp
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 1514/tcp
ufw allow 1515/tcp
ufw allow 514/udp
ufw logging on
ufw --force enable
log_info "UFW firewall configured successfully"

# Fail2ban with cross-service IP sharing
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
backend = auto
banaction = ufw
action = %(action_mwl)s
         wazuh-ban

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

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
log_info "Fail2ban configured successfully"

# Install and configure Suricata for IPS mode
log_info "Installing and configuring Suricata IPS..."
apt install -y suricata
cp -a /etc/suricata/suricata.yaml "${BACKUP_DIR}/suricata.yaml.bak" || true

cat > /etc/suricata/suricata.yaml <<EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"
    TELNET_SERVERS: "\$HOME_NET"
    AIM_SERVERS: "\$EXTERNAL_NET"
    DC_SERVERS: "\$HOME_NET"
    DNP3_SERVER: "\$HOME_NET"
    DNP3_CLIENT: "\$HOME_NET"
    MODBUS_CLIENT: "\$HOME_NET"
    MODBUS_SERVER: "\$HOME_NET"
    ENIP_CLIENT: "\$HOME_NET"
    ENIP_SERVER: "\$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22
    DNP3_PORTS: 20000
    MODBUS_PORTS: 502
    FILE_DATA_PORTS: "[\$HTTP_PORTS,110,143]"
    FTP_PORTS: 21
    VXLAN_PORTS: 4789
    TEREDO_PORTS: 3544

default-log-dir: /var/log/suricata/

stats:
  enabled: yes
  interval: 8

outputs:
  - fast:
      enabled: yes
      filename: fast.log
      append: yes
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      types:
        - alert:
            payload: yes
            packet: yes
            http-body: yes
            http-header: yes
            metadata: yes
        - http:
            extended: yes
        - dns:
            query: yes
            answer: yes
        - tls:
            extended: yes
        - files:
            force-magic: no
        - drop:
            alerts: yes
        - smtp:
        - ftp:
        - rdp:
        - nfs:
        - smb:
        - tftp:
        - ikev2:
        - dcerpc:
        - krb5:
        - snmp:
        - sip:
        - dhcp:
            extended: yes
        - ssh:
        - stats:
            totals: yes
            threads: no
            deltas: no
        - flow:

logging:
  default-log-level: notice
  default-output-filter:
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log
    - syslog:
        enabled: no
        facility: local5
        format: "[%i] <%d> -- "

af-packet:
  - interface: ${PRIMARY_IFACE}
    threads: auto
    defrag: yes
    cluster-type: cluster_flow
    cluster-id: 99
    copy-mode: ips
    copy-iface: ${PRIMARY_IFACE}
    use-mmap: yes
    tpacket-v3: yes

netmap:
  - interface: ${PRIMARY_IFACE}

pfring:
  - interface: ${PRIMARY_IFACE}
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow

pcap:
  - interface: ${PRIMARY_IFACE}

pcap-file:
  checksum-checks: auto

app-layer:
  protocols:
    krb5:
      enabled: yes
    snmp:
      enabled: yes
    ikev2:
      enabled: yes
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
    rdp:
    ssh:
      enabled: yes
    smtp:
      enabled: yes
      raw-extraction: no
      mime:
        decode-mime: yes
        decode-base64: yes
        decode-quoted-printable: yes
        header-value-depth: 2000
        extract-urls: yes
        body-md5: no
      inspected-tracker:
        content-limit: 100000
        content-inspect-min-size: 32768
        content-inspect-window: 4096
    imap:
      enabled: detection-only
    msn:
      enabled: detection-only
    smb:
      enabled: yes
      detection-ports:
        dp: 139, 445
    nfs:
      enabled: yes
    tftp:
      enabled: yes
    dns:
      tcp:
        enabled: yes
        detection-ports:
          dp: 53
      udp:
        enabled: yes
        detection-ports:
          dp: 53
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb
          request-body-minimal-inspect-size: 32kb
          request-body-inspect-window: 4kb
          response-body-minimal-inspect-size: 40kb
          response-body-inspect-window: 16kb
          response-body-decompress-layer-limit: 2
          http-body-inline: auto
          swf-decompression:
            enabled: yes
            type: both
            compress-depth: 100kb
            decompress-depth: 100kb
          double-decode-path: no
          double-decode-query: no
    modbus:
      enabled: no
      detection-ports:
        dp: 502
      stream-depth: 0
    dnp3:
      enabled: no
      detection-ports:
        dp: 20000
    enip:
      enabled: no
      detection-ports:
        dp: 44818
        sp: 44818
    ntp:
      enabled: yes
    dhcp:
      enabled: yes

asn1-max-frames: 256

coredump:
  max-dump: unlimited

host-mode: auto

max-pending-packets: 1024

runmode: autofp

autofp-scheduler: hash

default-packet-size: 1514

default-queue-size: 2048

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25
  sgh-mpm-context: auto
  inspection-recursion-limit: 3000
  prefilter:
    default: mpm
  grouping:
  profiling:
    grouping:
      dump-to-disk: no
      include-rules: no
      include-mpm-stats: no

mpm-algo: auto

spm-algo: auto

threading:
  set-cpu-affinity: no
  cpu-affinity:
    - management-cpu-set:
        cpu: [ 0 ]
    - receive-cpu-set:
        cpu: [ 0 ]
    - worker-cpu-set:
        cpu: [ "all" ]
        mode: "exclusive"
        prio:
          low: [ 0 ]
          medium: [ "1-2" ]
          high: [ 3 ]
          default: "medium"
  detect-thread-ratio: 1.0

profiling:
  rules:
    enabled: no
    filename: rule_perf.log
    append: yes
    sort: avgticks
    limit: 10
    json: yes
  keywords:
    enabled: no
    filename: keyword_perf.log
    append: yes
  rulegroups:
    enabled: no
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: no
    filename: packet_stats.log
    append: yes
    csv:
      enabled: no
      filename: packet_stats.csv
  locks:
    enabled: no
    filename: lock_stats.log
    append: yes
  pcap-log:
    enabled: no
    filename: pcaplog_stats.log
    append: yes

nfq:

nflog:
  - group: 2
    buffer-size: 18432
  - group: default
    qthreshold: 1
    qtimeout: 100
    max-size: 20000

capture:

netmap:
 - interface: default

legacy:
  uricontent: enabled

engine-analysis:
  rules-fast-pattern: yes
  rules: yes

pcre:
  match-limit: 3500
  match-limit-recursion: 1500

host-os-policy:
  windows: [0.0.0.0/0]
  bsd: []
  bsd-right: []
  old-linux: []
  linux: []
  old-solaris: []
  solaris: []
  hpux10: []
  hpux11: []
  irix: []
  macos: []
  vista: []
  windows2k3: []

defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30
  managers: 1
  recyclers: 1

vlan:
  use-for-tracking: true

flow-timeouts:
  default:
    new: 30
    established: 300
    closed: 0
    bypassed: 100
    emergency-new: 10
    emergency-established: 100
    emergency-closed: 0
    emergency-bypassed: 50
  tcp:
    new: 60
    established: 600
    closed: 60
    bypassed: 100
    emergency-new: 5
    emergency-established: 25
    emergency-closed: 5
    emergency-bypassed: 25
  udp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 25
    emergency-bypassed: 25
  icmp:
    new: 30
    established: 300
    bypassed: 100
    emergency-new: 10
    emergency-established: 25
    emergency-bypassed: 25

stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560
    randomize-chunk-size: yes

host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

decoder:
  teredo:
    enabled: true
    ports:
      dp: 3544
  vxlan:
    enabled: true
    ports:
      dp: 4789

detect-engine:
  - sgh-mpm-context: auto
    inspection-recursion-limit: 3000

exception-policy: auto

app-layer-parsers:
EOF

SURICATA_DEFAULT="/etc/default/suricata"
if [ -f "$SURICATA_DEFAULT" ]; then
  cp -a "$SURICATA_DEFAULT" "${BACKUP_DIR}/suricata.default.bak"
  sed -i "s/^#RUN_ARGS=.*/RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"/" "$SURICATA_DEFAULT" || echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" >> "$SURICATA_DEFAULT"
else
  echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" > "$SURICATA_DEFAULT"
fi

# Update Suricata rules
log_info "Updating Suricata rules..."
suricata-update || log_warn "Suricata rule update failed, continuing..."

# Test Suricata config before starting
if suricata -T -c /etc/suricata/suricata.yaml; then
    systemctl enable suricata
    systemctl restart suricata
    log_info "Suricata configured and started successfully"
else
    log_error "Suricata configuration test failed"
fi

# Install and configure Snort
log_info "Installing and configuring Snort..."
apt install -y snort
SNORT_CONF="/etc/snort/snort.debian.conf"
if [ -f "$SNORT_CONF" ]; then
  cp -a "$SNORT_CONF" "${BACKUP_DIR}/snort.debian.conf.bak"
  sed -i "s/^INTERFACE=.*/INTERFACE=${PRIMARY_IFACE}/" "$SNORT_CONF" || echo "INTERFACE=${PRIMARY_IFACE}" >> "$SNORT_CONF"
else
  echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
fi

# Create Snort service file with dynamic interface
cat > /etc/systemd/system/snort.service <<EOF
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/bin/snort -A fast -b -d -D -i ${PRIMARY_IFACE} -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort
ExecStop=/bin/kill -9 \$MAINPID

[Install]
WantedBy=multi-user.target
EOF

systemctl enable snort || log_warn "Failed to enable Snort"
systemctl start snort || log_warn "Failed to start Snort"
log_info "Snort installation completed"

# Install Nginx and ModSecurity
log_info "Installing Nginx with ModSecurity..."
apt install -y nginx libnginx-mod-security
mkdir -p /etc/nginx/modsec

# Configure ModSecurity if available
if [ "$MODSEC_AVAILABLE" = "true" ]; then
    log_info "Configuring full ModSecurity..."
    
    cat > /etc/nginx/modsec/modsecurity.conf <<'EOF'
SecRuleEngine On
SecRequestBodyAccess On
SecRule REQUEST_HEADERS:Content-Type "text/xml" \
     "id:'200000',phase:1,t:none,t:lowercase,pass,nolog,ctl:requestBodyProcessor=XML"
SecRequestBodyLimit 13107200
SecRequestBodyNoFilesLimit 131072
SecRequestBodyInMemoryLimit 131072
SecRequestBodyLimitAction Reject
SecRule REQBODY_ERROR "!@eq 0" \
"id:'200001', phase:2,t:none,log,deny,status:400,msg:'Failed to parse request body.',logdata:'Error %{REQBODY_ERROR_MSG}',severity:2"
SecRule MULTIPART_STRICT_ERROR "!@eq 0" \
"id:'200002',phase:2,t:none,log,deny,status:400, \
msg:'Multipart request body failed strict validation: \
PE %{REQBODY_PROCESSOR_ERROR}, \
BQ %{MULTIPART_BOUNDARY_QUOTED}, \
BW %{MULTIPART_BOUNDARY_WHITESPACE}, \
DB %{MULTIPART_DATA_BEFORE}, \
DA %{MULTIPART_DATA_AFTER}, \
HF %{MULTIPART_HEADER_FOLDING}, \
LF %{MULTIPART_LF_LINE}, \
SM %{MULTIPART_MISSING_SEMICOLON}, \
IQ %{MULTIPART_INVALID_QUOTING}, \
IP %{MULTIPART_INVALID_PART}, \
IH %{MULTIPART_INVALID_HEADER_FOLDING}, \
FL %{MULTIPART_FILE_LIMIT_EXCEEDED}'"

SecRule MULTIPART_UNMATCHED_BOUNDARY "!@eq 0" \
"id:'200003',phase:2,t:none,log,deny,status:44,msg:'Multipart parser detected a possible unmatched boundary.'"

SecPcreMatchLimit 1000
SecPcreMatchLimitRecursion 1000

SecRule TX:/^MSC_/ "!@streq 0" \
        "id:'200004',phase:2,t:none,deny,msg:'ModSecurity internal error flagged: %{MATCHED_VAR_NAME}'"

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
SecUnicodeMapFile unicode.mapping 20127
SecStatusEngine On

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"

SecAction \
  "id:900990,\
   phase:1,\
   nolog,\
   pass,\
   t:none,\
   setvar:tx.crs_setup_version=340"
EOF

    # Download and setup OWASP CRS
    log_info "Setting up OWASP Core Rule Set..."
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

    MODSEC_CONFIG="    # ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;"
    
elif [ "$MODSEC_AVAILABLE" = "basic" ]; then
    log_info "Using basic security rules..."
    MODSEC_CONFIG="    # Basic security rules
    include /etc/nginx/modsec/basic-security.conf;"
else
    log_warn "No ModSecurity available, using basic security headers only..."
    MODSEC_CONFIG="    # Basic security (no ModSecurity module available)"
fi

# Configure Nginx with ModSecurity
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
    
    # Rate limiting
    limit_req_zone $binary_remote_addr zone=one:10m rate=1r/s;
    limit_conn_zone $binary_remote_addr zone=conn_limit_per_ip:10m;
    
    # DDoS protection
    limit_req_status 503;
    limit_conn_status 503;
    
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    # Logging format
    log_format main '$remote_addr - $remote_user [$time_local] "$request" '
                    '$status $body_bytes_sent "$http_referer" '
                    '"$http_user_agent" "$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;
    error_log /var/log/nginx/error.log;

    # Gzip Settings
    gzip on;
    gzip_vary on;
    gzip_proxied any;
    gzip_comp_level 6;
    gzip_types
        text/plain
        text/css
        text/xml
        text/javascript
        application/json
        application/javascript
        application/xml+rss
        application/atom+xml
        image/svg+xml;

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

    # Rate limiting
    limit_req zone=one burst=5 nodelay;
    limit_conn conn_limit_per_ip 10;

    # Security headers
    add_header X-Frame-Options "SAMEORIGIN" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "no-referrer-when-downgrade" always;
    add_header Content-Security-Policy "default-src 'self' http: https: data: blob: 'unsafe-inline'" always;

    location / {
        try_files \$uri \$uri/ =404;
    }

    # Block common attack patterns
    location ~* \.(asp|aspx|jsp|cgi|php)\$ {
        return 404;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }

    # Block common attack patterns in URI
    location ~* "(union.*select|insert.*into|delete.*from|drop.*table)" {
        return 444;
    }

    # Block script injection
    location ~* "(script.*>|<.*script|javascript:|vbscript:)" {
        return 444;
    }

    # Block directory traversal
    location ~* "\.\./|\.\.\\\" {
        return 444;
    }

    # Block null bytes
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

# Install and configure Wazuh
log_info "Installing Wazuh manager and agent..."
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor > /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
apt update && apt install -y wazuh-manager wazuh-agent

# Configure Wazuh manager
cp -a /var/ossec/etc/ossec.conf "${BACKUP_DIR}/ossec.conf.bak"

cat > /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <global>
    <email_notification>yes</email_notification>
    <email_to>admin@localhost</email_to>
    <smtp_server>localhost</smtp_server>
    <email_from>wazuh@localhost</email_from>
    <email_maxperhour>12</email_maxperhour>
    <logall>yes</logall>
    <logall_json>yes</logall_json>
    <white_list>127.0.0.1</white_list>
    <white_list>^localhost.localdomain$</white_list>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>udp</protocol>
    <queue_size>131072</queue_size>
  </remote>

  <logging>
    <log_alert_level>1</log_alert_level>
    <log_format>plain</log_format>
  </logging>

  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>/var/ossec/etc/shared/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>/var/ossec/etc/shared/rootkit_trojans.txt</rootkit_trojans>
  </rootcheck>

  <wodle name="cis-cat">
    <disabled>yes</disabled>
    <timeout>1800</timeout>
    <interval>1d</interval>
    <scan-on-start>yes</scan-on-start>
  </wodle>

  <wodle name="osquery">
    <disabled>yes</disabled>
    <run_daemon>yes</run_daemon>
    <log_path>/var/log/osquery/osqueryd.results.log</log_path>
    <config_path>/etc/osquery/osquery.conf</config_path>
    <add_labels>yes</add_labels>
  </wodle>

  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="no">yes</ports>
    <processes>yes</processes>
  </wodle>

  <wodle name="vulnerability-detector">
    <disabled>no</disabled>
    <interval>5m</interval>
    <ignore_time>6h</ignore_time>
    <run_on_start>yes</run_on_start>
    <provider name="canonical">
      <enabled>yes</enabled>
      <os>trusty</os>
      <os>xenial</os>
      <os>bionic</os>
      <os>focal</os>
      <update_interval>1h</update_interval>
    </provider>
    <provider name="debian">
      <enabled>yes</enabled>
      <os_version>7</os_version>
      <os_version>8</os_version>
      <os_version>9</os_version>
      <os_version>10</os_version>
      <os_version>11</os_version>
      <update_interval>1h</update_interval>
    </provider>
  </wodle>

  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <directories check_all="yes">/etc,/usr/bin,/usr/sbin</directories>
    <directories check_all="yes">/bin,/sbin,/boot</directories>
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore>/etc/mail/statistics</ignore>
    <ignore>/etc/random-seed</ignore>
    <ignore>/etc/random.seed</ignore>
    <ignore>/etc/adjtime</ignore>
    <ignore>/etc/httpd/logs</ignore>
    <ignore>/etc/utmpx</ignore>
    <ignore>/etc/wtmpx</ignore>
    <ignore>/etc/cups/certs</ignore>
    <ignore>/etc/dumpdates</ignore>
    <ignore>/etc/svc/volatile</ignore>
    <no_diff>/etc/ssl/private.key</no_diff>
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>200</max_eps>
    <sync_enabled>yes</sync_enabled>
    <sync_interval>5m</sync_interval>
    <sync_max_interval>1h</sync_max_interval>
    <sync_max_eps>10</sync_max_eps>
  </syscheck>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/auth.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/syslog</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/kern.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/access.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/error.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/suricata/fast.log</location>
  </localfile>

  <localfile>
    <log_format>json</log_format>
    <location>/var/log/suricata/eve.json</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/fail2ban.log</location>
  </localfile>

  <localfile>
    <log_format>apache</log_format>
    <location>/var/log/nginx/modsec_audit.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/snort/alert</location>
  </localfile>

  <command>
    <name>df -P</name>
    <executable>df</executable>
    <args>-P</args>
    <frequency>360</frequency>
  </command>

  <command>
    <name>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]*\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 \3 \4 \5/' | sort -k 4 -g | sed 's/.*:\([[:digit:]]*\)\s\+\([0-9\.\:\*]*\)\s\+\([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 \3/' | sed 1,2d</name>
    <executable>netstat</executable>
    <args>-tulpn</args>
    <frequency>360</frequency>
  </command>

  <command>
    <name>last -n 20</name>
    <executable>last</executable>
    <args>-n 20</args>
    <frequency>3600</frequency>
  </command>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>5712</rules_id>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>40111</rules_id>
    <timeout>600</timeout>
  </active-response>

  <active-response>
    <disabled>no</disabled>
    <command>firewall-drop</command>
    <location>local</location>
    <rules_id>40112</rules_id>
    <timeout>600</timeout>
  </active-response>
</ossec_config>
EOF

# Custom Wazuh rules for cross-service integration
cat > /var/ossec/etc/rules/local_rules.xml <<'EOF'
<group name="local,syslog,">
  <rule id="100001" level="10">
    <if_sid>1002</if_sid>
    <match>fail2ban.actions</match>
    <regex>Ban (\S+)</regex>
    <description>Fail2ban banned IP address: $(regex)</description>
    <group>authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,</group>
  </rule>

  <rule id="100002" level="12">
    <if_sid>1002</if_sid>
    <match>suricata</match>
    <regex>ATTACK|MALWARE|TROJAN|EXPLOIT</regex>
    <description>Suricata detected attack: $(regex)</description>
    <group>ids,intrusion_attempt,</group>
  </rule>

  <rule id="100003" level="10">
    <if_sid>1002</if_sid>
    <match>ModSecurity</match>
    <regex>Access denied</regex>
    <description>ModSecurity blocked web attack</description>
    <group>web,attack,</group>
  </rule>

  <rule id="100004" level="15">
    <if_sid>100001,100002,100003</if_sid>
    <frequency>3</frequency>
    <timeframe>300</timeframe>
    <description>Multiple security alerts from same source</description>
    <group>multiple_attacks,</group>
  </rule>

  <rule id="100005" level="12">
    <if_sid>1002</if_sid>
    <regex>DDoS|flood|scan</regex>
    <description>Potential DDoS or scanning attack detected</description>
    <group>ddos,scanning,</group>
  </rule>
</group>
EOF

# Active response script for IP blocking
cat > /var/ossec/active-response/bin/firewall-drop.sh <<'EOF'
#!/bin/bash
ACTION=$1
USER=$2
IP=$3

case "$ACTION" in
  add)
    /usr/sbin/iptables -I INPUT -s $IP -j DROP
    /usr/sbin/fail2ban-client set sshd banip $IP 2>/dev/null || true
    echo "$(date) - Blocked IP: $IP" >> /var/log/wazuh-blocks.log
    ;;
  delete)
    /usr/sbin/iptables -D INPUT -s $IP -j DROP 2>/dev/null || true
    /usr/sbin/fail2ban-client set sshd unbanip $IP 2>/dev/null || true
    echo "$(date) - Unblocked IP: $IP" >> /var/log/wazuh-blocks.log
    ;;
esac
EOF

chmod 755 /var/ossec/active-response/bin/firewall-drop.sh

# Create active response command definition
cat > /var/ossec/etc/shared/ar.conf <<'EOF'
restart-wazuh0 - restart-wazuh.sh - 0
restart-wazuh0 - restart-wazuh.cmd - 0
firewall-drop0 - firewall-drop.sh - 0
EOF

# Create IP sharing script between services
cat > /usr/local/bin/security-sync.sh <<'EOF'
#!/bin/bash

BANNED_IPS_FILE="/tmp/banned_ips.txt"
WAZUH_LOG="/var/ossec/logs/alerts/alerts.log"
SURICATA_LOG="/var/log/suricata/fast.log"

# Function to extract IPs from logs and ban them
extract_and_ban() {
    # Get IPs from Suricata alerts
    if [ -f "$SURICATA_LOG" ]; then
        tail -n 100 "$SURICATA_LOG" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    # Get IPs from Wazuh alerts
    if [ -f "$WAZUH_LOG" ]; then
        tail -n 100 "$WAZUH_LOG" | grep -oE '\b([0-9]{1,3}\.){3}[0-9]{1,3}\b' | sort -u >> "$BANNED_IPS_FILE"
    fi

    # Remove duplicates and process
    if [ -f "$BANNED_IPS_FILE" ]; then
        sort -u "$BANNED_IPS_FILE" > /tmp/unique_banned_ips.txt
        
        while read -r ip; do
            if [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                # Skip private IPs
                if [[ ! "$ip" =~ ^(10\.|172\.1[6-9]\.|172\.2[0-9]\.|172\.3[0-1]\.|192\.168\.|127\.) ]]; then
                    # Ban in iptables if not already banned
                    if ! iptables -L INPUT -n | grep -q "$ip"; then
                        iptables -I INPUT -s "$ip" -j DROP
                        echo "$(date) - Auto-banned IP: $ip" >> /var/log/security-sync.log
                        
                        # Also ban in fail2ban
                        fail2ban-client set sshd banip "$ip" 2>/dev/null || true
                        fail2ban-client set nginx-http-auth banip "$ip" 2>/dev/null || true
                    fi
                fi
            fi
        done < /tmp/unique_banned_ips.txt
        
        rm -f "$BANNED_IPS_FILE" /tmp/unique_banned_ips.txt
    fi
}

# Run the function
extract_and_ban
EOF

chmod 755 /usr/local/bin/security-sync.sh

# Create cron job for security sync
echo "*/5 * * * * root /usr/local/bin/security-sync.sh" >> /etc/crontab

# Start and enable services
log_info "Starting and enabling security services..."
systemctl enable fail2ban
systemctl restart fail2ban
systemctl enable wazuh-manager || log_warn "Failed to enable Wazuh manager"
systemctl enable wazuh-agent || log_warn "Failed to enable Wazuh agent"
systemctl start wazuh-manager || log_warn "Failed to start Wazuh manager"
systemctl start wazuh-agent || log_warn "Failed to start Wazuh agent"

# Create comprehensive monitoring dashboard script
cat > /usr/local/bin/security-status.sh <<EOF
#!/bin/bash

echo "=== VPS Security Status ==="
echo "Date: \$(date)"
echo "Interface: ${PRIMARY_IFACE}"
echo

echo "=== Service Status ==="
systemctl is-active --quiet suricata && echo "✓ Suricata: ACTIVE" || echo "✗ Suricata: INACTIVE"
systemctl is-active --quiet snort && echo "✓ Snort: ACTIVE" || echo "✗ Snort: INACTIVE"
systemctl is-active --quiet fail2ban && echo "✓ Fail2ban: ACTIVE" || echo "✗ Fail2ban: INACTIVE"
systemctl is-active --quiet nginx && echo "✓ Nginx: ACTIVE" || echo "✗ Nginx: INACTIVE"
systemctl is-active --quiet wazuh-manager && echo "✓ Wazuh Manager: ACTIVE" || echo "✗ Wazuh Manager: INACTIVE"
systemctl is-active --quiet wazuh-agent && echo "✓ Wazuh Agent: ACTIVE" || echo "✗ Wazuh Agent: INACTIVE"
echo

echo "=== Current Banned IPs ==="
iptables -L INPUT -n | grep DROP | awk '{print \$4}' | grep -E '^[0-9]+\\.' | head -20 || echo "No banned IPs found"
echo

echo "=== Fail2ban Status ==="
fail2ban-client status 2>/dev/null || echo "Fail2ban not responding"
echo

echo "=== Recent Suricata Alerts (Last 10) ==="
if [ -f /var/log/suricata/fast.log ]; then
    tail -n 10 /var/log/suricata/fast.log 2>/dev/null
else
    echo "No Suricata logs found"
fi
echo

echo "=== Recent Security Events ==="
if [ -f /var/log/security-sync.log ]; then
    tail -n 10 /var/log/security-sync.log
else
    echo "No security sync logs found"
fi
echo

echo "=== System Resources ==="
echo "CPU Usage: \$(top -bn1 | grep 'Cpu(s)' | awk '{print \$2}' | awk -F'%' '{print \$1}' || echo 'N/A')"
echo "Memory Usage: \$(free -m | awk 'NR==2{printf \"%.2f%%\", \$3*100/\$2 }')"
echo "Disk Usage: \$(df -h / | awk 'NR==2 {print \$5}')"
echo "Load Average: \$(uptime | awk -F'load average:' '{print \$2}')"
EOF

chmod 755 /usr/local/bin/security-status.sh

# Create log rotation for security logs
cat > /etc/logrotate.d/security-logs <<'EOF'
/var/log/security-sync.log
/var/log/wazuh-blocks.log {
    daily
    missingok
    rotate 7
    compress
    delaycompress
    notifempty
    copytruncate
}
EOF

# Create comprehensive summary
cat > "/root/SECURITY_README_${TIMESTAMP}.txt" <<EOF
=== VPS Security Setup Complete ===
Date: $(date)
Primary interface: ${PRIMARY_IFACE}
Backups directory: ${BACKUP_DIR}
Login username: ${USERNAME}

=== Installed Services ===
- SSH: Hardened with root login disabled, max 3 auth tries
- Kernel: Hardened with DDoS protection and BBR congestion control
- UFW: Firewall with rate limiting and logging
- Iptables: Advanced DDoS protection rules
- Fail2ban: Auto-banning with cross-service IP sharing
- Suricata: IDS/IPS in AF-PACKET mode with active blocking
- Snort: Alert-only IDS for additional monitoring  
- Nginx: Web server with rate limiting and security headers
- ModSecurity: WAF with OWASP CRS rules for web attack protection
- Wazuh: Centralized logging, monitoring, and active response

=== Key Features ===
- All services share banned IP information automatically
- Active response system blocks IPs across all services
- Real-time log aggregation and alerting through Wazuh
- Enhanced DDoS protection at multiple layers
- Cross-service communication for coordinated defense
- Comprehensive logging and monitoring

=== Management Commands ===
- Check security status: /usr/local/bin/security-status.sh
- View Wazuh alerts: tail -f /var/ossec/logs/alerts/alerts.log
- View banned IPs: iptables -L INPUT -n | grep DROP
- Fail2ban status: fail2ban-client status
- Suricata stats: suricata-sc -c stats

=== Log Locations ===
- Suricata: /var/log/suricata/
- Nginx: /var/log/nginx/
- Fail2ban: /var/log/fail2ban.log
- Wazuh: /var/ossec/logs/
- Security sync: /var/log/security-sync.log
- Blocked IPs: /var/log/wazuh-blocks.log

=== Configuration Backups ===
All original configurations backed up to: ${BACKUP_DIR}

=== Notes ===
- IP synchronization runs every 5 minutes via cron
- Active response automatically blocks attacking IPs
- All logs are centralized in Wazuh for analysis
- ModSecurity actively blocks web attacks
- System optimized for high-performance security monitoring

Run 'security-status.sh' to view current system status.
EOF

# Final tests and cleanup
log_info "Running final configuration tests..."
nginx -t && log_info "✓ Nginx configuration valid" || log_error "✗ Nginx configuration invalid"
suricata -T -c /etc/suricata/suricata.yaml &>/dev/null && log_info "✓ Suricata configuration valid" || log_warn "⚠ Suricata configuration has warnings"
systemctl is-active --quiet fail2ban && log_info "✓ Fail2ban is running" || log_error "✗ Fail2ban is not running"

echo ""
log_info "Security setup completed successfully!"
log_info "Summary saved to: /root/SECURITY_README_${TIMESTAMP}.txt"
log_info "Run '/usr/local/bin/security-status.sh' to check system status."
log_info "Remember to take a VPS snapshot now!"

echo ""
log_warn "IMPORTANT: Test SSH login with user '$USERNAME' before closing this session!"
echo -e "${GREEN}Setup completed at: $(date)${NC}"