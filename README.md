# Enhanced VPS Security Blueprint

## Table of Contents

1. [Purpose & Scope](#purpose--scope)
2. [Recommended VPS Resources](#recommended-vps-resources)
3. [User Setup](#user-setup)
4. [SSH Configuration](#ssh-configuration)
5. [Kernel Hardening & DDoS Protection](#kernel-hardening--ddos-protection)
6. [Advanced Firewall Configuration](#advanced-firewall-configuration)
7. [Enhanced Fail2ban with Cross-Service Integration](#enhanced-fail2ban-with-cross-service-integration)
8. [Primary Network Interface Detection](#primary-network-interface-detection)
9. [Suricata - Advanced IDS/IPS with Active Blocking](#suricata---advanced-idsips-with-active-blocking)
10. [Snort - Alert-Only IDS](#snort---alert-only-ids)
11. [Enhanced ModSecurity + OWASP CRS](#enhanced-modsecurity--owasp-crs)
12. [Wazuh - Centralized Security Management](#wazuh---centralized-security-management)
13. [Cross-Service IP Synchronization](#cross-service-ip-synchronization)
14. [Monitoring and Management](#monitoring-and-management)
15. [Log Rotation and Maintenance](#log-rotation-and-maintenance)
16. [Snapshot Reminder](#snapshot-reminder)
17. [Summary & Logs](#summary--logs)

---

## Purpose & Scope

This enhanced blueprint provides a **fully automated, enterprise-grade VPS security setup** with **coordinated defense mechanisms**. Its purpose is to secure a single VPS by:

* **Hardening SSH and system login** with advanced authentication controls
* **Implementing multi-layer DDoS protection** at kernel, firewall, and application levels
* **Setting up coordinated firewalls** (UFW + iptables) with intelligent rate limiting
* **Deploying advanced IDS/IPS systems** that automatically block and share threat intelligence
* **Running Web Application Firewall** with real-time attack blocking
* **Centralizing security monitoring** with automated incident response
* **Cross-service IP synchronization** ensuring all security tools share threat data
* **Real-time alerting and logging** with comprehensive threat visibility

**Key Enhancement:** All security services now communicate and share blocked IP information automatically, creating a coordinated defense system where an attack detected by one service triggers blocking across all services.

**Scope:** Enterprise-grade security for VPS environments requiring maximum protection with automated threat response.

---

## Recommended VPS Resources

* **CPU:** 8-16 vCPU cores (increased for coordinated processing)
* **RAM:** 32-64 GB (enhanced for cross-service communication)
* **Storage:** 500 GB - 1 TB SSD/NVMe (additional space for comprehensive logging)

These resources support the enhanced security stack with cross-service coordination and comprehensive logging without performance degradation.

---

## User Setup

**Script Part:**

```bash
# User setup
while true; do
  read -rp "Enter a username for login: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    echo "User exists, choose another."
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
    echo "Password must be at least 12 chars, include upper, lower, number, and symbol."
  fi
done

useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo "$USERNAME"
```

**Explanation:**

* Creates secure non-root user account with sudo privileges
* Enforces strong password requirements for enhanced security
* Prevents direct root access reducing attack surface

**Security Impact:** Eliminates root login vulnerability and enforces strong authentication

---

## SSH Configuration

**Script Part:**

```bash
# SSH hardening
SSHD_CONFIG="/etc/ssh/sshd_config"
cp -a "$SSHD_CONFIG" "${BACKUP_DIR}/sshd_config.bak"
sed -i -E 's/^\s*PermitRootLogin\s+.*/PermitRootLogin no/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*PasswordAuthentication\s+.*/PasswordAuthentication yes/' "$SSHD_CONFIG" || true
sed -i -E 's/^\s*#?\s*MaxAuthTries\s+.*/MaxAuthTries 3/' "$SSHD_CONFIG" || echo "MaxAuthTries 3" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveInterval\s+.*/ClientAliveInterval 300/' "$SSHD_CONFIG" || echo "ClientAliveInterval 300" >> "$SSHD_CONFIG"
sed -i -E 's/^\s*#?\s*ClientAliveCountMax\s+.*/ClientAliveCountMax 2/' "$SSHD_CONFIG" || echo "ClientAliveCountMax 2" >> "$SSHD_CONFIG"
systemctl reload sshd || systemctl restart ssh || true
```

**Explanation:**

* Disables root login completely
* Limits authentication attempts to 3
* Implements connection timeout for idle sessions
* Enables password authentication for created user account

**Security Impact:** Significantly reduces SSH-based attack vectors and prevents brute force attempts

---

## Kernel Hardening & DDoS Protection

**Script Part:**

```bash
# Kernel hardening and DDoS protection
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
```

**Explanation:**

* Implements comprehensive network stack hardening
* Enables advanced DDoS protection mechanisms
* Optimizes TCP/IP stack for high-performance security
* Implements BBR congestion control for better performance under attack

**Security Impact:** Provides kernel-level protection against network-based attacks and DDoS

---

## Advanced Firewall Configuration

**Script Part:**

```bash
# Advanced DDoS protection with iptables
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

# UFW firewall with enhanced rules
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
```

**Explanation:**

* Implements advanced iptables rules to block malformed packets
* Rate limits SYN requests and ICMP to prevent flood attacks
* Creates SSH connection tracking to prevent brute force
* UFW provides user-friendly firewall management with logging
* Opens necessary ports for security services communication

**Security Impact:** Multi-layer firewall protection against sophisticated network attacks

---

## Enhanced Fail2ban with Cross-Service Integration

**Script Part:**

```bash
# Fail2ban with cross-service IP sharing
cp -a /etc/fail2ban/jail.conf "${BACKUP_DIR}/jail.conf.bak" || true

cat > /etc/fail2ban/action.d/wazuh-ban.conf <<'EOF'
[Definition]
actionstart = 
actionstop = 
actioncheck = 
actionban = echo "<86>$(date --rfc-3339=seconds) fail2ban banned IP <ip>" >> /var/ossec/logs/alerts/alerts.log
actionunban = echo "<86>$(date --rfc-3339=seconds) fail2ban unbanned IP <ip>" >> /var/ossec/logs/alerts/alerts.log
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
```

**Explanation:**

* Extended ban time (2 hours) for persistent attackers
* Integration with Wazuh for centralized logging
* Multiple service monitoring (SSH, Nginx, Suricata)
* Custom Suricata filter for IDS-triggered bans
* Cross-service communication through shared logging

**Security Impact:** Coordinated IP blocking across all security services with extended ban periods

---

## Primary Network Interface Detection

**Script Part:**

```bash
# Primary interface detection
PRIMARY_IFACE=$(ip route get 1.1.1.1 2>/dev/null | awk '/dev/ {for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)}' | head -n1 || true)
[ -z "$PRIMARY_IFACE" ] && PRIMARY_IFACE="eth0"
```

**Explanation:**

* Automatically detects the primary network interface for traffic monitoring
* Ensures IDS/IPS systems monitor the correct network interface
* Fallback to eth0 if detection fails

**Security Impact:** Ensures all network monitoring tools are properly configured

---

## Suricata - Advanced IDS/IPS with Active Blocking

**Script Part:**

```bash
# Install and configure Suricata for IPS mode
apt install -y suricata
cp -a /etc/suricata/suricata.yaml "${BACKUP_DIR}/suricata.yaml.bak" || true

cat > /etc/suricata/suricata.yaml <<EOF
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!\$HOME_NET"
    HTTP_SERVERS: "\$HOME_NET"
    SMTP_SERVERS: "\$HOME_NET"
    SQL_SERVERS: "\$HOME_NET"
    DNS_SERVERS: "\$HOME_NET"

  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: 1521
    SSH_PORTS: 22

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

app-layer:
  protocols:
    tls:
      enabled: yes
      detection-ports:
        dp: 443
    http:
      enabled: yes
      libhtp:
        default-config:
          personality: IDS
          request-body-limit: 100kb
          response-body-limit: 100kb

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

mpm-algo: auto

threading:
  set-cpu-affinity: no
  detect-thread-ratio: 1.0

flow:
  memcap: 128mb
  hash-size: 65536
  prealloc: 10000
  emergency-recovery: 30

stream:
  memcap: 64mb
  checksum-validation: yes
  inline: auto
  reassembly:
    memcap: 256mb
    depth: 1mb
EOF

SURICATA_DEFAULT="/etc/default/suricata"
if [ -f "$SURICATA_DEFAULT" ]; then
  cp -a "$SURICATA_DEFAULT" "${BACKUP_DIR}/suricata.default.bak"
  sed -i "s/^#RUN_ARGS=.*/RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"/" "$SURICATA_DEFAULT" || echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" >> "$SURICATA_DEFAULT"
else
  echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" > "$SURICATA_DEFAULT"
fi

suricata-update
systemctl enable suricata
systemctl restart suricata
```

**Explanation:**

* Configures Suricata in inline IPS mode for active packet dropping
* Uses AF-PACKET interface for high-performance packet processing
* Enables automatic rule updates for latest threat intelligence
* Multi-threaded processing for handling high traffic volumes
* Comprehensive logging for security analysis

**Security Impact:** Real-time network attack detection and automatic blocking

---

## Snort - Alert-Only IDS

**Script Part:**

```bash
# Install and configure Snort
apt install -y snort
SNORT_CONF="/etc/snort/snort.debian.conf"
if [ -f "$SNORT_CONF" ]; then
  cp -a "$SNORT_CONF" "${BACKUP_DIR}/snort.debian.conf.bak"
  sed -i "s/^INTERFACE=.*/INTERFACE=${PRIMARY_IFACE}/" "$SNORT_CONF" || echo "INTERFACE=${PRIMARY_IFACE}" >> "$SNORT_CONF"
else
  echo "INTERFACE=${PRIMARY_IFACE}" > "$SNORT_CONF"
fi

# Create Snort service for continuous monitoring
cat > /etc/systemd/system/snort.service <<'EOF'
[Unit]
Description=Snort NIDS Daemon
After=syslog.target network.target

[Service]
Type=simple
ExecStart=/usr/bin/snort -A fast -b -d -D -i eth0 -u snort -g snort -c /etc/snort/snort.conf -l /var/log/snort
ExecStop=/bin/kill -9 $MAINPID

[Install]
WantedBy=multi-user.target
EOF

systemctl enable snort
systemctl start snort
```

**Explanation:**

* Secondary IDS for comprehensive network monitoring
* Alert-only mode provides audit trail without affecting traffic
* Systemd service ensures continuous operation
* Complements Suricata by providing additional detection capabilities

**Security Impact:** Dual IDS coverage for enhanced threat detection

---

## Enhanced ModSecurity + OWASP CRS

**Script Part:**

```bash
# Install Nginx and ModSecurity
apt install -y nginx libnginx-mod-security
mkdir -p /etc/nginx/modsec

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

SecDefaultAction "phase:1,log,auditlog,pass"
SecDefaultAction "phase:2,log,auditlog,pass"
EOF

# Download and setup OWASP CRS
if [ ! -d /etc/nginx/modsec/crs ]; then
  git clone --depth 1 https://github.com/coreruleset/coreruleset /etc/nginx/modsec/crs
  cp /etc/nginx/modsec/crs/crs-setup.conf.example /etc/nginx/modsec/crs/crs-setup.conf
fi

cat > /etc/nginx/modsec/main.conf <<'EOF'
Include /etc/nginx/modsec/modsecurity.conf
Include /etc/nginx/modsec/crs/crs-setup.conf
Include /etc/nginx/modsec/crs/rules/*.conf
EOF

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

    include /etc/nginx/conf.d/*.conf;
    include /etc/nginx/sites-enabled/*;
}
EOF

cat > /etc/nginx/sites-available/default <<'EOF'
server {
    listen 80 default_server;
    listen [::]:80 default_server;

    root /var/www/html;
    index index.html index.htm index.nginx-debian.html;
    server_name _;

    # ModSecurity
    modsecurity on;
    modsecurity_rules_file /etc/nginx/modsec/main.conf;

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
        try_files $uri $uri/ =404;
    }

    # Block common attack patterns
    location ~* \.(asp|aspx|jsp|cgi|php)$ {
        return 404;
    }

    location ~ /\. {
        deny all;
        access_log off;
        log_not_found off;
    }
}
EOF

nginx -t && systemctl reload nginx
```

**Explanation:**

* Web Application Firewall with OWASP Core Rule Set
* Rate limiting to prevent application-layer DDoS
* Security headers for additional protection
* Automatic blocking of common attack patterns
* Integration with centralized logging system

**Security Impact:** Comprehensive web application protection against OWASP Top 10 attacks

---

## Wazuh - Centralized Security Management

**Script Part:**

```bash
# Install and configure Wazuh
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | apt-key add -
echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | tee /etc/apt/sources.list.d/wazuh.list
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
    <n>df -P</n>
    <executable>df</executable>
    <args>-P</args>
    <frequency>360</frequency>
  </command>

  <command>
    <n>netstat -tulpn | sed 's/\([[:alnum:]]\+\)\ \+[[:digit:]]\+\ \+[[:digit:]]\+\ \+\(.*\):\([[:digit:]]*\)\ \+\([0-9\.\:\*]*\).\+\ \([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 \3 \4 \5/' | sort -k 4 -g | sed 's/.*:\([[:digit:]]*\)\s\+\([0-9\.\:\*]*\)\s\+\([[:digit:]]*\/[[:alnum:]\-]*\).*/\1 \2 \3/' | sed 1,2d</n>
    <executable>netstat</executable>
    <args>-tulpn</args>
    <frequency>360</frequency>
  </command>

  <command>
    <n>last -n 20</n>
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
    /usr/sbin/fail2ban-client set sshd banip $IP
    echo "$(date) - Blocked IP: $IP" >> /var/log/wazuh-blocks.log
    ;;
  delete)
    /usr/sbin/iptables -D INPUT -s $IP -j DROP
    /usr/sbin/fail2ban-client set sshd unbanip $IP
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

systemctl enable wazuh-manager
systemctl enable wazuh-agent
systemctl start wazuh-manager
systemctl start wazuh-agent
```

**Explanation:**

* Centralized log management for all security services
* Custom correlation rules for cross-service analysis
* Automated active response system for IP blocking
* JSON and syslog format support for comprehensive monitoring
* Real-time alerting for security incidents
* System monitoring commands for infrastructure health
* Integration with all security tools for unified management

**Security Impact:** Unified security operations center with automated incident response

---

## Cross-Service IP Synchronization

**Script Part:**

```bash
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
```

**Explanation:**

* Automated IP synchronization between all security services
* Extracts threat intelligence from multiple log sources
* Prevents duplicate banning and excludes private networks
* Runs every 5 minutes for near real-time protection
* Centralized logging of all automated actions
* Cross-service blocking ensures coordinated defense

**Security Impact:** Coordinated defense where attacks detected by any service trigger system-wide blocking

---

## Monitoring and Management

**Script Part:**

```bash
# Create monitoring dashboard script
cat > /usr/local/bin/security-status.sh <<'EOF'
#!/bin/bash

echo "=== VPS Security Status ==="
echo "Date: $(date)"
echo

echo "=== Service Status ==="
systemctl is-active --quiet suricata && echo "Suricata: ACTIVE" || echo "Suricata: INACTIVE"
systemctl is-active --quiet snort && echo "Snort: ACTIVE" || echo "Snort: INACTIVE"
systemctl is-active --quiet fail2ban && echo "Fail2ban: ACTIVE" || echo "Fail2ban: INACTIVE"
systemctl is-active --quiet nginx && echo "Nginx: ACTIVE" || echo "Nginx: INACTIVE"
systemctl is-active --quiet wazuh-manager && echo "Wazuh Manager: ACTIVE" || echo "Wazuh Manager: INACTIVE"
systemctl is-active --quiet wazuh-agent && echo "Wazuh Agent: ACTIVE" || echo "Wazuh Agent: INACTIVE"
echo

echo "=== Current Banned IPs ==="
iptables -L INPUT -n | grep DROP | awk '{print $4}' | grep -E '^[0-9]+\.' | head -20
echo

echo "=== Fail2ban Status ==="
fail2ban-client status
echo

echo "=== Recent Suricata Alerts (Last 10) ==="
tail -n 10 /var/log/suricata/fast.log 2>/dev/null || echo "No Suricata logs found"
echo

echo "=== Recent Security Events ==="
tail -n 10 /var/log/security-sync.log 2>/dev/null || echo "No security sync logs found"
echo

echo "=== System Resources ==="
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | awk -F'%' '{print $1}')"
echo "Memory Usage: $(free -m | awk 'NR==2{printf "%.2f%%", $3*100/$2 }')"
echo "Disk Usage: $(df -h / | awk 'NR==2 {print $5}')"
EOF

chmod 755 /usr/local/bin/security-status.sh
```

**Explanation:**

* Comprehensive security dashboard for system monitoring
* Real-time service status checking
* Current threat landscape visibility
* Resource utilization monitoring
* Easy-to-use management interface
* Quick access to recent security events

**Security Impact:** Simplified security operations with comprehensive visibility

---

## Log Rotation and Maintenance

**Script Part:**

```bash
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

/var/log/suricata/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    copytruncate
    postrotate
        /bin/kill -USR2 `cat /var/run/suricata.pid 2>/dev/null` 2>/dev/null || true
    endscript
}

/var/log/nginx/*.log {
    daily
    missingok
    rotate 14
    compress
    delaycompress
    notifempty
    create 640 www-data adm
    sharedscripts
    postrotate
        if [ -f /var/run/nginx.pid ]; then
            kill -USR1 `cat /var/run/nginx.pid`
        fi
    endscript
}
EOF
```

**Explanation:**

* Automated log rotation for all security services
* Prevents disk space exhaustion from extensive logging
* Maintains historical data for forensic analysis
* Compresses old logs to save space
* Proper signal handling for service log rotation

**Security Impact:** Ensures continuous logging without system resource exhaustion

---

## Snapshot Reminder

**Script Part:**

```bash
# Snapshot reminder
echo "Setup complete. Remember to take a VPS snapshot now."
```

**Explanation:**

* Provides recovery point after complete security deployment
* Enables rapid restore in case of system issues
* Critical backup before production use

**Security Impact:** Disaster recovery capability for rapid system restoration

---

## Summary & Logs

**Script Part:**

```bash
# Final summary
cat > /root/SECURITY_README_${TIMESTAMP}.txt <<EOF
=== Enhanced VPS Security Setup Complete ===
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

echo "Security setup completed successfully!"
echo "Run '/usr/local/bin/security-status.sh' to check system status."
```

**Explanation:**

* Complete documentation of all installed security services
* Reference guide for ongoing security operations
* Backup locations for disaster recovery
* Management command reference for daily operations
* System status and maintenance instructions

**Security Impact:** Comprehensive documentation ensures proper ongoing security management

---

## Complete Setup Summary

This enhanced VPS security blueprint delivers enterprise-grade protection through:

**Multi-Layer Defense Architecture:**
- **Kernel-Level Protection** - Advanced sysctl hardening with DDoS mitigation
- **Network Firewall** - Dual firewall protection (UFW + iptables) with rate limiting
- **Intrusion Detection** - Dual IDS/IPS systems (Suricata + Snort) with active blocking
- **Web Application Security** - ModSecurity WAF with OWASP CRS rules
- **Automated Response** - Cross-service IP synchronization and active blocking

**Advanced Security Features:**
- **Cross-Service Integration** - All security tools share threat intelligence
- **Real-Time Response** - Attacks trigger immediate system-wide blocking
- **Centralized Management** - Unified monitoring and alerting through Wazuh
- **Performance Optimization** - BBR congestion control and multi-threaded processing
- **Comprehensive Logging** - Full audit trail with automated log rotation

**Operational Excellence:**
- **Single-Command Monitoring** - Complete security status in one command
- **Automated Maintenance** - Self-managing log rotation and cleanup
- **Disaster Recovery** - Complete configuration backups and restore capability
- **Documentation** - Comprehensive setup and management documentation

This setup transforms a standard VPS into a hardened security platform capable of defending against sophisticated attacks while maintaining high performance and operational simplicity. The coordinated defense ensures that detection by any security service triggers protection across the entire system.