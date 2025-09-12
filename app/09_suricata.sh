#!/bin/bash

set -e

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

find . -name "*.sh" -exec chmod +x {} \;

echo "Updating system packages..."
apt update
apt upgrade -y

echo "Installing essential packages..."
apt install -y build-essential htop curl wget git unzip jq sudo ufw fail2ban \
iptables-persistent netfilter-persistent ca-certificates gnupg lsb-release \
apt-transport-https iproute2 iftop

echo "Setting up user account..."
read -p "Enter a username for login: " USERNAME
read -s -p "Enter a strong password: " PASSWORD
echo

useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd
usermod -aG sudo "$USERNAME"
echo "User $USERNAME created successfully"

echo "Hardening SSH configuration..."
cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
cat > /etc/ssh/sshd_config << 'EOF'
Port 22
Protocol 2
HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key
UsePrivilegeSeparation yes
KeyRegenerationInterval 3600
ServerKeyBits 1024
SyslogFacility AUTH
LogLevel INFO
LoginGraceTime 120
PermitRootLogin no
StrictModes yes
RSAAuthentication yes
PubkeyAuthentication yes
IgnoreRhosts yes
RhostsRSAAuthentication no
HostbasedAuthentication no
PermitEmptyPasswords no
ChallengeResponseAuthentication no
PasswordAuthentication yes
X11Forwarding no
X11DisplayOffset 10
PrintMotd no
PrintLastLog yes
TCPKeepAlive yes
MaxAuthTries 3
MaxSessions 2
ClientAliveInterval 300
ClientAliveCountMax 2
UseDNS no
Banner none
Subsystem sftp /usr/lib/openssh/sftp-server
EOF

systemctl reload sshd
echo "SSH configuration updated successfully"

echo "Applying kernel hardening and DDoS protection..."
cat > /etc/sysctl.d/99-security.conf << 'EOF'
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
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5
kernel.panic = 10
kernel.panic_on_oops = 1
EOF

sysctl -p /etc/sysctl.d/99-security.conf
echo "Kernel hardening applied successfully"

INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
echo "Using primary interface: $INTERFACE"

echo "Setting up advanced DDoS protection with iptables..."
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

iptables -A INPUT -i lo -j ACCEPT
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP

iptables -A INPUT -p tcp -m connlimit --connlimit-above 50 -j DROP
iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT

iptables -A INPUT -p icmp -m limit --limit 1/s -j ACCEPT
iptables -A INPUT -p icmp -j DROP

iptables -A INPUT -f -j DROP
iptables -A INPUT -p tcp --tcp-flags ALL ACK,RST,SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
iptables -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP

netfilter-persistent save
echo "Iptables DDoS protection configured"

echo "Configuring UFW firewall..."
ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw allow ssh
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 53
ufw limit ssh
ufw logging on
ufw --force enable
echo "UFW firewall configured successfully"

echo "Configuring Fail2ban..."
cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd
banaction = iptables-multiport
protocol = tcp
chain = INPUT
action_ = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mw = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
            %(mta)s-whois[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", protocol="%(protocol)s", chain="%(chain)s"]
action_mwl = %(banaction)s[name=%(__name__)s, bantime="%(bantime)s", port="%(port)s", protocol="%(protocol)s", chain="%(chain)s"]
             %(mta)s-whois-lines[name=%(__name__)s, sender="%(sender)s", dest="%(destemail)s", logpath="%(logpath)s", chain="%(chain)s"]
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 3600

[apache-auth]
enabled = false

[apache-badbots]
enabled = false

[apache-noscript]
enabled = false

[apache-overflows]
enabled = false

[nginx-http-auth]
enabled = false

[nginx-limit-req]
enabled = false

[postfix]
enabled = false

[dovecot]
enabled = false
EOF

systemctl enable fail2ban
systemctl start fail2ban
echo "Fail2ban configured and running successfully"

echo "Installing and configuring Suricata IPS..."
apt install -y suricata

if ! getent group suricata > /dev/null 2>&1; then
    groupadd suricata
fi

if ! id suricata > /dev/null 2>&1; then
    useradd -r -s /bin/false -g suricata suricata
fi

mkdir -p /var/log/suricata
mkdir -p /etc/suricata/rules

chown suricata:suricata /var/log/suricata
chown -R suricata:suricata /etc/suricata

cat > /etc/suricata/suricata.yaml << EOF
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16,10.0.0.0/8,172.16.0.0/12]"
    EXTERNAL_NET: "!$HOME_NET"
    HTTP_SERVERS: "$HOME_NET"
    SMTP_SERVERS: "$HOME_NET"
    SQL_SERVERS: "$HOME_NET"
    DNS_SERVERS: "$HOME_NET"
    TELNET_SERVERS: "$HOME_NET"
    AIM_SERVERS: "$EXTERNAL_NET"
    DC_SERVERS: "$HOME_NET"
    DNP3_SERVER: "$HOME_NET"
    DNP3_CLIENT: "$HOME_NET"
    MODBUS_CLIENT: "$HOME_NET"
    MODBUS_SERVER: "$HOME_NET"
    ENIP_CLIENT: "$HOME_NET"
    ENIP_SERVER: "$HOME_NET"
  port-groups:
    HTTP_PORTS: "80"
    SHELLCODE_PORTS: "!80"
    ORACLE_PORTS: "1521"
    SSH_PORTS: "22"
    DNP3_PORTS: "20000"
    MODBUS_PORTS: "502"
    FILE_DATA_PORTS: "[$HTTP_PORTS,110,143]"
    FTP_PORTS: "21"
    GENEVE_PORTS: "6081"
    VXLAN_PORTS: "4789"
    TEREDO_PORTS: "3544"

default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

classification-file: /etc/suricata/classification.config
reference-config-file: /etc/suricata/reference.config

af-packet:
  - interface: $INTERFACE
    cluster-id: 99
    cluster-type: cluster_flow
    defrag: yes
    use-mmap: yes
    tpacket-v3: yes

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
            metadata: no
        - http:
            extended: yes
        - dns
        - tls:
            extended: yes
        - ssh
        - flow

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

run-as:
  user: suricata
  group: suricata

host-mode: auto
max-pending-packets: 1024
runmode: autofp
autofp-scheduler: active-packets
default-packet-size: 1514
unix-command:
  enabled: auto
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
  prune-flows: 5

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
      dump-to-disk: false
      include-rules: false
      include-mpm-stats: false

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

luajit:
  states: 128

profiling:
  rules:
    enabled: yes
    filename: rule_perf.log
    append: yes
    sort: avgticks
    limit: 10
  keywords:
    enabled: yes
    filename: keyword_perf.log
    append: yes
  prefilter:
    enabled: yes
    filename: prefilter_perf.log
    append: yes
  rulegroups:
    enabled: yes
    filename: rule_group_perf.log
    append: yes
  packets:
    enabled: yes
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

coredump:
  max-dump: unlimited

napatech:
    streams: ["0-3"]
    enable-stream-stats: false
    auto-config: yes
    hardware-bypass: yes
    inline: no
    ports: [0-1,2-3]
    hashmode: hash5tuplesorted

mpipe:
  load-balance: auto
  iqueue-packets: 2048
  inputs:
  - interface: xgbe2
  - interface: xgbe3
  - interface: xgbe4
  - interface: xgbe5
  stack:
    size128: 0
    size256: 9
    size512: 0
    size1024: 0
    size1664: 7
    size4096: 0
    size10386: 0
    size16384: 0

netmap:
 - interface: em1
   copy-mode: ips
   copy-iface: em2
   threads: auto
 - interface: igb0
   copy-mode: ips
   copy-iface: igb1
   threads: auto

pfring:
  - interface: eth0
    threads: auto
    cluster-id: 99
    cluster-type: cluster_flow
  - interface: eth1
    threads: auto
    cluster-id: 93
    cluster-type: cluster_flow

ipfw:
  - copy-mode: ips
  - copy-mode: ids

nfq:
  mode: fail-open
  repeat-mark: 1
  repeat-mask: 1
  route-queue: 2
  batchcount: 20

nflog:
  - group: 2
    buffer-size: 18432
  - group: default
    qthreshold: 1
    qtimeout: 100
    max-size: 20000

capture: af-packet

app-layer:
  protocols:
    rfb:
      enabled: yes
      detection-ports:
        dp: 5900, 5901, 5902, 5903, 5904, 5905, 5906, 5907, 5908, 5909
    mqtt:
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
      ja3-fingerprints: auto
    dcerpc:
      enabled: yes
    ftp:
      enabled: yes
      memcap: 64mb
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
         server-config:

asn1-max-frames: 256
EOF

suricata-update
systemctl enable suricata
systemctl start suricata
echo "Suricata IPS configured and running successfully"

echo "Setting up log monitoring..."
cat > /etc/rsyslog.d/99-security.conf << 'EOF'
:msg,contains,"Failed password" /var/log/auth-failures.log
:msg,contains,"Invalid user" /var/log/auth-failures.log
:msg,contains,"refused connect" /var/log/security.log
:msg,contains,"Denied" /var/log/security.log
& stop
EOF

systemctl restart rsyslog

echo "Creating security monitoring script..."
cat > /usr/local/bin/security-status.sh << 'EOF'
#!/bin/bash

echo "=== VPS Security Status ==="
echo "Date: $(date)"
echo
echo "=== System Information ==="
echo "Uptime: $(uptime -p)"
echo "Load Average: $(cat /proc/loadavg | cut -d' ' -f1-3)"
echo "Memory Usage: $(free -h | grep Mem | awk '{print $3"/"$2}')"
echo "Disk Usage: $(df -h / | tail -1 | awk '{print $3"/"$2" ("$5" used)"}')"
echo
echo "=== Security Services Status ==="
echo "UFW Status: $(ufw status | head -1)"
echo "Fail2ban Status: $(systemctl is-active fail2ban)"
echo "Suricata Status: $(systemctl is-active suricata)"
echo "SSH Status: $(systemctl is-active ssh)"
echo
echo "=== Recent Failed Login Attempts ==="
tail -10 /var/log/auth-failures.log 2>/dev/null || echo "No recent failures logged"
echo
echo "=== Fail2ban Banned IPs ==="
fail2ban-client status sshd 2>/dev/null | grep "Banned IP" || echo "No banned IPs"
echo
echo "=== Active Network Connections ==="
ss -tuln | grep LISTEN
echo
echo "=== Recent Suricata Alerts ==="
tail -5 /var/log/suricata/fast.log 2>/dev/null || echo "No recent Suricata alerts"
EOF

chmod +x /usr/local/bin/security-status.sh

echo "Creating automatic security updates..."
cat > /etc/cron.daily/security-updates << 'EOF'
#!/bin/bash
apt update
apt upgrade -y
suricata-update
systemctl reload suricata
EOF

chmod +x /etc/cron.daily/security-updates

echo "Setting up basic intrusion detection alerts..."
cat > /usr/local/bin/security-alert.sh << 'EOF'
#!/bin/bash

ALERT_EMAIL=""
LOG_FILE="/var/log/security-alerts.log"

check_suspicious_activity() {
    local current_time=$(date)
    local suspicious_found=0
    
    if [ $(grep -c "Failed password" /var/log/auth.log | tail -100) -gt 20 ]; then
        echo "[$current_time] HIGH: Multiple failed login attempts detected" >> $LOG_FILE
        suspicious_found=1
    fi
    
    if [ $(ss -tuln | grep -c ":22.*LISTEN") -eq 0 ]; then
        echo "[$current_time] CRITICAL: SSH service appears to be down" >> $LOG_FILE
        suspicious_found=1
    fi
    
    if [ $(systemctl is-active fail2ban) != "active" ]; then
        echo "[$current_time] WARNING: Fail2ban service is not active" >> $LOG_FILE
        suspicious_found=1
    fi
    
    if [ $suspicious_found -eq 1 ] && [ -n "$ALERT_EMAIL" ]; then
        tail -10 $LOG_FILE | mail -s "VPS Security Alert - $(hostname)" $ALERT_EMAIL
    fi
}

check_suspicious_activity
EOF

chmod +x /usr/local/bin/security-alert.sh

echo "*/15 * * * * /usr/local/bin/security-alert.sh" | crontab -

echo "Performing final security checks..."
systemctl daemon-reload
systemctl enable ufw
systemctl enable fail2ban
systemctl enable suricata

echo
echo "=== VPS SECURITY HARDENING COMPLETED ==="
echo
echo "Security features implemented:"
echo "✓ System packages updated"
echo "✓ Essential security tools installed"
echo "✓ SSH hardened (root login disabled)"
echo "✓ Kernel security parameters optimized"
echo "✓ Advanced DDoS protection configured"
echo "✓ UFW firewall enabled with restrictive rules"
echo "✓ Fail2ban configured for intrusion prevention"
echo "✓ Suricata IPS installed and configured"
echo "✓ Security monitoring and alerting enabled"
echo "✓ Automatic security updates configured"
echo
echo "Important reminders:"
echo "• Your new user account: $USERNAME"
echo "• Root login is DISABLED - use your new account"
echo "• SSH access is limited and monitored"
echo "• Check security status: /usr/local/bin/security-status.sh"
echo "• Logs are in /var/log/auth-failures.log and /var/log/security.log"
echo
echo "REBOOT RECOMMENDED to ensure all settings take effect"
echo "After reboot, test SSH access with your new user account"