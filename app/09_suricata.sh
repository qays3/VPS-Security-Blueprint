#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-enp0s3}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing and configuring Suricata IPS..."

apt update
apt install -y suricata suricata-update
systemctl stop suricata 2>/dev/null || true
mkdir -p "${BACKUP_DIR}"
cp -a /etc/suricata/suricata.yaml "${BACKUP_DIR}/suricata.yaml.bak" 2>/dev/null || true

groupadd -f suricata
useradd -r -g suricata -d /var/lib/suricata -s /sbin/nologin suricata 2>/dev/null || true
mkdir -p /var/lib/suricata/rules
mkdir -p /var/log/suricata
mkdir -p /etc/suricata/rules

chown -R suricata:suricata /var/lib/suricata
chown -R suricata:suricata /var/log/suricata
chown -R suricata:suricata /etc/suricata/rules

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
default-rule-path: /var/lib/suricata/rules
rule-files:
  - suricata.rules

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
            metadata: yes
        - http
        - dns
        - tls
        - files
        - drop
        - stats

af-packet:
  - interface: ${PRIMARY_IFACE}
    threads: auto
    cluster-type: cluster_flow
    cluster-id: 99
    copy-mode: ips
    copy-iface: ${PRIMARY_IFACE}
    buffer-size: 64kb
    use-mmap: yes
    ring-size: 2048

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
    ssh:
      enabled: yes
    dns:
      enabled: yes

detect:
  profile: medium
  custom-values:
    toclient-groups: 3
    toserver-groups: 25

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
    memcap: 64mb
    depth: 1mb
    toserver-chunk-size: 2560
    toclient-chunk-size: 2560

host:
  hash-size: 4096
  prealloc: 1000
  memcap: 32mb

defrag:
  memcap: 32mb
  hash-size: 65536
  trackers: 65535
  max-frags: 65535
  prealloc: yes
  timeout: 60

stats:
  enabled: yes
  interval: 8

logging:
  default-log-level: notice
  outputs:
    - console:
        enabled: yes
    - file:
        enabled: yes
        level: info
        filename: /var/log/suricata/suricata.log

runmode: workers
EOF

SURICATA_DEFAULT="/etc/default/suricata"
echo "RUN=yes" > "$SURICATA_DEFAULT"
echo "SURRICATA_OPTIONS=\"--af-packet=${PRIMARY_IFACE}\"" >> "$SURICATA_DEFAULT"

systemctl stop suricata 2>/dev/null || true

cd /tmp
if ! suricata-update --no-test 2>/dev/null; then
    log_warn "suricata-update failed, downloading rules manually..."
    rm -rf emerging-rules*
    wget -q https://rules.emergingthreats.net/open/suricata/emerging.rules.tar.gz || {
        log_error "Failed to download rules"
        exit 1
    }
    tar xzf emerging.rules.tar.gz
    cp emerging-rules/*.rules /var/lib/suricata/rules/
    cat emerging-rules/*.rules > /var/lib/suricata/rules/suricata.rules
    rm -rf emerging-rules* emerging.rules.tar.gz
fi

if [ ! -f /var/lib/suricata/rules/suricata.rules ]; then
    echo 'alert icmp any any -> $HOME_NET any (msg:"ICMP test"; sid:1; rev:1;)' > /var/lib/suricata/rules/suricata.rules
fi

chown -R suricata:suricata /var/lib/suricata
chown -R suricata:suricata /var/log/suricata
chmod 755 /var/lib/suricata/rules
chmod 644 /var/lib/suricata/rules/*.rules

if suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules; then
    systemctl enable suricata
    systemctl start suricata
    sleep 3
    if systemctl is-active --quiet suricata; then
        log_info "Suricata configured and started successfully"
    else
        log_error "Suricata failed to start after configuration"
        systemctl status suricata --no-pager
        journalctl -u suricata --no-pager -l
        exit 1
    fi
else
    log_error "Suricata configuration test failed"
    suricata -T -c /etc/suricata/suricata.yaml -S /var/lib/suricata/rules/suricata.rules -v
    exit 1
fi