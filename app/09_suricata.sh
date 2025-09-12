#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
BACKUP_DIR="${BACKUP_DIR:-/root/sec-backups-$(date +%F_%T)}"
[ -f /tmp/vps_network_vars.sh ] && source /tmp/vps_network_vars.sh
PRIMARY_IFACE="${PRIMARY_IFACE:-eth0}"

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Installing and configuring Suricata IPS..."

apt install -y suricata
systemctl stop suricata 2>/dev/null || true
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
    modbus:
      enabled: yes
      detection-ports:
        dp: 502
    dnp3:
      enabled: yes
      detection-ports:
        dp: 20000

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
EOF

if ! id -u suricata >/dev/null 2>&1; then
    groupadd --system suricata || true
    useradd --system --no-create-home --shell /usr/sbin/nologin --gid suricata suricata || true
fi

mkdir -p /var/log/suricata
chown suricata:suricata /var/log/suricata

SURICATA_DEFAULT="/etc/default/suricata"
echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" > "$SURICATA_DEFAULT"

if [ ! -f /var/lib/suricata/rules/suricata.rules ] || [ ! -s /var/lib/suricata/rules/suricata.rules ]; then
    log_warn "No Suricata rules found, downloading basic ruleset..."
    mkdir -p /var/lib/suricata/rules
    suricata-update || {
        wget -q -O /tmp/emerging.rules.tar.gz https://rules.emergingthreats.net/open/suricata-6.0.4/emerging.rules.tar.gz 2>/dev/null || true
        if [ -f /tmp/emerging.rules.tar.gz ]; then
            tar -xzf /tmp/emerging.rules.tar.gz -C /var/lib/suricata/rules/ --strip-components=1 2>/dev/null || true
            rm -f /tmp/emerging.rules.tar.gz
            log_info "Basic ruleset downloaded"
        fi
    }
fi

if suricata -T -c /etc/suricata/suricata.yaml; then
    systemctl enable suricata
    systemctl restart suricata
    sleep 5
    if systemctl is-active --quiet suricata; then
        log_info "Suricata configured and started successfully"
    else
        log_error "Suricata failed to start after configuration"
        systemctl status suricata --no-pager -l
    fi
else
    log_error "Suricata configuration test failed"
    exit 1
fi
