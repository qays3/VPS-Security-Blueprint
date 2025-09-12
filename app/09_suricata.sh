#!/usr/bin/env bash
# File: app/09_suricata.sh
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
        - http
        - dns
        - tls
        - files
        - drop

af-packet:
  - interface: ${PRIMARY_IFACE}
    threads: auto
    cluster-type: cluster_flow
    cluster-id: 99
    copy-mode: ips
    copy-iface: ${PRIMARY_IFACE}

app-layer:
  protocols:
    tls:
      enabled: yes
    http:
      enabled: yes
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

threading:
  set-cpu-affinity: no

flow:
  memcap: 64mb
  hash-size: 65536

stream:
  memcap: 32mb
EOF

SURICATA_DEFAULT="/etc/default/suricata"
if [ -f "$SURICATA_DEFAULT" ]; then
  cp -a "$SURICATA_DEFAULT" "${BACKUP_DIR}/suricata.default.bak"
  sed -i "s/^#RUN_ARGS=.*/RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"/" "$SURICATA_DEFAULT" || echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" >> "$SURICATA_DEFAULT"
else
  echo "RUN_ARGS=\"-i ${PRIMARY_IFACE} --af-packet\"" > "$SURICATA_DEFAULT"
fi

suricata-update || log_warn "Suricata rule update failed, continuing..."

if suricata -T -c /etc/suricata/suricata.yaml; then
    systemctl enable suricata
    systemctl restart suricata
    log_info "Suricata configured and started successfully"
else
    log_error "Suricata configuration test failed"
fi