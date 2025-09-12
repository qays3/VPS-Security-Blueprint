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

log_info "Applying kernel hardening and DDoS protection..."

cp -a /etc/sysctl.conf "${BACKUP_DIR}/sysctl.conf.bak"

grep -v "# VPS Security Hardening" /etc/sysctl.conf > /tmp/sysctl_clean.conf || cp /etc/sysctl.conf /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.all\.rp_filter/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.default\.rp_filter/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.icmp_echo_ignore_broadcasts/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.all\.accept_source_route/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.default\.accept_source_route/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_syncookies/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_max_syn_backlog/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_fin_timeout/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_keepalive_time/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.all\.accept_redirects/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.default\.accept_redirects/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.conf\.all\.log_martians/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.ip_local_port_range/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_max_tw_buckets/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_tw_reuse/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_rmem/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_wmem/d' /tmp/sysctl_clean.conf
sed -i '/^net\.core\.rmem_max/d' /tmp/sysctl_clean.conf
sed -i '/^net\.core\.wmem_max/d' /tmp/sysctl_clean.conf
sed -i '/^net\.core\.netdev_max_backlog/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_congestion_control/d' /tmp/sysctl_clean.conf
sed -i '/^net\.core\.default_qdisc/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_slow_start_after_idle/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_mtu_probing/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_timestamps/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_sack/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_fack/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_window_scaling/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_adv_win_scale/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_moderate_rcvbuf/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_rfc1337/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_max_orphans/d' /tmp/sysctl_clean.conf
sed -i '/^net\.ipv4\.tcp_orphan_retries/d' /tmp/sysctl_clean.conf

cat >> /tmp/sysctl_clean.conf <<'EOF'
# VPS Security Hardening
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
EOF

mv /tmp/sysctl_clean.conf /etc/sysctl.conf
sysctl -p
log_info "Kernel hardening applied successfully"