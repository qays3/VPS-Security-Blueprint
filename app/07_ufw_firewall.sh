#!/usr/bin/env bash
set -euo pipefail

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