#!/usr/bin/env bash
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

log_info "Setting up low privilege user, so you can login just through this account then you can switch to root user..."

while true; do
  read -rp "Enter a username for SSH login: " USERNAME
  if id "$USERNAME" &>/dev/null; then
    log_warn "User exists, choose another."
  else
    break
  fi
done

while true; do
  read -rsp "Enter a strong password for SSH login: " PASSWORD
  echo
  if [[ ${#PASSWORD} -ge 12 && "$PASSWORD" =~ [A-Z] && "$PASSWORD" =~ [a-z] && "$PASSWORD" =~ [0-9] && "$PASSWORD" =~ [^a-zA-Z0-9] ]]; then
    break
  else
    log_warn "Password must be at least 12 chars, include upper, lower, number, and symbol."
  fi
done

useradd -m -s /bin/bash "$USERNAME"
echo "$USERNAME:$PASSWORD" | chpasswd

echo "export USERNAME='$USERNAME'" > /tmp/vps_setup_vars.sh
echo "export PASSWORD='$PASSWORD'" >> /tmp/vps_setup_vars.sh

log_info "Low privilege user $USERNAME created - can su to root"