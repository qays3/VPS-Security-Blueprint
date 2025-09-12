#!/usr/bin/env bash
set -euo pipefail

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

export USERNAME PASSWORD

log_info "User $USERNAME created successfully"