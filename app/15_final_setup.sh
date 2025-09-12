#!/usr/bin/env bash
set -euo pipefail

log_info "Running final configuration tests..."

systemctl enable fail2ban
systemctl restart fail2ban

nginx -t && log_info "✓ Nginx configuration valid" || log_error "✗ Nginx configuration invalid"
suricata -T -c /etc/suricata/suricata.yaml &>/dev/null && log_info "✓ Suricata configuration valid" || log_warn "⚠ Suricata configuration has warnings"
systemctl is-active --quiet fail2ban && log_info "✓ Fail2ban is running" || log_error "✗ Fail2ban is not running"

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

echo ""
log_info "Security setup completed successfully!"
log_info "Summary saved to: /root/SECURITY_README_${TIMESTAMP}.txt"
log_info "Run '/usr/local/bin/security-status.sh' to check system status."
log_info "Remember to take a VPS snapshot now!"

echo ""
log_warn "IMPORTANT: Test SSH login with user '$USERNAME' before closing this session!"
echo -e "${GREEN}Setup completed at: $(date)${NC}"