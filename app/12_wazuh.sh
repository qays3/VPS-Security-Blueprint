#!/bin/bash

systemctl stop wazuh-manager

cat > /var/ossec/etc/ossec.conf <<'EOF'
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
  </global>

  <alerts>
    <log_alert_level>3</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
    <protocol>tcp</protocol>
  </remote>

  <syscheck>
    <disabled>yes</disabled>
  </syscheck>

  <rootcheck>
    <disabled>yes</disabled>
  </rootcheck>
</ossec_config>
EOF

mkdir -p /var/ossec/logs/alerts
mkdir -p /var/ossec/queue/alerts
mkdir -p /var/ossec/queue/diff
mkdir -p /var/ossec/queue/rids
mkdir -p /var/ossec/stats
mkdir -p /var/ossec/var/run

chown -R ossec:ossec /var/ossec/logs
chown -R ossec:ossec /var/ossec/queue
chown -R ossec:ossec /var/ossec/stats
chown -R ossec:ossec /var/ossec/var
chown -R root:ossec /var/ossec/etc
chmod -R 550 /var/ossec/etc
chmod 440 /var/ossec/etc/ossec.conf

systemctl daemon-reload
systemctl enable wazuh-manager
systemctl start wazuh-manager

echo "Fixed Wazuh XML configuration. Status:"
sleep 3
systemctl status wazuh-manager --no-pager