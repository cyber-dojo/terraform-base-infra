#!/bin/bash

# Download Monit binary
curl https://mmonit.com/monit/dist/binary/${MONIT_VERSION}/monit-${MONIT_VERSION}-linux-x64.tar.gz -o monit-${MONIT_VERSION}-linux-x64.tar.gz
tar zxvf monit-${MONIT_VERSION}-linux-x64.tar.gz
mv monit-${MONIT_VERSION}/bin/monit /usr/local/bin/

# Set up Monit configuration
cat > /etc/monitrc << EOF
set daemon  30             # check services at 30 seconds intervals
set log syslog
set httpd port 2812 and
    use address localhost  # only accept connection from localhost (drop if you use M/Monit)
    allow localhost        # allow localhost to connect to the server and
    allow admin:monit      # require user 'admin' with password 'monit'
include /etc/monit/config/*
EOF

chown root:root /etc/monitrc
chmod 0700 /etc/monitrc

# Set up Monit service
cat > /lib/systemd/system/monit.service << EOF
 [Unit]
 Description=Pro-active monitoring utility for unix systems
 After=network-online.target
 Documentation=man:monit(1) https://mmonit.com/wiki/Monit/HowTo 

 [Service]
 Type=simple
 KillMode=process
 ExecStart=/usr/local/bin/monit -I
 ExecStop=/usr/local/bin/monit quit
 ExecReload=/usr/local/bin/monit reload
 Restart = on-abnormal
 StandardOutput=null

 [Install]
 WantedBy=multi-user.target
EOF

# Download slack-notifier bin
curl -L https://github.com/cloudposse/slack-notifier/releases/download/${SLACK_NOTIFIER_VERSION}/slack-notifier_linux_amd64 -o slack-notifier
chmod +x ./slack-notifier
mv ./slack-notifier /bin/

# Set up script to send alerts to Slack
mkdir -p /etc/monit/alerts

cat > /etc/monit/alerts/send-notification.sh << 'EOF'
#!/bin/sh
set -x

slack-notifier \
    -webhook_url '${SLACK_WEBHOOK_URL}' \
    -user_name 'monit' \
    -icon_emoji ':octagonal_sign:' \
    -fallback 'Monit Alert!' \
    -color 'danger' \
    -title '${SLACK_MESSAGE_TITLE}' \
    -text "$${1}"
EOF
chmod +x /etc/monit/alerts/send-notification.sh

# Add alerts configuration
mkdir -p /etc/monit/config
cat > /etc/monit/config/monit-config << 'EOF'
check filesystem "root" with path /dev/nvme0n1p1
    if SPACE usage > 80% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'Root disk utilisation is above 80%'"

check filesystem "data" with path /dev/nvme1n1
    if SPACE usage > 80% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'Cyber-dojo data disk utilisation is above 80%'"

check system $HOST
    if memory usage > 90% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'RAM usage is above 90%'"
    if swap usage > 20% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'swap usage is above 20%'"
    if cpu usage (user) > 90% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'CPU usage (user) is above 90%'"
    if cpu usage (system) > 20% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'CPU usage (system) is above 20%'"
    if cpu usage (wait) > 20% for 10 cycles then exec "/etc/monit/alerts/send-notification.sh 'CPU usage (wait) is above 20%'"
EOF

systemctl enable monit.service
systemctl start monit.service
