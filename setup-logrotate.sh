#!/bin/bash

# Log file path
LOG_FILE="/var/log/ebpf-container-security.log"

# Logrotate config path
LOGROTATE_CONFIG="/etc/logrotate.d/ebpf-container-security"

# Create log file if it doesn't exist
if [ ! -f "$LOG_FILE" ]; then
    sudo touch "$LOG_FILE"
    sudo chmod 644 "$LOG_FILE"
    echo "✅ Created log file: $LOG_FILE"
fi

# Write logrotate configuration
sudo tee "$LOGROTATE_CONFIG" > /dev/null <<EOF
$LOG_FILE {
    daily
    rotate 7
    missingok
    compress
    delaycompress
    create 0644 root root
}
EOF

# Force logrotate to apply the new config
sudo logrotate --force "$LOGROTATE_CONFIG"

echo "✅ Log rotation configured at $LOGROTATE_CONFIG"
