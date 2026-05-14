#!/bin/bash
# Install and Configure Fail2ban, UFW, and AIDE
# Comprehensive security monitoring and intrusion detection

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/security-tools-setup-$(date +%Y%m%d-%H%M%S).log"

echo "=== Security Tools Installation ===" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Backup function
backup_file() {
    local file=$1
    if [ -f "$file" ]; then
        cp "$file" "${file}.backup-$(date +%Y%m%d-%H%M%S)"
        echo "[+] Backed up: $file" | tee -a "$LOG_FILE"
    fi
}

# ============================================
# 1. INSTALL AND CONFIGURE UFW (Firewall)
# ============================================
echo -e "${YELLOW}[*] Installing and configuring UFW...${NC}" | tee -a "$LOG_FILE"

apt-get update
apt-get install -y ufw

# Reset UFW to default
ufw --force reset

# Set default policies
ufw default deny incoming
ufw default allow outgoing
ufw default deny routed

# Allow SSH (change port if needed)
ufw allow 22/tcp comment 'SSH'

# Allow Proxmox Web Interface
ufw allow 8006/tcp comment 'Proxmox Web UI'

# Allow Proxmox cluster communication
ufw allow 5405:5412/udp comment 'Corosync'
ufw allow 3128/tcp comment 'Proxmox API'

# Allow VNC for VM consoles (if needed)
ufw allow 5900:5999/tcp comment 'VNC'

# Rate limiting for SSH
ufw limit 22/tcp

# Enable logging
ufw logging on

# Enable UFW
echo "y" | ufw enable

ufw status verbose | tee -a "$LOG_FILE"

echo -e "${GREEN}[✓] UFW configured and enabled${NC}" | tee -a "$LOG_FILE"

# ============================================
# 2. INSTALL AND CONFIGURE FAIL2BAN
# ============================================
echo -e "${YELLOW}[*] Installing and configuring Fail2ban...${NC}" | tee -a "$LOG_FILE"

apt-get install -y fail2ban

# Create local configuration
backup_file /etc/fail2ban/jail.local

cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
# Ban settings
bantime = 3600
findtime = 600
maxretry = 5
destemail = root@localhost
sendername = Fail2Ban
action = %(action_mwl)s

# Ignore local IPs (add your trusted IPs here)
ignoreip = 127.0.0.1/8 ::1

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200

[sshd-ddos]
enabled = true
port = ssh
filter = sshd-ddos
logpath = /var/log/auth.log
maxretry = 2
bantime = 7200

[proxmox]
enabled = true
port = https,http,8006
filter = proxmox
logpath = /var/log/daemon.log
maxretry = 3
bantime = 3600

[recidive]
enabled = true
filter = recidive
logpath = /var/log/fail2ban.log
action = %(action_mwl)s
bantime = 604800
findtime = 86400
maxretry = 5
EOF

# Create Proxmox filter
cat > /etc/fail2ban/filter.d/proxmox.conf << 'EOF'
[Definition]
failregex = pvedaemon\[.*authentication failure; rhost=<HOST> user=.* msg=.*
ignoreregex =
EOF

# Enable and start fail2ban
systemctl enable fail2ban
systemctl restart fail2ban

# Wait for fail2ban to start
sleep 3

fail2ban-client status | tee -a "$LOG_FILE"

echo -e "${GREEN}[✓] Fail2ban configured and running${NC}" | tee -a "$LOG_FILE"

# ============================================
# 3. INSTALL AND CONFIGURE AIDE
# ============================================
echo -e "${YELLOW}[*] Installing and configuring AIDE (Advanced Intrusion Detection)...${NC}" | tee -a "$LOG_FILE"

apt-get install -y aide aide-common

# Configure AIDE
backup_file /etc/aide/aide.conf

cat > /etc/aide/aide.conf << 'EOF'
# AIDE Configuration

database=file:/var/lib/aide/aide.db
database_out=file:/var/lib/aide/aide.db.new
gzip_dbout=yes

# Report settings
report_url=file:/var/log/aide/aide.log
report_url=stdout

# Custom rules
Binlib = p+i+n+u+g+s+b+m+c+md5+sha256
ConfFiles = p+i+n+u+g+s+b+m+c+md5+sha256
Logs = p+i+n+u+g+S
Devices = p+i+n+u+g+s+b+c+md5+sha256
Databases = p+n+u+g
StaticDir = p+i+n+u+g
ManPages = p+i+n+u+g+s+b+m+c+md5+sha256

# Directories to monitor
/boot Binlib
/bin Binlib
/sbin Binlib
/usr/bin Binlib
/usr/sbin Binlib
/lib Binlib
/lib64 Binlib
/usr/lib Binlib
/usr/lib64 Binlib

# Configuration files
/etc ConfFiles
!/etc/mtab

# System files
/root ConfFiles

# Proxmox specific
/etc/pve ConfFiles
/var/lib/pve-cluster ConfFiles

# Logs (only metadata)
/var/log Logs

# Exclude frequently changing files
!/var/log/.*
!/var/cache/.*
!/var/tmp/.*
!/tmp/.*
!/proc/.*
!/sys/.*
!/dev/.*
!/run/.*
!/var/lib/aide/.*
!/var/lib/docker/.*
!/var/lib/lxc/.*
!/var/lib/vz/.*
EOF

# Create log directory
mkdir -p /var/log/aide

# Initialize AIDE database (this may take several minutes)
echo -e "${YELLOW}[*] Initializing AIDE database (this may take 5-10 minutes)...${NC}" | tee -a "$LOG_FILE"
aideinit

# Copy new database to active database
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db

# Create daily check cron job
cat > /etc/cron.daily/aide-check << 'EOF'
#!/bin/bash
# Daily AIDE integrity check

/usr/bin/aide --check > /var/log/aide/aide-check-$(date +\%Y\%m\%d).log 2>&1

# If changes detected, send alert
if [ $? -ne 0 ]; then
    echo "AIDE detected file system changes on $(hostname)" | mail -s "AIDE Alert: File Changes Detected" root
fi
EOF

chmod +x /etc/cron.daily/aide-check

echo -e "${GREEN}[✓] AIDE installed and configured${NC}" | tee -a "$LOG_FILE"

# ============================================
# 4. ADDITIONAL SECURITY TOOLS
# ============================================
echo -e "${YELLOW}[*] Installing additional security tools...${NC}" | tee -a "$LOG_FILE"

# Install rkhunter (rootkit hunter)
apt-get install -y rkhunter

# Update rkhunter database
rkhunter --update
rkhunter --propupd

# Install chkrootkit
apt-get install -y chkrootkit

# Install lynis (security auditing)
apt-get install -y lynis

echo -e "${GREEN}[✓] Additional security tools installed${NC}" | tee -a "$LOG_FILE"

# ============================================
# 5. CREATE MONITORING SCRIPT
# ============================================
echo -e "${YELLOW}[*] Creating security monitoring script...${NC}" | tee -a "$LOG_FILE"

cat > /usr/local/bin/security-check.sh << 'EOF'
#!/bin/bash
# Daily security check script

REPORT_FILE="/var/log/security-check-$(date +%Y%m%d).log"

echo "=== Daily Security Check ===" > "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

echo "=== UFW Status ===" >> "$REPORT_FILE"
ufw status verbose >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

echo "=== Fail2ban Status ===" >> "$REPORT_FILE"
fail2ban-client status >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

echo "=== Active Bans ===" >> "$REPORT_FILE"
for jail in $(fail2ban-client status | grep "Jail list" | sed "s/.*://g" | sed "s/,//g"); do
    echo "Jail: $jail" >> "$REPORT_FILE"
    fail2ban-client status "$jail" >> "$REPORT_FILE" 2>&1
done
echo "" >> "$REPORT_FILE"

echo "=== Listening Ports ===" >> "$REPORT_FILE"
ss -tulpn >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

echo "=== Recent Failed Login Attempts ===" >> "$REPORT_FILE"
grep "Failed password" /var/log/auth.log | tail -20 >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

echo "=== Recent Successful Logins ===" >> "$REPORT_FILE"
last -20 >> "$REPORT_FILE" 2>&1
echo "" >> "$REPORT_FILE"

echo "Security check completed. Report saved to: $REPORT_FILE"
EOF

chmod +x /usr/local/bin/security-check.sh

# Add to daily cron
cat > /etc/cron.daily/security-check << 'EOF'
#!/bin/bash
/usr/local/bin/security-check.sh
EOF

chmod +x /etc/cron.daily/security-check

echo -e "${GREEN}[✓] Security monitoring script created${NC}" | tee -a "$LOG_FILE"

echo -e "${GREEN}=== Security Tools Setup Complete ===${NC}" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Summary:" | tee -a "$LOG_FILE"
echo "- UFW: Enabled with Proxmox-specific rules" | tee -a "$LOG_FILE"
echo "- Fail2ban: Monitoring SSH and Proxmox" | tee -a "$LOG_FILE"
echo "- AIDE: Database initialized, daily checks scheduled" | tee -a "$LOG_FILE"
echo "- Additional tools: rkhunter, chkrootkit, lynis installed" | tee -a "$LOG_FILE"
echo "- Daily security checks: /usr/local/bin/security-check.sh" | tee -a "$LOG_FILE"
