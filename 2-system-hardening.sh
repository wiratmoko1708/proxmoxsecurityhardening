#!/bin/bash
# System Hardening Script for Proxmox
# Implements high security standards

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/system-hardening-$(date +%Y%m%d-%H%M%S).log"

echo "=== Proxmox System Hardening ===" | tee -a "$LOG_FILE"
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

# 1. Kernel hardening via sysctl
echo -e "${YELLOW}[*] Applying kernel hardening...${NC}" | tee -a "$LOG_FILE"
backup_file /etc/sysctl.conf

cat >> /etc/sysctl.conf << 'EOF'

# === Security Hardening ===
# IP Forwarding (keep enabled for Proxmox)
net.ipv4.ip_forward = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1

# Prevent IP spoofing
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0

# Disable ICMP redirect sending
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0

# Log Martians (packets with impossible addresses)
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping requests
net.ipv4.icmp_echo_ignore_all = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1

# Ignore bogus ICMP error responses
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies (DDoS protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_max_syn_backlog = 4096

# Disable IPv6 router advertisements
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0

# Increase system file descriptor limit
fs.file-max = 65535

# Protect against time-wait assassination
net.ipv4.tcp_rfc1337 = 1

# Kernel pointer protection
kernel.kptr_restrict = 2

# Restrict dmesg access
kernel.dmesg_restrict = 1

# Restrict kernel logs
kernel.printk = 3 3 3 3

# Protect against ptrace
kernel.yama.ptrace_scope = 1

# Disable core dumps
kernel.core_uses_pid = 1
fs.suid_dumpable = 0

# Address Space Layout Randomization
kernel.randomize_va_space = 2
EOF

sysctl -p | tee -a "$LOG_FILE"
echo -e "${GREEN}[✓] Kernel hardening applied${NC}" | tee -a "$LOG_FILE"

# 2. Disable unnecessary services
echo -e "${YELLOW}[*] Disabling unnecessary services...${NC}" | tee -a "$LOG_FILE"
for service in avahi-daemon cups bluetooth; do
    if systemctl is-enabled "$service" 2>/dev/null | grep -q enabled; then
        systemctl disable "$service" 2>/dev/null || true
        systemctl stop "$service" 2>/dev/null || true
        echo "[+] Disabled: $service" | tee -a "$LOG_FILE"
    fi
done

# 3. Set password policies
echo -e "${YELLOW}[*] Configuring password policies...${NC}" | tee -a "$LOG_FILE"
backup_file /etc/login.defs

sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_MIN_LEN.*/PASS_MIN_LEN    14/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

echo -e "${GREEN}[✓] Password policies configured${NC}" | tee -a "$LOG_FILE"

# 4. Configure PAM for strong passwords
echo -e "${YELLOW}[*] Configuring PAM for strong passwords...${NC}" | tee -a "$LOG_FILE"
apt-get update && apt-get install -y libpam-pwquality

backup_file /etc/pam.d/common-password

# Add password quality requirements
if ! grep -q "pam_pwquality.so" /etc/pam.d/common-password; then
    sed -i '/pam_unix.so/i password requisite pam_pwquality.so retry=3 minlen=14 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=3 reject_username enforce_for_root' /etc/pam.d/common-password
fi

echo -e "${GREEN}[✓] PAM configured${NC}" | tee -a "$LOG_FILE"

# 5. Set account lockout policy
echo -e "${YELLOW}[*] Configuring account lockout...${NC}" | tee -a "$LOG_FILE"
backup_file /etc/pam.d/common-auth

if ! grep -q "pam_faillock.so" /etc/pam.d/common-auth; then
    cat > /etc/pam.d/common-auth << 'EOF'
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth [success=1 default=bad] pam_unix.so
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800
auth sufficient pam_faillock.so authsucc audit deny=5 unlock_time=1800
auth requisite pam_deny.so
auth required pam_permit.so
EOF
fi

echo -e "${GREEN}[✓] Account lockout configured${NC}" | tee -a "$LOG_FILE"

# 6. Secure shared memory
echo -e "${YELLOW}[*] Securing shared memory...${NC}" | tee -a "$LOG_FILE"
if ! grep -q "/run/shm" /etc/fstab; then
    echo "tmpfs /run/shm tmpfs defaults,noexec,nodev,nosuid 0 0" >> /etc/fstab
fi

echo -e "${GREEN}[✓] Shared memory secured${NC}" | tee -a "$LOG_FILE"

# 7. Disable USB storage
echo -e "${YELLOW}[*] Disabling USB storage...${NC}" | tee -a "$LOG_FILE"
echo "install usb-storage /bin/true" > /etc/modprobe.d/disable-usb-storage.conf

echo -e "${GREEN}[✓] USB storage disabled${NC}" | tee -a "$LOG_FILE"

# 8. Configure audit logging
echo -e "${YELLOW}[*] Installing and configuring auditd...${NC}" | tee -a "$LOG_FILE"
apt-get install -y auditd audispd-plugins

cat > /etc/audit/rules.d/hardening.rules << 'EOF'
# Delete all existing rules
-D

# Buffer Size
-b 8192

# Failure Mode (0=silent 1=printk 2=panic)
-f 1

# Audit system calls
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change

# Audit user/group modifications
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity

# Audit network configuration
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/network -p wa -k system-locale

# Audit login/logout events
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins

# Audit session initiation
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins

# Audit permission modifications
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod

# Audit sudo usage
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope

# Make configuration immutable
-e 2
EOF

systemctl enable auditd
systemctl restart auditd

echo -e "${GREEN}[✓] Auditd configured${NC}" | tee -a "$LOG_FILE"

echo -e "${GREEN}=== System Hardening Complete ===${NC}" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
