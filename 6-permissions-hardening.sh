#!/bin/bash
# File Permissions Hardening Script
# Secures critical system files and directories

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/permissions-hardening-$(date +%Y%m%d-%H%M%S).log"

echo "=== File Permissions Hardening ===" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Function to set permissions safely
set_permissions() {
    local path=$1
    local perms=$2
    local owner=$3
    
    if [ -e "$path" ]; then
        chmod "$perms" "$path" 2>/dev/null || true
        chown "$owner" "$path" 2>/dev/null || true
        echo "[+] Set $path: $perms $owner" | tee -a "$LOG_FILE"
    fi
}

# 1. Secure system configuration files
echo -e "${YELLOW}[*] Securing system configuration files...${NC}" | tee -a "$LOG_FILE"

set_permissions /etc/passwd 0644 root:root
set_permissions /etc/shadow 0000 root:root
set_permissions /etc/group 0644 root:root
set_permissions /etc/gshadow 0000 root:root
set_permissions /etc/passwd- 0600 root:root
set_permissions /etc/shadow- 0000 root:root
set_permissions /etc/group- 0600 root:root
set_permissions /etc/gshadow- 0000 root:root

echo -e "${GREEN}[✓] System files secured${NC}" | tee -a "$LOG_FILE"

# 2. Secure SSH configuration
echo -e "${YELLOW}[*] Securing SSH configuration...${NC}" | tee -a "$LOG_FILE"

set_permissions /etc/ssh 0755 root:root
set_permissions /etc/ssh/sshd_config 0600 root:root
set_permissions /etc/ssh/ssh_config 0644 root:root

# Secure SSH host keys
for key in /etc/ssh/ssh_host_*_key; do
    if [ -f "$key" ]; then
        chmod 0600 "$key"
        chown root:root "$key"
        echo "[+] Secured: $key" | tee -a "$LOG_FILE"
    fi
done

for key in /etc/ssh/ssh_host_*_key.pub; do
    if [ -f "$key" ]; then
        chmod 0644 "$key"
        chown root:root "$key"
        echo "[+] Secured: $key" | tee -a "$LOG_FILE"
    fi
done

echo -e "${GREEN}[✓] SSH configuration secured${NC}" | tee -a "$LOG_FILE"

# 3. Secure boot files
echo -e "${YELLOW}[*] Securing boot files...${NC}" | tee -a "$LOG_FILE"

set_permissions /boot 0755 root:root
set_permissions /boot/grub/grub.cfg 0600 root:root
set_permissions /etc/grub.d 0755 root:root

echo -e "${GREEN}[✓] Boot files secured${NC}" | tee -a "$LOG_FILE"

# 4. Secure cron
echo -e "${YELLOW}[*] Securing cron...${NC}" | tee -a "$LOG_FILE"

set_permissions /etc/crontab 0600 root:root
set_permissions /etc/cron.hourly 0700 root:root
set_permissions /etc/cron.daily 0700 root:root
set_permissions /etc/cron.weekly 0700 root:root
set_permissions /etc/cron.monthly 0700 root:root
set_permissions /etc/cron.d 0700 root:root
set_permissions /var/spool/cron 0700 root:root
set_permissions /var/spool/cron/crontabs 0700 root:root

echo -e "${GREEN}[✓] Cron secured${NC}" | tee -a "$LOG_FILE"

# 5. Secure log files
echo -e "${YELLOW}[*] Securing log files...${NC}" | tee -a "$LOG_FILE"

set_permissions /var/log 0755 root:root
set_permissions /var/log/auth.log 0640 root:adm
set_permissions /var/log/syslog 0640 root:adm
set_permissions /var/log/daemon.log 0640 root:adm
set_permissions /var/log/kern.log 0640 root:adm

# Secure all log files
find /var/log -type f -exec chmod 0640 {} \; 2>/dev/null || true
find /var/log -type d -exec chmod 0755 {} \; 2>/dev/null || true

echo -e "${GREEN}[✓] Log files secured${NC}" | tee -a "$LOG_FILE"

# 6. Secure home directories
echo -e "${YELLOW}[*] Securing home directories...${NC}" | tee -a "$LOG_FILE"

# Root home
set_permissions /root 0700 root:root
set_permissions /root/.ssh 0700 root:root
set_permissions /root/.ssh/authorized_keys 0600 root:root

# User home directories
for homedir in /home/*; do
    if [ -d "$homedir" ]; then
        username=$(basename "$homedir")
        chmod 0750 "$homedir" 2>/dev/null || true
        chown "$username:$username" "$homedir" 2>/dev/null || true
        echo "[+] Secured: $homedir" | tee -a "$LOG_FILE"
        
        # Secure .ssh directories
        if [ -d "$homedir/.ssh" ]; then
            chmod 0700 "$homedir/.ssh" 2>/dev/null || true
            chown -R "$username:$username" "$homedir/.ssh" 2>/dev/null || true
            
            if [ -f "$homedir/.ssh/authorized_keys" ]; then
                chmod 0600 "$homedir/.ssh/authorized_keys" 2>/dev/null || true
                chown "$username:$username" "$homedir/.ssh/authorized_keys" 2>/dev/null || true
            fi
        fi
    fi
done

echo -e "${GREEN}[✓] Home directories secured${NC}" | tee -a "$LOG_FILE"

# 7. Find and fix world-writable files
echo -e "${YELLOW}[*] Finding and fixing world-writable files...${NC}" | tee -a "$LOG_FILE"

echo "[+] Scanning for world-writable files (excluding /proc, /sys, /dev)..." | tee -a "$LOG_FILE"

# Find world-writable files (excluding system directories)
find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | while read -r file; do
    echo -e "${YELLOW}[!] World-writable file found: $file${NC}" | tee -a "$LOG_FILE"
    chmod o-w "$file" 2>/dev/null || true
    echo "[+] Removed world-write permission: $file" | tee -a "$LOG_FILE"
done

echo -e "${GREEN}[✓] World-writable files fixed${NC}" | tee -a "$LOG_FILE"

# 8. Find and fix world-writable directories
echo -e "${YELLOW}[*] Finding world-writable directories...${NC}" | tee -a "$LOG_FILE"

find / -xdev -type d -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp" ! -path "/var/tmp" ! -path "/dev/shm" 2>/dev/null | while read -r dir; do
    echo -e "${YELLOW}[!] World-writable directory found: $dir${NC}" | tee -a "$LOG_FILE"
    # Check if sticky bit is set
    if [ ! -k "$dir" ]; then
        chmod +t "$dir" 2>/dev/null || true
        echo "[+] Added sticky bit: $dir" | tee -a "$LOG_FILE"
    fi
done

echo -e "${GREEN}[✓] World-writable directories secured${NC}" | tee -a "$LOG_FILE"

# 9. Secure temporary directories
echo -e "${YELLOW}[*] Securing temporary directories...${NC}" | tee -a "$LOG_FILE"

chmod 1777 /tmp 2>/dev/null || true
chmod 1777 /var/tmp 2>/dev/null || true
chmod 1777 /dev/shm 2>/dev/null || true

echo -e "${GREEN}[✓] Temporary directories secured${NC}" | tee -a "$LOG_FILE"

# 10. Find files with no owner
echo -e "${YELLOW}[*] Finding files with no owner...${NC}" | tee -a "$LOG_FILE"

find / -xdev -nouser -o -nogroup 2>/dev/null | tee -a "$LOG_FILE" || true

echo -e "${GREEN}[✓] Orphaned files check complete${NC}" | tee -a "$LOG_FILE"

# 11. Secure Proxmox specific files
echo -e "${YELLOW}[*] Securing Proxmox configuration...${NC}" | tee -a "$LOG_FILE"

if [ -d /etc/pve ]; then
    set_permissions /etc/pve 0750 root:www-data
    find /etc/pve -type f -exec chmod 0640 {} \; 2>/dev/null || true
    find /etc/pve -type d -exec chmod 0750 {} \; 2>/dev/null || true
    echo "[+] Secured /etc/pve" | tee -a "$LOG_FILE"
fi

if [ -d /var/lib/vz ]; then
    set_permissions /var/lib/vz 0755 root:root
    echo "[+] Secured /var/lib/vz" | tee -a "$LOG_FILE"
fi

echo -e "${GREEN}[✓] Proxmox files secured${NC}" | tee -a "$LOG_FILE"

# 12. Secure web directories (if they exist)
echo -e "${YELLOW}[*] Securing web directories...${NC}" | tee -a "$LOG_FILE"

for webdir in /var/www /usr/share/nginx/html; do
    if [ -d "$webdir" ]; then
        find "$webdir" -type d -exec chmod 0755 {} \; 2>/dev/null || true
        find "$webdir" -type f -exec chmod 0644 {} \; 2>/dev/null || true
        echo "[+] Secured: $webdir" | tee -a "$LOG_FILE"
    fi
done

echo -e "${GREEN}[✓] Web directories secured${NC}" | tee -a "$LOG_FILE"

# 13. Remove dangerous SUID/SGID bits from unnecessary files
echo -e "${YELLOW}[*] Auditing SUID/SGID files...${NC}" | tee -a "$LOG_FILE"

# List of files that should keep SUID/SGID
ALLOWED_SUID=(
    "/usr/bin/sudo"
    "/usr/bin/su"
    "/usr/bin/passwd"
    "/usr/bin/chsh"
    "/usr/bin/chfn"
    "/usr/bin/gpasswd"
    "/usr/bin/newgrp"
    "/usr/bin/mount"
    "/usr/bin/umount"
    "/usr/bin/ping"
    "/usr/bin/ping6"
    "/usr/lib/openssh/ssh-keysign"
    "/usr/lib/dbus-1.0/dbus-daemon-launch-helper"
)

echo "[+] Finding SUID/SGID files..." | tee -a "$LOG_FILE"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | while read -r file; do
    # Check if file is in allowed list
    allowed=false
    for allowed_file in "${ALLOWED_SUID[@]}"; do
        if [ "$file" = "$allowed_file" ]; then
            allowed=true
            break
        fi
    done
    
    if [ "$allowed" = false ]; then
        echo -e "${YELLOW}[!] Suspicious SUID/SGID file: $file${NC}" | tee -a "$LOG_FILE"
        echo "[i] Review and remove SUID/SGID if not needed: chmod u-s,g-s $file" | tee -a "$LOG_FILE"
    fi
done

echo -e "${GREEN}[✓] SUID/SGID audit complete${NC}" | tee -a "$LOG_FILE"

# 14. Create permission check script
echo -e "${YELLOW}[*] Creating permission check script...${NC}" | tee -a "$LOG_FILE"

cat > /usr/local/bin/check-permissions.sh << 'EOF'
#!/bin/bash
# Permission Check Script

echo "=== System Permissions Check ==="
echo ""

echo "Critical System Files:"
ls -l /etc/passwd /etc/shadow /etc/group /etc/gshadow 2>/dev/null
echo ""

echo "SSH Configuration:"
ls -l /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key 2>/dev/null
echo ""

echo "Root Home:"
ls -ld /root /root/.ssh 2>/dev/null
ls -l /root/.ssh/authorized_keys 2>/dev/null
echo ""

echo "World-Writable Files (excluding /tmp, /proc, /sys, /dev):"
find / -xdev -type f -perm -0002 ! -path "/proc/*" ! -path "/sys/*" ! -path "/dev/*" ! -path "/run/*" ! -path "/tmp/*" ! -path "/var/tmp/*" 2>/dev/null | head -20
echo ""

echo "SUID/SGID Files:"
find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null
echo ""

echo "Files with no owner:"
find / -xdev \( -nouser -o -nogroup \) 2>/dev/null | head -20
EOF

chmod +x /usr/local/bin/check-permissions.sh

echo -e "${GREEN}[✓] Permission check script created: /usr/local/bin/check-permissions.sh${NC}" | tee -a "$LOG_FILE"

echo -e "${GREEN}=== File Permissions Hardening Complete ===${NC}" | tee -a "$LOG_FILE"
echo "Log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Summary:" | tee -a "$LOG_FILE"
echo "- System configuration files secured" | tee -a "$LOG_FILE"
echo "- SSH files and keys secured" | tee -a "$LOG_FILE"
echo "- Home directories secured" | tee -a "$LOG_FILE"
echo "- World-writable files fixed" | tee -a "$LOG_FILE"
echo "- SUID/SGID files audited" | tee -a "$LOG_FILE"
echo "- Permission check script: /usr/local/bin/check-permissions.sh" | tee -a "$LOG_FILE"
