#!/bin/bash
# Backdoor Detection Script for Proxmox CTs
# Scans all containers for common backdoors, malicious files, and suspicious activities

set -euo pipefail

RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
NC='\033[0m' # No Color

LOG_FILE="/var/log/backdoor-scan-$(date +%Y%m%d-%H%M%S).log"

echo "=== Proxmox CT Backdoor Scanner ===" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Function to scan a single CT
scan_ct() {
    local ctid=$1
    local ct_name=$2
    
    echo -e "${YELLOW}[*] Scanning CT $ctid ($ct_name)...${NC}" | tee -a "$LOG_FILE"
    
    # Check if CT is running
    if ! pct status "$ctid" | grep -q "running"; then
        echo -e "${YELLOW}[!] CT $ctid is not running, skipping...${NC}" | tee -a "$LOG_FILE"
        return
    fi
    
    # 1. Check for suspicious processes
    echo "[+] Checking suspicious processes..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- ps aux | grep -E "(nc|netcat|ncat|/dev/tcp|/dev/udp|perl.*socket|python.*socket|ruby.*socket|php.*socket)" | grep -v grep >> "$LOG_FILE" 2>&1 || true
    
    # 2. Check for reverse shells
    echo "[+] Checking for reverse shell scripts..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- find /tmp /var/tmp /dev/shm /home -type f \( -name "*.sh" -o -name "*.py" -o -name "*.pl" -o -name "*.php" \) -exec grep -l "socket\|exec\|system\|passthru\|shell_exec\|base64_decode" {} \; 2>/dev/null >> "$LOG_FILE" || true
    
    # 3. Check for webshells in common web directories
    echo "[+] Checking for webshells..." | tee -a "$LOG_FILE"
    for webdir in /var/www /usr/share/nginx /opt/www /home/*/public_html; do
        if pct exec "$ctid" -- test -d "$webdir" 2>/dev/null; then
            pct exec "$ctid" -- find "$webdir" -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php3" -o -name "*.php4" -o -name "*.php5" \) -exec grep -l "eval\|base64_decode\|gzinflate\|str_rot13\|assert\|system\|passthru\|shell_exec\|exec\|popen\|proc_open" {} \; 2>/dev/null >> "$LOG_FILE" || true
        fi
    done
    
    # 4. Check for suspicious cron jobs
    echo "[+] Checking cron jobs..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- cat /etc/crontab 2>/dev/null >> "$LOG_FILE" || true
    pct exec "$ctid" -- ls -la /etc/cron.* 2>/dev/null >> "$LOG_FILE" || true
    pct exec "$ctid" -- crontab -l 2>/dev/null >> "$LOG_FILE" || true
    
    # 5. Check for suspicious systemd services
    echo "[+] Checking systemd services..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- systemctl list-units --type=service --state=running 2>/dev/null | grep -vE "(ssh|cron|systemd|dbus|rsyslog|networking)" >> "$LOG_FILE" || true
    
    # 6. Check for hidden files in suspicious locations
    echo "[+] Checking hidden files..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- find /tmp /var/tmp /dev/shm -name ".*" -type f 2>/dev/null >> "$LOG_FILE" || true
    
    # 7. Check for SUID/SGID files
    echo "[+] Checking SUID/SGID files..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- find / -type f \( -perm -4000 -o -perm -2000 \) -ls 2>/dev/null | grep -vE "(sudo|su|passwd|ping|mount|umount)" >> "$LOG_FILE" || true
    
    # 8. Check listening ports
    echo "[+] Checking listening ports..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- ss -tulpn 2>/dev/null >> "$LOG_FILE" || true
    
    # 9. Check for suspicious users
    echo "[+] Checking user accounts..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- awk -F: '$3 >= 1000 && $3 < 65534 {print $1":"$3":"$6":"$7}' /etc/passwd 2>/dev/null >> "$LOG_FILE" || true
    
    # 10. Check SSH authorized_keys
    echo "[+] Checking SSH authorized_keys..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- find /root /home -name "authorized_keys" -exec ls -la {} \; -exec cat {} \; 2>/dev/null >> "$LOG_FILE" || true
    
    # 11. Check for rootkits using basic checks
    echo "[+] Checking for rootkit indicators..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- ls -la /dev | grep -E "(tcp|udp|raw)" >> "$LOG_FILE" 2>&1 || true
    pct exec "$ctid" -- find /usr/bin /usr/sbin /bin /sbin -type f -mtime -7 2>/dev/null >> "$LOG_FILE" || true
    
    # 12. Check bash history for suspicious commands
    echo "[+] Checking bash history..." | tee -a "$LOG_FILE"
    pct exec "$ctid" -- find /root /home -name ".bash_history" -exec grep -H -E "(wget|curl|nc|netcat|chmod 777|base64|eval)" {} \; 2>/dev/null >> "$LOG_FILE" || true
    
    echo -e "${GREEN}[✓] CT $ctid scan completed${NC}" | tee -a "$LOG_FILE"
    echo "" | tee -a "$LOG_FILE"
}

# Get all CTs
echo "[*] Detecting all containers..." | tee -a "$LOG_FILE"
pct list | tail -n +2 | while read -r line; do
    ctid=$(echo "$line" | awk '{print $1}')
    ct_name=$(echo "$line" | awk '{print $3}')
    scan_ct "$ctid" "$ct_name"
done

echo -e "${GREEN}=== Scan Complete ===${NC}" | tee -a "$LOG_FILE"
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Review the log file for any suspicious findings." | tee -a "$LOG_FILE"
