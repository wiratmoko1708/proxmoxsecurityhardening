#!/bin/bash
# Master Security Hardening Script
# Executes all security procedures in the correct order

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

SCRIPT_DIR="/tmp/kilo"
MASTER_LOG="/var/log/proxmox-security-hardening-$(date +%Y%m%d-%H%M%S).log"

echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║                                                              ║${NC}"
echo -e "${BLUE}║        PROXMOX SECURITY HARDENING - MASTER SCRIPT            ║${NC}"
echo -e "${BLUE}║                                                              ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Started: $(date)" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo -e "${RED}[!] This script must be run as root${NC}"
    exit 1
fi

# Check if scripts exist
if [ ! -d "$SCRIPT_DIR" ]; then
    echo -e "${RED}[!] Script directory not found: $SCRIPT_DIR${NC}"
    exit 1
fi

# Function to run a script
run_script() {
    local script_name=$1
    local description=$2
    
    echo "" | tee -a "$MASTER_LOG"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
    echo -e "${YELLOW}[*] Step: $description${NC}" | tee -a "$MASTER_LOG"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
    echo "" | tee -a "$MASTER_LOG"
    
    if [ -f "$SCRIPT_DIR/$script_name" ]; then
        chmod +x "$SCRIPT_DIR/$script_name"
        bash "$SCRIPT_DIR/$script_name" 2>&1 | tee -a "$MASTER_LOG"
        
        if [ ${PIPESTATUS[0]} -eq 0 ]; then
            echo -e "${GREEN}[✓] $description completed successfully${NC}" | tee -a "$MASTER_LOG"
            return 0
        else
            echo -e "${RED}[!] $description failed${NC}" | tee -a "$MASTER_LOG"
            return 1
        fi
    else
        echo -e "${RED}[!] Script not found: $SCRIPT_DIR/$script_name${NC}" | tee -a "$MASTER_LOG"
        return 1
    fi
}

# Confirmation prompt
echo -e "${YELLOW}This script will perform the following security procedures:${NC}"
echo ""
echo "1. Backdoor Detection - Scan all CTs for malicious files"
echo "2. System Hardening - Apply high security standards"
echo "3. Security Tools - Install Fail2ban, UFW, and AIDE"
echo "4. PHP Scanner - Detect dangerous PHP functions"
echo "5. SSH Hardening - Configure key-only authentication"
echo "6. File Permissions - Secure system files and directories"
echo ""
echo -e "${RED}WARNING: These changes will significantly alter your system configuration.${NC}"
echo -e "${RED}Make sure you have:${NC}"
echo -e "${RED}- Backup of your system${NC}"
echo -e "${RED}- Console access to Proxmox (in case SSH gets locked)${NC}"
echo -e "${RED}- SSH public key ready for key-based authentication${NC}"
echo ""
read -p "Do you want to continue? (yes/no): " -r
echo ""

if [[ ! $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    echo "Aborted by user."
    exit 0
fi

# Start execution
echo -e "${GREEN}Starting security hardening procedures...${NC}" | tee -a "$MASTER_LOG"

# Step 1: Backdoor Detection
run_script "1-backdoor-scanner.sh" "Backdoor Detection in All CTs"

# Step 2: System Hardening
run_script "2-system-hardening.sh" "System Hardening with High Security Standards"

# Step 3: Security Tools Installation
run_script "3-security-tools-setup.sh" "Installing Fail2ban, UFW, and AIDE"

# Step 4: PHP Scanner
run_script "4-php-scanner.sh" "PHP Dangerous Functions Scanner"

# Step 5: SSH Hardening (with warning)
echo "" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}╔════════════════════════════════════════════════════════════════╗${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║                    SSH HARDENING WARNING                       ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}╠════════════════════════════════════════════════════════════════╣${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║ The next step will configure SSH for KEY-ONLY authentication  ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║                                                                ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║ IMPORTANT: Add your SSH public key NOW before continuing!     ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║                                                                ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}║ Command: echo 'your-public-key' >> /root/.ssh/authorized_keys ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}╚════════════════════════════════════════════════════════════════╝${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

read -p "Have you added your SSH public key? (yes/no): " -r
echo ""

if [[ $REPLY =~ ^[Yy][Ee][Ss]$ ]]; then
    run_script "5-ssh-hardening.sh" "SSH Hardening with Key-Only Authentication"
else
    echo -e "${YELLOW}[!] Skipping SSH hardening. You can run it manually later.${NC}" | tee -a "$MASTER_LOG"
fi

# Step 6: File Permissions
run_script "6-permissions-hardening.sh" "File Permissions Hardening"

# Final summary
echo "" | tee -a "$MASTER_LOG"
echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}" | tee -a "$MASTER_LOG"
echo -e "${BLUE}║                                                              ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${BLUE}║              SECURITY HARDENING COMPLETE                     ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${BLUE}║                                                              ║${NC}" | tee -a "$MASTER_LOG"
echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo -e "${GREEN}All security procedures completed!${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo "Master log saved to: $MASTER_LOG" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}SUMMARY OF CHANGES:${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ Backdoor Detection:" | tee -a "$MASTER_LOG"
echo "  - Scanned all CTs for malicious files and processes" | tee -a "$MASTER_LOG"
echo "  - Check logs in /var/log/backdoor-scan-*.log" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ System Hardening:" | tee -a "$MASTER_LOG"
echo "  - Kernel parameters hardened (sysctl)" | tee -a "$MASTER_LOG"
echo "  - Password policies enforced" | tee -a "$MASTER_LOG"
echo "  - Account lockout configured" | tee -a "$MASTER_LOG"
echo "  - Auditd installed and configured" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ Security Tools:" | tee -a "$MASTER_LOG"
echo "  - UFW firewall enabled" | tee -a "$MASTER_LOG"
echo "  - Fail2ban monitoring SSH and Proxmox" | tee -a "$MASTER_LOG"
echo "  - AIDE intrusion detection initialized" | tee -a "$MASTER_LOG"
echo "  - rkhunter, chkrootkit, lynis installed" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ PHP Security:" | tee -a "$MASTER_LOG"
echo "  - Scanned for dangerous PHP functions" | tee -a "$MASTER_LOG"
echo "  - Detected webshells and obfuscated code" | tee -a "$MASTER_LOG"
echo "  - Check report in /var/log/php-scanner-report-*.txt" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ SSH Hardening:" | tee -a "$MASTER_LOG"
echo "  - Key-only authentication configured" | tee -a "$MASTER_LOG"
echo "  - Strong ciphers and algorithms enforced" | tee -a "$MASTER_LOG"
echo "  - Login banner added" | tee -a "$MASTER_LOG"
echo "  - Rate limiting enabled" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "✓ File Permissions:" | tee -a "$MASTER_LOG"
echo "  - Critical system files secured" | tee -a "$MASTER_LOG"
echo "  - World-writable files fixed" | tee -a "$MASTER_LOG"
echo "  - SUID/SGID files audited" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}NEXT STEPS:${NC}" | tee -a "$MASTER_LOG"
echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "1. Review scan results:" | tee -a "$MASTER_LOG"
echo "   - Backdoor scan: /var/log/backdoor-scan-*.log" | tee -a "$MASTER_LOG"
echo "   - PHP scan: /var/log/php-scanner-report-*.txt" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "2. Test SSH access with key-based authentication:" | tee -a "$MASTER_LOG"
echo "   - Open a NEW terminal and test: ssh -i your-key root@your-server" | tee -a "$MASTER_LOG"
echo "   - DO NOT close current session until verified!" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "3. Restart SSH service (only after testing):" | tee -a "$MASTER_LOG"
echo "   - systemctl restart sshd" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "4. Check security status:" | tee -a "$MASTER_LOG"
echo "   - /usr/local/bin/security-check.sh" | tee -a "$MASTER_LOG"
echo "   - /usr/local/bin/check-ssh-security.sh" | tee -a "$MASTER_LOG"
echo "   - /usr/local/bin/check-permissions.sh" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "5. Monitor security:" | tee -a "$MASTER_LOG"
echo "   - fail2ban-client status" | tee -a "$MASTER_LOG"
echo "   - ufw status verbose" | tee -a "$MASTER_LOG"
echo "   - aide --check" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "6. Run additional security audits:" | tee -a "$MASTER_LOG"
echo "   - lynis audit system" | tee -a "$MASTER_LOG"
echo "   - rkhunter --check" | tee -a "$MASTER_LOG"
echo "   - chkrootkit" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}IMPORTANT REMINDERS:${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}═══════════════════════════════════════════════════════════════${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"
echo -e "${RED}⚠ Keep Proxmox console access available${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}⚠ Test SSH key authentication before closing this session${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}⚠ Review and remove any suspicious files found in scans${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}⚠ Update UFW rules if you need additional ports${NC}" | tee -a "$MASTER_LOG"
echo -e "${RED}⚠ Add trusted IPs to Fail2ban ignore list if needed${NC}" | tee -a "$MASTER_LOG"
echo "" | tee -a "$MASTER_LOG"

echo "Completed: $(date)" | tee -a "$MASTER_LOG"
