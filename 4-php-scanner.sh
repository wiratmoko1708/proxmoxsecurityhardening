#!/bin/bash
# PHP Dangerous Functions Scanner
# Scans all CTs for PHP files with dangerous functions

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

LOG_FILE="/var/log/php-scanner-$(date +%Y%m%d-%H%M%S).log"
REPORT_FILE="/var/log/php-scanner-report-$(date +%Y%m%d-%H%M%S).txt"

echo "=== PHP Dangerous Functions Scanner ===" | tee -a "$LOG_FILE"
echo "Started: $(date)" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"

# Dangerous PHP functions to scan for
DANGEROUS_FUNCTIONS=(
    "eval"
    "exec"
    "system"
    "passthru"
    "shell_exec"
    "popen"
    "proc_open"
    "pcntl_exec"
    "assert"
    "create_function"
    "include"
    "require"
    "include_once"
    "require_once"
    "file_get_contents"
    "file_put_contents"
    "fopen"
    "readfile"
    "fread"
    "fwrite"
    "fputs"
    "curl_exec"
    "curl_multi_exec"
    "parse_ini_file"
    "show_source"
    "base64_decode"
    "gzinflate"
    "gzuncompress"
    "gzdecode"
    "str_rot13"
    "move_uploaded_file"
    "copy"
    "rename"
    "unlink"
    "rmdir"
    "mkdir"
    "chmod"
    "chown"
    "chgrp"
    "touch"
    "symlink"
    "link"
    "tempnam"
    "tmpfile"
    "parse_str"
    "extract"
    "putenv"
    "ini_set"
    "mail"
    "mb_send_mail"
    "dl"
    "set_time_limit"
    "ignore_user_abort"
    "highlight_file"
    "virtual"
    "posix_kill"
    "posix_mkfifo"
    "posix_setpgid"
    "posix_setsid"
    "posix_setuid"
    "proc_nice"
    "proc_terminate"
    "proc_close"
    "apache_child_terminate"
    "apache_setenv"
    "define_syslog_variables"
    "escapeshellarg"
    "escapeshellcmd"
    "ini_alter"
    "ini_restore"
    "inject_code"
    "syslog"
    "openlog"
    "stream_socket_server"
    "stream_socket_client"
    "socket_create"
    "socket_bind"
    "socket_listen"
    "socket_accept"
)

# Webshell indicators
WEBSHELL_PATTERNS=(
    "c99"
    "r57"
    "b374k"
    "wso"
    "shell"
    "backdoor"
    "FilesMan"
    "c100"
    "r00t"
    "Fx29Sh"
    "indoxploit"
    "adminer"
    "phpMyAdmin"
    "webadmin"
)

# Function to scan a single CT
scan_ct_php() {
    local ctid=$1
    local ct_name=$2
    
    echo -e "${YELLOW}[*] Scanning CT $ctid ($ct_name) for PHP threats...${NC}" | tee -a "$LOG_FILE"
    
    # Check if CT is running
    if ! pct status "$ctid" | grep -q "running"; then
        echo -e "${YELLOW}[!] CT $ctid is not running, skipping...${NC}" | tee -a "$LOG_FILE"
        return
    fi
    
    echo "=== CT $ctid ($ct_name) ===" >> "$REPORT_FILE"
    
    # Find all PHP files
    echo "[+] Finding PHP files..." | tee -a "$LOG_FILE"
    local php_files=$(pct exec "$ctid" -- find /var/www /usr/share/nginx /opt/www /home -type f \( -name "*.php" -o -name "*.phtml" -o -name "*.php3" -o -name "*.php4" -o -name "*.php5" -o -name "*.phar" \) 2>/dev/null || true)
    
    if [ -z "$php_files" ]; then
        echo "[i] No PHP files found in CT $ctid" | tee -a "$LOG_FILE"
        echo "No PHP files found" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
        return
    fi
    
    local file_count=$(echo "$php_files" | wc -l)
    echo "[+] Found $file_count PHP files" | tee -a "$LOG_FILE"
    
    # Scan for dangerous functions
    echo "[+] Scanning for dangerous functions..." | tee -a "$LOG_FILE"
    
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        local matches=$(pct exec "$ctid" -- grep -r -l -E "\b${func}\s*\(" /var/www /usr/share/nginx /opt/www /home --include="*.php" --include="*.phtml" 2>/dev/null || true)
        
        if [ -n "$matches" ]; then
            echo -e "${RED}[!] Found dangerous function: $func${NC}" | tee -a "$LOG_FILE"
            echo "Dangerous function: $func" >> "$REPORT_FILE"
            echo "$matches" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    done
    
    # Scan for obfuscated code
    echo "[+] Scanning for obfuscated code..." | tee -a "$LOG_FILE"
    local obfuscated=$(pct exec "$ctid" -- grep -r -l -E "(base64_decode|gzinflate|gzuncompress|str_rot13|eval).*\(" /var/www /usr/share/nginx /opt/www /home --include="*.php" 2>/dev/null || true)
    
    if [ -n "$obfuscated" ]; then
        echo -e "${RED}[!] Found potentially obfuscated code${NC}" | tee -a "$LOG_FILE"
        echo "Potentially obfuscated files:" >> "$REPORT_FILE"
        echo "$obfuscated" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Scan for webshell patterns
    echo "[+] Scanning for webshell patterns..." | tee -a "$LOG_FILE"
    for pattern in "${WEBSHELL_PATTERNS[@]}"; do
        local webshells=$(pct exec "$ctid" -- grep -r -i -l "$pattern" /var/www /usr/share/nginx /opt/www /home --include="*.php" 2>/dev/null || true)
        
        if [ -n "$webshells" ]; then
            echo -e "${RED}[!] Found potential webshell pattern: $pattern${NC}" | tee -a "$LOG_FILE"
            echo "Webshell pattern: $pattern" >> "$REPORT_FILE"
            echo "$webshells" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    done
    
    # Check for suspicious file permissions (777)
    echo "[+] Checking file permissions..." | tee -a "$LOG_FILE"
    local writable=$(pct exec "$ctid" -- find /var/www /usr/share/nginx /opt/www /home -type f \( -name "*.php" -o -name "*.phtml" \) -perm 0777 2>/dev/null || true)
    
    if [ -n "$writable" ]; then
        echo -e "${RED}[!] Found world-writable PHP files (777)${NC}" | tee -a "$LOG_FILE"
        echo "World-writable PHP files:" >> "$REPORT_FILE"
        echo "$writable" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Check for recently modified PHP files (last 7 days)
    echo "[+] Checking recently modified files..." | tee -a "$LOG_FILE"
    local recent=$(pct exec "$ctid" -- find /var/www /usr/share/nginx /opt/www /home -type f \( -name "*.php" -o -name "*.phtml" \) -mtime -7 2>/dev/null || true)
    
    if [ -n "$recent" ]; then
        echo "[i] Recently modified PHP files (last 7 days):" | tee -a "$LOG_FILE"
        echo "Recently modified files (last 7 days):" >> "$REPORT_FILE"
        echo "$recent" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Check for PHP files in unusual locations
    echo "[+] Checking for PHP files in unusual locations..." | tee -a "$LOG_FILE"
    local unusual=$(pct exec "$ctid" -- find /tmp /var/tmp /dev/shm -type f \( -name "*.php" -o -name "*.phtml" \) 2>/dev/null || true)
    
    if [ -n "$unusual" ]; then
        echo -e "${RED}[!] Found PHP files in unusual locations${NC}" | tee -a "$LOG_FILE"
        echo "PHP files in unusual locations:" >> "$REPORT_FILE"
        echo "$unusual" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Scan for one-liner webshells
    echo "[+] Scanning for one-liner webshells..." | tee -a "$LOG_FILE"
    local oneliners=$(pct exec "$ctid" -- grep -r -E "^\s*<\?php\s+(eval|system|exec|passthru|shell_exec)\s*\(" /var/www /usr/share/nginx /opt/www /home --include="*.php" 2>/dev/null || true)
    
    if [ -n "$oneliners" ]; then
        echo -e "${RED}[!] Found potential one-liner webshells${NC}" | tee -a "$LOG_FILE"
        echo "Potential one-liner webshells:" >> "$REPORT_FILE"
        echo "$oneliners" >> "$REPORT_FILE"
        echo "" >> "$REPORT_FILE"
    fi
    
    # Check php.ini for dangerous settings
    echo "[+] Checking PHP configuration..." | tee -a "$LOG_FILE"
    if pct exec "$ctid" -- test -f /etc/php/*/apache2/php.ini 2>/dev/null || pct exec "$ctid" -- test -f /etc/php/*/fpm/php.ini 2>/dev/null; then
        echo "PHP Configuration Issues:" >> "$REPORT_FILE"
        
        # Check if dangerous functions are disabled
        local disabled=$(pct exec "$ctid" -- grep "disable_functions" /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini 2>/dev/null || true)
        if [ -z "$disabled" ] || echo "$disabled" | grep -q "disable_functions\s*=\s*$"; then
            echo -e "${YELLOW}[!] No PHP functions are disabled${NC}" | tee -a "$LOG_FILE"
            echo "WARNING: No dangerous PHP functions are disabled" >> "$REPORT_FILE"
        fi
        
        # Check allow_url_fopen
        local url_fopen=$(pct exec "$ctid" -- grep "allow_url_fopen" /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini 2>/dev/null | grep -v "^;" || true)
        if echo "$url_fopen" | grep -q "allow_url_fopen\s*=\s*On"; then
            echo -e "${YELLOW}[!] allow_url_fopen is enabled${NC}" | tee -a "$LOG_FILE"
            echo "WARNING: allow_url_fopen is enabled" >> "$REPORT_FILE"
        fi
        
        # Check allow_url_include
        local url_include=$(pct exec "$ctid" -- grep "allow_url_include" /etc/php/*/apache2/php.ini /etc/php/*/fpm/php.ini 2>/dev/null | grep -v "^;" || true)
        if echo "$url_include" | grep -q "allow_url_include\s*=\s*On"; then
            echo -e "${RED}[!] allow_url_include is enabled (CRITICAL)${NC}" | tee -a "$LOG_FILE"
            echo "CRITICAL: allow_url_include is enabled" >> "$REPORT_FILE"
        fi
        
        echo "" >> "$REPORT_FILE"
    fi
    
    echo -e "${GREEN}[✓] CT $ctid scan completed${NC}" | tee -a "$LOG_FILE"
    echo "================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# Scan host system
echo -e "${YELLOW}[*] Scanning host system for PHP threats...${NC}" | tee -a "$LOG_FILE"
echo "=== HOST SYSTEM ===" >> "$REPORT_FILE"

if [ -d /var/www ] || [ -d /usr/share/nginx ]; then
    echo "[+] Scanning host PHP files..." | tee -a "$LOG_FILE"
    
    for func in "${DANGEROUS_FUNCTIONS[@]}"; do
        local matches=$(grep -r -l -E "\b${func}\s*\(" /var/www /usr/share/nginx /opt/www 2>/dev/null --include="*.php" --include="*.phtml" || true)
        
        if [ -n "$matches" ]; then
            echo -e "${RED}[!] Found dangerous function on host: $func${NC}" | tee -a "$LOG_FILE"
            echo "Dangerous function: $func" >> "$REPORT_FILE"
            echo "$matches" >> "$REPORT_FILE"
            echo "" >> "$REPORT_FILE"
        fi
    done
else
    echo "[i] No web directories found on host" | tee -a "$LOG_FILE"
    echo "No web directories found on host" >> "$REPORT_FILE"
fi

echo "================================" >> "$REPORT_FILE"
echo "" >> "$REPORT_FILE"

# Scan all CTs
echo "[*] Detecting all containers..." | tee -a "$LOG_FILE"
pct list | tail -n +2 | while read -r line; do
    ctid=$(echo "$line" | awk '{print $1}')
    ct_name=$(echo "$line" | awk '{print $3}')
    scan_ct_php "$ctid" "$ct_name"
done

echo -e "${GREEN}=== PHP Scan Complete ===${NC}" | tee -a "$LOG_FILE"
echo "Full log saved to: $LOG_FILE" | tee -a "$LOG_FILE"
echo "Detailed report saved to: $REPORT_FILE" | tee -a "$LOG_FILE"
echo "" | tee -a "$LOG_FILE"
echo "Review the report file for detailed findings." | tee -a "$LOG_FILE"
