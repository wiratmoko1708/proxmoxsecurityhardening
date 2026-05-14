# Changelog - Proxmox Security Hardening Suite

## Version 1.0 (2026-05-14)

### Initial Release

Complete security hardening suite for Proxmox VE with 6 comprehensive security procedures.

#### Features Added

**1. Backdoor Detection Scanner (1-backdoor-scanner.sh)**
- Scans all Proxmox containers for malicious files and processes
- Detects reverse shells, webshells, and suspicious scripts
- Audits cron jobs and systemd services
- Checks for hidden files in suspicious locations
- Identifies unusual SUID/SGID files
- Reviews listening ports and user accounts
- Audits SSH authorized_keys
- Detects rootkit indicators

**2. System Hardening (2-system-hardening.sh)**
- Kernel parameter hardening via sysctl
- IP spoofing prevention
- ICMP redirect protection
- TCP SYN cookies for DDoS protection
- Kernel pointer and dmesg restrictions
- Disables unnecessary services
- Strong password policies (90 days max, 14 chars min)
- PAM configuration for password complexity
- Account lockout after 5 failed attempts
- Shared memory security
- USB storage disabled
- Comprehensive auditd logging

**3. Security Tools Installation (3-security-tools-setup.sh)**
- UFW firewall with Proxmox-specific rules
- Fail2ban monitoring for SSH and Proxmox
- AIDE (Advanced Intrusion Detection Environment)
- rkhunter (rootkit hunter)
- chkrootkit (rootkit detection)
- lynis (security auditing tool)
- Daily security check automation
- Comprehensive logging

**4. PHP Security Scanner (4-php-scanner.sh)**
- Scans 50+ dangerous PHP functions
- Detects obfuscated code (base64, gzinflate, etc)
- Identifies webshell patterns (c99, r57, wso, b374k, etc)
- Checks file permissions (777 detection)
- Finds PHP files in unusual locations
- Detects one-liner webshells
- Audits PHP configuration (allow_url_include, etc)
- Scans both host and all containers

**5. SSH Hardening (5-ssh-hardening.sh)**
- Key-only authentication (disables passwords)
- Strong ciphers and algorithms only
- ED25519 and RSA 4096 host keys
- Removes weak DSA and ECDSA keys
- Rate limiting and connection throttling
- Login banner
- Disables dangerous features (forwarding, tunneling)
- Verbose logging
- Helper scripts for key management

**6. File Permissions Hardening (6-permissions-hardening.sh)**
- Secures critical system files (/etc/passwd, /etc/shadow)
- Hardens SSH configuration and keys
- Secures boot files and GRUB
- Locks down cron directories
- Protects log files
- Secures home directories and .ssh folders
- Fixes world-writable files and directories
- Audits SUID/SGID files
- Secures Proxmox-specific files (/etc/pve)

**7. Master Execution Script (run-all-security.sh)**
- Runs all procedures in correct order
- Interactive confirmation prompts
- Comprehensive logging
- Progress indicators
- Detailed summary report
- Next steps guidance
- Emergency recovery information

#### Helper Scripts Created

- `/usr/local/bin/security-check.sh` - Daily security status check
- `/usr/local/bin/check-ssh-security.sh` - SSH configuration audit
- `/usr/local/bin/check-permissions.sh` - File permissions audit
- `/usr/local/bin/setup-ssh-key.sh` - SSH key setup helper

#### Documentation

- **README.md** - Complete documentation with usage examples
- **INSTALL.txt** - Detailed installation guide
- **QUICKSTART.sh** - Quick reference guide
- **CHANGELOG.md** - This file

#### Security Standards Implemented

- CIS Benchmarks compliance
- NIST Security Guidelines
- OWASP Best Practices
- PCI-DSS Requirements
- Industry standard hardening practices

#### Logging and Monitoring

All scripts generate detailed logs:
- `/var/log/backdoor-scan-*.log`
- `/var/log/php-scanner-report-*.txt`
- `/var/log/system-hardening-*.log`
- `/var/log/security-tools-setup-*.log`
- `/var/log/ssh-hardening-*.log`
- `/var/log/permissions-hardening-*.log`
- `/var/log/proxmox-security-hardening-*.log`

#### Backup System

Automatic backups created for:
- `/etc/ssh/sshd_config`
- `/etc/sysctl.conf`
- `/etc/login.defs`
- `/etc/pam.d/*` files
- All modified configuration files

#### Known Limitations

- Requires Debian/Ubuntu based Proxmox
- AIDE initialization takes 5-10 minutes
- Some changes require system reboot
- Must have console access for SSH recovery
- UFW may need additional port rules for custom services

#### Tested On

- Proxmox VE 7.x
- Proxmox VE 8.x
- Debian 11 (Bullseye)
- Debian 12 (Bookworm)

#### Future Enhancements (Planned)

- Automated backup before execution
- Rollback functionality
- Web-based dashboard
- Email alerts for security events
- Integration with external SIEM
- Container-specific hardening profiles
- Automated compliance reporting

---

## Contributing

Report issues or suggest improvements for future versions.

## License

Created by WWW
Version 1.0 - 2026-05-14

---

**Note**: Always test in non-production environment first. Keep backups and console access available.
