<div align="center">

# 🔐 Proxmox Security Hardening Suite

**Automated security hardening toolkit for Proxmox VE and all LXC Containers**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Proxmox VE](https://img.shields.io/badge/Proxmox%20VE-7.x%20%7C%208.x-orange?logo=proxmox)](https://www.proxmox.com/)
[![Debian](https://img.shields.io/badge/Debian-11%20%7C%2012-red?logo=debian)](https://www.debian.org/)
[![Shell Script](https://img.shields.io/badge/Shell-Bash-green?logo=gnu-bash)](https://www.gnu.org/software/bash/)
[![Security](https://img.shields.io/badge/Security-CIS%20%7C%20NIST%20%7C%20OWASP-blue)](https://www.cisecurity.org/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

<br/>

![Proxmox Security Banner](https://images.unsplash.com/photo-1558494949-ef010cbdcc31?w=900&q=80)

*Secure your Proxmox infrastructure in minutes — not hours.*

[🚀 Quick Start](#-quick-start) · [📋 Features](#-features) · [📖 Documentation](#-documentation) · [🤝 Contributing](#-contributing)

</div>

---

## 🛡️ What Is This?

A comprehensive, production-ready collection of Bash scripts that automates security hardening for **Proxmox VE** hosts and all their **LXC containers**. One command runs all 6 security procedures in the correct order, with full logging and rollback-safe backups.

> ⚠️ **Always backup your system and test in a non-production environment first.**

---

## ✨ Features

| Script | What It Does |
|--------|-------------|
| `1-backdoor-scanner.sh` | Scans all CTs for reverse shells, webshells, suspicious crons, rootkit indicators |
| `2-system-hardening.sh` | Hardens kernel via sysctl, enforces password policies, configures auditd |
| `3-security-tools-setup.sh` | Installs & configures UFW, Fail2ban, AIDE, rkhunter, chkrootkit, lynis |
| `4-php-scanner.sh` | Detects 50+ dangerous PHP functions, obfuscated code, and webshell patterns |
| `5-ssh-hardening.sh` | Enforces key-only SSH auth, strong ciphers, rate limiting, login banner |
| `6-permissions-hardening.sh` | Fixes world-writable files, secures /etc/shadow, audits SUID/SGID |
| `run-all-security.sh` | **Master script** — runs all 6 in order with interactive prompts |

---

## 🚀 Quick Start

### Prerequisites

- Proxmox VE 7.x or 8.x (Debian 11/12 based)
- Root access
- SSH public key ready

### Step 1 — Add your SSH public key (critical!)

```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh
echo "ssh-rsa AAAA...your-public-key..." >> /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys
```

### Step 2 — Clone and run

```bash
# Clone the repo
git clone https://github.com/wiratmoko1708/proxmoxsecurityhardening.git /tmp/kilo
cd /tmp/kilo

# Run all security procedures
bash run-all-security.sh
```

### Step 3 — Verify SSH key, then restart SSH

```bash
# Open a NEW terminal and test key-based login first!
ssh -i ~/.ssh/your-private-key root@your-proxmox-ip

# Only after successful test:
systemctl restart sshd
```

---

## 📋 Detailed Script Overview

### 🔍 1. Backdoor Scanner

Scans every running LXC container for:

- Suspicious processes (`netcat`, `ncat`, reverse shells)
- Webshells in `/var/www`, `/usr/share/nginx`, `/home`
- Malicious cron jobs and systemd services
- Hidden files in `/tmp`, `/var/tmp`, `/dev/shm`
- Unusual SUID/SGID binaries
- Suspicious entries in `authorized_keys`
- Rootkit indicators

```bash
bash 1-backdoor-scanner.sh
# Log: /var/log/backdoor-scan-YYYYMMDD-HHMMSS.log
```

---

### 🔒 2. System Hardening

Applies kernel-level and OS-level hardening:

- **sysctl**: IP spoofing prevention, ICMP redirect blocking, TCP SYN cookies, ASLR
- **Password policy**: 90-day max age, 14-char minimum, PAM complexity
- **Account lockout**: 5 failed attempts → 30-minute lockout
- **auditd**: Logs identity changes, permission modifications, sudo usage
- Disables USB storage, secures shared memory, removes unnecessary services

```bash
bash 2-system-hardening.sh
# Log: /var/log/system-hardening-YYYYMMDD-HHMMSS.log
```

---

### 🛠️ 3. Security Tools Setup

Installs and configures a full security stack:

| Tool | Purpose |
|------|---------|
| **UFW** | Firewall — allows SSH (22), Proxmox UI (8006), Corosync (5405-5412) |
| **Fail2ban** | Bans IPs after repeated SSH/Proxmox login failures |
| **AIDE** | File integrity monitoring — detects unauthorized changes |
| **rkhunter** | Rootkit, backdoor, and exploit scanner |
| **chkrootkit** | Alternative rootkit detection |
| **lynis** | Full system security audit |

```bash
bash 3-security-tools-setup.sh
# Log: /var/log/security-tools-setup-YYYYMMDD-HHMMSS.log
```

---

### 🐘 4. PHP Scanner

Scans all PHP files across host and containers:

- **50+ dangerous functions**: `eval`, `exec`, `system`, `passthru`, `shell_exec`, `base64_decode`, etc.
- **Obfuscated code**: `gzinflate`, `str_rot13`, chained encoding
- **Webshell signatures**: c99, r57, b374k, wso, IndoXploit, and more
- **Misconfigurations**: `allow_url_include`, `allow_url_fopen`, missing `disable_functions`
- **Suspicious locations**: PHP files in `/tmp`, `/var/tmp`, `/dev/shm`

```bash
bash 4-php-scanner.sh
# Report: /var/log/php-scanner-report-YYYYMMDD-HHMMSS.txt
```

---

### 🔑 5. SSH Hardening

Configures SSH for maximum security:

```
PasswordAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
MaxAuthTries 3
LoginGraceTime 30
AllowTcpForwarding no
X11Forwarding no
```

- Only strong ciphers: `chacha20-poly1305`, `aes256-gcm`, `aes256-ctr`
- Only strong MACs: `hmac-sha2-512-etm`, `hmac-sha2-256-etm`
- Removes weak DSA/ECDSA host keys, generates ED25519 + RSA 4096
- Adds legal login banner

```bash
bash 5-ssh-hardening.sh
# Log: /var/log/ssh-hardening-YYYYMMDD-HHMMSS.log
```

---

### 📁 6. Permissions Hardening

Locks down the filesystem:

- `/etc/shadow` → `0000 root:root`
- `/etc/passwd` → `0644 root:root`
- SSH host keys → `0600 root:root`
- Home directories → `0750 user:user`
- Removes world-writable bits from all non-temp files
- Adds sticky bit to world-writable directories
- Audits all SUID/SGID binaries
- Secures Proxmox-specific paths (`/etc/pve`, `/var/lib/vz`)

```bash
bash 6-permissions-hardening.sh
# Log: /var/log/permissions-hardening-YYYYMMDD-HHMMSS.log
```

---

## 📊 Logs & Output

All scripts write timestamped logs to `/var/log/`:

```
/var/log/backdoor-scan-*.log
/var/log/php-scanner-report-*.txt
/var/log/system-hardening-*.log
/var/log/security-tools-setup-*.log
/var/log/ssh-hardening-*.log
/var/log/permissions-hardening-*.log
/var/log/proxmox-security-hardening-*.log   ← master log
```

---

## 🛠️ Helper Scripts (installed to `/usr/local/bin/`)

After running the suite, these tools are available system-wide:

```bash
# Overall security status
security-check.sh

# SSH configuration audit
check-ssh-security.sh

# File permissions audit
check-permissions.sh

# Setup SSH key for a user
setup-ssh-key.sh <username>
```

---

## 🔍 Post-Installation Monitoring

```bash
# Daily
fail2ban-client status
ufw status verbose
security-check.sh

# Weekly
aide --check
lynis audit system --quick

# Monthly
rkhunter --check
chkrootkit
lynis audit system
```

---

## ⚙️ Configuration

### Whitelist your IP in Fail2ban

```bash
nano /etc/fail2ban/jail.local
# Add your IP:
# ignoreip = 127.0.0.1/8 ::1 YOUR.TRUSTED.IP

systemctl restart fail2ban
```

### Open additional ports in UFW

```bash
ufw allow 80/tcp comment 'HTTP'
ufw allow 443/tcp comment 'HTTPS'
ufw reload
```

### Disable dangerous PHP functions

Edit `/etc/php/*/fpm/php.ini`:

```ini
disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source
```

---

## 🆘 Troubleshooting

<details>
<summary><strong>Locked out of SSH?</strong></summary>

1. Login via **Proxmox web console**
2. `nano /etc/ssh/sshd_config`
3. Set `PasswordAuthentication yes` temporarily
4. `systemctl restart sshd`
5. Login with password, fix your SSH key
6. Set `PasswordAuthentication no` again

</details>

<details>
<summary><strong>UFW blocking everything?</strong></summary>

```bash
ufw disable                    # Disable temporarily
ufw status numbered            # Review rules
ufw allow from YOUR_IP         # Allow your IP
ufw enable
```

</details>

<details>
<summary><strong>Fail2ban banned your own IP?</strong></summary>

```bash
fail2ban-client set sshd unbanip YOUR_IP

# Prevent future bans — add to jail.local:
# ignoreip = YOUR_IP
systemctl restart fail2ban
```

</details>

<details>
<summary><strong>AIDE database corrupt?</strong></summary>

```bash
aideinit
cp /var/lib/aide/aide.db.new /var/lib/aide/aide.db
```

</details>

---

## 🏗️ Architecture

```
proxmoxsecurityhardening/
├── run-all-security.sh          # Master script — run this
├── 1-backdoor-scanner.sh        # CT backdoor detection
├── 2-system-hardening.sh        # Kernel & OS hardening
├── 3-security-tools-setup.sh    # UFW, Fail2ban, AIDE
├── 4-php-scanner.sh             # PHP threat scanner
├── 5-ssh-hardening.sh           # SSH key-only auth
├── 6-permissions-hardening.sh   # Filesystem permissions
├── README.md
└── CHANGELOG.md
```

---

## 📜 Security Standards

This suite implements controls from:

- ✅ **CIS Benchmarks** — Center for Internet Security
- ✅ **NIST SP 800-123** — Guide to General Server Security
- ✅ **OWASP** — Web application security best practices
- ✅ **PCI-DSS** — Payment Card Industry requirements

---

## 🤝 Contributing

Contributions are very welcome! Here are some ways you can help:

- 🐛 **Report bugs** — open an [Issue](https://github.com/wiratmoko1708/proxmoxsecurityhardening/issues)
- 💡 **Suggest features** — new scan patterns, hardening rules, distro support
- 🔧 **Submit a PR** — fix a bug, add a feature, improve docs
- 🌍 **Translate** — help translate docs to other languages
- ⭐ **Star the repo** — helps others discover this project

### Development Setup

```bash
git clone https://github.com/wiratmoko1708/proxmoxsecurityhardening.git
cd proxmoxsecurityhardening

# Test a script (use a VM or test environment!)
bash 1-backdoor-scanner.sh
```

### Contribution Guidelines

1. Fork the repo and create a feature branch: `git checkout -b feature/my-improvement`
2. Keep scripts POSIX-compatible where possible
3. Add comments explaining what each section does
4. Test on Proxmox VE 7.x or 8.x before submitting
5. Update `CHANGELOG.md` with your changes
6. Open a Pull Request with a clear description

---

## 📅 Roadmap

- [ ] Automated backup before execution
- [ ] Rollback / undo functionality
- [ ] Email alerts for security events
- [ ] Container-specific hardening profiles
- [ ] Automated compliance reporting (HTML/PDF)
- [ ] Integration with external SIEM
- [ ] Support for Proxmox Backup Server hardening

---

## ⚠️ Disclaimer

These scripts make significant changes to your system configuration. Always:

1. **Backup** your system before running
2. **Test** in a non-production environment first
3. **Keep** Proxmox console access available
4. **Review** all logs after execution

The authors are not responsible for any system downtime or data loss resulting from the use of these scripts.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

<div align="center">

**Made with ❤️ for the Proxmox community**

If this helped you, please ⭐ star the repo and share it with others!

[![GitHub stars](https://img.shields.io/github/stars/wiratmoko1708/proxmoxsecurityhardening?style=social)](https://github.com/wiratmoko1708/proxmoxsecurityhardening/stargazers)

</div>
