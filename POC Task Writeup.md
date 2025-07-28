# 🔐 Security POC Tasks

This repository contains hands-on Proof-of-Concept (POC) tasks designed to simulate real-world security misconfigurations and demonstrate how to exploit and mitigate them. Each task is categorized by vulnerability type and includes setup, exploitation (if applicable), and mitigation steps.

---

## 🧑‍💻 Task 1: User & Permission Misconfigurations

### 🔎 Description

Improper file permissions can allow unauthorized users to access sensitive system files, leading to privilege escalation. This task demonstrates how weak permissions pose security risks and how to secure them properly.

### ⚙️ Setup: Creating Users & Misconfiguring Permissions

    # Create a new user
    sudo useradd attacker
    sudo passwd attacker

    # Create a sensitive file and assign weak permissions
    echo "root:myrootpassword" > /root/secrets.txt
    chmod 777 /root/secrets.txt

### 🚨 Exploitation: Accessing Sensitive Files

    # Switch to attacker and read the sensitive file
    su attacker
    cat /root/secrets.txt

### ✅ Mitigation: Fixing Security Issues

    chmod 600 /root/secrets.txt
    chown root:root /root/secrets.txt

---

## 🌐 Task 2: Remote Access & SSH Hardening

### 🔎 Description

Weak SSH configurations can allow unauthorized users to gain system access. This task covers common SSH vulnerabilities and best practices for securing remote access.

### ⚙️ Setup: Weak SSH Configuration

Edit `/etc/ssh/sshd_config`:

    PermitRootLogin yes
    PasswordAuthentication yes

Restart SSH:

    sudo systemctl restart sshd

### ✅ Mitigation: Secure SSH

    # Recommended SSH configuration
    PermitRootLogin no
    PasswordAuthentication no
    AllowUsers youruser

    # Restart service
    sudo systemctl restart sshd

---

## 🔥 Task 3: Firewall & Network Security

### 🔎 Description

A misconfigured firewall can expose a system to unauthorized access. This task demonstrates how to scan open ports and configure firewall rules securely.

### ⚙️ Setup: Open Ports & Firewall Misconfigurations

    # Open all ports (not recommended)
    sudo ufw allow from any

    # Scan open ports using Nmap
    nmap -sS -Pn <target-ip>

### ✅ Mitigation: Restrict Access

    # Reset firewall and allow only necessary ports
    sudo ufw reset
    sudo ufw allow 22
    sudo ufw enable

---

## 🧨 Task 4: SUID & Privilege Escalation

### 🔎 Description

SUID binaries can be abused to gain unauthorized root access. This task highlights how attackers exploit SUID permissions and how to secure these files.

### ⚙️ Setup: Exploitable SUID Permissions

    # Give SUID permission to a binary
    sudo cp /bin/bash /tmp/rootbash
    sudo chmod +s /tmp/rootbash

### 🚨 Exploitation: Escalating Privileges

    # Run the SUID binary as root
    /tmp/rootbash -p
    whoami  # should print root

### ✅ Mitigation: Remove Unnecessary SUID

    sudo find / -perm -4000 -type f -exec ls -la {} \;
    sudo chmod u-s /tmp/rootbash

---

## ⚙️ Task 5: Automated Security Auditing & Scripting

### 🔎 Description

Automated security monitoring helps detect vulnerabilities in real time. This task focuses on writing scripts to monitor login attempts and running services.

### ⚙️ Setup: Writing a Security Audit Script

`security_check.sh`:

    #!/bin/bash
    echo "[*] Checking login attempts:"
    lastb | head -n 10

    echo "[*] Running services:"
    ps aux | grep ssh

    echo "[*] Listening Ports:"
    netstat -tulnp

Make it executable:

    chmod +x security_check.sh
    ./security_check.sh

### ✅ Mitigation: Automate Security Checks

- Schedule the script using `cron` or systemd timers.
- Integrate it with monitoring tools (e.g., Nagios, Zabbix).

---

## 📊 Task 6: Log Analysis & Intrusion Detection

### 🔎 Description

System logs provide crucial insights into security threats. This task demonstrates how to analyze logs for failed authentication attempts and implement preventive measures.

### ⚙️ Setup: Enabling System Logs

    sudo systemctl status rsyslog
    sudo journalctl -xe

### ✅ Mitigation: Use Fail2Ban

    sudo apt install fail2ban
    sudo systemctl enable fail2ban
    sudo systemctl start fail2ban

Monitor bans:

    sudo fail2ban-client status

---

## 📁 License

This project is for educational purposes only. Use responsibly.

---

## 🤝 Contributions

Feel free to fork and improve this repo with new POC tasks or enhancements!
