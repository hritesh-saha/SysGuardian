# 🛡️ System Health & Security Audit Script

A comprehensive Bash script that performs a quick health check and security audit on a Linux system. It checks system resources, network connections, and failed login attempts, highlighting potential security risks and generating a timestamped report.

## ✨ Features

* 📊 **System Resource Monitoring:** Color-coded (warn/critical) thresholds for CPU, memory, and disk usage.
* 🌐 **Network Monitoring:** Lists all active TCP and UDP connections.
* 🔥 **Firewall Status:** Checks the status of `ufw` (Uncomplicated Firewall).
* *️⃣ **WSL-Aware:** Automatically skips the firewall check when running in Windows Subsystem for Linux (WSL) to prevent errors.
* 🔐 **Security Audit:** Analyzes the last 5 failed login attempts from `/var/log/auth.log`.
* 🚦 **IP Whitelisting:** Highlights suspicious failed logins. Unknown/untrusted IPs are marked in red, while known local/private IPs (e.g., `127.0.0.1`, `192.168.x.x`) are marked in green.
* ⏱️ **System Uptime:** Displays the current system uptime and load average.
* 📝 **Report Generation:** Saves a complete, timestamped report of the audit to a text file (e.g., `system_audit_2025-10-21_17-30-01.log`).

## 📋 Requirements

* **Bash:** The script is written in Bash.
* **Core Utilities:** Requires standard Linux/GNU utilities such as `awk`, `grep`, `sed`, `df`, `free`, `top` (or `mpstat`), `ss` (or `netstat`), and `uptime`.
* **`sudo` Access:** Required to read `/var/log/auth.log` and get a complete list of network connections.
* **Log Files:** The script is designed for Debian/Ubuntu-based systems using `/var/log/auth.log`. For RHEL/CentOS-based systems, you may need to modify the script to read `/var/log/secure`.

## 🌐 Usage

1.  Clone this repository or download the script (`system_audit.sh`).
2.  Make the script executable:
    ```bash
    chmod +x system_audit.sh
    ```
3.  Run the script with `sudo` to ensure it has the necessary permissions:
    ```bash
    sudo ./system_audit.sh
    ```
4.  The audit results will be printed to the console, and a log file with the full report will be created in the same directory.

## 📄 Example Output

Here is a sample of the console output (colors are represented by text tags like `[CRITICAL]` or `[UNKNOWN IP]`):

```plaintext
=====================================================
    SYSTEM HEALTH & SECURITY AUDIT
    Timestamp: Tue Oct 21 17:35:01 IST 2025
=====================================================

--- [ 📊 System Resources ] --------------------------

[WARNING]  CPU Usage: 62.5%
[CRITICAL] Memory Usage: 91.2% (Used: 14.2G / Total: 15.6G)
[OK]       Disk Usage (/): 35.4% (Used: 171G / Total: 488G)

--- [ ⏱️ System Uptime ] -----------------------------

 17:35:01 up 14 days,  2:20,  1 user,  load average: 1.05, 1.01, 0.98

--- [ 🔥 Firewall Status ] ---------------------------

Status: active
To                         Action      From
--                         ------      ----
22/tcp                     LIMIT       Anywhere
80/tcp                     ALLOW       Anywhere
443/tcp                    ALLOW       Anywhere

--- [ 🌐 Active Network Connections ] -----------------

Netid  State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port
udp    UNCONN  0       0         127.0.0.53:53          0.0.0.0:*
tcp    LISTEN  0       4096      127.0.0.1:3306         0.0.0.0:*
tcp    LISTEN  0       511       0.0.0.0:80             0.0.0.0:*
tcp    ESTAB   0       0         192.168.1.10:22        192.168.1.50:54321

--- [ 🔐 Failed Login Analysis (Last 5) ] -----------

[UNKNOWN IP] Oct 21 17:30:01 server sshd[12345]: Failed password for root from 114.23.10.55 port 45122 ssh2
[UNKNOWN IP] Oct 21 17:31:15 server sshd[12347]: Failed password for invalid user admin from 103.44.12.9 port 22
[LOCAL IP]   Oct 21 17:32:05 server sshd[12349]: Failed password for hritesh from 192.168.1.50 port 54888 ssh2
[UNKNOWN IP] Oct 21 17:33:40 server sshd[12351]: Failed password for root from 114.23.10.55 port 45122 ssh2
[LOCALHOST]  Oct 21 17:34:12 server sshd[12355]: Failed password for (invalid user) from 127.0.0.1 port 45122 ssh2

=====================================================
    AUDIT COMPLETE
    Report saved to: system_audit_report_2025-10-21_17-35-01.txt
=====================================================
```
## ⚙️ How It Works

The script is divided into several functions:

1.  **Resource Check:** Uses `top` or `/proc/stat` for CPU, `free` for memory, and `df` for disk. It pipes these values through `awk` to calculate percentages and compares them against `WARN_THRESHOLD` and `CRIT_THRESHOLD` variables to apply ANSI color codes.
2.  **Uptime Check:** Runs the `uptime` command.
3.  **Firewall Check:** First, it checks for the existence of `/proc/version` and searches for "Microsoft" or "WSL" strings. If found, it skips the check. Otherwise, it executes `sudo ufw status`.
4.  **Network Check:** Runs `ss -tunap` (or `netstat -tunap`) to list all active TCP and UDP connections.
5.  **Login Analysis:** This is the core security check.
    * It uses `grep "Failed password" /var/log/auth.log` (or equivalent) and selects the last 5 entries.
    * It iterates through each line, extracting the IP address.
    * Each IP is compared against a **whitelist** of known-safe IP patterns (see below).
    * If the IP matches the whitelist, it's colored green and tagged as `[LOCAL IP]` or `[LOCALHOST]`.
    * If the IP does *not* match, it is considered external and potentially malicious, so it's colored red and tagged as `[UNKNOWN IP]`.
6.  **Report Generation:** The entire output of the script is piped to the `tee` command, which simultaneously prints it to the console and writes it to a file named with the current timestamp.

### 💡 Known vs. Unknown IPs

The script's primary security value comes from distinguishing between routine internal failed logins (like a typo from your own computer) and potential brute-force attacks from the internet.

* ✅ **Known IPs (Whitelisted):** These are considered "safe" and are printed in green. The script's whitelist includes:
    * `127.0.0.1` (localhost)
    * `10.0.0.0/8` (Private network)
    * `172.16.0.0/12` (Private network, from 172.16.x.x to 172.31.x.x)
    * `192.168.0.0/16` (Private network)

* ⛔ **Unknown IPs (External):** Any IP address that does *not* fall into one of the ranges above. A failed login from an unknown IP (like `114.23.10.55` in the example) is a clear indicator of an external entity attempting to gain access to your server.

## 📝 Notes

* This script is intended for quick audits and monitoring. It is not a replacement for a full-featured Intrusion Detection System (IDS) like Fail2Ban or OSSEC.
* Always review the `[UNKNOWN IP]` entries. If you see repeated attempts from the same IP, you should consider blocking it at your firewall.
* The ANSI color codes may not render in all terminal emulators or when viewing the raw log file.

<p align="center"><a href="https://github.com/hritesh-saha/SysGuardian/blob/main/LICENSE"><img src="https://img.shields.io/static/v1.svg?style=for-the-badge&label=License&message=BSD-3-Clause&logoColor=d9e0ee&colorA=363a4f&colorB=b7bdf8"/></a></p>
