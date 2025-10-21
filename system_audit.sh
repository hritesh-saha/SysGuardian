#!/bin/bash
# =====================================
#   System Health & Security Audit Tool
#   Author: Hritesh
#   Version: 1.0
# =====================================

# Color Codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Create output file
output="system_audit_report_$(date +%F_%H-%M-%S).txt"

# --- Main Header ---
TIMESTAMP=$(date)
echo -e "${BOLD}${CYAN}=====================================================${NC}" | tee -a $output
echo -e "${BOLD}${CYAN}    SYSTEM HEALTH & SECURITY AUDIT${NC}" | tee -a $output
echo -e "${BOLD}${CYAN}    Timestamp: $TIMESTAMP${NC}" | tee -a $output
echo -e "${BOLD}${CYAN}=====================================================${NC}" | tee -a $output

# 1. System Resources
echo -e "\n--- [ 📊 System Resources ] --------------------------\n" | tee -a $output

# --- CPU Check ---
# Using user's thresholds: 50% WARN, 75% CRIT
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{usage=$2+$4; printf("%.1f", usage)}')
CPU_TAG="[OK]      " # 8 chars padding
CPU_COLOR=$GREEN
if (( $(echo "$CPU_USAGE > 75" | bc -l) )); then
    CPU_TAG="[CRITICAL]"
    CPU_COLOR=$RED
elif (( $(echo "$CPU_USAGE > 50" | bc -l) )); then
    CPU_TAG="[WARNING] " # 1 char padding
    CPU_COLOR=$YELLOW
fi
echo -e "${CPU_COLOR}${CPU_TAG}${NC} CPU Usage: $CPU_USAGE%" | tee -a $output

# --- Memory Check ---
# Using 90% CRIT, 75% WARN
# Get human-readable values
MEM_HUMAN=$(free -h | awk 'NR==2{print "Used: " $3 " / Total: " $2}')
# Get values for calculation (in MiB)
MEM_CALC=$(free -m | awk 'NR==2{print $3, $2}')
MEM_USED_M=$(echo $MEM_CALC | awk '{print $1}')
MEM_TOTAL_M=$(echo $MEM_CALC | awk '{print $2}')
MEM_PERCENT=$(awk -v used="$MEM_USED_M" -v total="$MEM_TOTAL_M" 'BEGIN {if (total > 0) printf "%.1f", (used/total)*100; else print "0.0"}')

MEM_TAG="[OK]      " # 8 chars padding
MEM_COLOR=$GREEN
if (( $(echo "$MEM_PERCENT > 90" | bc -l) )); then
    MEM_TAG="[CRITICAL]"
    MEM_COLOR=$RED
elif (( $(echo "$MEM_PERCENT > 75" | bc -l) )); then
    MEM_TAG="[WARNING] " # 1 char padding
    MEM_COLOR=$YELLOW
fi
echo -e "${MEM_COLOR}${MEM_TAG}${NC} Memory Usage: $MEM_PERCENT% ($MEM_HUMAN)" | tee -a $output

# --- Disk Check ---
# Using user's thresholds: 60% WARN, 80% CRIT
# Get values for / filesystem (matches target format)
DISK_STATS=$(df -h / | awk 'NR==2{print $5, $3, $2}') # Percent, Used, Total
DISK_PERCENT_NUM=$(echo $DISK_STATS | awk '{print $1}' | tr -d '%')
DISK_USED=$(echo $DISK_STATS | awk '{print $2}')
DISK_TOTAL=$(echo $DISK_STATS | awk '{print $3}')

DISK_TAG="[OK]      " # 8 chars padding
DISK_COLOR=$GREEN
if [ "$DISK_PERCENT_NUM" -gt 80 ]; then
    DISK_TAG="[CRITICAL]"
    DISK_COLOR=$RED
elif [ "$DISK_PERCENT_NUM" -gt 60 ]; then
    DISK_TAG="[WARNING] " # 1 char padding
    DISK_COLOR=$YELLOW
fi
echo -e "${DISK_COLOR}${DISK_TAG}${NC} Disk Usage (/): $DISK_PERCENT_NUM% (Used: $DISK_USED / Total: $DISK_TOTAL)" | tee -a $output


# 2. System Uptime
echo -e "\n--- [ ⏱️ System Uptime ] -----------------------------\n" | tee -a $output
uptime | sed 's/^[ \t]*//' | tee -a $output # `sed` removes leading whitespace

# 3. Firewall Status
echo -e "\n--- [ 🔥 Firewall Status ] ---------------------------\n" | tee -a $output
# User's WSL detection logic
if grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null ; then
    echo -e "${YELLOW}Firewall check skipped (running in WSL)${NC}" | tee -a $output
else
    # Show full status table as in the target example
    sudo ufw status | tee -a $output
fi

# 4. Network Info
echo -e "\n--- [ 🌐 Active Network Connections ] -----------------\n" | tee -a $output
# header to match 'ss' command
echo -e "${BOLD}Netid  State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port${NC}" | tee -a $output
# ss -tuna (tcp, udp, numeric, all) gives the exact format needed
ss -tuna | tail -n +2 | tee -a $output

# 5. Security Log Check
echo -e "\n--- [ 🔐 Failed Login Analysis (Last 5) ] -----------\n" | tee -a $output

# User's trusted IP list
trusted_ips=("127.0.0.1" "::1" "local" "192.168." "10." "172.16." "172.17." "172.18." "172.19." "172.20." "172.21." "172.22." "172.23." "172.24." "172.25." "172.26." "172.27." "172.28." "172.29." "172.30." "172.31.")

# User's IP check function
is_trusted_ip() {
    local ip=$1
    for trusted in "${trusted_ips[@]}"; do
        if [[ "$ip" == "$trusted"* ]]; then
            return 0  # trusted
        fi
    done
    return 1  # unknown
}

# Read log file
if [ -f /var/log/auth.log ]; then
    sudo grep "Failed password" /var/log/auth.log | tail -5 | while read line; do
        # Extract IP
        ip=$(echo $line | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}')
        if [[ -z "$ip" ]]; then ip="local"; fi

        # Format output to match target
        if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" == "local" ]]; then
            echo -e "${GREEN}[LOCALHOST]${NC}  $line" | tee -a $output
        elif is_trusted_ip "$ip"; then
            echo -e "${GREEN}[LOCAL IP]${NC}   $line" | tee -a $output
        else
            echo -e "${RED}[UNKNOWN IP]${NC} $line" | tee -a $output
        fi

    done
else
    echo -e "${YELLOW}No auth.log found (WSL or restricted permissions)${NC}" | tee -a $output
fi


# --- Footer ---
echo -e "\n${BOLD}${CYAN}=====================================================${NC}" | tee -a $output
echo -e "    AUDIT COMPLETE" | tee -a $output
echo -e "    Report saved to: ${YELLOW}$output${NC}" | tee -a $output
echo -e "${BOLD}${CYAN}=====================================================${NC}" | tee -a $output
sed -i -E 's/\x1b\[[0-9;]*[mK]//g' "$output"