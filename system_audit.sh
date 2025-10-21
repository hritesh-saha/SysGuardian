#!/bin/bash
# =====================================
#  System Health & Security Audit Tool
#  Author: Hritesh
#  Version: 1.1 - WSL Compatible + Known IP Whitelist + Readable Tables
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

echo -e "${BOLD}${CYAN}===== SYSTEM AUDIT REPORT =====${NC}" | tee -a $output
echo -e "Report Generated: $(date)" | tee -a $output
echo -e "Host Name: $(hostname)" | tee -a $output
echo -e "---------------------------------" | tee -a $output

# 1. System Health
echo -e "\n${BOLD}${BLUE}===== 1. SYSTEM HEALTH =====${NC}" | tee -a $output

CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{usage=$2+$4; printf("%.2f", usage)}')
CPU_COLOR=$GREEN
if (( $(echo "$CPU_USAGE > 75" | bc -l) )); then CPU_COLOR=$RED
elif (( $(echo "$CPU_USAGE > 50" | bc -l) )); then CPU_COLOR=$YELLOW
fi
echo -e "CPU Usage: ${CPU_COLOR}$CPU_USAGE%${NC}" | tee -a $output

MEM_USED=$(free -h | awk 'NR==2{print $3}')
MEM_FREE=$(free -h | awk 'NR==2{print $4}')
echo -e "Memory Used: ${YELLOW}$MEM_USED${NC}, Free: ${GREEN}$MEM_FREE${NC}" | tee -a $output

DISK_TOTAL=$(df -h --total | grep total | awk '{print $2}')
DISK_USED=$(df -h --total | grep total | awk '{print $3}')
DISK_FREE=$(df -h --total | grep total | awk '{print $4}')
DISK_PERCENT=$(df -h --total | grep total | awk '{print $5}' | tr -d '%')
DISK_COLOR=$GREEN
if [ "$DISK_PERCENT" -gt 80 ]; then DISK_COLOR=$RED
elif [ "$DISK_PERCENT" -gt 60 ]; then DISK_COLOR=$YELLOW
fi
echo -e "Disk Usage: Total: $DISK_TOTAL, Used: $DISK_USED, Free: $DISK_FREE, Usage: ${DISK_COLOR}$DISK_PERCENT%${NC}" | tee -a $output

# 2. Network Info
echo -e "\n${BOLD}${BLUE}===== 2. NETWORK INFORMATION =====${NC}" | tee -a $output
echo -e "${BOLD}Proto\tLocal Address\tPort\tState${NC}" | tee -a $output
ss -tuln | tail -n +2 | awk '{
    split($5,a,":");
    port=a[length(a)];
    state=($1=="LISTEN")?"LISTENING":"ESTABLISHED";
    printf "%s\t%s\t%s\t%s\n",$1,$4,port,state
}' | tee -a $output

# 3. Firewall Status (WSL Detection)
echo -e "\n${BOLD}${BLUE}===== 3. FIREWALL STATUS =====${NC}" | tee -a $output
if grep -qEi "(Microsoft|WSL)" /proc/version &> /dev/null ; then
    echo -e "${YELLOW}Firewall check skipped (running in WSL)${NC}" | tee -a $output
else
    FIREWALL=$(sudo ufw status | grep -i "Status" | awk '{print $2}')
    if [[ "$FIREWALL" == "active" ]]; then FIREWALL_COLOR=$GREEN; else FIREWALL_COLOR=$RED; fi
    echo -e "Status: ${FIREWALL_COLOR}$FIREWALL${NC}" | tee -a $output
fi

# 4. Security Log Check with Whitelist
echo -e "\n${BOLD}${BLUE}===== 4. SECURITY LOG CHECK =====${NC}" | tee -a $output
echo -e "${BOLD}Time\t\tUser\tIP${NC}" | tee -a $output

# Define known/trusted IPs (localhost, private networks, common trusted addresses)
trusted_ips=("127.0.0.1" "::1" "local" "192.168." "10." "172.16." "172.17." "172.18." "172.19." "172.20." "172.21." "172.22." "172.23." "172.24." "172.25." "172.26." "172.27." "172.28." "172.29." "172.30." "172.31.")

# Function to check if an IP matches the whitelist
is_trusted_ip() {
    local ip=$1
    for trusted in "${trusted_ips[@]}"; do
        if [[ "$ip" == "$trusted"* ]]; then
            return 0  # trusted
        fi
    done
    return 1  # unknown
}

# Format failed login attempts
if [ -f /var/log/auth.log ]; then
    sudo grep "Failed password" /var/log/auth.log | tail -5 | while read line; do
        time=$(echo $line | awk '{print $1" "$2" "$3}')
        user=$(echo $line | awk '{for(i=1;i<=NF;i++){if($i=="for"){print $(i+1)}}}')
        ip=$(echo $line | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}')
        if [[ -z "$user" ]]; then user="unknown"; fi
        if [[ -z "$ip" ]]; then ip="local"; fi

        if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" == "local" ]]; then
            echo -e "$time\t$user\t$ip (LOCAL)" | tee -a $output
        elif is_trusted_ip "$ip"; then
            echo -e "$time\t$user\t$ip (TRUSTED)" | tee -a $output
        else
            echo -e "${RED}$time\t$user\t$ip (UNKNOWN)${NC}" | tee -a $output
        fi

    done
else
    echo -e "${YELLOW}No auth.log found (WSL or restricted permissions)${NC}" | tee -a $output
fi

# 5. System Uptime
echo -e "\n${BOLD}${BLUE}===== 5. SYSTEM UPTIME =====${NC}" | tee -a $output
echo -e "Time since last reboot:" | tee -a $output
uptime | tee -a $output

echo -e "\n${BOLD}${CYAN}=================================${NC}" | tee -a $output
echo -e "Audit Completed. Report saved at: ${YELLOW}$output${NC}" | tee -a $output