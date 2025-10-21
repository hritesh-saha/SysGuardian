#!/bin/bash
# =====================================
#   System Health & Security Audit Tool
#   CRON-FRIENDLY VERSION (No Colors, No Files)
# =====================================

# --- Main Header ---
TIMESTAMP=$(date)
echo "====================================================="
echo "    SYSTEM HEALTH & SECURITY AUDIT"
echo "    Timestamp: $TIMESTAMP"
echo "====================================================="

# 1. System Resources
echo -e "\n--- [ 📊 System Resources ] --------------------------\n"

# --- CPU Check ---
CPU_USAGE=$(top -bn1 | grep "Cpu(s)" | awk '{usage=$2+$4; printf("%.1f", usage)}')
CPU_TAG="[OK]"
if (( $(echo "$CPU_USAGE > 75" | bc -l) )); then CPU_TAG="[CRITICAL]"
elif (( $(echo "$CPU_USAGE > 50" | bc -l) )); then CPU_TAG="[WARNING]"
fi
echo "${CPU_TAG} CPU Usage: $CPU_USAGE%"

# --- Memory Check ---
MEM_HUMAN=$(free -h | awk 'NR==2{print "Used: " $3 " / Total: " $2}')
MEM_CALC=$(free -m | awk 'NR==2{print $3, $2}')
MEM_USED_M=$(echo $MEM_CALC | awk '{print $1}')
MEM_TOTAL_M=$(echo $MEM_CALC | awk '{print $2}')
MEM_PERCENT=$(awk -v used="$MEM_USED_M" -v total="$MEM_TOTAL_M" 'BEGIN {if (total > 0) printf "%.1f", (used/total)*100; else print "0.0"}')
MEM_TAG="[OK]"
if (( $(echo "$MEM_PERCENT > 90" | bc -l) )); then MEM_TAG="[CRITICAL]"
elif (( $(echo "$MEM_PERCENT > 75" | bc -l) )); then MEM_TAG="[WARNING]"
fi
echo "${MEM_TAG} Memory Usage: $MEM_PERCENT% ($MEM_HUMAN)"

# --- Disk Check ---
DISK_STATS=$(df -h / | awk 'NR==2{print $5, $3, $2}')
DISK_PERCENT_NUM=$(echo $DISK_STATS | awk '{print $1}' | tr -d '%')
DISK_USED=$(echo $DISK_STATS | awk '{print $2}')
DISK_TOTAL=$(echo $DISK_STATS | awk '{print $3}')
DISK_TAG="[OK]"
if [ "$DISK_PERCENT_NUM" -gt 80 ]; then DISK_TAG="[CRITICAL]"
elif [ "$DISK_PERCENT_NUM" -gt 60 ]; then DISK_TAG="[WARNING]"
fi
echo "${DISK_TAG} Disk Usage (/): $DISK_PERCENT_NUM% (Used: $DISK_USED / Total: $DISK_TOTAL)"

# 2. System Uptime
echo -e "\n--- [ ⏱️ System Uptime ] -----------------------------\n"
uptime | sed 's/^[ \t]*//'

# 3. Network Info
echo -e "\n--- [ 🌐 Active Network Connections ] -----------------\n"
echo "Netid  State   Recv-Q  Send-Q    Local Address:Port     Peer Address:Port"
ss -tuna | tail -n +2

# 4. Security Log Check
echo -e "\n--- [ 🔐 Failed Login Analysis (Last 5) ] -----------\n"
trusted_ips=("127.0.0.1" "::1" "local" "192.168." "10." "172.16." "172.17." "172.18." "172.19." "172.20." "172.21." "172.22." "172.23." "172.24." "172.25." "172.26." "172.27." "172.28." "172.29." "172.30." "172.31.")
is_trusted_ip() {
    local ip=$1
    for trusted in "${trusted_ips[@]}"; do
        if [[ "$ip" == "$trusted"* ]]; then return 0; fi
    done
    return 1
}

if [ -f /var/log/auth.log ]; then
    sudo grep "Failed password" /var/log/auth.log | tail -5 | while read line; do
        ip=$(echo $line | awk '{for(i=1;i<=NF;i++){if($i=="from"){print $(i+1)}}}')
        if [[ -z "$ip" ]]; then ip="local"; fi

        if [[ "$ip" == "127.0.0.1" || "$ip" == "::1" || "$ip" == "local" ]]; then
            echo "[LOCALHOST]  $line"
        elif is_trusted_ip "$ip"; then
            echo "[LOCAL IP]   $line"
        else
            echo "[UNKNOWN IP] $line"
        fi
    done
else
    echo "No auth.log found (WSL or restricted permissions)"
fi

# --- Footer ---
echo -e "\n====================================================="
echo "    AUDIT COMPLETE"
echo "====================================================="