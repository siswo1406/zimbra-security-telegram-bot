#!/bin/bash
################################################################################
# Zimbra Security Monitor (Server-Side)
# Purpose: Monitor failed login attempts and send alerts to Telegram
# Features: Top 20 Limit, Pattern Detection (SSH/Web), Smart Block Command, Local User Filter
# Author: IT Team PT MJL
# Location: /opt/zimbra/scripts/zimbra_security_monitor.sh
################################################################################

set -euo pipefail

# ==================== CONFIGURATION ====================
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"

# Zimbra Server Info
ZIMBRA_SERVER_IP="YOUR_ZIMBRA_IP"
HOSTNAME=$(hostname)

# Log Files
LOCAL_LOG_DIR="/opt/zimbra/.log-zimbra-cleanup"
mkdir -p "${LOCAL_LOG_DIR}"

SCRIPT_LOG="${LOCAL_LOG_DIR}/zimbra_security_monitor.log"
TRACKED_IPS="/tmp/zimbra_tracked_ips.dat"

# Monitoring Configuration
FAILED_THRESHOLD=3   # Alert after 3 failed attempts from same IP
WHITELIST_IPS="127.0.0.1 192.168.4.5 192.168.4.1" # Local/Trusted IPs

# ==================== FUNCTIONS ====================

log() {
    # Consistent Log Format: [Mon DD YYYY - HH:MM:SS] [CATEGORY] Message
    local timestamp=$(date '+%b %d %Y - %H:%M:%S')
    echo "[${timestamp}] [SECURITY] $1" | tee -a "${SCRIPT_LOG}"
}

send_telegram() {
    local message="$1"
    local parse_mode="${2:-HTML}"
    
    curl -s -X POST \
        "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
        -d chat_id="${TELEGRAM_CHAT_ID}" \
        -d text="${message}" \
        -d parse_mode="${parse_mode}" \
        > /dev/null 2>&1
}

get_ip_location_short() {
    local ip=$1
    # Get short location: "Country" only to save space in summary
    local location=$(curl -s "http://ip-api.com/json/${ip}?fields=country" 2>/dev/null)
    
    if [ $? -eq 0 ] && [ -n "$location" ]; then
        echo "$location" | grep -o '"country":"[^"]*"' | cut -d'"' -f4
    else
        echo "Unknown"
    fi
}

get_attack_pattern() {
    local ip=$1
    # Check SSH (Secure/Auth Log)
    local ssh_user=$(grep "$ip" /var/log/secure /var/log/auth.log 2>/dev/null | grep "Failed password" | tail -1 | sed -n 's/.*for \(invalid user \)\?\([^ ]*\) from.*/\2/p')
    
    if [ -n "$ssh_user" ]; then
        echo "SSH:${ssh_user}"
        return
    fi
    
    # Check Zimbra (Mailbox Log)
    local zim_user=$(grep "$ip" /opt/zimbra/log/mailbox.log 2>/dev/null | grep "authentication failed" | tail -1 | grep -oP 'authentication failed for \[\K[^\]]+')
    
    if [ -n "$zim_user" ]; then
        # Take username only (remove @domain) to save space
        local short_user=$(echo "$zim_user" | cut -d'@' -f1)
        echo "WEB:${short_user}"
        return
    fi
    
    echo "UNK:N/A"
}

get_last_attack_time() {
    local ip=$1
    local last_time=$(grep "$ip" /var/log/secure /var/log/auth.log 2>/dev/null | grep "Failed" | tail -1 | awk '{print $3}')
    if [ -z "$last_time" ]; then
        last_time=$(grep "$ip" /opt/zimbra/log/mailbox.log 2>/dev/null | grep "authentication failed" | tail -1 | awk '{print $2}' | cut -d',' -f1)
    fi
    echo "${last_time:-N/A}"
}

is_ip_blocked() {
    local ip=$1
    if iptables -vnL INPUT 2>/dev/null | grep -q "$ip"; then
        return 0 # True, blocked
    else
        return 1 # False, not blocked
    fi
}

check_failed_logins() {
    log "Checking for failed login attempts (Top 20 Unblocked IPs)..."
    
    # 1. Analyze logs directly on the server to get counts
    local failed_attempts=$(
    {
        # --- RHEL/CentOS Secure Log ---
        grep "$(date '+%b %d')" /var/log/secure 2>/dev/null | grep "Failed password" | \
            awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}'
        
        grep "$(date '+%b %d')" /var/log/secure 2>/dev/null | grep "authentication failure" | \
            grep -oP 'rhost=\K\S+' 

        # --- Debian/Ubuntu Auth Log ---
        grep "$(date '+%b %d')" /var/log/auth.log 2>/dev/null | grep "Failed password" | \
            awk '{for(i=1;i<=NF;i++) if($i=="from") print $(i+1)}'

        # --- Zimbra Mailbox Log (Format: YYYY-MM-DD) ---
        grep "$(date '+%Y-%m-%d')" /opt/zimbra/log/mailbox.log 2>/dev/null | \
            grep -i "authentication failed" | \
            grep -oP 'ip=\K[0-9.]+' 
            
    } | sort | uniq -c | sort -rn | awk '{ip[$2]+=$1} END {for(i in ip) print ip[i], i}' | sort -rn
    )
    
    if [ -z "$failed_attempts" ]; then
        log "No failed login attempts found"
        return 0
    fi
    
    # 2. Process IPs
    local summary_report=""
    local alert_count=0
    local block_list_cmd=""
    
    while read count ip; do
        if [ -z "$ip" ] || [ "$ip" = "from" ]; then continue; fi
        if [ "$count" -lt "$FAILED_THRESHOLD" ]; then continue; fi
        
        # Stop processing if we reached 20 alerts
        if [ "$alert_count" -ge 20 ]; then break; fi

        # Whitelist Check
        if [[ " ${WHITELIST_IPS} " =~ " ${ip} " ]]; then
            log "[SKIP] Whitelisted Trusted IP: $ip"
            continue
        fi

        # Filter Blocked IPs
        if is_ip_blocked "$ip"; then
            continue
        fi

        # Gather Information Needed for Logic
        local country=$(get_ip_location_short "$ip")
        local pattern=$(get_attack_pattern "$ip")
        local last_time=$(get_last_attack_time "$ip")

        # --- SMART FILTER: Skipping Indonesian Web Users (Likely Employee Error) ---
        if [[ "$country" == "Indonesia" ]] && [[ "$pattern" == WEB:* ]]; then
            log "[USER_ERROR] $ip (Indonesia) | Count: $count | $pattern | Action: Logged Only (Skipping Alert)"
            continue
        fi

        # Otherwise: Treat as Threat
        log "[THREAT] $ip ($country) | Count: $count | $pattern | Action: Added to Report"

        # Increase Alert Count
        alert_count=$((alert_count + 1))
        
        # Add to Report
        summary_report="${summary_report}
👉 <b>${ip}</b> (${country})
   Qt: <b>${count}x</b> | Time: ${last_time} | 🎯 <b>${pattern}</b>"

        # Add to block command list
        block_list_cmd="${block_list_cmd}${ip},"
    done <<< "$failed_attempts"

    # 3. Send Telegram if there are NEW threats
    if [ "$alert_count" -gt 0 ]; then
        block_list_cmd=${block_list_cmd%,}
        
        local header="🚨 <b>Zimbra Security Summary</b>
Detected <b>${alert_count} Active Attackers</b> (Not Blocked):"
        
        local footer="
⚠️ <b>Action Required!</b>
To block all these IPs at once, run:

<code>iptables -I INPUT -s ${block_list_cmd} -j DROP</code>"

        send_telegram "${header}${summary_report}${footer}"
        log "[ALERT] Sent summary report for ${alert_count} new IPs."
    else
        log "[INFO] No actionable threats found (Local errors filtered or already blocked)."
    fi
}

# ==================== MAIN ====================

if [[ "${1:-}" == "--once" ]]; then
    # Run single check
    check_failed_logins
    exit 0
fi

echo "Usage: $0 --once"
