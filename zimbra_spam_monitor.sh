#!/bin/bash
################################################################################
# Zimbra Spam & Email Abuse Monitor (Server-Side)
# Purpose: Detect compromised accounts & unusual email activity
# Author: IT Team PT MJL
# Location: /opt/zimbra/scripts/zimbra_spam_monitor.sh
################################################################################

set -euo pipefail

# ==================== CONFIGURATION ====================
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"

# Zimbra Server Info
ZIMBRA_SERVER_IP="YOUR_ZIMBRA_IP"
HOSTNAME=$(hostname)

# Alert Thresholds
EMAIL_VOLUME_THRESHOLD=50     # Alert if account sends >50 emails/hour
BOUNCE_RATE_THRESHOLD=30      # Alert if bounce rate >30%
SUSPICIOUS_VOLUME_THRESHOLD=100  # Critical alert if >100 emails/hour

# Log Files
LOCAL_LOG_DIR="/opt/zimbra/.log-zimbra-cleanup"
mkdir -p "${LOCAL_LOG_DIR}"
SCRIPT_LOG="${LOCAL_LOG_DIR}/zimbra_spam_monitor.log"
TRACKED_IPS="/tmp/zimbra_tracked_ips.dat" # Shared with security monitor

# Monitoring Window
MONITORING_WINDOW_HOURS=1  # Check last 1 hour

# ==================== FUNCTIONS ====================

log() {
    local timestamp=$(date '+%b %d %Y - %H:%M:%S')
    echo "[${timestamp}] [SPAM-MONITOR] $1" | tee -a "${SCRIPT_LOG}"
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

check_email_volume() {
    log "Checking email volume per account (last ${MONITORING_WINDOW_HOURS}h)..."
    
    # Analyze mailbox.log locally
    local volume_data=$(
        grep "$(date '+%b %d')" /opt/zimbra/log/mailbox.log 2>/dev/null | \
        grep -i "lmtp.*delivered" | \
        grep -oP 'oip=\K[^,]+|name=\K[^,]+' | \
        paste -d',' - - | \
        awk -F',' '{count[$2]++} END {for(email in count) print count[email], email}' | \
        sort -rn | head -20
    )
    
    if [ -z "$volume_data" ]; then
        log "No significant email activity detected"
        return 0
    fi
    
    # Process results
    echo "$volume_data" | while read count email; do
        if [ -z "$email" ] || [ -z "$count" ]; then continue; fi
        
        log "Account ${email}: ${count} emails sent in last hour"
        
        # Alert for suspicious volume
        if [ "$count" -ge "$SUSPICIOUS_VOLUME_THRESHOLD" ]; then
            send_critical_volume_alert "$email" "$count"
        elif [ "$count" -ge "$EMAIL_VOLUME_THRESHOLD" ]; then
            send_volume_alert "$email" "$count"
        fi
    done
}

send_volume_alert() {
    local account=$1
    local count=$2
    
    local message="📧 <b>High Email Volume Alert</b>

⚠️ <b>Unusual Email Activity Detected</b>

📬 <b>Account:</b> <code>${account}</code>
📊 <b>Emails Sent:</b> ${count} in last ${MONITORING_WINDOW_HOURS} hour(s)
⏰ <b>Time:</b> $(date '+%Y-%m-%d %H:%M:%S')
🔗 <b>Server:</b> ${HOSTNAME}

⚠️ <b>Threshold:</b> ${EMAIL_VOLUME_THRESHOLD} emails/hour

💡 <b>Recommended Actions:</b>
• Review account activity
• Check if account password was compromised"
    
    send_telegram "$message"
}

send_critical_volume_alert() {
    local account=$1
    local count=$2
    
    local message="🚨 <b>CRITICAL: Potential Spam Account</b> 🚨

⛔ <b>EXTREMELY High Email Volume!</b>

📬 <b>Account:</b> <code>${account}</code>
📊 <b>Emails Sent:</b> <u>${count}</u> (Threshold: ${SUSPICIOUS_VOLUME_THRESHOLD})
⏰ <b>Time:</b> $(date '+%Y-%m-%d %H:%M:%S')

⚡ <b>URGENT ACTIONS REQUIRED:</b>
1. <b>SUSPEND account immediately</b>
   <code>zmprov ma ${account} zimbraAccountStatus locked</code>
2. Review login history"
    
    send_telegram "$message"
}

check_bounce_rate() {
    log "Checking bounce rate per account..."
    
    # Check zimbra.log locally
    local bounce_data=$(
        grep "$(date '+%b %d')" /var/log/zimbra.log 2>/dev/null | \
        grep "status=bounced" | \
        grep -oP 'from=<\K[^>]+' | \
        sort | uniq -c | sort -rn | head -10
    )
    
    if [ -z "$bounce_data" ]; then return 0; fi
    
    echo "$bounce_data" | while read bounces email; do
        if [ "$bounces" -ge 10 ]; then
            log "Account ${email}: ${bounces} bounced emails"
            send_bounce_alert "$email" "$bounces"
        fi
    done
}

send_bounce_alert() {
    local account=$1
    local bounce_count=$2
    
    local message="⚠️ <b>High Bounce Rate Alert</b>

📨 <b>Suspicious Bounce Pattern Detected</b>

📬 <b>Account:</b> <code>${account}</code>
📉 <b>Bounced Emails:</b> ${bounce_count}
🔗 <b>Server:</b> ${HOSTNAME}

🚨 <b>Possible Indicators:</b>
• Spam campaign usage
• Sending to invalid/purchased email lists"
    
    send_telegram "$message"
}

check_successful_login_after_failure() {
    log "Checking for successful logins after failed attempts..."
    
    # Get IPs that had recent failed attempts
    if [ ! -f "${TRACKED_IPS}" ]; then return 0; fi
    
    # Get today's successful logins from mailbox.log
    local successful_logins=$(
        grep "$(date '+%b %d')" /opt/zimbra/log/mailbox.log 2>/dev/null | \
        grep -i "authentication succeeded" | \
        grep -oP 'account=\K[^,]+|oip=\K[0-9.]+' | \
        paste -d',' - - | tail -20
    )
    
    if [ -z "$successful_logins" ]; then return 0; fi
    
    # Match IPs
    while IFS= read -r line; do
        local suspicious_ip=$(echo "$line" | cut -d: -f1)
        
        echo "$successful_logins" | while IFS=',' read ip account; do
            if [ "$ip" = "$suspicious_ip" ]; then
                log "ALERT: IP $ip had failed attempts and now successful login to $account"
                send_compromised_alert "$account" "$ip"
            fi
        done
    done < "${TRACKED_IPS}"
}

send_compromised_alert() {
    local account=$1
    local ip=$2
    
    local message="🔓 <b>Potential Account Compromise!</b>

⚠️ <b>Successful Login After Brute Force</b>

📬 <b>Account:</b> <code>${account}</code>
📍 <b>IP Address:</b> <code>${ip}</code>
⏰ <b>Time:</b> $(date '+%Y-%m-%d %H:%M:%S')

⚡ <b>IMMEDIATE ACTIONS:</b>
1. <b>Force password reset</b>
2. <b>Lock Account:</b>
   <code>zmprov ma ${account} zimbraAccountStatus locked</code>"
    
    send_telegram "$message"
}

# ==================== MAIN ====================

check_email_volume
check_bounce_rate
check_successful_login_after_failure

log "Spam check completed"
