# Zimbra Security & Telegram Bot 🤖

Automated security monitoring for Zimbra Mail Server. Detects brute-force attacks, spam accounts, and anomalous email traffic with real-time Telegram alerts.

## Features

- **🚨 Security Monitor**:
  - Detects failed login attempts (SSH & Web) from the same IP.
  - Geolocates suspicious IPs (Country, City, ISP).
  - Alerts when failed attempts exceed threshold (default: 3).

- **📧 Spam & Abuse Monitor**:
  - **High Volume**: Alerts if an account sends >50 emails/hour.
  - **Critical Volume**: Urgently alerts if >100 emails/hour (potential compromise).
  - **High Bounce Rate**: Detects accounts sending to invalid recipients (>30% bounce).
  - **Compromise Detection**: Alerts if an IP with recent failed logins successfully logs in.

## Installation

### 1. Requirements
- Zimbra Mail Server (Tested on 8.8.15 / 9.0)
- Root access to server
- `curl` installed

### 2. Setup
Clone this repo to your Zimbra server:
```bash
cd /opt/zimbra/
git clone https://github.com/YOUR_USERNAME/zimbra-security-monitoring.git scripts
cd scripts
chmod +x *.sh
```

### 3. Configuration
Edit `zimbra_security_monitor.sh` and `zimbra_spam_monitor.sh`:
```bash
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID"
ZIMBRA_SERVER_IP="YOUR_SERVER_IP"
```

### 4. Cron Scheduler
Add these lines to `crontab -e` (root user):

```bash
# Security Monitor (Every hour)
0 * * * * /opt/zimbra/scripts/zimbra_security_monitor.sh --once

# Spam/Abuse Monitor (Every hour at :30)
30 * * * * /opt/zimbra/scripts/zimbra_spam_monitor.sh
```

## Logs
Logs are stored in `/opt/zimbra/.log-zimbra-cleanup/`:
- `zimbra_security_monitor.log` - Login attempts
- `zimbra_spam_monitor.log` - Email volume/bounce activity

## Disclaimer
These scripts are provided AS IS. Test in a staging environment before deploying to production.
