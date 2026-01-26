#!/bin/bash
# AuraSecurity Health Check Monitor
# Runs every 5 minutes via cron to detect outages

SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
LOG_FILE="/tmp/aura-health.log"

alert() {
    local message=$1
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $message" | tee -a $LOG_FILE

    # Slack alert
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$message\"}" "$SLACK_WEBHOOK" > /dev/null
    fi

    # Discord alert
    if [ -n "$DISCORD_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"content\":\"$message\"}" "$DISCORD_WEBHOOK" > /dev/null
    fi
}

check_endpoint() {
    local name=$1
    local url=$2

    response=$(curl -s -o /dev/null -w "%{http_code}" --max-time 15 "$url" 2>/dev/null)

    if [ "$response" != "200" ]; then
        alert "🚨 *ALERT*: $name is DOWN (HTTP $response)"
        return 1
    fi
    return 0
}

# Track failures
failures=0

# Check core services
check_endpoint "Main API" "https://app.aurasecurity.io/info" || ((failures++))
check_endpoint "Scanner" "https://app.aurasecurity.io/scanner/info" || ((failures++))
check_endpoint "Coordinator" "https://app.aurasecurity.io/coordinator/info" || ((failures++))
check_endpoint "Web UI" "https://app.aurasecurity.io/app" || ((failures++))

# Summary
if [ $failures -eq 0 ]; then
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] All services healthy" >> $LOG_FILE
else
    alert "⚠️ $failures service(s) are down - check immediately!"
fi

exit $failures
