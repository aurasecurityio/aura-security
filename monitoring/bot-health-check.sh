#!/bin/bash
# AuraSecurity Bot Health Monitor
# Tests actual bot functionality, not just endpoints
# Run every 5 minutes via cron

set -e

SLACK_WEBHOOK="${SLACK_WEBHOOK:-}"
DISCORD_WEBHOOK="${DISCORD_WEBHOOK:-}"
TELEGRAM_ADMIN_CHAT="${TELEGRAM_ADMIN_CHAT:-}"
BOT_TOKEN="${BOT_TOKEN:-}"
LOG_FILE="/var/log/aura-bot-health.log"
STATE_FILE="/tmp/aura-health-state.json"

# Colors for terminal
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a $LOG_FILE
}

alert() {
    local message=$1
    local severity=${2:-warning}

    log "ALERT [$severity]: $message"

    # Slack
    if [ -n "$SLACK_WEBHOOK" ]; then
        local emoji="⚠️"
        [ "$severity" = "critical" ] && emoji="🚨"
        [ "$severity" = "resolved" ] && emoji="✅"

        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"$emoji $message\"}" "$SLACK_WEBHOOK" > /dev/null 2>&1 || true
    fi

    # Discord
    if [ -n "$DISCORD_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"content\":\"$message\"}" "$DISCORD_WEBHOOK" > /dev/null 2>&1 || true
    fi

    # Telegram (to admin)
    if [ -n "$TELEGRAM_ADMIN_CHAT" ] && [ -n "$BOT_TOKEN" ]; then
        curl -s -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
            -d "chat_id=${TELEGRAM_ADMIN_CHAT}" \
            -d "text=$message" > /dev/null 2>&1 || true
    fi
}

check_endpoint() {
    local name=$1
    local url=$2
    local expected_status=${3:-200}
    local timeout=${4:-15}

    local start_time=$(date +%s%N)
    local response=$(curl -s -o /tmp/health_response.txt -w "%{http_code}" --max-time $timeout "$url" 2>/dev/null || echo "000")
    local end_time=$(date +%s%N)
    local latency=$(( (end_time - start_time) / 1000000 ))

    if [ "$response" = "$expected_status" ]; then
        log "✓ $name: OK (${latency}ms)"
        echo "$latency"
        return 0
    else
        log "✗ $name: FAILED (HTTP $response)"
        echo "-1"
        return 1
    fi
}

check_bot_webhook() {
    # Check if Telegram bot webhook is properly set
    if [ -z "$BOT_TOKEN" ]; then
        log "⚠ BOT_TOKEN not set, skipping webhook check"
        return 0
    fi

    local webhook_info=$(curl -s "https://api.telegram.org/bot${BOT_TOKEN}/getWebhookInfo" 2>/dev/null)
    local webhook_url=$(echo "$webhook_info" | grep -o '"url":"[^"]*"' | cut -d'"' -f4)
    local pending=$(echo "$webhook_info" | grep -o '"pending_update_count":[0-9]*' | cut -d':' -f2)
    local last_error=$(echo "$webhook_info" | grep -o '"last_error_message":"[^"]*"' | cut -d'"' -f4)

    if [ -z "$webhook_url" ]; then
        alert "Bot webhook is NOT SET!" "critical"
        return 1
    fi

    if [ -n "$last_error" ]; then
        alert "Bot webhook error: $last_error" "warning"
    fi

    if [ -n "$pending" ] && [ "$pending" -gt 100 ]; then
        alert "Bot has $pending pending updates - may be backed up!" "warning"
    fi

    log "✓ Bot webhook: $webhook_url (pending: ${pending:-0})"
    return 0
}

check_lambda_health() {
    # Check Lambda function URL directly
    local lambda_url="https://wnvoixtc26c35hgzr3w6lsz73y0rplzd.lambda-url.us-east-1.on.aws/health"

    local response=$(curl -s --max-time 10 "$lambda_url" 2>/dev/null)
    local status=$(echo "$response" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)

    if [ "$status" = "ok" ]; then
        log "✓ Lambda health: OK"
        return 0
    else
        log "✗ Lambda health: FAILED"
        return 1
    fi
}

# Main health check
main() {
    log "========== Health Check Started =========="

    failures=0
    warnings=0

    # 1. Check core API endpoints
    log "--- Core Services ---"
    check_endpoint "Main API" "https://app.aurasecurity.io/info" || ((failures++))
    check_endpoint "Scanner Agent" "https://app.aurasecurity.io/scanner/info" || ((failures++))
    check_endpoint "Coordinator" "https://app.aurasecurity.io/coordinator/info" || ((failures++))

    # 2. Check bot infrastructure
    log "--- Bot Infrastructure ---"
    check_lambda_health || ((failures++))
    check_bot_webhook || ((warnings++))

    # 3. Check external dependencies
    log "--- External Dependencies ---"
    check_endpoint "GitHub API" "https://api.github.com/rate_limit" || ((warnings++))
    check_endpoint "Telegram API" "https://api.telegram.org" 200 5 || ((failures++))

    # 4. Summary
    log "========== Health Check Complete =========="
    log "Failures: $failures, Warnings: $warnings"

    # Load previous state
    prev_failures=0
    if [ -f "$STATE_FILE" ]; then
        prev_failures=$(cat "$STATE_FILE" | grep -o '"failures":[0-9]*' | cut -d':' -f2 || echo 0)
    fi

    # Save current state
    echo "{\"failures\":$failures,\"warnings\":$warnings,\"timestamp\":\"$(date -Iseconds)\"}" > $STATE_FILE

    # Alert on state changes
    if [ $failures -gt 0 ] && [ $prev_failures -eq 0 ]; then
        alert "🚨 OUTAGE DETECTED: $failures service(s) down!" "critical"
    elif [ $failures -eq 0 ] && [ $prev_failures -gt 0 ]; then
        alert "✅ All services recovered!" "resolved"
    elif [ $failures -gt 0 ]; then
        # Only alert every 15 minutes during ongoing outage (3 checks)
        check_count=$(cat /tmp/aura-outage-count 2>/dev/null || echo 0)
        check_count=$((check_count + 1))
        echo $check_count > /tmp/aura-outage-count

        if [ $((check_count % 3)) -eq 0 ]; then
            alert "⚠️ ONGOING OUTAGE: $failures service(s) still down (${check_count}x5min)" "critical"
        fi
    else
        rm -f /tmp/aura-outage-count 2>/dev/null || true
    fi

    exit $failures
}

main "$@"
