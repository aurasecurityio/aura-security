# AuraSecurity Monitoring

Enterprise-grade monitoring for the AuraSecurity Telegram bot.

## Quick Setup (5 minutes)

### 1. AWS CloudWatch Alarms (Recommended)

```bash
# Set up SNS topic and alarms
export SNS_TOPIC_ARN=$(aws sns create-topic --name aura-security-alerts --query 'TopicArn' --output text)

# Subscribe your email
aws sns subscribe --topic-arn $SNS_TOPIC_ARN --protocol email --notification-endpoint your@email.com

# Create alarms
chmod +x cloudwatch-alarms.sh
./cloudwatch-alarms.sh
```

This creates alerts for:
- Lambda errors (>5 in 5 minutes)
- Lambda throttling (any)
- Slow responses (>60s average)
- No traffic for 30 minutes (bot may be disconnected)

### 2. Server Health Check (Active)

```bash
# On your EC2 server - already running every 5 minutes
crontab -l | grep health-check

# View logs
tail -50 /tmp/aura-health.log
```

For comprehensive bot monitoring:
```bash
chmod +x bot-health-check.sh

# Add to crontab
*/5 * * * * /path/to/monitoring/bot-health-check.sh >> /var/log/aura-cron.log 2>&1
```

Optional: Add webhook URLs for alerts
```bash
export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK"
export TELEGRAM_ADMIN_CHAT="your_chat_id"
export BOT_TOKEN="your_bot_token"
```

### 3. External Uptime Monitoring (Highly Recommended)

Use a free external service to monitor from outside AWS:

**UptimeRobot (Free - 50 monitors)**
1. Go to https://uptimerobot.com
2. Add HTTP monitor: `https://app.aurasecurity.io/info`
3. Add HTTP monitor: `https://app.aurasecurity.io/scanner/info`
4. Set check interval: 5 minutes
5. Add alert contacts (email, Telegram, Slack)

**Better Uptime (Free tier)**
1. Go to https://betteruptime.com
2. Similar setup, includes status page

## Monitoring Endpoints

| Endpoint | Purpose | Expected Response |
|----------|---------|-------------------|
| `https://app.aurasecurity.io/info` | Main API | `{"name":"aura-security"...}` |
| `https://app.aurasecurity.io/scanner/info` | Scanner agent | `{"name":"scanner-agent"...}` |
| `https://app.aurasecurity.io/coordinator/info` | Coordinator | `{"name":"coordinator"...}` |
| Lambda `/health` | Bot health | `{"status":"ok"...}` |

## Alert Channels

### Slack Webhook
```bash
curl -X POST -H 'Content-type: application/json' \
    --data '{"text":"Alert: Service down!"}' \
    "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
```

### Discord Webhook
```bash
curl -X POST -H 'Content-type: application/json' \
    --data '{"content":"Alert: Service down!"}' \
    "https://discord.com/api/webhooks/YOUR/WEBHOOK"
```

### Telegram (to admin)
```bash
curl -X POST "https://api.telegram.org/bot${BOT_TOKEN}/sendMessage" \
    -d "chat_id=${ADMIN_CHAT_ID}" \
    -d "text=Service Alert: API is down!"
```

## Runbook: Common Issues

### Bot not responding
1. Check Lambda CloudWatch logs
2. Check webhook is set: `curl https://api.telegram.org/bot$TOKEN/getWebhookInfo`
3. Check pending updates (if >1000, may need clearing)

### Slow scans
1. `fastMode: true` should be enabled (skips semgrep/checkov)
2. Check EC2 CPU/memory usage
3. Check GitHub API rate limits

### Rate limiting
- GitHub API: 5000 requests/hour with token
- Twitter API: 450 requests/15 min
- Telegram: 30 messages/second

## Files

| File | Purpose |
|------|---------|
| `health-check.sh` | Basic endpoint monitoring |
| `bot-health-check.sh` | Comprehensive bot health check |
| `cloudwatch-alarms.sh` | AWS CloudWatch alarm setup |
| `set-bot-logo.sh` | Instructions for bot profile photo |

## Quick Commands

```bash
# Check health manually
./health-check.sh && echo "All good!"

# View health logs
tail -50 /tmp/aura-health.log

# Check Lambda webhook
curl -s "https://api.telegram.org/bot$BOT_TOKEN/getWebhookInfo" | jq

# Test specific endpoint
curl -s -w "\n%{http_code}" https://app.aurasecurity.io/info
```
