# AuraSecurity Monitoring

## Active Monitoring

### 1. Server Health Check (Running)
- **Script**: `~/health-check.sh` on production server
- **Frequency**: Every 5 minutes via cron
- **Checks**: Main API, Scanner, Coordinator, Web UI

### 2. Set Up Alerts (Choose One)

#### Option A: Slack Alerts (Recommended)
1. Create a Slack webhook: https://api.slack.com/messaging/webhooks
2. Add to server:
```bash
ssh ubuntu@54.90.137.98
echo 'export SLACK_WEBHOOK="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"' >> ~/.bashrc
source ~/.bashrc
```

#### Option B: Discord Alerts
1. Create a Discord webhook in your server settings
2. Add to server:
```bash
ssh ubuntu@54.90.137.98
echo 'export DISCORD_WEBHOOK="https://discord.com/api/webhooks/YOUR/WEBHOOK"' >> ~/.bashrc
source ~/.bashrc
```

### 3. External Uptime Monitoring (Highly Recommended)

Use a free external service to monitor from outside your infrastructure:

#### UptimeRobot (Free - 50 monitors)
1. Go to https://uptimerobot.com
2. Add monitors:
   - `https://app.aurasecurity.io/info` (Main API)
   - `https://app.aurasecurity.io/scanner/info` (Scanner)
   - TG Bot health endpoint (if available)
3. Set alert contacts (email, Slack, SMS)

#### Better Uptime (Free tier)
1. Go to https://betteruptime.com
2. Similar setup - monitors + incident pages

### 4. TG Bot Lambda Monitoring (AWS)

```bash
# Error alarm - alerts when bot errors > 3 in 5 minutes
aws cloudwatch put-metric-alarm \
  --alarm-name "TG-Bot-Errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 3 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=AuraSecurityTelegramBot \
  --evaluation-periods 1 \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT:alerts

# Duration alarm - alerts when bot is slow (approaching timeout)
aws cloudwatch put-metric-alarm \
  --alarm-name "TG-Bot-Slow" \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 120000 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=AuraSecurityTelegramBot \
  --evaluation-periods 2 \
  --alarm-actions arn:aws:sns:us-east-1:YOUR_ACCOUNT:alerts
```

## Status Page (Optional)

Create a public status page for users:

1. **Instatus** (free): https://instatus.com
2. **Cachet** (self-hosted): https://cachethq.io

## Quick Commands

```bash
# Check health manually
~/health-check.sh && echo "All good!"

# View health logs
tail -50 /tmp/aura-health.log

# Test a specific endpoint
curl -s -o /dev/null -w "%{http_code}" https://app.aurasecurity.io/info
```
