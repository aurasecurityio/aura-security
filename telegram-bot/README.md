# AuraSecurity Telegram Bot

**Mission-critical** Telegram bot for checking developer trust scores and code security.

Bot: [@aurasecuritychecker_bot](https://t.me/aurasecuritychecker_bot)

## Commands

| Command | Description |
|---------|-------------|
| `/devcheck @username` | Full dev audit (identity + security) |
| `/xcheck @username` | Same as devcheck |
| `/rugcheck <github-url>` | Trust score for repo |
| `/scan <github-url>` | Full security scan |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `BOT_TOKEN` | Yes | Telegram bot token from @BotFather |
| `X_BEARER_TOKEN` | Yes | Twitter/X API bearer token |
| `ANTHROPIC_API_KEY` | Yes | Claude API key for AI analysis |
| `AURA_API_URL` | No | Aura Security API URL (default: https://app.aurasecurity.io) |

## Reliability Features

This bot is designed for **zero downtime**:

- **Retry Logic**: All API calls retry 3x with exponential backoff
- **Timeouts**: 3-minute timeout for scans (handles large repos)
- **Graceful Errors**: Users always get a response, even on failures
- **Health Check**: `/health` endpoint for monitoring

## Deployment (AWS Lambda)

### Initial Setup

1. Create Lambda function:
   ```bash
   aws lambda create-function \
     --function-name AuraSecurityTelegramBot \
     --runtime nodejs20.x \
     --handler index.handler \
     --timeout 180 \
     --memory-size 512 \
     --role arn:aws:iam::ACCOUNT:role/lambda-execution-role
   ```

2. Set environment variables:
   ```bash
   aws lambda update-function-configuration \
     --function-name AuraSecurityTelegramBot \
     --environment "Variables={BOT_TOKEN=xxx,X_BEARER_TOKEN=xxx,ANTHROPIC_API_KEY=xxx}"
   ```

3. Create API Gateway trigger (HTTP API, not REST API)

4. Set Telegram webhook:
   ```bash
   curl "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=<API_GATEWAY_URL>"
   ```

### Deploy Updates

```bash
cd telegram-bot
zip function.zip index.mjs
aws lambda update-function-code \
  --function-name AuraSecurityTelegramBot \
  --zip-file fileb://function.zip
```

## Monitoring & Alerts (CRITICAL)

### 1. CloudWatch Alarms (Required)

Create these alarms in AWS CloudWatch:

```bash
# Error rate alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "TelegramBot-Errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=FunctionName,Value=AuraSecurityTelegramBot \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:alerts

# Throttle alarm
aws cloudwatch put-metric-alarm \
  --alarm-name "TelegramBot-Throttled" \
  --metric-name Throttles \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --threshold 1 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 1 \
  --dimensions Name=FunctionName,Value=AuraSecurityTelegramBot \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:alerts

# Duration alarm (approaching timeout)
aws cloudwatch put-metric-alarm \
  --alarm-name "TelegramBot-SlowResponses" \
  --metric-name Duration \
  --namespace AWS/Lambda \
  --statistic Average \
  --period 300 \
  --threshold 150000 \
  --comparison-operator GreaterThanThreshold \
  --evaluation-periods 2 \
  --dimensions Name=FunctionName,Value=AuraSecurityTelegramBot \
  --alarm-actions arn:aws:sns:us-east-1:ACCOUNT:alerts
```

### 2. Health Check Monitoring

Set up external uptime monitoring (UptimeRobot, Better Uptime, etc.):

- URL: `https://<API_GATEWAY_URL>/health`
- Method: GET
- Expected response: `{"status":"ok",...}`
- Check interval: 5 minutes
- Alert on: Non-200 response or timeout

### 3. Log Insights Query

Use this CloudWatch Logs Insights query to find errors:

```
fields @timestamp, @message
| filter @message like /error|Error|ERROR|failed|Failed/
| sort @timestamp desc
| limit 50
```

## Scaling Considerations

### Current Limits
- Lambda concurrent executions: 1000 (default)
- Lambda timeout: 180 seconds (3 minutes)
- Memory: 512 MB

### If You Need More Scale

1. **Request concurrency increase** from AWS (free):
   ```bash
   aws service-quotas request-service-quota-increase \
     --service-code lambda \
     --quota-code L-B99A9384 \
     --desired-value 3000
   ```

2. **Provision concurrency** for consistent performance:
   ```bash
   aws lambda put-provisioned-concurrency-config \
     --function-name AuraSecurityTelegramBot \
     --qualifier '$LATEST' \
     --provisioned-concurrent-executions 10
   ```

## Architecture

```
User --> Telegram --> API Gateway --> Lambda (this bot) --> Aura API
                                          |
                                          +--> X API + Claude API
```

## Troubleshooting

### Bot not responding
1. Check Lambda errors: CloudWatch > Log Groups > /aws/lambda/AuraSecurityTelegramBot
2. Verify webhook: `curl "https://api.telegram.org/bot<TOKEN>/getWebhookInfo"`
3. Check API Gateway: Ensure it's pointing to correct Lambda
4. Test health check: `curl <API_GATEWAY_URL>/health`

### Slow responses
1. Check Aura API: `curl https://app.aurasecurity.io/info`
2. Monitor Lambda duration in CloudWatch metrics
3. Consider increasing memory (also increases CPU)

### Rate limited
1. Twitter API: Check X Developer Portal for usage
2. Claude API: Check Anthropic Console for quota
3. Lambda: Check CloudWatch for throttles

## Emergency Procedures

### If Bot Goes Down

1. **Check Lambda**:
   ```bash
   aws lambda get-function --function-name AuraSecurityTelegramBot
   ```

2. **Check Recent Errors**:
   ```bash
   aws logs tail /aws/lambda/AuraSecurityTelegramBot --since 1h
   ```

3. **Redeploy**:
   ```bash
   cd telegram-bot
   zip function.zip index.mjs
   aws lambda update-function-code \
     --function-name AuraSecurityTelegramBot \
     --zip-file fileb://function.zip
   ```

4. **Reset Webhook** (if needed):
   ```bash
   curl "https://api.telegram.org/bot<TOKEN>/deleteWebhook"
   curl "https://api.telegram.org/bot<TOKEN>/setWebhook?url=<API_GATEWAY_URL>"
   ```

### If Aura API Goes Down

The bot will automatically:
1. Retry 2x with exponential backoff
2. Return user-friendly error message
3. Continue working for non-scan commands (devcheck, rugcheck basic)

To fix Aura API, SSH to server and restart:
```bash
ssh -i ~/.ssh/slop-auditor-key.pem ubuntu@54.90.137.98
cd ~/slop-security-auditor
kill $(lsof -t -i:3000); nohup node dist/index.js > api.log 2>&1 &
```
