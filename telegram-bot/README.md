# AuraSecurity Telegram Bot

Telegram bot for checking developer trust scores and code security.

## Commands

| Command | Description |
|---------|-------------|
| `/devcheck @username` | Full dev audit (identity + security) |
| `/xcheck @username` | Same as devcheck |
| `/rugcheck <github-url>` | Trust score for repo |
| `/scan <github-url>` | Full security scan |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `BOT_TOKEN` | Telegram bot token from @BotFather |
| `X_BEARER_TOKEN` | Twitter/X API bearer token |
| `ANTHROPIC_API_KEY` | Claude API key for AI analysis |
| `AURA_API_URL` | Aura Security API URL (default: https://app.aurasecurity.io) |

## Deployment (AWS Lambda)

1. Zip the file:
   ```bash
   zip function.zip index.mjs
   ```

2. Deploy to Lambda:
   ```bash
   aws lambda update-function-code \
     --function-name AuraSecurityTelegramBot \
     --zip-file fileb://function.zip
   ```

3. Set up API Gateway trigger pointing to the Lambda

4. Set Telegram webhook:
   ```bash
   curl "https://api.telegram.org/bot<BOT_TOKEN>/setWebhook?url=<API_GATEWAY_URL>"
   ```

## Features

- **Trust Score**: Combines X profile analysis + GitHub verification + security scan
- **Social Stats**: Follower quality, tweet analysis, following check
- **Security Scan**: Detects secrets, vulnerabilities via Aura API
- **AI Analysis**: Claude-powered deep dive on profiles
- **GOAT Detection**: Identifies elite verified developers

## Architecture

```
User → Telegram → API Gateway → Lambda (this bot) → Aura API
                                    ↓
                              X API + GitHub API
```
