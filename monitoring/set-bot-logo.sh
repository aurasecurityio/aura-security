#!/bin/bash
# Set Telegram Bot Profile Photo
# Usage: ./set-bot-logo.sh <BOT_TOKEN> <IMAGE_PATH>

BOT_TOKEN=$1
IMAGE_PATH=$2

if [ -z "$BOT_TOKEN" ] || [ -z "$IMAGE_PATH" ]; then
    echo "Usage: ./set-bot-logo.sh <BOT_TOKEN> <IMAGE_PATH>"
    echo "Example: ./set-bot-logo.sh 123456:ABC-DEF ./logo.png"
    exit 1
fi

if [ ! -f "$IMAGE_PATH" ]; then
    echo "Error: Image file not found: $IMAGE_PATH"
    exit 1
fi

echo "Setting bot profile photo..."

# Set profile photo
curl -F "photo=@$IMAGE_PATH" \
    "https://api.telegram.org/bot${BOT_TOKEN}/setMyPhoto"

echo ""
echo "Done! Check your bot profile to confirm."
