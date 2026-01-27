#!/bin/bash
# Set up CloudWatch Alarms for AuraSecurity Bot
# Run once to create alarms in AWS

LAMBDA_FUNCTION="aurasecurity-telegram-bot"
SNS_TOPIC_ARN="${SNS_TOPIC_ARN:-}"  # Create SNS topic first for alerts

if [ -z "$SNS_TOPIC_ARN" ]; then
    echo "Creating SNS topic for alerts..."
    SNS_TOPIC_ARN=$(aws sns create-topic --name aura-security-alerts --query 'TopicArn' --output text)
    echo "Created: $SNS_TOPIC_ARN"
    echo ""
    echo "Subscribe your email/phone:"
    echo "  aws sns subscribe --topic-arn $SNS_TOPIC_ARN --protocol email --notification-endpoint your@email.com"
    echo ""
fi

echo "Setting up CloudWatch alarms for Lambda: $LAMBDA_FUNCTION"

# 1. Lambda Errors Alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "AuraSecurity-Lambda-Errors" \
    --alarm-description "Alert when Lambda has errors" \
    --metric-name Errors \
    --namespace AWS/Lambda \
    --statistic Sum \
    --period 300 \
    --threshold 5 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION \
    --evaluation-periods 1 \
    --alarm-actions $SNS_TOPIC_ARN \
    --ok-actions $SNS_TOPIC_ARN

echo "✓ Lambda Errors alarm created"

# 2. Lambda Throttles Alarm
aws cloudwatch put-metric-alarm \
    --alarm-name "AuraSecurity-Lambda-Throttles" \
    --alarm-description "Alert when Lambda is being throttled" \
    --metric-name Throttles \
    --namespace AWS/Lambda \
    --statistic Sum \
    --period 300 \
    --threshold 1 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION \
    --evaluation-periods 1 \
    --alarm-actions $SNS_TOPIC_ARN

echo "✓ Lambda Throttles alarm created"

# 3. Lambda Duration Alarm (slow responses)
aws cloudwatch put-metric-alarm \
    --alarm-name "AuraSecurity-Lambda-SlowResponse" \
    --alarm-description "Alert when Lambda is taking too long" \
    --metric-name Duration \
    --namespace AWS/Lambda \
    --statistic Average \
    --period 300 \
    --threshold 60000 \
    --comparison-operator GreaterThanThreshold \
    --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION \
    --evaluation-periods 2 \
    --alarm-actions $SNS_TOPIC_ARN

echo "✓ Lambda Duration alarm created"

# 4. Lambda Invocations (detect if bot stops receiving traffic)
aws cloudwatch put-metric-alarm \
    --alarm-name "AuraSecurity-Lambda-NoTraffic" \
    --alarm-description "Alert when bot receives no traffic for 30 min" \
    --metric-name Invocations \
    --namespace AWS/Lambda \
    --statistic Sum \
    --period 1800 \
    --threshold 1 \
    --comparison-operator LessThanThreshold \
    --dimensions Name=FunctionName,Value=$LAMBDA_FUNCTION \
    --evaluation-periods 1 \
    --alarm-actions $SNS_TOPIC_ARN \
    --treat-missing-data notBreaching

echo "✓ Lambda No-Traffic alarm created"

# 5. API Gateway 5xx errors (if using API Gateway)
# aws cloudwatch put-metric-alarm \
#     --alarm-name "AuraSecurity-API-5xx" \
#     --alarm-description "Alert on API Gateway 5xx errors" \
#     --metric-name 5XXError \
#     --namespace AWS/ApiGateway \
#     --statistic Sum \
#     --period 300 \
#     --threshold 5 \
#     --comparison-operator GreaterThanThreshold \
#     --evaluation-periods 1 \
#     --alarm-actions $SNS_TOPIC_ARN

echo ""
echo "=========================================="
echo "CloudWatch alarms configured!"
echo ""
echo "Alarms created:"
echo "  - Lambda Errors (>5 in 5 min)"
echo "  - Lambda Throttles (any)"
echo "  - Lambda Slow Response (>60s avg)"
echo "  - Lambda No Traffic (0 invocations in 30 min)"
echo ""
echo "View alarms: https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#alarmsV2:"
echo "=========================================="
