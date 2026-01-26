#!/bin/bash
# Deploy Aura Security Swarm to AWS EC2
# Usage: ./deploy-swarm.sh <EC2_HOST> [SSH_KEY]

set -e

EC2_HOST="${1:-}"
SSH_KEY="${2:-~/.ssh/id_rsa}"
APP_DIR="/var/www/aura-security"

if [ -z "$EC2_HOST" ]; then
    echo "Usage: ./deploy-swarm.sh <EC2_HOST> [SSH_KEY]"
    echo "Example: ./deploy-swarm.sh ubuntu@ec2-xx-xx-xx-xx.compute-1.amazonaws.com ~/.ssh/my-key.pem"
    exit 1
fi

echo "======================================"
echo "Aura Security Swarm Deployment"
echo "======================================"
echo "Target: $EC2_HOST"
echo "App Dir: $APP_DIR"
echo ""

# Build locally first
echo "[1/5] Building locally..."
npm run build

# Create deployment package
echo "[2/5] Creating deployment package..."
tar -czf /tmp/aura-swarm-deploy.tar.gz \
    dist/ \
    visualizer/ \
    schemas/ \
    package.json \
    package-lock.json \
    deploy/aura-swarm.service

# Upload to EC2
echo "[3/5] Uploading to EC2..."
scp -i "$SSH_KEY" /tmp/aura-swarm-deploy.tar.gz "$EC2_HOST:/tmp/"

# Deploy on EC2
echo "[4/5] Deploying on EC2..."
ssh -i "$SSH_KEY" "$EC2_HOST" << 'REMOTE_SCRIPT'
set -e

APP_DIR="/var/www/aura-security"

# Backup current version
if [ -d "$APP_DIR" ]; then
    sudo cp -r "$APP_DIR" "${APP_DIR}.backup.$(date +%Y%m%d_%H%M%S)" 2>/dev/null || true
fi

# Extract new version
sudo mkdir -p "$APP_DIR"
sudo tar -xzf /tmp/aura-swarm-deploy.tar.gz -C "$APP_DIR"
sudo chown -R ubuntu:ubuntu "$APP_DIR"

# Install dependencies
cd "$APP_DIR"
npm ci --omit=dev

# Install swarm systemd service
if [ -f deploy/aura-swarm.service ]; then
    sudo cp deploy/aura-swarm.service /etc/systemd/system/
    sudo systemctl daemon-reload
    sudo systemctl enable aura-swarm
fi

# Restart services
echo "Restarting services..."
sudo systemctl restart aura-api 2>/dev/null || true
sudo systemctl restart aura-visualizer 2>/dev/null || true
sudo systemctl restart aura-swarm 2>/dev/null || sudo systemctl start aura-swarm

# Check status
echo ""
echo "Service Status:"
sudo systemctl status aura-swarm --no-pager -l | head -20

echo ""
echo "Swarm Endpoints:"
echo "  Coordinator:   http://localhost:4000/info"
echo "  Scanner:       http://localhost:4001/tools"
echo "  Grader:        http://localhost:4002/tools"
echo "  Fixer:         http://localhost:4003/tools"
echo "  Scout:         http://localhost:4004/tools"
echo "  Chain Mapper:  http://localhost:4005/tools"
echo "  Red Team:      http://localhost:4006/tools"
REMOTE_SCRIPT

echo ""
echo "[5/5] Deployment complete!"
echo ""
echo "======================================"
echo "Swarm is now running on $EC2_HOST"
echo "======================================"
echo ""
echo "Test with:"
echo "  curl http://$EC2_HOST:4000/info"
echo ""
echo "Run a scan:"
echo "  curl -X POST http://$EC2_HOST:4001/tools \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"tool\":\"scan\",\"arguments\":{\"targetPath\":\"/projects/test-repo\"}}'"
