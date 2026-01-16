# AWS Deployment Guide

This guide covers deploying SLOP Auditor to AWS with a professional setup including:
- EC2 instance running the application
- nginx reverse proxy with SSL
- Domain setup with Route 53
- Optional: Load balancer for high availability

## Architecture

```
                    ┌─────────────┐
                    │   Route 53  │
                    │  (DNS)      │
                    └──────┬──────┘
                           │
                    ┌──────▼──────┐
                    │ Application │
                    │ Load Balancer│ (optional)
                    └──────┬──────┘
                           │
              ┌────────────┼────────────┐
              │            │            │
        ┌─────▼─────┐┌─────▼─────┐┌─────▼─────┐
        │   EC2     ││   EC2     ││   EC2     │
        │ (nginx +  ││ (nginx +  ││ (nginx +  │
        │  node)    ││  node)    ││  node)    │
        └───────────┘└───────────┘└───────────┘
```

For most use cases, a single EC2 instance is sufficient.

---

## Option 1: Single EC2 Instance (Recommended for Start)

### Step 1: Launch EC2 Instance

1. Go to AWS Console → EC2 → Launch Instance
2. Choose settings:
   - **AMI**: Ubuntu 22.04 LTS
   - **Instance type**: t3.small (2 vCPU, 2GB RAM) or larger
   - **Key pair**: Create or select existing
   - **Security Group**: Allow ports 22 (SSH), 80 (HTTP), 443 (HTTPS)

### Step 2: Connect and Install Dependencies

```bash
# SSH into your instance
ssh -i your-key.pem ubuntu@<EC2-PUBLIC-IP>

# Update system
sudo apt update && sudo apt upgrade -y

# Install Node.js 20
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install nginx
sudo apt install -y nginx

# Install security tools (optional but recommended)
sudo apt install -y gitleaks
sudo snap install trivy

# Install pip and semgrep
sudo apt install -y python3-pip
pip3 install semgrep

# Verify installations
node --version   # Should show v20.x
nginx -v         # Should show nginx version
```

### Step 3: Deploy SLOP Auditor

```bash
# Create app directory
sudo mkdir -p /var/www/slop-auditor
sudo chown ubuntu:ubuntu /var/www/slop-auditor

# Install SLOP Auditor
cd /var/www/slop-auditor
npm install slop-auditor

# Or clone from GitHub for latest
git clone https://github.com/slopsecurityadmin/slop-security-auditor.git .
npm install
npm run build
```

### Step 4: Create systemd Services

Create the API service:

```bash
sudo tee /etc/systemd/system/slop-api.service << 'EOF'
[Unit]
Description=SLOP Auditor API Server
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/var/www/slop-auditor
ExecStart=/usr/bin/node dist/index.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=SLOP_PORT=3000
Environment=WS_PORT=3001

[Install]
WantedBy=multi-user.target
EOF
```

Create the visualizer service:

```bash
sudo tee /etc/systemd/system/slop-visualizer.service << 'EOF'
[Unit]
Description=SLOP Auditor Visualizer
After=network.target

[Service]
Type=simple
User=ubuntu
WorkingDirectory=/var/www/slop-auditor
ExecStart=/usr/bin/node dist/serve-visualizer.js
Restart=on-failure
RestartSec=10
Environment=NODE_ENV=production
Environment=VISUALIZER_PORT=8080

[Install]
WantedBy=multi-user.target
EOF
```

Enable and start services:

```bash
sudo systemctl daemon-reload
sudo systemctl enable slop-api slop-visualizer
sudo systemctl start slop-api slop-visualizer

# Check status
sudo systemctl status slop-api
sudo systemctl status slop-visualizer
```

### Step 5: Configure nginx

```bash
sudo tee /etc/nginx/sites-available/slop-auditor << 'EOF'
server {
    listen 80;
    server_name your-domain.com www.your-domain.com;

    # Landing page and static assets
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # API endpoints
    location /api/ {
        rewrite ^/api/(.*)$ /$1 break;
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }

    # Direct SLOP endpoints (info, tools, memory, etc.)
    location ~ ^/(info|tools|memory|settings|audits|stats|notifications)(/.*)?$ {
        proxy_pass http://127.0.0.1:3000;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }

    # WebSocket for real-time updates
    location /ws {
        proxy_pass http://127.0.0.1:3001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_read_timeout 86400;
    }
}
EOF

# Enable site
sudo ln -sf /etc/nginx/sites-available/slop-auditor /etc/nginx/sites-enabled/
sudo rm -f /etc/nginx/sites-enabled/default

# Test and reload
sudo nginx -t
sudo systemctl reload nginx
```

### Step 6: Add SSL with Let's Encrypt

```bash
# Install certbot
sudo apt install -y certbot python3-certbot-nginx

# Get certificate (replace with your domain)
sudo certbot --nginx -d your-domain.com -d www.your-domain.com

# Auto-renewal is set up automatically
# Test renewal:
sudo certbot renew --dry-run
```

### Step 7: Configure Domain (Route 53)

1. Go to AWS Route 53
2. Create/select your hosted zone
3. Create an A record:
   - Name: `your-domain.com` (or subdomain like `security.your-domain.com`)
   - Type: A
   - Value: Your EC2 public IP
   - TTL: 300

---

## Option 2: Docker Deployment

If you prefer Docker:

```bash
# Install Docker
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker ubuntu

# Pull and run
docker pull slopsecurityadmin/slop-auditor:latest
docker run -d \
  --name slop-auditor \
  -p 3000:3000 \
  -p 3001:3001 \
  -p 8080:8080 \
  -v slop-data:/app/.slop-auditor \
  slopsecurityadmin/slop-auditor:latest
```

Then configure nginx as shown above.

---

## Environment Variables

Set these in your systemd service or `.env` file:

| Variable | Default | Description |
|----------|---------|-------------|
| `SLOP_PORT` | 3000 | API server port |
| `WS_PORT` | 3001 | WebSocket port |
| `VISUALIZER_PORT` | 8080 | Web UI port |
| `AWS_ACCESS_KEY_ID` | - | For AWS scanning |
| `AWS_SECRET_ACCESS_KEY` | - | For AWS scanning |
| `AWS_DEFAULT_REGION` | us-east-1 | AWS region |

---

## Security Recommendations

1. **Use IAM Roles**: Instead of hardcoding AWS credentials, attach an IAM role to your EC2 instance with the permissions needed for scanning.

2. **Security Groups**: Only allow:
   - Port 22 from your IP only
   - Ports 80/443 from anywhere

3. **Enable AWS WAF**: If using ALB, add WAF rules for additional protection.

4. **Regular Updates**:
   ```bash
   # Set up unattended upgrades
   sudo apt install -y unattended-upgrades
   sudo dpkg-reconfigure -plow unattended-upgrades
   ```

---

## Monitoring

### CloudWatch Logs

```bash
# Install CloudWatch agent
wget https://s3.amazonaws.com/amazoncloudwatch-agent/ubuntu/amd64/latest/amazon-cloudwatch-agent.deb
sudo dpkg -i amazon-cloudwatch-agent.deb

# Configure to send logs
sudo /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-config-wizard
```

### Health Checks

Add to nginx config:

```nginx
location /health {
    proxy_pass http://127.0.0.1:3000/info;
    access_log off;
}
```

---

## Cost Estimate

| Resource | Specification | Monthly Cost (approx) |
|----------|--------------|----------------------|
| EC2 t3.small | 2 vCPU, 2GB RAM | ~$15 |
| EBS | 20GB gp3 | ~$2 |
| Route 53 | Hosted zone | ~$0.50 |
| Data transfer | 10GB | ~$1 |
| **Total** | | **~$20/month** |

For higher traffic, consider t3.medium (~$30/month) or add a load balancer.

---

## Troubleshooting

### Services not starting

```bash
# Check logs
sudo journalctl -u slop-api -f
sudo journalctl -u slop-visualizer -f
```

### 502 Bad Gateway

```bash
# Check if services are running
sudo systemctl status slop-api
sudo systemctl status slop-visualizer

# Check ports
sudo netstat -tlnp | grep -E '3000|3001|8080'
```

### WebSocket not connecting

Make sure your nginx config has the WebSocket upgrade headers and the security group allows port 3001 (or use nginx proxy for all WebSocket traffic).
