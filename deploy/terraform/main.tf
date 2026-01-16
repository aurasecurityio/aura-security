# SLOP Auditor - AWS Infrastructure
# Deploy with: terraform init && terraform apply

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {
  region = var.aws_region
}

# Variables
variable "aws_region" {
  description = "AWS region"
  default     = "us-east-1"
}

variable "instance_type" {
  description = "EC2 instance type"
  default     = "t3.small"
}

variable "key_name" {
  description = "SSH key pair name"
  type        = string
}

variable "domain_name" {
  description = "Domain name for the application (optional)"
  default     = ""
}

# Data sources
data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}

# VPC
resource "aws_vpc" "main" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "slop-auditor-vpc"
  }
}

resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.main.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true

  tags = {
    Name = "slop-auditor-public"
  }
}

resource "aws_internet_gateway" "main" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "slop-auditor-igw"
  }
}

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.main.id
  }

  tags = {
    Name = "slop-auditor-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

# Security Group
resource "aws_security_group" "slop_auditor" {
  name        = "slop-auditor-sg"
  description = "Security group for SLOP Auditor"
  vpc_id      = aws_vpc.main.id

  # SSH
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"] # Restrict to your IP in production
    description = "SSH access"
  }

  # HTTP
  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTP access"
  }

  # HTTPS
  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
    description = "HTTPS access"
  }

  # All outbound
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "slop-auditor-sg"
  }
}

# IAM Role for EC2 (for AWS scanning)
resource "aws_iam_role" "slop_auditor" {
  name = "slop-auditor-ec2-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

# IAM Policy for security scanning (read-only)
resource "aws_iam_role_policy" "slop_auditor_scan" {
  name = "slop-auditor-scan-policy"
  role = aws_iam_role.slop_auditor.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "iam:List*",
          "iam:Get*",
          "s3:List*",
          "s3:GetBucket*",
          "s3:GetEncryptionConfiguration",
          "ec2:Describe*",
          "lambda:List*",
          "lambda:GetFunction*",
          "rds:Describe*"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_instance_profile" "slop_auditor" {
  name = "slop-auditor-instance-profile"
  role = aws_iam_role.slop_auditor.name
}

# EC2 Instance
resource "aws_instance" "slop_auditor" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = aws_subnet.public.id
  vpc_security_group_ids = [aws_security_group.slop_auditor.id]
  iam_instance_profile   = aws_iam_instance_profile.slop_auditor.name

  root_block_device {
    volume_size = 20
    volume_type = "gp3"
  }

  user_data = <<-EOF
    #!/bin/bash
    set -e

    # Update system
    apt-get update
    apt-get upgrade -y

    # Install Node.js 20
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y nodejs

    # Install nginx
    apt-get install -y nginx

    # Install security tools
    apt-get install -y gitleaks python3-pip
    snap install trivy
    pip3 install semgrep

    # Create app directory
    mkdir -p /var/www/slop-auditor
    cd /var/www/slop-auditor

    # Install SLOP Auditor
    npm install slop-auditor

    # Create systemd services
    cat > /etc/systemd/system/slop-api.service << 'SVCEOF'
    [Unit]
    Description=SLOP Auditor API Server
    After=network.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/var/www/slop-auditor
    ExecStart=/usr/bin/npx slop-auditor serve
    Restart=on-failure
    RestartSec=10
    Environment=NODE_ENV=production

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    cat > /etc/systemd/system/slop-visualizer.service << 'SVCEOF'
    [Unit]
    Description=SLOP Auditor Visualizer
    After=network.target

    [Service]
    Type=simple
    User=root
    WorkingDirectory=/var/www/slop-auditor
    ExecStart=/usr/bin/npx slop-auditor visualizer
    Restart=on-failure
    RestartSec=10
    Environment=NODE_ENV=production

    [Install]
    WantedBy=multi-user.target
    SVCEOF

    # Enable and start services
    systemctl daemon-reload
    systemctl enable slop-api slop-visualizer
    systemctl start slop-api slop-visualizer

    # Configure nginx
    cat > /etc/nginx/sites-available/slop-auditor << 'NGINXEOF'
    server {
        listen 80;
        server_name _;

        location / {
            proxy_pass http://127.0.0.1:8080;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;
        }

        location ~ ^/(info|tools|memory|settings|audits|stats|notifications)(/.*)?$ {
            proxy_pass http://127.0.0.1:3000;
            proxy_http_version 1.1;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
        }

        location /ws {
            proxy_pass http://127.0.0.1:3001;
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";
            proxy_set_header Host $host;
            proxy_read_timeout 86400;
        }
    }
    NGINXEOF

    ln -sf /etc/nginx/sites-available/slop-auditor /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    nginx -t && systemctl reload nginx
  EOF

  tags = {
    Name = "slop-auditor"
  }
}

# Elastic IP (optional, for stable IP)
resource "aws_eip" "slop_auditor" {
  instance = aws_instance.slop_auditor.id
  domain   = "vpc"

  tags = {
    Name = "slop-auditor-eip"
  }
}

# Outputs
output "public_ip" {
  description = "Public IP address"
  value       = aws_eip.slop_auditor.public_ip
}

output "public_dns" {
  description = "Public DNS name"
  value       = aws_instance.slop_auditor.public_dns
}

output "landing_url" {
  description = "Landing page URL"
  value       = "http://${aws_eip.slop_auditor.public_ip}"
}

output "dashboard_url" {
  description = "Dashboard URL"
  value       = "http://${aws_eip.slop_auditor.public_ip}/app"
}

output "ssh_command" {
  description = "SSH command to connect"
  value       = "ssh -i ${var.key_name}.pem ubuntu@${aws_eip.slop_auditor.public_ip}"
}
