# SLOP Auditor

[![npm version](https://badge.fury.io/js/slop-auditor.svg)](https://www.npmjs.com/package/slop-auditor)
[![Docker](https://img.shields.io/badge/docker-ready-blue)](https://hub.docker.com)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A deterministic security auditing engine with an optional AI advisory layer.**

SLOP Auditor can be run as a CLI, a CI step, or a long-running service. The AI does not make enforcement decisions—all security findings come from deterministic scanners (Gitleaks, Trivy, Semgrep, etc.) with reproducible results.

Built on the SLOP (Simple Lightweight Orchestration Protocol) framework, it provides automated security analysis for code repositories and AWS infrastructure with a 3D visualization control plane.

## Features

- **Multi-Scanner Integration** - Gitleaks, Trivy, Semgrep, npm audit
- **AWS Infrastructure Scanning** - IAM, S3, EC2, Lambda, RDS security checks
- **Real-time WebSocket Updates** - Instant notifications when scans complete
- **3D Visualization** - Interactive Three.js control plane
- **Notifications** - Slack, Discord, and custom webhook integrations
- **Persistent Storage** - SQLite database for audit history
- **Docker Ready** - Full containerization with security tools included
- **CI/CD Pipeline** - GitHub Actions for automated testing and publishing

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Commands](#cli-commands)
- [API Endpoints](#api-endpoints)
- [Usage Examples](#usage-examples)
- [Security Scanning Tools](#security-scanning-tools)
- [AWS Scanning](#aws-scanning)
- [Docker Deployment](#docker-deployment)
- [Environment Variables](#environment-variables)
- [3D Visualizer Features](#3d-visualizer-features)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Installation

### Prerequisites

- **Node.js** 18.x or higher
- **npm** 8.x or higher
- **Git** (for cloning the repository)

### Option 1: Install via npm (Recommended)

```bash
npm install -g slop-auditor

# Check installed tools
slop-auditor doctor
```

After installation, you can use the `slop-auditor` command directly:

```bash
slop-auditor --help
```

### Option 2: Clone from GitHub

```bash
# Step 1: Clone the repository
git clone https://github.com/slopsecurityadmin/slop-security-auditor.git

# Step 2: Navigate to the project directory
cd slop-audtior

# Step 3: Install dependencies
npm install

# Step 4: Build the TypeScript code
npm run build

# Step 5: Verify installation
npm start -- --help
```

### Option 3: Run with Docker

```bash
# Using Docker Compose (recommended)
docker-compose up -d

# Or build and run manually
docker build -t slop-auditor .
docker run -p 3000:3000 -p 3001:3001 -p 8080:8080 slop-auditor
```

## Quick Start

### Running the Full Stack

**Terminal 1 - Start the SLOP API Server:**
```bash
npm start
# Server starts on http://127.0.0.1:3000
# WebSocket on ws://127.0.0.1:3001
```

**Terminal 2 - Start the 3D Visualizer:**
```bash
npm run visualizer
# Visualizer starts on http://127.0.0.1:8080
```

**Open your browser:**
Navigate to http://127.0.0.1:8080 to access the 3D control plane.

### Quick Test

Run a scan on a local directory:
```bash
# Via CLI
slop-auditor scan ./my-project

# Or via API
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{"tool":"scan-local","arguments":{"targetPath":"./my-project"}}'
```

### One-Command Development Mode

```bash
# Start both server and visualizer together
npm run full
```

## CLI Commands

```bash
# Initialize configuration
slop-auditor init [path]

# Scan local directory
slop-auditor scan <path>

# Scan AWS infrastructure
slop-auditor aws
slop-auditor aws --region us-west-2 -s iam,s3,ec2

# Start SLOP server
slop-auditor serve

# Start 3D visualizer
slop-auditor visualizer
```

## Architecture

```
slop-auditor/
├── src/
│   ├── index.ts              # Main entry + SLOP server
│   ├── cli.ts                # CLI commands
│   ├── serve-visualizer.ts   # 3D web UI server
│   ├── auditor/              # Core audit logic
│   ├── client/               # High-level SDK
│   ├── database/             # SQLite persistence
│   ├── integrations/         # External connectors
│   │   ├── aws-scanner.ts    # AWS security scanning
│   │   ├── local-scanner.ts  # Local repo scanning
│   │   ├── notifications.ts  # Slack/Discord/webhooks
│   │   └── ...
│   ├── websocket/            # Real-time updates
│   └── slop/                 # SLOP protocol impl
├── visualizer/               # 3D Web UI (Three.js)
├── Dockerfile                # Docker build
├── docker-compose.yml        # Docker Compose
└── .github/workflows/        # CI/CD pipeline
```

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/info` | GET | Server information |
| `/tools` | GET | List available tools |
| `/tools` | POST | Execute a tool (scan, audit) |
| `/memory` | GET | List/retrieve from memory |
| `/memory` | POST | Store data in memory |
| `/settings` | GET | Get all settings |
| `/settings` | POST | Save settings |
| `/audits` | GET | List audit history |
| `/audits/:id` | GET | Get audit details |
| `/audits/:id` | DELETE | Delete an audit |
| `/stats` | GET | Audit statistics |
| `/notifications` | GET | Notification history |
| `/notifications/test` | POST | Test notification channel |
| `/notifications/send` | POST | Send notification |

### WebSocket

Connect to `ws://127.0.0.1:3001` for real-time updates:

```javascript
const ws = new WebSocket('ws://127.0.0.1:3001');
ws.onmessage = (event) => {
  const msg = JSON.parse(event.data);
  // msg.type: 'audit_started', 'audit_completed', 'finding', 'settings_changed'
};
```

## Usage Examples

### Scan Local Directory

```bash
# Via CLI
slop-auditor scan ./my-project

# Via API
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "scan-local",
    "arguments": {
      "targetPath": "/path/to/project"
    }
  }'
```

### Scan AWS Infrastructure

```bash
# Via CLI
slop-auditor aws --region us-east-1 -s iam,s3,ec2

# Via API (configure in Settings UI first)
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "scan-aws",
    "arguments": {
      "region": "us-east-1",
      "services": ["iam", "s3", "ec2"]
    }
  }'
```

### Configure Notifications

Use the Settings panel in the 3D visualizer or via API:

```bash
curl -X POST http://127.0.0.1:3000/settings \
  -H "Content-Type: application/json" \
  -d '{
    "settings": {
      "notifications.slack.enabled": "true",
      "notifications.slack.webhookUrl": "https://hooks.slack.com/services/..."
    }
  }'
```

### Use the Client SDK

```typescript
import { AuditClient, createPullRequestEvent } from 'slop-auditor';

const client = new AuditClient({
  serverUrl: 'http://127.0.0.1:3000'
});

// Check server health
const healthy = await client.isHealthy();

// Run an audit
const result = await client.audit({
  changeEvent: createPullRequestEvent(
    'acme/webapp',
    'abc123...',
    ['src/auth/login.ts'],
    '+const API_KEY = "secret";',
    'staging'
  ),
  evidenceBundle: { vuln_scan: 'critical: 1' },
  policyContext: {
    critical_assets: ['auth', 'billing'],
    risk_tolerance: 'low'
  }
});

console.log(result.output?.agent_state); // 'blocked', 'escalated', etc.
```

## Security Scanning Tools

The scanner integrates with these security tools when available:

| Tool | Purpose | Install |
|------|---------|---------|
| **gitleaks** | Secrets detection | `winget install gitleaks` |
| **trivy** | Vulnerability scanning | `winget install trivy` |
| **semgrep** | SAST analysis | `pip install semgrep` |
| **npm audit** | NPM vulnerabilities | Built into npm |

Falls back to regex patterns if tools aren't installed.

## AWS Scanning

Scans for security misconfigurations:

- **IAM**: Overly permissive policies, unused credentials, MFA status
- **S3**: Public buckets, missing encryption, insecure ACLs
- **EC2**: Open security groups, public IPs, unencrypted volumes
- **Lambda**: Overly permissive roles, exposed environment variables
- **RDS**: Public accessibility, encryption status, backup config

## Docker Deployment

```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t slop-auditor .
docker run -p 3000:3000 -p 3001:3001 -p 8080:8080 slop-auditor

# With AWS credentials
docker run -p 3000:3000 -p 3001:3001 -p 8080:8080 \
  -e AWS_ACCESS_KEY_ID=xxx \
  -e AWS_SECRET_ACCESS_KEY=xxx \
  -e AWS_DEFAULT_REGION=us-east-1 \
  slop-auditor
```

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SLOP_PORT` | 3000 | SLOP HTTP server port |
| `WS_PORT` | 3001 | WebSocket server port |
| `VISUALIZER_PORT` | 8080 | 3D visualizer web server port |
| `SLOP_BUS_URL` | - | External SLOP bus URL (optional) |
| `AWS_DEFAULT_REGION` | us-east-1 | AWS region for scanning |

## 3D Visualizer Features

The web-based 3D control plane provides:

- Real-time agent state visualization
- Interactive Three.js scene with orbit controls
- Module management (add/remove/configure)
- Audit history browser with click-to-view details
- Settings panel for AWS/Slack/Discord configuration
- Live WebSocket updates (no polling delay)
- Quick-action presets for testing

## Development

```bash
# Install dependencies
npm install

# Build TypeScript
npm run build

# Run in development mode
npm run dev

# Run both server and visualizer
npm run full

# Run tests
npm test
```

## Publishing

```bash
# npm
npm login
npm publish --access public

# Docker Hub
docker build -t yourusername/slop-auditor .
docker push yourusername/slop-auditor
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## Troubleshooting

### Common Issues

**Port already in use:**
```bash
# Check what's using port 3000
netstat -ano | findstr :3000  # Windows
lsof -i :3000                 # macOS/Linux

# Use a different port
SLOP_PORT=3001 npm start
```

**Security tools not found:**
The scanner will fall back to regex patterns if tools aren't installed. For best results, install:
```bash
# Windows
winget install gitleaks
winget install trivy

# macOS
brew install gitleaks
brew install trivy

# Linux
# See respective tool documentation for installation
```

**WebSocket connection failed:**
Ensure the WebSocket server is running on port 3001. Check browser console for errors.

**Database errors:**
The SQLite database is stored in `.slop-auditor/auditor.db`. To reset:
```bash
rm -rf .slop-auditor/
npm start  # Will recreate the database
```

### Getting Help

- Check the [Issue Tracker](https://github.com/slopsecurityadmin/slop-security-auditor/issues) for known issues
- Open a new issue with your error message and environment details

## License

MIT - See [LICENSE](LICENSE) for details.

## Links

- [GitHub Repository](https://github.com/slopsecurityadmin/slop-security-auditor)
- [npm Package](https://www.npmjs.com/package/slop-auditor)
- [Issue Tracker](https://github.com/slopsecurityadmin/slop-security-auditor/issues)
- [Changelog](CHANGELOG.md)
