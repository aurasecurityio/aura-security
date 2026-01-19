# aurasecurity - Project Brain

This file tracks the current state of the project for Claude to pick up where we left off.

## Project Overview

**aurasecurity** is a security audit pipeline built on the Aura framework. It provides automated security analysis for code changes with a 3D visualization control plane.

## Current Status: ACTIVE DEVELOPMENT

**Last Updated:** January 13, 2026
**Phase:** Integration & Enhancement
**GitHub:** https://github.com/yvasisht/aura-security

---

## Architecture

```
aura-security/
├── src/
│   ├── index.ts              # Main entry + exports
│   ├── cli.ts                # CLI tool
│   ├── serve-visualizer.ts   # 3D web UI server
│   ├── auditor/              # Core audit logic
│   │   ├── pipeline.ts       # Analysis pipeline
│   │   └── validator.ts      # Schema validation
│   ├── client/               # High-level SDK
│   │   └── index.ts          # AuditClient class
│   ├── pipeline/             # Extensible pipeline stages
│   │   └── index.ts          # SecurityPipeline + stages
│   ├── integrations/         # External system connectors
│   │   ├── index.ts          # Exports
│   │   ├── webhook.ts        # Webhook server
│   │   ├── github.ts         # GitHub integration
│   │   ├── gitlab.ts         # GitLab integration
│   │   ├── scanners.ts       # Scanner parsers (Snyk, Trivy, etc.)
│   │   └── config.ts         # Configuration system
│   ├── schemas/              # JSON schemas
│   ├── aura/                 # Aura server/client
│   ├── types/                # TypeScript types
│   └── visualizer/           # Console visualization
├── visualizer/               # 3D Web UI (Three.js)
│   └── index.html            # Full control plane UI
├── examples/                 # Sample inputs
├── README.md                 # Documentation
├── package.json
└── tsconfig.json
```

---

## Completed Features

### Core
- [x] Aura Server with /info, /tools, /memory endpoints
- [x] Aura Client for API communication
- [x] Auditor Pipeline with rule-based analysis
- [x] Schema validation (input/output)
- [x] CLI tool (status, audit, logs, watch)

### Analysis Stages
- [x] Secrets Detection (API keys, passwords, tokens, private keys)
- [x] Vulnerability Scan Parser
- [x] Critical Asset Monitor
- [x] Infrastructure Change Detection
- [x] Production Deploy Guard

### Client SDK
- [x] AuditClient class with retry logic
- [x] Helper functions for creating events
- [x] Async generator for watching audits

### 3D Visualizer
- [x] Three.js scene with orbit controls
- [x] Central Security Auditor node
- [x] 6 System Modules (AUTH, DATABASE, API, INFRA, BILLING, SECRETS)
- [x] Connection lines (audit + data flow)
- [x] Legend panel explaining all elements
- [x] Module Status panel
- [x] Preset audit buttons
- [x] Findings panel with severity badges
- [x] Stats bar (Critical/High/Medium/Low counts)
- [x] Hover tooltips on 3D objects
- [x] Real-time polling of Aura server
- [x] Audit History panel (browse past audits)
- [x] Click-to-view audit details
- [x] Selected audit info panel

### Integrations
- [x] Webhook Server (GitHub, GitLab, Jenkins, custom)
- [x] GitHub Integration (PR fetch, check runs, comments)
- [x] GitLab Integration (MR fetch, comments, status)
- [x] Scanner Parsers (Snyk, Trivy, Semgrep, npm audit)
- [x] Configuration System (JSON, YAML, env vars)

---

## In Progress / Next Steps

### High Priority
- [x] Local system scanner (secrets, packages, env files)
- [x] Clickable module selection in visualizer
- [x] Module management (add/remove/enable/disable)
- [x] Audit source selector (Demo/Local/Custom)
- [x] Audit history browsing in visualizer
- [x] Scan results stored to Aura memory
- [ ] Create example config file (aura.config.json)
- [ ] AWS integration for cloud resource auditing
- [ ] End-to-end testing with real GitHub webhook
- [ ] Add persistent database (SQLite/file-based) for audit history

### Medium Priority
- [ ] Add more scanner parsers (Grype, Clair, Checkov)
- [ ] Add Slack/Discord notification integration
- [ ] Add authentication to Aura server
- [ ] Code simplifier/linter stage

### Low Priority
- [ ] Add custom rule definition support
- [ ] Add metrics/telemetry export
- [ ] Add report generation (PDF, HTML)

---

## How to Run

```bash
# Navigate to project
cd C:\Users\Justin\Documents\Projects\AI_Test\apps\aura-security

# Install dependencies
npm install

# Build TypeScript
npm run build

# Start Aura server (port 3000)
npm start

# Start 3D visualizer (port 8080) - separate terminal
npm run visualizer

# Open browser: http://127.0.0.1:8080
```

---

## Key Files to Know

| File | Purpose |
|------|---------|
| `src/index.ts` | Main entry, starts server, exports |
| `src/auditor/pipeline.ts` | Core analysis logic |
| `src/pipeline/index.ts` | Extensible analysis stages |
| `src/integrations/webhook.ts` | Webhook receiver |
| `src/integrations/github.ts` | GitHub API integration |
| `src/integrations/config.ts` | Config loading |
| `src/integrations/local-scanner.ts` | Local filesystem scanning |
| `visualizer/index.html` | 3D control plane UI |

---

## Module Definitions

The system monitors these modules:

| ID | Name | Description | Color |
|----|------|-------------|-------|
| auth | AUTH | Authentication & Identity | Green |
| database | DATABASE | Data Storage & Queries | Blue |
| api | API | External Endpoints | Orange |
| infra | INFRA | Infrastructure & Network | Purple |
| billing | BILLING | Payment Processing | Orange |
| secrets | SECRETS | Credentials & Keys | Pink |

---

## Data Flow Connections

| From | To | Label |
|------|----|-------|
| auth | database | User Data |
| auth | secrets | Credentials |
| api | auth | Auth Requests |
| api | database | Queries |
| billing | database | Transactions |
| billing | secrets | Payment Keys |
| infra | database | Backups |
| infra | secrets | Service Accounts |

---

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| AURA_PORT | 3000 | Aura server port |
| VISUALIZER_PORT | 8080 | 3D visualizer port |
| WEBHOOK_PORT | 3001 | Webhook server port |
| WEBHOOK_SECRET | - | Webhook signature secret |
| GITHUB_TOKEN | - | GitHub API token |
| GITLAB_TOKEN | - | GitLab API token |
| RISK_TOLERANCE | medium | Default risk tolerance |

---

## Backend Libraries & Detection Methods

### Dependencies (package.json)
| Library | Purpose |
|---------|---------|
| **AJV** (ajv + ajv-formats) | JSON Schema validation for input/output |
| **Node.js crypto** (built-in) | HMAC signature verification for webhooks |

### Real Security Scanning Tools (Integrated)

The scanner now directly invokes **real security tools** when available, with automatic fallback to regex patterns:

| Tool | Purpose | Installation |
|------|---------|--------------|
| **gitleaks** | Secrets detection | `winget install gitleaks` |
| **trivy** | Vulnerability scanning | `winget install trivy` |
| **semgrep** | SAST (Static Analysis) | `pip install semgrep` |
| **npm audit** | NPM package vulnerabilities | Built into npm |

#### How It Works

The scanner (`src/integrations/local-scanner.ts`) automatically:
1. Checks if each tool is available via `--version`
2. Runs available tools and parses JSON output
3. Falls back to regex patterns if tools aren't installed
4. Reports which tools were used in `toolsUsed` field

#### Response Fields
| Field | Description |
|-------|-------------|
| `tools_used` | Array of tools that ran (e.g., `["gitleaks", "trivy", "semgrep", "npm-audit"]`) |
| `secrets_found` | Count of secrets detected |
| `packages_scanned` | Count of packages checked |
| `package_vulns` | Count of vulnerable packages |
| `sast_findings` | Count of SAST issues |
| `raw_findings.sastFindings` | Array of SAST findings with file, line, rule, message, severity |

#### Fallback Modes
- **No gitleaks** → Uses regex patterns for secrets
- **No trivy** → Uses npm audit only
- **No semgrep** → Skips SAST analysis

### Regex Fallback Patterns

When real tools aren't available, these regex patterns are used:

| Pattern | Detects |
|---------|---------|
| `AKIA[0-9A-Z]{16}` | AWS Access Keys |
| `gh[pousr]_[A-Za-z0-9_]{36,}` | GitHub Tokens |
| `sk_live_[A-Za-z0-9]{24,}` | Stripe Keys |
| `eyJ...\\.eyJ...\\.` | JWT Tokens |
| `-----BEGIN.*PRIVATE KEY-----` | Private Keys |

### Installing Security Tools

```bash
# Windows (via winget)
winget install gitleaks
winget install trivy

# Python (semgrep)
pip install semgrep

# Verify installation
gitleaks --version
trivy --version
semgrep --version
```

---

## Known Issues

1. **Buttons not clickable** - Fixed by moving `window.runPreset` assignment after function definition
2. **Module exports** - Ensure all new files are exported from `src/index.ts`
3. **TypeScript build** - Run `npm run build` after changes

---

## Quick Commands for Claude

```bash
# Check if servers are running
curl http://127.0.0.1:3000/info
curl http://127.0.0.1:8080/

# Run an audit via CLI
npx tsx src/cli.ts audit

# Run a preset audit via curl
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{"tool":"audit","arguments":{"change_event":{"id":"test","type":"pull_request","environment":"staging","repo":"test/repo","commit":"abc123","files_changed":["src/auth.ts"],"diff":"+password=secret"},"evidence_bundle":{},"policy_context":{"critical_assets":["auth"],"risk_tolerance":"low"}}}'

# Run a LOCAL SYSTEM SCAN via curl
curl -X POST http://127.0.0.1:3000/tools \
  -H "Content-Type: application/json" \
  -d '{"tool":"scan-local","arguments":{"targetPath":"C:/Users/Justin/Documents/Projects","scanSecrets":true,"scanPackages":true}}'

# Build the project
cd /c/Users/Justin/Documents/Projects/AI_Test/apps/aura-security && npm run build
```

---

## Available Aura Tools

| Tool | Description |
|------|-------------|
| `audit` | Analyze a change event (PR, deploy, infra change) for security findings |
| `scan-local` | Scan local filesystem for secrets, vulnerabilities, env files |

---

## Notes for Next Session

### Session Summary (Jan 13, 2026 - Latest)
**Documentation and release preparation completed.**

- **COMPLETED**: Created CHANGELOG.md with full version history
- **COMPLETED**: Enhanced README.md with detailed installation instructions
- **COMPLETED**: Added Table of Contents to README
- **COMPLETED**: Added Troubleshooting section to README
- **COMPLETED**: All code builds successfully with no errors

### Session Summary (Jan 14, 2026)
**All major features completed! Product is ready for deployment.**

- **COMPLETED**: SQLite database for persistent audit history
- **COMPLETED**: Slack/Discord notification integrations
- **COMPLETED**: Real-time WebSocket updates (ws://127.0.0.1:3001)
- **COMPLETED**: Web UI settings panel for AWS/Slack/Discord configuration
- **COMPLETED**: Docker containerization (Dockerfile + docker-compose.yml)
- **COMPLETED**: CI/CD GitHub Actions workflow (.github/workflows/ci.yml)
- **PACKAGE**: Ready for `npm publish` (scoped @aura/auditor)
- **PACKAGE**: Python wrapper in `python/` directory ready for PyPI

### New Features This Session
1. **SQLite Database** - Audits persist across restarts, stored in `.aura-security/auditor.db`
2. **WebSocket Server** - Real-time updates on port 3001, visualizer auto-connects
3. **Settings Panel** - Configure AWS, Slack, Discord, webhooks from the UI
4. **Notifications** - Send alerts to Slack/Discord when scans complete
5. **Docker Support** - Full containerization with security tools included
6. **CI/CD Pipeline** - Automated build, test, security scan, and publish

### API Endpoints
```
GET  /info              # Server info
GET  /tools             # List tools
POST /tools             # Call a tool
GET  /memory            # List/read memory
POST /memory            # Write to memory
GET  /settings          # Get all settings
POST /settings          # Save settings
GET  /audits            # List audit history
GET  /audits/:id        # Get audit details
DELETE /audits/:id      # Delete audit
GET  /stats             # Audit statistics
GET  /notifications     # Notification history
POST /notifications/test  # Test notification channel
POST /notifications/send  # Send notification
```

### Docker Deployment
```bash
# Build and run with Docker Compose
docker-compose up -d

# Or build manually
docker build -t aura-security .
docker run -p 3000:3000 -p 3001:3001 -p 8080:8080 aura-security
```

### Publishing Commands
```bash
# npm (requires npm login)
cd /path/to/aura-security
npm publish --access public

# pip (requires twine)
cd /path/to/aura-security/python
pip install build twine
python -m build
twine upload dist/*

# Docker Hub
docker build -t yourusername/aura-security .
docker push yourusername/aura-security
```

### Suggested Next Steps
1. Add authentication to Aura server (JWT/API keys)
2. Add more scanner parsers (Grype, Clair, Checkov)
3. Add report generation (PDF, HTML)
4. Integrate with CI/CD systems (webhook triggers)

### Test Repos Available
The following repos are cloned in `test-repos/` for testing:
- express, lodash, axios, chalk, dotenv
- jsonwebtoken, bcrypt, mongoose, socket.io, passport

### How to Resume
```bash
cd C:\Users\Justin\Documents\Projects\AI_Test\apps\aura-security
npm run build
npm start                    # Terminal 1: Aura server on :3000
npm run visualizer           # Terminal 2: Visualizer on :8080
# Open http://127.0.0.1:8080
```

---

*This file is the "brain" for continuing development. Update after each session.*
