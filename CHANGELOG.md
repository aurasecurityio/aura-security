# Changelog

All notable changes to SLOP Auditor will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-13

### Added

#### Core Features
- **SLOP Server** - HTTP API server on port 3000 with `/info`, `/tools`, `/memory`, `/settings`, `/audits`, `/stats`, `/notifications` endpoints
- **SQLite Database** - Persistent audit history stored in `.slop-auditor/auditor.db`
- **WebSocket Server** - Real-time updates on port 3001 for live audit notifications
- **CLI Tool** - Command-line interface with `init`, `scan`, `aws`, `serve`, `visualizer` commands

#### Security Scanning
- **Local Scanner** - Scan local directories for secrets, vulnerabilities, and misconfigurations
- **Multi-Scanner Integration** - Gitleaks, Trivy, Semgrep, npm audit support with automatic fallback to regex patterns
- **AWS Infrastructure Scanner** - Security checks for IAM, S3, EC2, Lambda, RDS services
- **Secrets Detection** - API keys, passwords, tokens, private keys, JWT tokens

#### 3D Visualizer
- **Three.js Control Plane** - Interactive 3D visualization of security audit state
- **Real-time Updates** - WebSocket connection for instant audit notifications
- **Audit History Browser** - Browse and view past audit results
- **Settings Panel** - Configure AWS, Slack, Discord from the web UI
- **Module Management** - Add, remove, enable/disable monitored modules
- **Stats Dashboard** - Critical/High/Medium/Low finding counts

#### Integrations
- **Slack Notifications** - Send audit alerts to Slack channels via webhook
- **Discord Notifications** - Send audit alerts to Discord channels via webhook
- **Custom Webhooks** - Send audit data to any HTTP endpoint
- **GitHub Integration** - PR fetch, check runs, comments (via token)
- **GitLab Integration** - MR fetch, comments, status updates (via token)

#### Deployment
- **Docker Support** - Multi-stage Dockerfile with security tools included
- **Docker Compose** - Easy deployment with volume persistence
- **npm Package** - Published as `@slop/auditor` for easy installation
- **Python Wrapper** - PyPI package available in `python/` directory

#### Developer Experience
- **TypeScript** - Full TypeScript implementation with type definitions
- **JSON Schema Validation** - Input/output validation with AJV
- **Extensible Pipeline** - Add custom analysis stages
- **Client SDK** - `AuditClient` class with retry logic and helpers

### API Endpoints

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

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SLOP_PORT` | 3000 | SLOP HTTP server port |
| `WS_PORT` | 3001 | WebSocket server port |
| `VISUALIZER_PORT` | 8080 | 3D visualizer web server port |
| `SLOP_BUS_URL` | - | External SLOP bus URL (optional) |
| `AWS_DEFAULT_REGION` | us-east-1 | AWS region for scanning |

### Security Tools Supported

| Tool | Purpose | Detection Method |
|------|---------|------------------|
| gitleaks | Secrets detection | Direct invocation or regex fallback |
| trivy | Vulnerability scanning | Direct invocation |
| semgrep | SAST analysis | Direct invocation |
| npm audit | NPM vulnerabilities | Built-in npm command |

---

## [0.1.0] - 2026-01-12

### Added
- Initial project structure
- Basic SLOP server implementation
- Auditor pipeline with rule-based analysis
- Console visualization
- GitHub/GitLab webhook integration
- Scanner parsers for Snyk, Trivy, Semgrep output

---

## Future Roadmap

### Planned for v1.1.0
- [ ] JWT/API key authentication for SLOP server
- [ ] More scanner parsers (Grype, Clair, Checkov)
- [ ] Report generation (PDF, HTML)
- [ ] Custom rule definition support

### Planned for v1.2.0
- [ ] Metrics/telemetry export (Prometheus, Datadog)
- [ ] SAML/OIDC authentication
- [ ] Multi-tenant support
- [ ] Kubernetes deployment manifests

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

## License

MIT License - see [LICENSE](LICENSE) for details.
