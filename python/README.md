# SLOP Auditor - Python Wrapper

Security auditor with 3D visualization - Python wrapper for the `@slop/auditor` npm package.

Scan code repositories and AWS infrastructure for security issues including:
- Secrets and credentials (API keys, passwords, tokens)
- Package vulnerabilities (npm, pip)
- SAST findings (code quality issues)
- AWS misconfigurations (IAM, S3, EC2, Lambda, RDS)

## Requirements

- Python 3.8+
- Node.js 18+ (required for the underlying scanner)

## Installation

```bash
pip install slop-auditor
```

## Quick Start

### Command Line

```bash
# Scan current directory
slop-auditor scan .

# Scan a specific repo
slop-auditor scan /path/to/repo

# Scan AWS infrastructure
slop-auditor aws --region us-west-2

# Initialize config in a project
slop-auditor init

# Start the 3D visualizer
slop-auditor serve &
slop-auditor visualizer
```

### Python API

```python
from slop_auditor import scan, scan_aws, SlopAuditor

# Quick scan
result = scan("./my-project")
print(f"Found {len(result['secrets'])} secrets")
print(f"Found {len(result['packages'])} package vulnerabilities")

# AWS scan
aws_result = scan_aws(region="us-west-2", services=["iam", "s3"])
print(f"Found {aws_result['summary']['critical']} critical issues")

# Using the class interface
auditor = SlopAuditor()
auditor.init("./my-project")  # Initialize config
result = auditor.scan("./my-project")
```

## Features

- **Secrets Detection**: Uses gitleaks for finding exposed credentials
- **Vulnerability Scanning**: Uses trivy and npm audit for package vulnerabilities
- **SAST Analysis**: Uses semgrep for static analysis
- **AWS Auditing**: Scans IAM, S3, EC2, Lambda, RDS for misconfigurations
- **3D Visualization**: Interactive web-based control plane
- **SLOP Protocol**: Compatible with the Simple Language Open Protocol

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AWS_REGION` | Default AWS region |
| `AWS_PROFILE` | AWS profile name |
| `SLOP_URL` | SLOP server URL (default: http://127.0.0.1:3000) |

## Links

- [GitHub Repository](https://github.com/slopsecurityadmin/slop-security-auditor)
- [npm Package](https://www.npmjs.com/package/@slop/auditor)
- [SLOP Protocol](https://github.com/agnt-gg/slop)

## License

MIT
