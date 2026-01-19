# aurasecurity - Python Wrapper

Security auditor with 3D visualization - Python wrapper for the `aura-security` npm package.

## Installation

```bash
pip install aurasecurity
```

## Requirements

- Python 3.8+
- Node.js 18+ (for the underlying scanner)

## CLI Usage

```bash
# Scan current directory
aurasecurity scan .

# Scan specific directory
aurasecurity scan /path/to/repo

# Scan AWS infrastructure
aurasecurity aws --region us-west-2

# Initialize configuration
aurasecurity init

# Start server and visualizer
aurasecurity serve &
aurasecurity visualizer
```

## Python API

```python
from aurasecurity import scan, scan_aws, AuraSecurity

# Quick scan
results = scan("./my-project")
print(f"Found {len(results['secrets'])} secrets")

# AWS scan
aws_results = scan_aws(region="us-west-2", services=["s3", "iam"])

# Full API
auditor = AuraSecurity()
results = auditor.scan("./project", output_json=True)
```

## Features

- **Multi-Scanner Integration**: Gitleaks, Trivy, Semgrep, npm audit
- **AWS Infrastructure Scanning**: IAM, S3, EC2, Lambda, RDS security checks
- **3D Visualization**: Interactive Three.js control plane
- **SLOP Protocol**: Compatible with the Simple Language Open Protocol

## Environment Variables

| Variable | Description |
|----------|-------------|
| `AURA_PORT` | Aura server port (default: 3000) |
| `VISUALIZER_PORT` | Visualizer port (default: 8080) |

## Links

- [GitHub Repository](https://github.com/yvasisht/aura-security)
- [npm Package](https://www.npmjs.com/package/aura-security)
- [SLOP Protocol](https://github.com/agnt-gg/slop)
