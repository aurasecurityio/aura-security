#!/usr/bin/env node
/**
 * SLOP Auditor CLI
 *
 * A security auditor that can scan local directories, git repos, and more.
 * Works standalone (no server needed) or connected to SLOP server.
 *
 * Usage:
 *   slop-auditor scan <path>       Scan a local directory for security issues
 *   slop-auditor serve             Start the SLOP server
 *   slop-auditor visualizer        Start the 3D visualizer
 *   slop-auditor status            Show server status
 *   slop-auditor audit [file]      Run audit via server
 *   slop-auditor logs              Show audit log entries
 *   slop-auditor watch             Watch for new audits
 */

import { visualize, visualizeState, visualizeCompact } from './visualizer/index.js';
import { LocalScanner, quickLocalScan, type LocalScanResult } from './integrations/local-scanner.js';
import { scanAWS, type AWSScanResult, type AWSFinding } from './integrations/aws-scanner.js';
import { generateSBOM, generateCycloneDX, generateSPDX } from './sbom/index.js';
import { checkLicenses, POLICY_NAMES } from './compliance/index.js';
import { toSARIF, toJUnit, toJSONSummary, toGitLabReport } from './output/index.js';
import type { AuditorOutput } from './types/events.js';
import { existsSync, writeFileSync, mkdirSync } from 'fs';
import { join, resolve, basename } from 'path';
import { spawnSync } from 'child_process';

const SLOP_URL = process.env.SLOP_URL ?? 'http://127.0.0.1:3000';
const VERSION = '0.3.0';

// ANSI colors for terminal output
const colors = {
  reset: '\x1b[0m',
  bold: '\x1b[1m',
  dim: '\x1b[2m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  white: '\x1b[37m',
  bgRed: '\x1b[41m',
  bgYellow: '\x1b[43m',
  bgGreen: '\x1b[42m',
};

function c(color: keyof typeof colors, text: string): string {
  return `${colors[color]}${text}${colors.reset}`;
}

// ============ TOOL DEFINITIONS ============

interface ToolInfo {
  name: string;
  command: string;
  description: string;
  category: 'secrets' | 'vulnerabilities' | 'sast' | 'iac' | 'container' | 'license';
  install: {
    brew?: string;
    apt?: string;
    pip?: string;
    npm?: string;
    go?: string;
    cargo?: string;
    gem?: string;
    other?: string;
  };
  license: string;
  required: boolean;
}

const SECURITY_TOOLS: ToolInfo[] = [
  {
    name: 'gitleaks',
    command: 'gitleaks',
    description: 'Secrets detection in code and git history',
    category: 'secrets',
    install: { brew: 'brew install gitleaks', apt: 'apt install gitleaks', other: 'https://github.com/gitleaks/gitleaks#installing' },
    license: 'MIT (Free)',
    required: true
  },
  {
    name: 'trivy',
    command: 'trivy',
    description: 'Vulnerability scanner for containers and filesystems',
    category: 'vulnerabilities',
    install: { brew: 'brew install trivy', apt: 'apt install trivy', other: 'https://github.com/aquasecurity/trivy#installation' },
    license: 'Apache 2.0 (Free)',
    required: true
  },
  {
    name: 'grype',
    command: 'grype',
    description: 'Universal vulnerability scanner',
    category: 'vulnerabilities',
    install: { brew: 'brew install grype', other: 'curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh' },
    license: 'Apache 2.0 (Free)',
    required: false
  },
  {
    name: 'semgrep',
    command: 'semgrep',
    description: 'Static analysis (SAST) for code security',
    category: 'sast',
    install: { pip: 'pip install semgrep', brew: 'brew install semgrep' },
    license: 'LGPL 2.1 (Free, Pro rules paid)',
    required: false
  },
  {
    name: 'checkov',
    command: 'checkov',
    description: 'Infrastructure as Code (IaC) security scanner',
    category: 'iac',
    install: { pip: 'pip install checkov', brew: 'brew install checkov' },
    license: 'Apache 2.0 (Free)',
    required: false
  },
  {
    name: 'hadolint',
    command: 'hadolint',
    description: 'Dockerfile linter and security checker',
    category: 'container',
    install: { brew: 'brew install hadolint', other: 'https://github.com/hadolint/hadolint#install' },
    license: 'GPL-3.0 (Free)',
    required: false
  },
  {
    name: 'pip-audit',
    command: 'pip-audit',
    description: 'Python package vulnerability scanner',
    category: 'vulnerabilities',
    install: { pip: 'pip install pip-audit' },
    license: 'Apache 2.0 (Free)',
    required: false
  },
  {
    name: 'govulncheck',
    command: 'govulncheck',
    description: 'Go module vulnerability scanner',
    category: 'vulnerabilities',
    install: { go: 'go install golang.org/x/vuln/cmd/govulncheck@latest' },
    license: 'BSD-3-Clause (Free)',
    required: false
  },
  {
    name: 'cargo-audit',
    command: 'cargo-audit',
    description: 'Rust crate vulnerability scanner',
    category: 'vulnerabilities',
    install: { cargo: 'cargo install cargo-audit' },
    license: 'Apache 2.0 / MIT (Free)',
    required: false
  },
  {
    name: 'bundle-audit',
    command: 'bundle-audit',
    description: 'Ruby gem vulnerability scanner',
    category: 'vulnerabilities',
    install: { gem: 'gem install bundler-audit' },
    license: 'GPLv3 (Free)',
    required: false
  }
];

function isToolInstalled(command: string): { installed: boolean; version?: string } {
  try {
    const result = spawnSync(command, ['--version'], {
      encoding: 'utf-8',
      timeout: 5000,
      stdio: ['pipe', 'pipe', 'pipe']
    });
    if (result.status === 0) {
      const version = (result.stdout || result.stderr || '').split('\n')[0].trim().slice(0, 50);
      return { installed: true, version };
    }
    return { installed: false };
  } catch {
    return { installed: false };
  }
}

async function runDoctor(): Promise<void> {
  console.log('');
  console.log(c('cyan', '╔═══════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bold', '           SLOP AUDITOR - Security Tools Check               ') + c('cyan', '║'));
  console.log(c('cyan', '╚═══════════════════════════════════════════════════════════════╝'));
  console.log('');

  // Check Node.js
  console.log(c('bold', '► Runtime Environment'));
  console.log(`  ${c('green', '✓')} Node.js ${process.version}`);
  console.log(`  ${c('green', '✓')} Platform: ${process.platform} (${process.arch})`);
  console.log('');

  // Check Git
  const gitCheck = isToolInstalled('git');
  console.log(c('bold', '► Required Tools'));
  if (gitCheck.installed) {
    console.log(`  ${c('green', '✓')} git ${c('dim', gitCheck.version || '')}`);
  } else {
    console.log(`  ${c('red', '✗')} git - ${c('yellow', 'Required for remote repo scanning')}`);
  }

  // Group tools by category
  const categories = {
    secrets: { name: 'Secrets Detection', tools: [] as ToolInfo[] },
    vulnerabilities: { name: 'Vulnerability Scanning', tools: [] as ToolInfo[] },
    sast: { name: 'Static Analysis (SAST)', tools: [] as ToolInfo[] },
    iac: { name: 'Infrastructure as Code', tools: [] as ToolInfo[] },
    container: { name: 'Container Security', tools: [] as ToolInfo[] },
    license: { name: 'License Compliance', tools: [] as ToolInfo[] }
  };

  for (const tool of SECURITY_TOOLS) {
    categories[tool.category].tools.push(tool);
  }

  let installedCount = 0;
  let totalCount = 0;
  const missingTools: ToolInfo[] = [];

  for (const [, category] of Object.entries(categories)) {
    if (category.tools.length === 0) continue;

    console.log('');
    console.log(c('bold', `► ${category.name}`));

    for (const tool of category.tools) {
      totalCount++;
      const check = isToolInstalled(tool.command);

      if (check.installed) {
        installedCount++;
        console.log(`  ${c('green', '✓')} ${tool.name} ${c('dim', check.version || '')}`);
        console.log(`    ${c('dim', tool.description)}`);
        console.log(`    ${c('dim', `License: ${tool.license}`)}`);
      } else {
        missingTools.push(tool);
        const marker = tool.required ? c('red', '✗') : c('yellow', '○');
        const status = tool.required ? c('red', 'MISSING') : c('yellow', 'optional');
        console.log(`  ${marker} ${tool.name} [${status}]`);
        console.log(`    ${c('dim', tool.description)}`);
      }
    }
  }

  // Native capabilities
  console.log('');
  console.log(c('bold', '► Native Capabilities (No External Tools Needed)'));
  console.log(`  ${c('green', '✓')} Regex-based secret detection (fallback)`);
  console.log(`  ${c('green', '✓')} Service/technology discovery`);
  console.log(`  ${c('green', '✓')} Codebase structure mapping`);
  console.log(`  ${c('green', '✓')} Environment file scanning`);
  console.log(`  ${c('green', '✓')} Git repository analysis`);
  console.log(`  ${c('green', '✓')} Language auto-detection`);
  console.log(`  ${c('green', '✓')} npm audit (built into npm)`);

  // Summary
  console.log('');
  console.log('─'.repeat(67));
  const pct = Math.round((installedCount / totalCount) * 100);
  const pctColor = pct >= 80 ? 'green' : pct >= 50 ? 'yellow' : 'red';
  console.log(`Tools installed: ${c(pctColor, `${installedCount}/${totalCount}`)} (${pct}%)`);

  if (missingTools.length > 0) {
    console.log('');
    console.log(c('yellow', '► Installation Commands for Missing Tools:'));
    console.log('');

    for (const tool of missingTools) {
      console.log(`  ${c('cyan', tool.name)}:`);
      if (tool.install.brew) console.log(`    macOS:   ${tool.install.brew}`);
      if (tool.install.apt) console.log(`    Linux:   ${tool.install.apt}`);
      if (tool.install.pip) console.log(`    pip:     ${tool.install.pip}`);
      if (tool.install.npm) console.log(`    npm:     ${tool.install.npm}`);
      if (tool.install.go) console.log(`    go:      ${tool.install.go}`);
      if (tool.install.cargo) console.log(`    cargo:   ${tool.install.cargo}`);
      if (tool.install.gem) console.log(`    gem:     ${tool.install.gem}`);
      if (tool.install.other) console.log(`    other:   ${tool.install.other}`);
    }
  }

  // Quick install script suggestion
  const requiredMissing = missingTools.filter(t => t.required);
  if (requiredMissing.length > 0) {
    console.log('');
    console.log(c('yellow', '⚠ Some required tools are missing. Quick install (macOS):'));
    console.log('');
    console.log(c('cyan', `  brew install ${requiredMissing.filter(t => t.install.brew).map(t => t.name).join(' ')}`));
  } else {
    console.log('');
    console.log(c('green', '✓ All required tools are installed!'));
  }

  console.log('');
}

async function main() {
  const args = process.argv.slice(2);
  const command = args[0];

  // Handle flags
  if (args.includes('--version') || args.includes('-v')) {
    console.log(`slop-auditor v${VERSION}`);
    process.exit(0);
  }

  if (args.includes('--help') || args.includes('-h') || !command) {
    showHelp();
    process.exit(0);
  }

  switch (command) {
    case 'init':
      await runInit(args.slice(1));
      break;
    case 'doctor':
    case 'check':
      await runDoctor();
      break;
    case 'scan':
      await runScan(args.slice(1));
      break;
    case 'aws':
      await runAWSScan(args.slice(1));
      break;
    case 'sbom':
      await runSBOM(args.slice(1));
      break;
    case 'license-check':
      await runLicenseCheck(args.slice(1));
      break;
    case 'serve':
      await startServer();
      break;
    case 'visualizer':
      await startVisualizer();
      break;
    case 'status':
      await showStatus();
      break;
    case 'audit':
      await runAudit(args.slice(1));
      break;
    case 'logs':
      await showLogs();
      break;
    case 'watch':
      await watchMode();
      break;
    default:
      console.error(c('red', `Unknown command: ${command}`));
      console.log('Run slop-auditor --help for usage information.');
      process.exit(1);
  }
}

// ============ INIT COMMAND ============

async function runInit(args: string[]) {
  const targetDir = args[0] ? resolve(args[0]) : process.cwd();
  const configDir = join(targetDir, '.slop-auditor');
  const configFile = join(configDir, 'config.json');
  const gitignorePath = join(targetDir, '.gitignore');

  console.log('');
  console.log(c('cyan', '🔧 Initializing SLOP Auditor configuration...'));
  console.log('');

  // Check if already initialized
  if (existsSync(configFile)) {
    console.log(c('yellow', `Configuration already exists at: ${configFile}`));
    console.log('');
    console.log('To reinitialize, delete the .slop-auditor directory first.');
    process.exit(0);
  }

  // Create config directory
  if (!existsSync(configDir)) {
    mkdirSync(configDir, { recursive: true });
    console.log(c('green', '✓') + ` Created directory: ${configDir}`);
  }

  // Default configuration
  const defaultConfig = {
    "$schema": "https://raw.githubusercontent.com/slopsecurityadmin/slop-security-auditor/main/schemas/config.schema.json",
    "version": "1.0",
    "project": {
      "name": basename(targetDir),
      "description": "Security audit configuration"
    },
    "scanning": {
      "enabled": true,
      "secrets": true,
      "packages": true,
      "sast": true,
      "maxDepth": 5,
      "exclude": [
        "node_modules",
        ".git",
        "dist",
        "build",
        ".next",
        "coverage",
        "__pycache__",
        "venv",
        ".venv"
      ]
    },
    "tools": {
      "gitleaks": {
        "enabled": true,
        "configPath": null
      },
      "trivy": {
        "enabled": true,
        "severity": ["CRITICAL", "HIGH", "MEDIUM"]
      },
      "semgrep": {
        "enabled": true,
        "config": "auto"
      }
    },
    "server": {
      "port": 3000,
      "visualizerPort": 8080
    },
    "thresholds": {
      "failOnCritical": true,
      "failOnHigh": false,
      "maxCritical": 0,
      "maxHigh": 5
    },
    "notifications": {
      "slack": {
        "enabled": false,
        "webhookUrl": null
      },
      "discord": {
        "enabled": false,
        "webhookUrl": null
      }
    },
    "integrations": {
      "github": {
        "enabled": false,
        "token": null,
        "createCheckRuns": true,
        "commentOnPR": true
      },
      "gitlab": {
        "enabled": false,
        "token": null
      },
      "aws": {
        "enabled": false,
        "region": "us-east-1",
        "services": ["iam", "s3", "ec2", "lambda", "rds"]
      }
    }
  };

  // Write config file
  writeFileSync(configFile, JSON.stringify(defaultConfig, null, 2));
  console.log(c('green', '✓') + ` Created config: ${configFile}`);

  // Create a sample .env.example
  const envExamplePath = join(configDir, '.env.example');
  const envExample = `# SLOP Auditor Environment Variables
# Copy this to .env and fill in your values

# Server Configuration
SLOP_PORT=3000
VISUALIZER_PORT=8080

# GitHub Integration (optional)
GITHUB_TOKEN=

# GitLab Integration (optional)
GITLAB_TOKEN=

# Slack Notifications (optional)
SLACK_WEBHOOK_URL=

# Discord Notifications (optional)
DISCORD_WEBHOOK_URL=

# AWS Integration (optional)
AWS_REGION=us-east-1
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
`;

  writeFileSync(envExamplePath, envExample);
  console.log(c('green', '✓') + ` Created: ${envExamplePath}`);

  // Update .gitignore if it exists
  if (existsSync(gitignorePath)) {
    const { readFileSync } = await import('fs');
    const gitignore = readFileSync(gitignorePath, 'utf-8');
    const linesToAdd = [
      '.slop-auditor/.env',
      '.slop-auditor/results/',
      '.slop-auditor/*.log'
    ];

    const missingLines = linesToAdd.filter(line => !gitignore.includes(line));
    if (missingLines.length > 0) {
      const addition = '\n# SLOP Auditor\n' + missingLines.join('\n') + '\n';
      const { appendFileSync } = await import('fs');
      appendFileSync(gitignorePath, addition);
      console.log(c('green', '✓') + ' Updated .gitignore');
    }
  }

  console.log('');
  console.log(c('green', '✓ Initialization complete!'));
  console.log('');
  console.log('Next steps:');
  console.log(`  1. Edit ${c('cyan', configFile)} to customize settings`);
  console.log(`  2. Copy ${c('cyan', envExamplePath)} to .env and add credentials`);
  console.log(`  3. Run ${c('cyan', 'slop-auditor scan .')} to scan your project`);
  console.log('');
}

// ============ SCAN COMMAND (Standalone - no server needed) ============

async function runScan(args: string[]) {
  // Parse arguments
  let targetPath = '.';
  type OutputFormat = 'console' | 'json' | 'sarif' | 'junit' | 'gitlab-sast' | 'gitlab-deps' | 'summary';
  let outputFormat: OutputFormat = 'console';
  let outputFile: string | undefined;
  let languages: string[] | undefined;
  let scanners: string[] | undefined;
  let failOn: string[] = ['critical'];  // Default: fail on critical

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--json' || arg === '-j') {
      outputFormat = 'json';
    } else if (arg === '--format' || arg === '-f') {
      const fmt = args[++i]?.toLowerCase();
      if (['json', 'sarif', 'junit', 'gitlab-sast', 'gitlab-deps', 'summary', 'console'].includes(fmt)) {
        outputFormat = fmt as OutputFormat;
      } else {
        console.error(c('red', `Unknown format: ${fmt}`));
        console.log('Available formats: console, json, sarif, junit, gitlab-sast, gitlab-deps, summary');
        process.exit(1);
      }
    } else if (arg === '--output' || arg === '-o') {
      outputFile = args[++i];
    } else if (arg === '--languages' || arg === '-l') {
      languages = args[++i].split(',').map(l => l.trim());
    } else if (arg === '--scanners' || arg === '-S') {
      scanners = args[++i].split(',').map(s => s.trim());
    } else if (arg === '--fail-on') {
      failOn = args[++i].split(',').map(s => s.trim().toLowerCase());
    } else if (arg === '--no-fail') {
      failOn = [];
    } else if (!arg.startsWith('-')) {
      targetPath = arg;
    }
  }

  // Resolve path
  targetPath = resolve(targetPath);

  if (!existsSync(targetPath)) {
    console.error(c('red', `Error: Path does not exist: ${targetPath}`));
    process.exit(1);
  }

  // Print header
  console.log('');
  console.log(c('cyan', '╔═══════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bold', '               SLOP AUDITOR - Security Scanner               ') + c('cyan', '║'));
  console.log(c('cyan', '╚═══════════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(c('dim', `Target: ${targetPath}`));
  console.log(c('dim', `Time:   ${new Date().toISOString()}`));
  if (languages) console.log(c('dim', `Languages: ${languages.join(', ')}`));
  if (scanners) console.log(c('dim', `Scanners: ${scanners.join(', ')}`));
  console.log('');

  // Run the scan
  console.log(c('yellow', '⏳ Starting security scan...'));
  console.log('');

  const startTime = Date.now();
  const scanner = new LocalScanner({
    targetPath,
    languages,
    scanners,
    scanIaC: true,
    scanDockerfiles: true
  });
  const result = await scanner.scan();
  const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

  console.log('');
  console.log(c('green', `✓ Scan completed in ${elapsed}s`));
  console.log('');

  // Generate output based on format
  let outputContent: string;
  let showConsole = true;

  switch (outputFormat) {
    case 'json':
      outputContent = JSON.stringify(result, null, 2);
      showConsole = false;
      console.log(outputContent);
      break;
    case 'sarif':
      outputContent = JSON.stringify(toSARIF(result, targetPath), null, 2);
      showConsole = false;
      if (!outputFile) console.log(outputContent);
      break;
    case 'junit':
      outputContent = toJUnit(result);
      showConsole = false;
      if (!outputFile) console.log(outputContent);
      break;
    case 'gitlab-sast':
      outputContent = JSON.stringify(toGitLabReport(result, 'sast'), null, 2);
      showConsole = false;
      if (!outputFile) console.log(outputContent);
      break;
    case 'gitlab-deps':
      outputContent = JSON.stringify(toGitLabReport(result, 'dependency_scanning'), null, 2);
      showConsole = false;
      if (!outputFile) console.log(outputContent);
      break;
    case 'summary':
      outputContent = JSON.stringify(toJSONSummary(result), null, 2);
      showConsole = false;
      console.log(outputContent);
      break;
    default:
      outputContent = JSON.stringify(result, null, 2);
      displayScanResults(result);
  }

  // Write to file if requested
  if (outputFile) {
    const outputPath = resolve(outputFile);
    writeFileSync(outputPath, outputContent);
    if (showConsole) {
      console.log('');
    }
    console.log(c('green', `✓ Results saved to: ${outputPath}`));
  }

  // Exit with appropriate code based on --fail-on flag
  const hasCritical = result.secrets.some(s => s.severity === 'critical') ||
                      result.packages.some(p => p.severity === 'critical') ||
                      result.iacFindings.some(i => i.severity === 'critical') ||
                      result.dockerfileFindings.some(d => d.severity === 'critical');
  const hasHigh = result.secrets.some(s => s.severity === 'high') ||
                  result.packages.some(p => p.severity === 'high') ||
                  result.iacFindings.some(i => i.severity === 'high') ||
                  result.dockerfileFindings.some(d => d.severity === 'high');
  const hasMedium = result.secrets.some(s => s.severity === 'medium') ||
                    result.packages.some(p => p.severity === 'medium') ||
                    result.iacFindings.some(i => i.severity === 'medium') ||
                    result.dockerfileFindings.some(d => d.severity === 'medium');

  if (failOn.includes('critical') && hasCritical) {
    process.exit(2);  // Critical findings
  } else if (failOn.includes('high') && hasHigh) {
    process.exit(1);  // High findings
  } else if (failOn.includes('medium') && hasMedium) {
    process.exit(1);  // Medium findings
  }
  process.exit(0);  // Clean
}

function displayScanResults(result: LocalScanResult) {
  // Summary counts
  const secretCount = result.secrets.length;
  const packageCount = result.packages.length;
  const sastCount = result.sastFindings.length;
  const iacCount = result.iacFindings.length;
  const dockerfileCount = result.dockerfileFindings.length;
  const serviceCount = result.discoveredServices.length;
  const moduleCount = result.discoveredModules.length;

  const criticalCount = result.secrets.filter(s => s.severity === 'critical').length +
                        result.packages.filter(p => p.severity === 'critical').length +
                        result.iacFindings.filter(i => i.severity === 'critical').length +
                        result.dockerfileFindings.filter(d => d.severity === 'critical').length;
  const highCount = result.secrets.filter(s => s.severity === 'high').length +
                    result.packages.filter(p => p.severity === 'high').length +
                    result.iacFindings.filter(i => i.severity === 'high').length +
                    result.dockerfileFindings.filter(d => d.severity === 'high').length;
  const mediumCount = result.secrets.filter(s => s.severity === 'medium').length +
                      result.packages.filter(p => p.severity === 'medium').length +
                      result.iacFindings.filter(i => i.severity === 'medium').length +
                      result.dockerfileFindings.filter(d => d.severity === 'medium').length;
  const lowCount = result.secrets.filter(s => s.severity === 'low').length +
                   result.packages.filter(p => p.severity === 'low').length +
                   result.iacFindings.filter(i => i.severity === 'low').length +
                   result.dockerfileFindings.filter(d => d.severity === 'low').length;

  // Stats bar
  console.log('┌─────────────────────────────────────────────────────────────────┐');
  console.log(`│  ${c('bgRed', ` CRITICAL ${criticalCount} `)}  ${c('red', `HIGH ${highCount}`)}  ${c('yellow', `MEDIUM ${mediumCount}`)}  ${c('dim', `LOW ${lowCount}`)}  │`);
  console.log('└─────────────────────────────────────────────────────────────────┘');
  console.log('');

  // Tools used
  console.log(c('cyan', '► Tools Used:'));
  console.log(`  ${result.toolsUsed.join(', ') || 'regex-patterns (fallback)'}`);
  console.log('');

  // Secrets
  if (secretCount > 0) {
    console.log(c('red', `► Secrets Found (${secretCount}):`));
    for (const s of result.secrets.slice(0, 10)) {
      const sev = s.severity === 'critical' ? c('bgRed', ' CRIT ') :
                  s.severity === 'high' ? c('red', ' HIGH ') :
                  s.severity === 'medium' ? c('yellow', ' MED  ') : c('dim', ' LOW  ');
      console.log(`  ${sev} ${s.type}`);
      console.log(`       ${c('dim', s.file)}:${s.line}`);
    }
    if (secretCount > 10) {
      console.log(c('dim', `  ... and ${secretCount - 10} more`));
    }
    console.log('');
  }

  // Package vulnerabilities
  if (packageCount > 0) {
    console.log(c('yellow', `► Package Vulnerabilities (${packageCount}):`));
    for (const p of result.packages.slice(0, 10)) {
      const sev = p.severity === 'critical' ? c('bgRed', ' CRIT ') :
                  p.severity === 'high' ? c('red', ' HIGH ') :
                  p.severity === 'medium' ? c('yellow', ' MED  ') : c('dim', ' LOW  ');
      console.log(`  ${sev} ${p.name}@${p.version}`);
      if (p.vulnId) {
        console.log(`       ${c('dim', p.vulnId)}${p.title ? ': ' + p.title : ''}`);
      }
      if (p.fixedVersion) {
        console.log(`       ${c('green', 'Fix:')} Upgrade to ${p.fixedVersion}`);
      }
    }
    if (packageCount > 10) {
      console.log(c('dim', `  ... and ${packageCount - 10} more`));
    }
    console.log('');
  }

  // SAST findings
  if (sastCount > 0) {
    console.log(c('magenta', `► SAST Findings (${sastCount}):`));
    for (const s of result.sastFindings.slice(0, 10)) {
      console.log(`  [${s.severity}] ${s.rule}`);
      console.log(`       ${c('dim', s.file)}:${s.line}`);
      console.log(`       ${s.message}`);
    }
    if (sastCount > 10) {
      console.log(c('dim', `  ... and ${sastCount - 10} more`));
    }
    console.log('');
  }

  // IaC findings
  if (iacCount > 0) {
    console.log(c('cyan', `► IaC Security Issues (${iacCount}):`));
    for (const i of result.iacFindings.slice(0, 10)) {
      const sev = i.severity === 'critical' ? c('bgRed', ' CRIT ') :
                  i.severity === 'high' ? c('red', ' HIGH ') :
                  i.severity === 'medium' ? c('yellow', ' MED  ') : c('dim', ' LOW  ');
      console.log(`  ${sev} ${i.checkId}`);
      console.log(`       ${c('dim', i.file)} - ${i.resource}`);
      if (i.guideline) {
        console.log(`       ${c('green', 'Guide:')} ${i.guideline}`);
      }
    }
    if (iacCount > 10) {
      console.log(c('dim', `  ... and ${iacCount - 10} more`));
    }
    console.log('');
  }

  // Dockerfile findings
  if (dockerfileCount > 0) {
    console.log(c('blue', `► Dockerfile Issues (${dockerfileCount}):`));
    for (const d of result.dockerfileFindings.slice(0, 10)) {
      const sev = d.severity === 'critical' ? c('bgRed', ' CRIT ') :
                  d.severity === 'high' ? c('red', ' HIGH ') :
                  d.severity === 'medium' ? c('yellow', ' MED  ') : c('dim', ' LOW  ');
      console.log(`  ${sev} ${d.code}`);
      console.log(`       ${c('dim', d.file)}:${d.line}`);
      console.log(`       ${d.message}`);
    }
    if (dockerfileCount > 10) {
      console.log(c('dim', `  ... and ${dockerfileCount - 10} more`));
    }
    console.log('');
  }

  // Languages detected
  if (result.languagesDetected && result.languagesDetected.length > 0) {
    console.log(c('dim', '► Languages Detected:'));
    console.log(`  ${result.languagesDetected.join(', ')}`);
    console.log('');
  }

  // Discovered services
  if (serviceCount > 0) {
    console.log(c('blue', `► Discovered Services (${serviceCount}):`));
    for (const s of result.discoveredServices) {
      const typeColor = s.type === 'database' ? 'blue' :
                        s.type === 'cloud' ? 'cyan' :
                        s.type === 'api' ? 'yellow' :
                        s.type === 'auth' ? 'green' : 'white';
      console.log(`  ${c(typeColor as keyof typeof colors, `[${s.type.toUpperCase()}]`)} ${s.name}`);
      console.log(`       ${c('dim', 'Source:')} ${s.source}`);
    }
    console.log('');
  }

  // Discovered modules
  if (moduleCount > 0) {
    console.log(c('green', `► Codebase Structure (${moduleCount} modules):`));
    for (const m of result.discoveredModules) {
      console.log(`  [${m.type}] ${m.name} (${m.fileCount} files)`);
    }
    console.log('');
  }

  // Git info
  if (result.gitInfo) {
    console.log(c('dim', '► Git Info:'));
    console.log(`  Branch: ${result.gitInfo.branch}`);
    if (result.gitInfo.remoteUrl) {
      console.log(`  Remote: ${result.gitInfo.remoteUrl}`);
    }
    if (result.gitInfo.uncommittedChanges > 0) {
      console.log(`  ${c('yellow', `Uncommitted changes: ${result.gitInfo.uncommittedChanges}`)}`);
    }
    console.log('');
  }

  // Env files
  if (result.envFiles.length > 0) {
    console.log(c('dim', '► Environment Files:'));
    for (const e of result.envFiles) {
      const warning = e.hasSecrets ? c('yellow', ' (contains secrets)') : '';
      console.log(`  ${e.file}${warning} - ${e.variables.length} variables`);
    }
    console.log('');
  }

  // Summary
  const totalIssues = criticalCount + highCount + mediumCount + lowCount;
  if (totalIssues === 0) {
    console.log(c('green', '✓ No security issues found!'));
  } else {
    console.log('─'.repeat(67));
    console.log(`Total issues: ${totalIssues}`);
    if (criticalCount > 0) {
      console.log(c('red', `⚠ ${criticalCount} critical issues require immediate attention!`));
    }
  }
}

// ============ AWS SCAN COMMAND ============

async function runAWSScan(args: string[]) {
  // Parse arguments
  let region = process.env.AWS_REGION || 'us-east-1';
  let profile: string | undefined;
  let services: ('iam' | 's3' | 'ec2' | 'lambda' | 'rds')[] | undefined;
  let outputFormat: 'console' | 'json' | 'both' = 'console';
  let outputFile: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--region' || arg === '-r') {
      region = args[++i];
    } else if (arg === '--profile' || arg === '-p') {
      profile = args[++i];
    } else if (arg === '--services' || arg === '-s') {
      services = args[++i].split(',') as ('iam' | 's3' | 'ec2' | 'lambda' | 'rds')[];
    } else if (arg === '--json' || arg === '-j') {
      outputFormat = 'json';
    } else if (arg === '--output' || arg === '-o') {
      outputFile = args[++i];
      outputFormat = 'both';
    }
  }

  // Print header
  console.log('');
  console.log(c('cyan', '╔═══════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bold', '              SLOP AUDITOR - AWS Security Scan              ') + c('cyan', '║'));
  console.log(c('cyan', '╚═══════════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(c('dim', `Region:  ${region}`));
  if (profile) console.log(c('dim', `Profile: ${profile}`));
  console.log(c('dim', `Time:    ${new Date().toISOString()}`));
  console.log('');

  // Check for AWS credentials
  if (!process.env.AWS_ACCESS_KEY_ID && !process.env.AWS_PROFILE && !profile) {
    console.log(c('yellow', '⚠ No AWS credentials detected.'));
    console.log('');
    console.log('Set credentials using one of these methods:');
    console.log(`  1. Environment variables: ${c('cyan', 'AWS_ACCESS_KEY_ID')} and ${c('cyan', 'AWS_SECRET_ACCESS_KEY')}`);
    console.log(`  2. AWS profile: ${c('cyan', 'slop-auditor aws --profile <name>')}`);
    console.log(`  3. AWS config file: ${c('cyan', '~/.aws/credentials')}`);
    console.log('');
    process.exit(1);
  }

  console.log(c('yellow', '⏳ Scanning AWS infrastructure...'));
  console.log('');

  const startTime = Date.now();

  try {
    const result = await scanAWS({ region, profile, services });
    const elapsed = ((Date.now() - startTime) / 1000).toFixed(2);

    console.log('');
    console.log(c('green', `✓ Scan completed in ${elapsed}s`));
    console.log('');

    // Display results
    if (outputFormat === 'json') {
      console.log(JSON.stringify(result, null, 2));
    } else {
      displayAWSResults(result);
    }

    // Write to file if requested
    if (outputFile) {
      const outputPath = resolve(outputFile);
      writeFileSync(outputPath, JSON.stringify(result, null, 2));
      console.log('');
      console.log(c('green', `✓ Results saved to: ${outputPath}`));
    }

    // Exit with appropriate code
    if (result.summary.critical > 0) {
      process.exit(2);
    } else if (result.summary.high > 0) {
      process.exit(1);
    }
    process.exit(0);

  } catch (err) {
    console.error(c('red', 'AWS scan failed:'), (err as Error).message || err);
    console.log('');
    console.log('Possible causes:');
    console.log('  - Invalid credentials');
    console.log('  - Insufficient IAM permissions');
    console.log('  - Network connectivity issues');
    console.log('');
    process.exit(1);
  }
}

// ============ SBOM COMMAND ============

async function runSBOM(args: string[]) {
  let targetPath = '.';
  let format: 'cyclonedx' | 'spdx' = 'cyclonedx';
  let outputFile: string | undefined;
  let includeVulns = false;
  let projectName: string | undefined;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--format' || arg === '-f') {
      const fmt = args[++i]?.toLowerCase();
      if (fmt === 'cyclonedx' || fmt === 'spdx') {
        format = fmt;
      } else {
        console.error(c('red', `Unknown SBOM format: ${fmt}`));
        console.log('Available formats: cyclonedx, spdx');
        process.exit(1);
      }
    } else if (arg === '--output' || arg === '-o') {
      outputFile = args[++i];
    } else if (arg === '--include-vulns' || arg === '--vulns') {
      includeVulns = true;
    } else if (arg === '--name') {
      projectName = args[++i];
    } else if (!arg.startsWith('-')) {
      targetPath = arg;
    }
  }

  targetPath = resolve(targetPath);

  if (!existsSync(targetPath)) {
    console.error(c('red', `Error: Path does not exist: ${targetPath}`));
    process.exit(1);
  }

  console.log('');
  console.log(c('cyan', '╔═══════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bold', '              SLOP AUDITOR - SBOM Generator                  ') + c('cyan', '║'));
  console.log(c('cyan', '╚═══════════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(c('dim', `Target: ${targetPath}`));
  console.log(c('dim', `Format: ${format.toUpperCase()}`));
  console.log('');

  console.log(c('yellow', '⏳ Generating SBOM...'));

  // Run a quick scan if including vulnerabilities
  let scanResult: LocalScanResult | undefined;
  if (includeVulns) {
    console.log(c('dim', '   Including vulnerability information...'));
    scanResult = await quickLocalScan(targetPath);
  }

  const sbom = generateSBOM(targetPath, scanResult, {
    format,
    includeVulnerabilities: includeVulns,
    projectName: projectName || basename(targetPath)
  });

  const output = JSON.stringify(sbom, null, 2);

  console.log('');
  console.log(c('green', '✓ SBOM generated successfully'));

  if (outputFile) {
    const outputPath = resolve(outputFile);
    writeFileSync(outputPath, output);
    console.log(c('green', `✓ Saved to: ${outputPath}`));
  } else {
    console.log('');
    console.log(output);
  }

  // Summary
  const componentCount = 'components' in sbom ? sbom.components.length : ('packages' in sbom ? sbom.packages.length : 0);
  console.log('');
  console.log(c('dim', `Components: ${componentCount}`));
  if (includeVulns && scanResult) {
    console.log(c('dim', `Vulnerabilities: ${scanResult.packages.length}`));
  }
}

// ============ LICENSE CHECK COMMAND ============

async function runLicenseCheck(args: string[]) {
  let targetPath = '.';
  let policy = 'permissive';
  let allowedLicenses: string[] = [];
  let deniedLicenses: string[] = [];
  let outputFile: string | undefined;
  let outputJson = false;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    if (arg === '--policy' || arg === '-p') {
      policy = args[++i] || 'permissive';
      if (!POLICY_NAMES.includes(policy)) {
        console.error(c('red', `Unknown policy: ${policy}`));
        console.log(`Available policies: ${POLICY_NAMES.join(', ')}`);
        process.exit(1);
      }
    } else if (arg === '--allow') {
      allowedLicenses = args[++i].split(',').map(s => s.trim());
    } else if (arg === '--deny') {
      deniedLicenses = args[++i].split(',').map(s => s.trim());
    } else if (arg === '--output' || arg === '-o') {
      outputFile = args[++i];
    } else if (arg === '--json') {
      outputJson = true;
    } else if (!arg.startsWith('-')) {
      targetPath = arg;
    }
  }

  targetPath = resolve(targetPath);

  if (!existsSync(targetPath)) {
    console.error(c('red', `Error: Path does not exist: ${targetPath}`));
    process.exit(1);
  }

  console.log('');
  console.log(c('cyan', '╔═══════════════════════════════════════════════════════════════╗'));
  console.log(c('cyan', '║') + c('bold', '            SLOP AUDITOR - License Compliance                ') + c('cyan', '║'));
  console.log(c('cyan', '╚═══════════════════════════════════════════════════════════════╝'));
  console.log('');
  console.log(c('dim', `Target: ${targetPath}`));
  console.log(c('dim', `Policy: ${policy}`));
  console.log('');

  console.log(c('yellow', '⏳ Checking licenses...'));
  console.log('');

  const result = checkLicenses(targetPath, {
    policy,
    allowedLicenses: allowedLicenses.length > 0 ? allowedLicenses : undefined,
    deniedLicenses: deniedLicenses.length > 0 ? deniedLicenses : undefined
  });

  if (outputJson) {
    const output = JSON.stringify(result, null, 2);
    if (outputFile) {
      writeFileSync(resolve(outputFile), output);
      console.log(c('green', `✓ Results saved to: ${outputFile}`));
    } else {
      console.log(output);
    }
  } else {
    // Display results
    console.log('┌─────────────────────────────────────────────────────────────────┐');
    console.log(`│  Total: ${result.summary.total}  ${c('green', `Compliant: ${result.summary.compliant}`)}  ${c('red', `Violations: ${result.summary.violations}`)}  ${c('yellow', `Unknown: ${result.summary.unknown}`)}  │`);
    console.log('└─────────────────────────────────────────────────────────────────┘');
    console.log('');

    if (result.violations.length > 0) {
      console.log(c('red', `► License Violations (${result.violations.length}):`));
      for (const v of result.violations.slice(0, 15)) {
        const sev = v.severity === 'high' ? c('red', ' HIGH ') :
                    v.severity === 'medium' ? c('yellow', ' MED  ') : c('dim', ' LOW  ');
        console.log(`  ${sev} ${v.package}@${v.version}`);
        console.log(`       License: ${v.license}`);
        console.log(`       ${c('dim', v.violation)}`);
      }
      if (result.violations.length > 15) {
        console.log(c('dim', `  ... and ${result.violations.length - 15} more`));
      }
      console.log('');
    }

    // Show some compliant licenses
    const compliant = result.licenses.filter(l =>
      !result.violations.some(v => v.package === l.package && v.version === l.version)
    );
    if (compliant.length > 0) {
      console.log(c('green', `► Compliant Packages (${compliant.length}):`));
      const licenseCounts = new Map<string, number>();
      for (const l of compliant) {
        licenseCounts.set(l.license, (licenseCounts.get(l.license) || 0) + 1);
      }
      const sorted = [...licenseCounts.entries()].sort((a, b) => b[1] - a[1]);
      for (const [license, count] of sorted.slice(0, 10)) {
        console.log(`  ${license}: ${count} packages`);
      }
      console.log('');
    }

    if (outputFile) {
      writeFileSync(resolve(outputFile), JSON.stringify(result, null, 2));
      console.log(c('green', `✓ Results saved to: ${outputFile}`));
    }
  }

  // Exit with error if violations found
  const highViolations = result.violations.filter(v => v.severity === 'high').length;
  if (highViolations > 0) {
    process.exit(1);
  }
}

function displayAWSResults(result: AWSScanResult) {
  const { summary, findings, scannedServices, errors } = result;

  // Stats bar
  console.log('┌─────────────────────────────────────────────────────────────────┐');
  console.log(`│  ${c('bgRed', ` CRITICAL ${summary.critical} `)}  ${c('red', `HIGH ${summary.high}`)}  ${c('yellow', `MEDIUM ${summary.medium}`)}  ${c('dim', `LOW ${summary.low}`)}  INFO ${summary.info}  │`);
  console.log('└─────────────────────────────────────────────────────────────────┘');
  console.log('');

  // Scanned services
  console.log(c('cyan', '► Services Scanned:'));
  console.log(`  ${scannedServices.join(', ') || 'None'}`);
  console.log('');

  // Errors
  if (errors.length > 0) {
    console.log(c('red', '► Scan Errors:'));
    for (const err of errors) {
      console.log(`  [${err.service}] ${err.error}`);
    }
    console.log('');
  }

  // Group findings by service
  const byService = new Map<string, AWSFinding[]>();
  for (const finding of findings) {
    const existing = byService.get(finding.service) || [];
    existing.push(finding);
    byService.set(finding.service, existing);
  }

  // Display findings by service
  for (const [service, serviceFindings] of byService) {
    const serviceUpper = service.toUpperCase();
    const serviceColor = service === 'iam' ? 'green' :
                         service === 's3' ? 'blue' :
                         service === 'ec2' ? 'yellow' :
                         service === 'lambda' ? 'magenta' :
                         service === 'rds' ? 'cyan' : 'white';

    console.log(c(serviceColor as keyof typeof colors, `► ${serviceUpper} Findings (${serviceFindings.length}):`));

    for (const f of serviceFindings.slice(0, 10)) {
      const sev = f.severity === 'critical' ? c('bgRed', ' CRIT ') :
                  f.severity === 'high' ? c('red', ' HIGH ') :
                  f.severity === 'medium' ? c('yellow', ' MED  ') :
                  f.severity === 'low' ? c('dim', ' LOW  ') : c('dim', ' INFO ');

      console.log(`  ${sev} ${f.title}`);
      console.log(`       ${c('dim', f.resourceType)}: ${f.resourceId}`);
      if (f.remediation) {
        console.log(`       ${c('green', 'Fix:')} ${f.remediation}`);
      }
    }

    if (serviceFindings.length > 10) {
      console.log(c('dim', `  ... and ${serviceFindings.length - 10} more`));
    }
    console.log('');
  }

  // Summary
  if (summary.total === 0) {
    console.log(c('green', '✓ No security issues found in AWS!'));
  } else {
    console.log('─'.repeat(67));
    console.log(`Total AWS findings: ${summary.total}`);
    if (summary.critical > 0) {
      console.log(c('red', `⚠ ${summary.critical} critical issues require immediate attention!`));
    }
  }
}

// ============ SERVER COMMANDS ============

async function startServer() {
  console.log(c('cyan', '🚀 Starting SLOP Auditor server...'));
  console.log('');

  // Dynamically import index.js which auto-starts the server
  try {
    await import('./index.js');
    // The server runs until stopped via SIGINT/SIGTERM
  } catch (err) {
    console.error(c('red', 'Failed to start server:'), err);
    process.exit(1);
  }
}

async function startVisualizer() {
  console.log(c('cyan', '🎮 Starting 3D Visualizer...'));
  console.log('');

  try {
    // Dynamically import serve-visualizer.js which auto-starts
    await import('./serve-visualizer.js');
  } catch (err) {
    console.error(c('red', 'Failed to start visualizer:'), err);
    process.exit(1);
  }
}

async function showStatus() {
  try {
    const res = await fetch(`${SLOP_URL}/info`);
    const info = await res.json();
    console.log('');
    console.log(c('cyan', '╔═══════════════════════════════════════╗'));
    console.log(c('cyan', '║') + c('bold', '       SLOP AUDITOR STATUS            ') + c('cyan', '║'));
    console.log(c('cyan', '╚═══════════════════════════════════════╝'));
    console.log('');
    console.log(`  Server:    ${c('green', SLOP_URL)}`);
    console.log(`  Name:      ${info.name}`);
    console.log(`  Version:   ${info.version}`);
    console.log(`  Tools:     ${info.tools.join(', ')}`);
    console.log(`  Endpoints: ${info.endpoints.join(', ')}`);
    console.log('');
  } catch (err) {
    console.error(c('red', '✗ Cannot connect to SLOP server at'), SLOP_URL);
    console.log('');
    console.log('  Is the server running? Start it with:');
    console.log(c('cyan', '    slop-auditor serve'));
    console.log('');
    process.exit(1);
  }
}

async function runAudit(args: string[]) {
  const inputFile = args[0];

  if (!inputFile) {
    // Run interactive demo
    const demoInput = {
      tool: 'audit',
      arguments: {
        change_event: {
          id: 'demo-' + Date.now(),
          type: 'pull_request',
          environment: 'staging',
          repo: 'demo/app',
          commit: 'a'.repeat(40),
          files_changed: ['src/auth/login.ts'],
          diff: '+const API_KEY = "secret123";'
        },
        evidence_bundle: {
          vuln_scan: 'critical: 1\nhigh: 2'
        },
        policy_context: {
          critical_assets: ['auth'],
          risk_tolerance: 'low'
        }
      }
    };

    console.log('');
    console.log(c('yellow', '🔍 Running demo audit...'));
    console.log('');

    try {
      const res = await fetch(`${SLOP_URL}/tools`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(demoInput)
      });

      const data = await res.json();
      const output = data.result as AuditorOutput;

      console.log(visualize(output));
      console.log('');
      console.log(visualizeState(output.agent_state));
      console.log('');
      console.log(visualizeCompact(output));
    } catch (err) {
      console.error(c('red', '✗ Server not reachable. Start it with: slop-auditor serve'));
      process.exit(1);
    }
  } else {
    // Load from file
    const { readFileSync } = await import('fs');
    const input = JSON.parse(readFileSync(inputFile, 'utf-8'));

    const payload = input.tool ? input : { tool: 'audit', arguments: input };

    const res = await fetch(`${SLOP_URL}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });

    const data = await res.json();
    const output = data.result as AuditorOutput;

    console.log(visualize(output));
  }
}

async function showLogs() {
  try {
    const res = await fetch(`${SLOP_URL}/memory`);
    const data = await res.json();

    console.log('');
    console.log(c('cyan', '╔═══════════════════════════════════════╗'));
    console.log(c('cyan', '║') + c('bold', '        AUDIT LOG ENTRIES             ') + c('cyan', '║'));
    console.log(c('cyan', '╚═══════════════════════════════════════╝'));
    console.log('');

    if (data.keys.length === 0) {
      console.log('  No audit logs found.');
    } else {
      for (const key of data.keys) {
        const parts = key.split(':');
        console.log(`  • ${parts[1]} (${new Date(parseInt(parts[2])).toISOString()})`);
      }
    }
    console.log('');
  } catch {
    console.error(c('red', '✗ Server not reachable. Start it with: slop-auditor serve'));
    process.exit(1);
  }
}

async function watchMode() {
  console.log('');
  console.log(c('cyan', '👁️  SLOP Auditor Watch Mode'));
  console.log(c('dim', '   Monitoring for new audits... (Ctrl+C to exit)'));
  console.log('');

  let lastCount = 0;

  setInterval(async () => {
    try {
      const res = await fetch(`${SLOP_URL}/memory`);
      const data = await res.json();

      if (data.keys.length > lastCount) {
        const newKeys = data.keys.slice(lastCount);
        for (const key of newKeys) {
          const entryRes = await fetch(`${SLOP_URL}/memory?key=${encodeURIComponent(key)}`);
          const entry = await entryRes.json();

          if (entry.value) {
            console.log('');
            console.log(c('green', '━━━ NEW AUDIT ━━━'));
            console.log(visualizeCompact(entry.value as AuditorOutput));
          }
        }
        lastCount = data.keys.length;
      }
    } catch {
      // Ignore errors in watch mode
    }
  }, 2000);
}

function showHelp() {
  console.log(`
${c('cyan', 'SLOP Auditor')} - Security Scanner & Audit Pipeline
${c('dim', `Version ${VERSION}`)}

${c('bold', 'USAGE:')}
  slop-auditor <command> [options]

${c('bold', 'COMMANDS:')}
  ${c('green', 'doctor')}                 Check installed security tools and show install commands
  ${c('green', 'init')} [path]            Initialize config in a project directory
  ${c('green', 'scan')} <path>            Scan a directory for security issues (standalone)
  ${c('green', 'sbom')} <path>            Generate Software Bill of Materials
  ${c('green', 'license-check')} <path>   Check license compliance
  ${c('green', 'aws')}                    Scan AWS infrastructure for security issues
  ${c('green', 'serve')}                  Start the SLOP server (port 3000)
  ${c('green', 'visualizer')}             Start the 3D visualizer (port 8080)
  ${c('green', 'status')}                 Show server connection status
  ${c('green', 'audit')} [file]           Run audit via server (demo if no file)
  ${c('green', 'logs')}                   Show audit log entries from server
  ${c('green', 'watch')}                  Watch for new audits in real-time

${c('bold', 'SCAN OPTIONS:')}
  -j, --json        Output results as JSON
  -f, --format      Output format: console, json, sarif, junit, gitlab-sast, gitlab-deps, summary
  -o, --output      Save results to file
  -l, --languages   Filter by languages: js,py,go,rust,ruby,php,java
  -S, --scanners    Use specific scanners: grype,trivy,gitleaks,semgrep,checkov,hadolint,pip-audit,govulncheck,cargo-audit,bundle-audit,composer
  --fail-on         Exit with error on severity: critical,high,medium (default: critical)
  --no-fail         Never exit with error code

${c('bold', 'SBOM OPTIONS:')}
  -f, --format      SBOM format: cyclonedx (default), spdx
  -o, --output      Save SBOM to file
  --include-vulns   Include vulnerability information
  --name            Project name for SBOM metadata

${c('bold', 'LICENSE OPTIONS:')}
  -p, --policy      License policy: permissive (default), strict, copyleft
  --allow           Additional licenses to allow (comma-separated)
  --deny            Additional licenses to deny (comma-separated)
  --json            Output as JSON
  -o, --output      Save results to file

${c('bold', 'AWS OPTIONS:')}
  -r, --region      AWS region (default: us-east-1)
  -p, --profile     AWS profile name
  -s, --services    Services to scan: iam,s3,ec2,lambda,rds

${c('bold', 'EXAMPLES:')}
  ${c('dim', '# Initialize config in current directory')}
  slop-auditor init

  ${c('dim', '# Scan current directory')}
  slop-auditor scan .

  ${c('dim', '# Scan with SARIF output (GitHub Code Scanning)')}
  slop-auditor scan . --format sarif -o results.sarif

  ${c('dim', '# Scan with GitLab security report format')}
  slop-auditor scan . --format gitlab-sast -o gl-sast-report.json

  ${c('dim', '# Scan only Python projects')}
  slop-auditor scan . --languages py

  ${c('dim', '# Use specific scanners')}
  slop-auditor scan . --scanners grype,checkov,hadolint

  ${c('dim', '# Generate CycloneDX SBOM')}
  slop-auditor sbom . --format cyclonedx -o sbom.json

  ${c('dim', '# Generate SPDX SBOM with vulnerabilities')}
  slop-auditor sbom . --format spdx --include-vulns -o sbom-spdx.json

  ${c('dim', '# Check license compliance')}
  slop-auditor license-check . --policy strict

  ${c('dim', '# License check with custom allowed licenses')}
  slop-auditor license-check . --allow "MPL-2.0,LGPL-3.0"

  ${c('dim', '# Scan AWS infrastructure')}
  slop-auditor aws --region us-west-2

  ${c('dim', '# Start full stack (2 terminals)')}
  slop-auditor serve        ${c('dim', '# Terminal 1')}
  slop-auditor visualizer   ${c('dim', '# Terminal 2')}

${c('bold', 'CI/CD INTEGRATION:')}
  ${c('dim', 'See templates/ci/ for GitHub Actions and GitLab CI examples')}

${c('bold', 'OUTPUT FORMATS:')}
  console       Interactive terminal output (default)
  json          Full JSON results
  sarif         SARIF 2.1.0 for GitHub Code Scanning, VS Code
  junit         JUnit XML for CI test reporters
  gitlab-sast   GitLab SAST security report
  gitlab-deps   GitLab Dependency Scanning report
  summary       Compact JSON summary

${c('bold', 'ENVIRONMENT:')}
  SLOP_URL          Server URL (default: http://127.0.0.1:3000)

${c('bold', 'EXIT CODES:')}
  0    Clean - no issues found
  1    High severity issues found
  2    Critical severity issues found

${c('dim', 'For more info: https://github.com/slopsecurityadmin/slop-security-auditor')}
`);
}

main().catch((err) => {
  console.error(c('red', 'Error:'), err.message || err);
  process.exit(1);
});
