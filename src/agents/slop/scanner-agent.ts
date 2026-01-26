/**
 * Scanner SLOP Agent
 *
 * SLOP-native agent that runs security scans.
 * Wraps Gitleaks, Trivy, Semgrep, and npm audit.
 */

import { execSync, spawn } from 'child_process';
import { SLOPAgent } from './base.js';
import { SLOPAgentConfig, SLOPTool, SLOPToolCall, SLOPToolResult, Finding } from './types.js';

const SCANNER_TOOLS: SLOPTool[] = [
  {
    name: 'scan',
    description: 'Run all available security scanners on a target',
    parameters: {
      target: { type: 'string', description: 'Path or Git URL to scan', required: true },
      scanners: { type: 'array', description: 'Which scanners to run (gitleaks, trivy, semgrep, npm-audit, bandit, checkov, osv-scanner)', required: false },
    },
  },
  {
    name: 'scan-secrets',
    description: 'Scan for secrets and API keys using Gitleaks',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'scan-vulnerabilities',
    description: 'Scan for dependency vulnerabilities using Trivy',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'scan-code',
    description: 'Run static analysis using Semgrep',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'scan-python',
    description: 'Scan Python code for security issues using Bandit',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'scan-iac',
    description: 'Scan Infrastructure as Code using Checkov',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'scan-osv',
    description: 'Scan for vulnerabilities using OSV database',
    parameters: {
      target: { type: 'string', description: 'Path to scan', required: true },
    },
  },
  {
    name: 'check-tools',
    description: 'Check which scanning tools are available',
    parameters: {},
  },
];

export class ScannerAgent extends SLOPAgent {
  private availableTools: Set<string> = new Set();

  constructor(config: Partial<SLOPAgentConfig> = {}) {
    super(
      {
        id: config.id || 'scanner-agent',
        name: config.name || 'Scanner Agent',
        port: config.port || 3010,
        description: 'Security scanner agent - detects secrets, vulnerabilities, and code issues',
        coordinatorUrl: config.coordinatorUrl,
        peers: config.peers,
      },
      SCANNER_TOOLS
    );
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    console.log(`[Scanner] Tool call: ${call.tool}`, call.arguments);

    try {
      switch (call.tool) {
        case 'scan':
          return { result: await this.runFullScan(call.arguments.target as string, call.arguments.scanners as string[] | undefined) };
        case 'scan-secrets':
          return { result: await this.runGitleaks(call.arguments.target as string) };
        case 'scan-vulnerabilities':
          return { result: await this.runTrivy(call.arguments.target as string) };
        case 'scan-code':
          return { result: await this.runSemgrep(call.arguments.target as string) };
        case 'scan-python':
          return { result: await this.runBandit(call.arguments.target as string) };
        case 'scan-iac':
          return { result: await this.runCheckov(call.arguments.target as string) };
        case 'scan-osv':
          return { result: await this.runOsvScanner(call.arguments.target as string) };
        case 'check-tools':
          return { result: await this.checkAvailableTools() };
        default:
          return { error: `Unknown tool: ${call.tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  private async checkAvailableTools(): Promise<{ available: string[]; missing: string[] }> {
    const tools = ['gitleaks', 'trivy', 'semgrep', 'npm', 'bandit', 'checkov', 'osv-scanner', 'nuclei'];
    const available: string[] = [];
    const missing: string[] = [];

    for (const tool of tools) {
      try {
        // Check in PATH and common locations
        execSync(`which ${tool} || test -f /home/ubuntu/.local/bin/${tool} || where ${tool} 2>/dev/null`, { stdio: 'ignore' });
        available.push(tool);
        this.availableTools.add(tool);
      } catch {
        missing.push(tool);
      }
    }

    return { available, missing };
  }

  private async runFullScan(target: string, scanners?: string[]): Promise<{ findings: Finding[]; summary: Record<string, number> }> {
    await this.checkAvailableTools();
    const findings: Finding[] = [];

    const enabledScanners = scanners || ['gitleaks', 'trivy', 'semgrep', 'npm-audit', 'bandit', 'checkov', 'osv-scanner'];

    // Run scanners in parallel
    const scanPromises: Promise<Finding[]>[] = [];

    if (enabledScanners.includes('gitleaks') && this.availableTools.has('gitleaks')) {
      scanPromises.push(this.runGitleaks(target));
    }
    if (enabledScanners.includes('trivy') && this.availableTools.has('trivy')) {
      scanPromises.push(this.runTrivy(target));
    }
    if (enabledScanners.includes('semgrep') && this.availableTools.has('semgrep')) {
      scanPromises.push(this.runSemgrep(target));
    }
    if (enabledScanners.includes('npm-audit') && this.availableTools.has('npm')) {
      scanPromises.push(this.runNpmAudit(target));
    }
    if (enabledScanners.includes('bandit') && this.availableTools.has('bandit')) {
      scanPromises.push(this.runBandit(target));
    }
    if (enabledScanners.includes('checkov') && this.availableTools.has('checkov')) {
      scanPromises.push(this.runCheckov(target));
    }
    if (enabledScanners.includes('osv-scanner') && this.availableTools.has('osv-scanner')) {
      scanPromises.push(this.runOsvScanner(target));
    }

    const results = await Promise.allSettled(scanPromises);

    for (const result of results) {
      if (result.status === 'fulfilled') {
        findings.push(...result.value);
      }
    }

    // Calculate summary
    const summary = {
      total: findings.length,
      critical: findings.filter((f) => f.severity === 'critical').length,
      high: findings.filter((f) => f.severity === 'high').length,
      medium: findings.filter((f) => f.severity === 'medium').length,
      low: findings.filter((f) => f.severity === 'low').length,
      secrets: findings.filter((f) => f.type === 'secret').length,
      vulnerabilities: findings.filter((f) => f.type === 'vulnerability').length,
      codeIssues: findings.filter((f) => f.type === 'code-issue').length,
    };

    // Write to shared memory
    await this.writeMemory(`scan:${target}:${Date.now()}`, {
      target,
      findings,
      summary,
      timestamp: Date.now(),
    });

    return { findings, summary };
  }

  private async runGitleaks(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];
    const tempFile = `/tmp/gitleaks-${Date.now()}.json`;

    // Patterns to exclude (false positives)
    const excludePatterns = [
      /\.secrets\.baseline$/,      // detect-secrets baseline files
      /\.test\.[jt]sx?$/,          // Test files (.test.ts, .test.js, .test.tsx, .test.jsx)
      /\.spec\.[jt]sx?$/,          // Spec files (.spec.ts, .spec.js)
      /test\.py$/,                 // Python test files
      /_test\.go$/,                // Go test files
      /\.fuzz\.test\.[jt]s$/,      // Fuzz test files
      /\/tests?\//i,               // Files in test directories
      /\/fixtures?\//i,            // Test fixtures
      /\/mocks?\//i,               // Mock files
    ];

    // Rule + path combinations to exclude (documentation examples)
    const excludeRulePaths = [
      { rule: /curl-auth-header/, path: /\.md$/ },       // curl examples in docs
      { rule: /generic-api-key/, path: /\.md$/ },        // API key examples in docs
      { rule: /generic-api-key/, path: /\.example$/ },   // Example files
    ];

    try {
      // Gitleaks exits with code 1 when it finds leaks - that's not an error!
      const result = await this.executeCommand('gitleaks', ['detect', '--source', target, '--report-format', 'json', '--report-path', tempFile, '--no-git']);

      // Read the JSON output file regardless of exit code
      const fs = await import('fs');
      if (fs.existsSync(tempFile)) {
        const jsonContent = fs.readFileSync(tempFile, 'utf-8');
        fs.unlinkSync(tempFile); // Clean up

        if (jsonContent && jsonContent.trim()) {
          const gitleaksFindings = JSON.parse(jsonContent);
          if (Array.isArray(gitleaksFindings)) {
            let skipped = 0;
            for (const f of gitleaksFindings) {
              const filePath = f.File || '';
              const ruleId = f.RuleID || f.Rule || f.rule || '';

              // Skip files matching exclusion patterns
              if (excludePatterns.some(pattern => pattern.test(filePath))) {
                skipped++;
                continue;
              }

              // Skip rule+path combinations (documentation examples)
              if (excludeRulePaths.some(({ rule, path }) => rule.test(ruleId) && path.test(filePath))) {
                skipped++;
                continue;
              }

              findings.push({
                id: `gitleaks-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
                type: 'secret',
                severity: this.mapGitleaksSeverity(f.RuleID || f.Rule || f.rule),
                title: f.Description || f.RuleID || f.rule || 'Secret detected',
                description: `${f.RuleID || f.Rule || f.rule}: Secret found in ${f.File}`,
                file: f.File,
                line: f.StartLine || f.Line,
                metadata: { rule: f.RuleID || f.Rule || f.rule, match: f.Match?.substring(0, 100) },
              });
            }
            console.log(`[Scanner] Gitleaks found ${findings.length} secrets (${skipped} filtered as false positives)`);
          }
        }
      }
    } catch (error) {
      console.log('[Scanner] Gitleaks scan error:', error);
    }

    return findings;
  }

  private async runTrivy(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('trivy', ['fs', '--format', 'json', target]);

      if (result.stdout) {
        const trivyResult = JSON.parse(result.stdout);
        const results = trivyResult.Results || [];

        for (const r of results) {
          for (const v of r.Vulnerabilities || []) {
            findings.push({
              id: `trivy-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
              type: 'vulnerability',
              severity: this.mapTrivySeverity(v.Severity),
              title: v.VulnerabilityID || v.Title,
              description: v.Description || v.Title || 'Vulnerability found',
              package: v.PkgName,
              version: v.InstalledVersion,
              cve: v.VulnerabilityID,
              metadata: {
                fixedVersion: v.FixedVersion,
                references: v.References,
              },
            });
          }
        }
      }
    } catch (error) {
      console.log('[Scanner] Trivy scan error:', error);
    }

    return findings;
  }

  private async runSemgrep(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('semgrep', ['scan', '--config', 'auto', '--json', target]);

      if (result.stdout) {
        const semgrepResult = JSON.parse(result.stdout);

        for (const r of semgrepResult.results || []) {
          findings.push({
            id: `semgrep-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
            type: 'code-issue',
            severity: this.mapSemgrepSeverity(r.extra?.severity || 'WARNING'),
            title: r.check_id || 'Code issue',
            description: r.extra?.message || r.check_id,
            file: r.path,
            line: r.start?.line,
            cwe: r.extra?.metadata?.cwe?.[0],
            metadata: {
              rule: r.check_id,
              category: r.extra?.metadata?.category,
            },
          });
        }
      }
    } catch (error) {
      console.log('[Scanner] Semgrep scan error:', error);
    }

    return findings;
  }

  private async runNpmAudit(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('npm', ['audit', '--json'], { cwd: target });

      if (result.stdout) {
        const auditResult = JSON.parse(result.stdout);
        const vulnerabilities = auditResult.vulnerabilities || {};

        for (const [name, vuln] of Object.entries(vulnerabilities)) {
          const v = vuln as { severity: string; via: Array<{ title: string; url: string; cwe: string[] }>; fixAvailable: unknown };
          const via = Array.isArray(v.via) ? v.via[0] : v.via;

          findings.push({
            id: `npm-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
            type: 'vulnerability',
            severity: this.mapNpmSeverity(v.severity),
            title: typeof via === 'object' ? via.title : String(via),
            description: typeof via === 'object' ? via.title : `Vulnerability in ${name}`,
            package: name,
            cwe: typeof via === 'object' ? via.cwe?.[0] : undefined,
            metadata: {
              fixAvailable: v.fixAvailable,
            },
          });
        }
      }
    } catch (error) {
      console.log('[Scanner] npm audit error:', error);
    }

    return findings;
  }

  private async runBandit(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('/home/ubuntu/.local/bin/bandit', ['-r', '-f', 'json', target]);

      if (result.stdout) {
        const banditResult = JSON.parse(result.stdout);

        for (const r of banditResult.results || []) {
          findings.push({
            id: `bandit-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
            type: 'code-issue',
            severity: this.mapBanditSeverity(r.issue_severity),
            title: r.issue_text,
            description: `${r.test_name}: ${r.issue_text}`,
            file: r.filename,
            line: r.line_number,
            cwe: r.issue_cwe?.id ? `CWE-${r.issue_cwe.id}` : undefined,
            metadata: {
              test_id: r.test_id,
              test_name: r.test_name,
              confidence: r.issue_confidence,
            },
          });
        }
        console.log(`[Scanner] Bandit found ${findings.length} Python security issues`);
      }
    } catch (error) {
      console.log('[Scanner] Bandit scan error:', error);
    }

    return findings;
  }

  private async runCheckov(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('/home/ubuntu/.local/bin/checkov', ['-d', target, '-o', 'json', '--quiet']);

      if (result.stdout) {
        // Checkov outputs multiple JSON objects, find the one with results
        const lines = result.stdout.split('\n').filter(l => l.trim().startsWith('{'));
        for (const line of lines) {
          try {
            const checkovResult = JSON.parse(line);
            const failed = checkovResult.results?.failed_checks || [];

            for (const check of failed) {
              findings.push({
                id: `checkov-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
                type: 'iac',
                severity: this.mapCheckovSeverity(check.check_result?.result || 'FAILED'),
                title: check.check_id,
                description: check.check_name || check.check_id,
                file: check.file_path,
                line: check.file_line_range?.[0],
                metadata: {
                  check_id: check.check_id,
                  resource: check.resource,
                  guideline: check.guideline,
                },
              });
            }
          } catch {
            // Skip invalid JSON lines
          }
        }
        console.log(`[Scanner] Checkov found ${findings.length} IaC issues`);
      }
    } catch (error) {
      console.log('[Scanner] Checkov scan error:', error);
    }

    return findings;
  }

  private async runOsvScanner(target: string): Promise<Finding[]> {
    const findings: Finding[] = [];

    try {
      const result = await this.executeCommand('osv-scanner', ['--json', '-r', target]);

      if (result.stdout) {
        const osvResult = JSON.parse(result.stdout);

        for (const r of osvResult.results || []) {
          for (const pkg of r.packages || []) {
            for (const v of pkg.vulnerabilities || []) {
              findings.push({
                id: `osv-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
                type: 'vulnerability',
                severity: this.mapOsvSeverity(v.database_specific?.severity || v.severity?.[0]?.type),
                title: v.id,
                description: v.summary || v.details?.substring(0, 200) || v.id,
                package: pkg.package?.name,
                version: pkg.package?.version,
                cve: v.aliases?.find((a: string) => a.startsWith('CVE-')),
                metadata: {
                  osv_id: v.id,
                  aliases: v.aliases,
                  references: v.references?.map((r: { url: string }) => r.url),
                },
              });
            }
          }
        }
        console.log(`[Scanner] OSV-Scanner found ${findings.length} vulnerabilities`);
      }
    } catch (error) {
      console.log('[Scanner] OSV-Scanner error:', error);
    }

    return findings;
  }

  private mapBanditSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = (severity || '').toUpperCase();
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    return 'low';
  }

  private mapCheckovSeverity(_result: string): 'critical' | 'high' | 'medium' | 'low' {
    // Checkov doesn't provide severity, all failures are treated as medium
    return 'medium';
  }

  private mapOsvSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MODERATE' || s === 'MEDIUM') return 'medium';
    return 'low';
  }

  private executeCommand(command: string, args: string[], options: { cwd?: string } = {}): Promise<{ stdout: string; stderr: string }> {
    return new Promise((resolve) => {
      const proc = spawn(command, args, { cwd: options.cwd, shell: true });
      let stdout = '';
      let stderr = '';

      proc.stdout?.on('data', (data) => (stdout += data));
      proc.stderr?.on('data', (data) => (stderr += data));
      proc.on('close', () => resolve({ stdout, stderr }));
      proc.on('error', () => resolve({ stdout, stderr }));
    });
  }

  private mapGitleaksSeverity(rule: string): 'critical' | 'high' | 'medium' | 'low' {
    const r = (rule || '').toLowerCase();
    if (r.includes('private') || r.includes('api')) return 'critical';
    if (r.includes('password') || r.includes('secret')) return 'high';
    return 'medium';
  }

  private mapTrivySeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = (severity || '').toUpperCase();
    if (s === 'CRITICAL') return 'critical';
    if (s === 'HIGH') return 'high';
    if (s === 'MEDIUM') return 'medium';
    return 'low';
  }

  private mapSemgrepSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = (severity || '').toUpperCase();
    if (s === 'ERROR') return 'high';
    if (s === 'WARNING') return 'medium';
    return 'low';
  }

  private mapNpmSeverity(severity: string): 'critical' | 'high' | 'medium' | 'low' {
    const s = (severity || '').toLowerCase();
    if (s === 'critical') return 'critical';
    if (s === 'high') return 'high';
    if (s === 'moderate') return 'medium';
    return 'low';
  }
}

// Allow running as standalone
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3010', 10);
  const agent = new ScannerAgent({ port });
  agent.start();
}
