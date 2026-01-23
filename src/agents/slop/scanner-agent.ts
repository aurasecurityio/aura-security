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
      scanners: { type: 'array', description: 'Which scanners to run (gitleaks, trivy, semgrep, npm-audit)', required: false },
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
    const tools = ['gitleaks', 'trivy', 'semgrep', 'npm'];
    const available: string[] = [];
    const missing: string[] = [];

    for (const tool of tools) {
      try {
        execSync(`which ${tool} || where ${tool}`, { stdio: 'ignore' });
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

    const enabledScanners = scanners || ['gitleaks', 'trivy', 'semgrep', 'npm-audit'];

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
            for (const f of gitleaksFindings) {
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
            console.log(`[Scanner] Gitleaks found ${findings.length} secrets`);
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
