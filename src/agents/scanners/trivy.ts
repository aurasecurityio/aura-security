/**
 * Aura Protocol - Trivy Agent
 *
 * Scans for vulnerabilities in dependencies and containers.
 */

import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'trivy',
  name: 'Trivy',
  role: 'scanner',
  description: 'Scan for vulnerabilities in dependencies and containers',
  enabled: true,
  externalTool: 'trivy',
};

const CAPABILITIES: AgentCapabilities = {
  fileTypes: ['package.json', 'package-lock.json', 'requirements.txt', 'Gemfile', 'go.mod', 'Cargo.toml'],
  languages: ['javascript', 'typescript', 'python', 'ruby', 'go', 'rust'],
  requiresExternalTool: true,
  supportsParallel: true,
};

interface TrivyVulnerability {
  VulnerabilityID: string;
  PkgName: string;
  InstalledVersion: string;
  FixedVersion?: string;
  Severity: string;
  Title?: string;
  Description?: string;
  References?: string[];
  CVSS?: Record<string, { V3Score?: number }>;
}

interface TrivyResult {
  Target: string;
  Type: string;
  Vulnerabilities?: TrivyVulnerability[];
}

interface TrivyOutput {
  Results?: TrivyResult[];
}

export class TrivyAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const findings: ZoneFinding[] = [];

    try {
      context.log('info', `Trivy scanning: ${context.targetPath}`);

      // Run trivy filesystem scan
      const { stdout, stderr, exitCode } = await this.executeCommand(
        'trivy',
        [
          'fs',
          '--format',
          'json',
          '--scanners',
          'vuln',
          '--skip-dirs',
          'node_modules,.git,dist,build',
          context.targetPath,
        ],
        { cwd: context.targetPath, timeout: 300000 }
      );

      if (stdout.trim()) {
        try {
          const output: TrivyOutput = JSON.parse(stdout);

          if (output.Results) {
            for (const result of output.Results) {
              if (result.Vulnerabilities) {
                for (const vuln of result.Vulnerabilities) {
                  const finding = this.createFinding('trivy', {
                    type: 'vulnerability',
                    severity: this.mapSeverity(vuln.Severity),
                    title: `${vuln.PkgName}: ${vuln.VulnerabilityID}`,
                    description: vuln.Title || vuln.Description || `Vulnerability in ${vuln.PkgName}`,
                    file: result.Target,
                    metadata: {
                      vulnerabilityId: vuln.VulnerabilityID,
                      package: vuln.PkgName,
                      installedVersion: vuln.InstalledVersion,
                      fixedVersion: vuln.FixedVersion,
                      references: vuln.References?.slice(0, 3),
                      cvssScore: this.getCvssScore(vuln),
                    },
                  });

                  findings.push(finding);
                  context.addFinding(finding);
                }
              }
            }
          }
        } catch (parseError) {
          context.log('warn', `Failed to parse trivy output: ${parseError}`);
        }
      }

      this.status = 'complete';
      context.log('info', `Trivy found ${findings.length} vulnerabilities`);

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'success',
        findings,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.status = 'error';
      const errorMsg = error instanceof Error ? error.message : String(error);
      context.log('error', `Trivy error: ${errorMsg}`);

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'error',
        findings,
        duration: Date.now() - startTime,
        error: errorMsg,
      };
    }
  }

  private mapSeverity(trivySeverity: string): ZoneFinding['severity'] {
    switch (trivySeverity.toUpperCase()) {
      case 'CRITICAL':
        return 'critical';
      case 'HIGH':
        return 'high';
      case 'MEDIUM':
        return 'medium';
      case 'LOW':
        return 'low';
      default:
        return 'info';
    }
  }

  private getCvssScore(vuln: TrivyVulnerability): number | undefined {
    if (!vuln.CVSS) return undefined;
    for (const source of Object.values(vuln.CVSS)) {
      if (source.V3Score) return source.V3Score;
    }
    return undefined;
  }
}
