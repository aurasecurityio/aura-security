/**
 * Aura Protocol - NPM Audit Agent
 *
 * Audit npm packages for vulnerabilities.
 */

import * as fs from 'fs';
import * as path from 'path';
import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'npm-audit',
  name: 'NPM Audit',
  role: 'scanner',
  description: 'Audit npm packages for vulnerabilities',
  enabled: true,
  externalTool: 'npm',
};

const CAPABILITIES: AgentCapabilities = {
  fileTypes: ['package.json', 'package-lock.json'],
  languages: ['javascript', 'typescript'],
  requiresExternalTool: true,
  supportsParallel: true,
};

interface NpmAuditVulnerability {
  name: string;
  severity: string;
  isDirect: boolean;
  via: Array<string | { title: string; url: string; severity: string; cwe: string[] }>;
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable:
    | boolean
    | {
        name: string;
        version: string;
        isSemVerMajor: boolean;
      };
}

interface NpmAuditOutput {
  vulnerabilities?: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities: {
      total: number;
      critical: number;
      high: number;
      moderate: number;
      low: number;
    };
  };
}

export class NpmAuditAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const findings: ZoneFinding[] = [];

    try {
      // Check if package.json exists
      const packageJsonPath = path.join(context.targetPath, 'package.json');
      if (!fs.existsSync(packageJsonPath)) {
        context.log('info', 'No package.json found, skipping npm audit');
        this.status = 'complete';
        return {
          agentId: this.config.id,
          agentName: this.config.name,
          status: 'skipped',
          findings: [],
          duration: Date.now() - startTime,
        };
      }

      context.log('info', `NPM Audit scanning: ${context.targetPath}`);

      // Run npm audit
      const { stdout, stderr, exitCode } = await this.executeCommand(
        'npm',
        ['audit', '--json'],
        { cwd: context.targetPath, timeout: 120000 }
      );

      if (stdout.trim()) {
        try {
          const output: NpmAuditOutput = JSON.parse(stdout);

          if (output.vulnerabilities) {
            for (const [pkgName, vuln] of Object.entries(output.vulnerabilities)) {
              // Get details from the 'via' field
              let title = `Vulnerability in ${pkgName}`;
              let cwe: string[] = [];
              let url: string | undefined;

              for (const via of vuln.via) {
                if (typeof via === 'object') {
                  title = via.title || title;
                  cwe = via.cwe || cwe;
                  url = via.url;
                  break;
                }
              }

              const finding = this.createFinding('npm-audit', {
                type: 'vulnerability',
                severity: this.mapSeverity(vuln.severity),
                title: `${pkgName}: ${title}`,
                description: `${title}. Affects versions: ${vuln.range}`,
                file: 'package.json',
                metadata: {
                  package: pkgName,
                  severity: vuln.severity,
                  isDirect: vuln.isDirect,
                  range: vuln.range,
                  cwe,
                  url,
                  fixAvailable: vuln.fixAvailable,
                  effects: vuln.effects,
                },
              });

              findings.push(finding);
              context.addFinding(finding);
            }
          }
        } catch (parseError) {
          context.log('warn', `Failed to parse npm audit output: ${parseError}`);
        }
      }

      this.status = 'complete';
      context.log('info', `NPM Audit found ${findings.length} vulnerabilities`);

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
      context.log('error', `NPM Audit error: ${errorMsg}`);

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

  private mapSeverity(npmSeverity: string): ZoneFinding['severity'] {
    switch (npmSeverity.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'moderate':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'info';
    }
  }
}
