/**
 * Aura Protocol - Grype Agent
 *
 * Vulnerability scanner for container images and filesystems.
 */

import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'grype',
  name: 'Grype',
  role: 'scanner',
  description: 'Vulnerability scanner for container images and filesystems',
  enabled: true,
  externalTool: 'grype',
};

const CAPABILITIES: AgentCapabilities = {
  fileTypes: ['*'],
  languages: ['*'],
  requiresExternalTool: true,
  supportsParallel: true,
};

interface GrypeMatch {
  vulnerability: {
    id: string;
    severity: string;
    description?: string;
    fix?: {
      versions?: string[];
      state?: string;
    };
    urls?: string[];
    cvss?: Array<{
      metrics: { baseScore: number };
      source: string;
    }>;
  };
  artifact: {
    name: string;
    version: string;
    type: string;
    locations?: Array<{ path: string }>;
  };
}

interface GrypeOutput {
  matches?: GrypeMatch[];
  source?: {
    type: string;
    target: string;
  };
}

export class GrypeAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const findings: ZoneFinding[] = [];

    try {
      context.log('info', `Grype scanning: ${context.targetPath}`);

      // Run grype
      const { stdout, stderr, exitCode } = await this.executeCommand(
        'grype',
        ['dir:' + context.targetPath, '-o', 'json', '--by-cve'],
        { cwd: context.targetPath, timeout: 300000 }
      );

      if (stdout.trim()) {
        try {
          const output: GrypeOutput = JSON.parse(stdout);

          if (output.matches) {
            for (const match of output.matches) {
              const finding = this.createFinding('grype', {
                type: 'vulnerability',
                severity: this.mapSeverity(match.vulnerability.severity),
                title: `${match.artifact.name}: ${match.vulnerability.id}`,
                description:
                  match.vulnerability.description ||
                  `Vulnerability in ${match.artifact.name}@${match.artifact.version}`,
                file: match.artifact.locations?.[0]?.path,
                metadata: {
                  vulnerabilityId: match.vulnerability.id,
                  package: match.artifact.name,
                  version: match.artifact.version,
                  type: match.artifact.type,
                  fixVersions: match.vulnerability.fix?.versions,
                  fixState: match.vulnerability.fix?.state,
                  cvssScore: this.getCvssScore(match),
                  references: match.vulnerability.urls?.slice(0, 3),
                },
              });

              findings.push(finding);
              context.addFinding(finding);
            }
          }
        } catch (parseError) {
          context.log('warn', `Failed to parse grype output: ${parseError}`);
        }
      }

      this.status = 'complete';
      context.log('info', `Grype found ${findings.length} vulnerabilities`);

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
      context.log('error', `Grype error: ${errorMsg}`);

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

  private mapSeverity(grypeSeverity: string): ZoneFinding['severity'] {
    switch (grypeSeverity.toLowerCase()) {
      case 'critical':
        return 'critical';
      case 'high':
        return 'high';
      case 'medium':
        return 'medium';
      case 'low':
        return 'low';
      default:
        return 'info';
    }
  }

  private getCvssScore(match: GrypeMatch): number | undefined {
    if (!match.vulnerability.cvss || match.vulnerability.cvss.length === 0) {
      return undefined;
    }
    return match.vulnerability.cvss[0].metrics.baseScore;
  }
}
