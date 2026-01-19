/**
 * Aura Protocol - Semgrep Agent
 *
 * Static analysis for security patterns.
 */

import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'semgrep',
  name: 'Semgrep',
  role: 'scanner',
  description: 'Static analysis for security patterns',
  enabled: true,
  externalTool: 'semgrep',
};

const CAPABILITIES: AgentCapabilities = {
  fileTypes: ['*.js', '*.ts', '*.py', '*.go', '*.java', '*.rb', '*.php'],
  languages: ['javascript', 'typescript', 'python', 'go', 'java', 'ruby', 'php'],
  requiresExternalTool: true,
  supportsParallel: true,
};

interface SemgrepResult {
  check_id: string;
  path: string;
  start: { line: number; col: number };
  end: { line: number; col: number };
  extra: {
    message: string;
    severity: string;
    metadata?: {
      category?: string;
      cwe?: string[];
      owasp?: string[];
      references?: string[];
    };
  };
}

interface SemgrepOutput {
  results?: SemgrepResult[];
  errors?: Array<{ message: string }>;
}

export class SemgrepAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const findings: ZoneFinding[] = [];

    try {
      context.log('info', `Semgrep scanning: ${context.targetPath}`);

      // Run semgrep with security ruleset
      const { stdout, stderr, exitCode } = await this.executeCommand(
        'semgrep',
        [
          'scan',
          '--config',
          'p/security-audit',
          '--config',
          'p/secrets',
          '--json',
          '--no-git-ignore',
          '--exclude',
          'node_modules',
          '--exclude',
          '.git',
          '--exclude',
          'dist',
          '--exclude',
          'build',
          context.targetPath,
        ],
        { cwd: context.targetPath, timeout: 600000 } // 10 min timeout for semgrep
      );

      if (stdout.trim()) {
        try {
          const output: SemgrepOutput = JSON.parse(stdout);

          if (output.results) {
            for (const result of output.results) {
              const finding = this.createFinding('semgrep', {
                type: this.getType(result),
                severity: this.mapSeverity(result.extra.severity),
                title: result.check_id,
                description: result.extra.message,
                file: result.path,
                line: result.start.line,
                metadata: {
                  checkId: result.check_id,
                  category: result.extra.metadata?.category,
                  cwe: result.extra.metadata?.cwe,
                  owasp: result.extra.metadata?.owasp,
                  references: result.extra.metadata?.references?.slice(0, 3),
                  endLine: result.end.line,
                  column: result.start.col,
                },
              });

              findings.push(finding);
              context.addFinding(finding);
            }
          }

          if (output.errors && output.errors.length > 0) {
            for (const error of output.errors) {
              context.log('warn', `Semgrep error: ${error.message}`);
            }
          }
        } catch (parseError) {
          context.log('warn', `Failed to parse semgrep output: ${parseError}`);
        }
      }

      this.status = 'complete';
      context.log('info', `Semgrep found ${findings.length} issues`);

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
      context.log('error', `Semgrep error: ${errorMsg}`);

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

  private getType(result: SemgrepResult): ZoneFinding['type'] {
    const checkId = result.check_id.toLowerCase();
    const category = result.extra.metadata?.category?.toLowerCase() || '';

    if (checkId.includes('secret') || category.includes('secret')) {
      return 'secret';
    }

    return 'vulnerability';
  }

  private mapSeverity(semgrepSeverity: string): ZoneFinding['severity'] {
    switch (semgrepSeverity.toUpperCase()) {
      case 'ERROR':
        return 'critical';
      case 'WARNING':
        return 'high';
      case 'INFO':
        return 'medium';
      default:
        return 'low';
    }
  }
}
