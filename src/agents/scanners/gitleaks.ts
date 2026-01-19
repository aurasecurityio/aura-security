/**
 * Aura Protocol - Gitleaks Agent
 *
 * Scans for secrets and API keys using gitleaks.
 */

import * as fs from 'fs';
import * as path from 'path';
import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'gitleaks',
  name: 'Gitleaks',
  role: 'scanner',
  description: 'Detect secrets and API keys in code',
  enabled: true,
  externalTool: 'gitleaks',
};

const CAPABILITIES: AgentCapabilities = {
  fileTypes: ['*'],
  languages: ['*'],
  requiresExternalTool: true,
  supportsParallel: true,
};

// Files to skip (lock files, generated files)
const SKIP_FILES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'composer.lock',
  'Gemfile.lock',
  'poetry.lock',
  'Cargo.lock',
  'go.sum',
];

// Rules to skip entirely (too many false positives)
const SKIP_RULES = ['aws-secret-access-key'];

interface GitleaksResult {
  Description: string;
  StartLine: number;
  EndLine: number;
  File: string;
  Secret: string;
  Match: string;
  RuleID: string;
  Entropy?: number;
}

export class GitleaksAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const findings: ZoneFinding[] = [];

    try {
      context.log('info', `Gitleaks scanning: ${context.targetPath}`);

      // Create temp config to exclude lock files
      const tempConfigPath = path.join(context.targetPath, '.gitleaks-temp.toml');
      const configContent = `
[allowlist]
paths = [
  ${SKIP_FILES.map((f) => `"**/${f}"`).join(',\n  ')}
]
`;
      fs.writeFileSync(tempConfigPath, configContent);

      // Run gitleaks
      const { stdout, stderr, exitCode } = await this.executeCommand(
        'gitleaks',
        [
          'detect',
          '--source',
          context.targetPath,
          '--report-format',
          'json',
          '--report-path',
          '/dev/stdout',
          '--config',
          tempConfigPath,
          '--no-git',
          '--exit-code',
          '0',
        ],
        { cwd: context.targetPath, timeout: 300000 }
      );

      // Clean up temp config
      try {
        fs.unlinkSync(tempConfigPath);
      } catch {
        // Ignore cleanup errors
      }

      if (stdout.trim()) {
        try {
          const results: GitleaksResult[] = JSON.parse(stdout);

          for (const result of results) {
            // Skip rules with too many false positives
            if (SKIP_RULES.includes(result.RuleID)) {
              continue;
            }

            // Skip lock files
            if (SKIP_FILES.some((f) => result.File.endsWith(f))) {
              continue;
            }

            const finding = this.createFinding('gitleaks', {
              type: 'secret',
              severity: this.getSeverity(result),
              title: result.Description || result.RuleID,
              description: `Secret detected: ${result.RuleID}`,
              file: result.File,
              line: result.StartLine,
              metadata: {
                ruleId: result.RuleID,
                match: this.maskSecret(result.Match),
                entropy: result.Entropy,
              },
            });

            findings.push(finding);
            context.addFinding(finding);
          }
        } catch (parseError) {
          context.log('warn', `Failed to parse gitleaks output: ${parseError}`);
        }
      }

      this.status = 'complete';
      context.log('info', `Gitleaks found ${findings.length} secrets`);

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
      context.log('error', `Gitleaks error: ${errorMsg}`);

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

  private getSeverity(result: GitleaksResult): ZoneFinding['severity'] {
    // High entropy secrets are more likely to be real
    if (result.Entropy && result.Entropy > 4.5) {
      return 'critical';
    }

    // Certain rule types are more critical
    const criticalRules = ['private-key', 'aws-access-key', 'github-pat', 'stripe-api-key'];
    if (criticalRules.some((r) => result.RuleID.toLowerCase().includes(r))) {
      return 'critical';
    }

    const highRules = ['api-key', 'token', 'password', 'secret'];
    if (highRules.some((r) => result.RuleID.toLowerCase().includes(r))) {
      return 'high';
    }

    return 'medium';
  }

  private maskSecret(secret: string): string {
    if (secret.length <= 8) return '***';
    return secret.slice(0, 4) + '...' + secret.slice(-4);
  }
}
