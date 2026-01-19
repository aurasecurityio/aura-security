/**
 * Aura Protocol - Validator Agent
 *
 * Validates and deduplicates findings, removes false positives.
 */

import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'validator',
  name: 'Finding Validator',
  role: 'validator',
  description: 'Validate and deduplicate findings, remove false positives',
  enabled: true,
};

const CAPABILITIES: AgentCapabilities = {
  requiresExternalTool: false,
  supportsParallel: false,
};

// Patterns that indicate false positive secrets
const FALSE_POSITIVE_PATTERNS = [
  // SHA hashes (commit hashes, file hashes)
  /^[a-f0-9]{40}$/i,
  /^[a-f0-9]{64}$/i,
  // UUIDs
  /^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$/i,
  // NPM package integrity hashes
  /^sha512-/i,
  /^sha256-/i,
  // Example/placeholder values
  /^(xxx|aaa|test|example|sample|placeholder|dummy|fake)/i,
  /^your[-_]?(api[-_]?key|secret|token|password)/i,
  // Version strings
  /^\d+\.\d+\.\d+$/,
];

// File paths that commonly have false positives
const FALSE_POSITIVE_PATHS = [
  /package-lock\.json$/i,
  /yarn\.lock$/i,
  /pnpm-lock\.yaml$/i,
  /composer\.lock$/i,
  /\.sum$/i,
  /integrity.*\.txt$/i,
];

export class ValidatorAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const validatedFindings: ZoneFinding[] = [];

    try {
      context.log('info', 'Validator analyzing findings');

      // Get findings from policy zone
      const evaluatedFindings =
        (context.memory.data.get('evaluated_findings') as ZoneFinding[]) ||
        (context.memory.data.get('scanner_findings') as ZoneFinding[]) ||
        [];

      if (evaluatedFindings.length === 0) {
        context.log('info', 'No findings to validate');
        this.status = 'complete';
        return {
          agentId: this.config.id,
          agentName: this.config.name,
          status: 'success',
          findings: [],
          duration: Date.now() - startTime,
        };
      }

      context.log('info', `Validating ${evaluatedFindings.length} findings`);

      const seenFindings = new Set<string>();
      let falsePositives = 0;
      let duplicates = 0;
      let suppressed = 0;

      for (const finding of evaluatedFindings) {
        // Check for duplicates
        const fingerprint = this.createFingerprint(finding);
        if (seenFindings.has(fingerprint)) {
          duplicates++;
          continue;
        }
        seenFindings.add(fingerprint);

        // Check if suppressed by policy
        if ((finding.metadata?.policyEvaluation as any)?.shouldSuppress) {
          suppressed++;
          continue;
        }

        // Check for false positives
        if (this.isFalsePositive(finding)) {
          falsePositives++;
          continue;
        }

        // Valid finding
        const validatedFinding = this.createFinding('validator', {
          ...finding,
          metadata: {
            ...finding.metadata,
            validated: true,
            fingerprint,
          },
        });

        validatedFindings.push(validatedFinding);
        context.addFinding(validatedFinding);
      }

      // Store validated findings
      context.memory.data.set('validated_findings', validatedFindings);

      this.status = 'complete';
      context.log(
        'info',
        `Validation complete: ${validatedFindings.length} valid, ` +
          `${falsePositives} false positives, ${duplicates} duplicates, ${suppressed} suppressed`
      );

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'success',
        findings: validatedFindings,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.status = 'error';
      const errorMsg = error instanceof Error ? error.message : String(error);
      context.log('error', `Validation error: ${errorMsg}`);

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'error',
        findings: validatedFindings,
        duration: Date.now() - startTime,
        error: errorMsg,
      };
    }
  }

  private createFingerprint(finding: ZoneFinding): string {
    // Create a unique fingerprint for deduplication
    const parts = [
      finding.type,
      finding.file || '',
      finding.line?.toString() || '',
      finding.title,
      (finding.metadata?.vulnerabilityId as string) || '',
      (finding.metadata?.package as string) || '',
    ];
    return parts.join('::').toLowerCase();
  }

  private isFalsePositive(finding: ZoneFinding): boolean {
    const filePath = finding.file || '';

    // Check file path patterns
    if (FALSE_POSITIVE_PATHS.some((p) => p.test(filePath))) {
      return true;
    }

    // Check secret-specific false positives
    if (finding.type === 'secret') {
      const match = (finding.metadata?.match as string) || '';

      // Check against false positive patterns
      if (FALSE_POSITIVE_PATTERNS.some((p) => p.test(match))) {
        return true;
      }

      // Very short matches are likely false positives
      if (match.length < 16) {
        return true;
      }

      // Check for low entropy (unlikely to be real secrets)
      const entropy = this.calculateEntropy(match);
      if (entropy < 2.5) {
        return true;
      }
    }

    return false;
  }

  private calculateEntropy(str: string): number {
    const len = str.length;
    if (len === 0) return 0;

    const freq: Record<string, number> = {};
    for (const char of str) {
      freq[char] = (freq[char] || 0) + 1;
    }

    let entropy = 0;
    for (const count of Object.values(freq)) {
      const p = count / len;
      entropy -= p * Math.log2(p);
    }

    return entropy;
  }
}
