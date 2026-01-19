/**
 * Aura Protocol - Policy Evaluator Agent
 *
 * Evaluates findings against security policies.
 * This agent provides context-aware analysis of findings.
 */

import * as path from 'path';
import { BaseAgent } from '../base.js';
import { AgentConfig, AgentCapabilities, AgentResult } from '../types.js';
import { ZoneContext, ZoneFinding } from '../../zones/types.js';

const CONFIG: AgentConfig = {
  id: 'policy-evaluator',
  name: 'Policy Evaluator',
  role: 'policy',
  description: 'Evaluate findings against security policies',
  enabled: true,
};

const CAPABILITIES: AgentCapabilities = {
  requiresExternalTool: false,
  supportsParallel: false, // Policy evaluation should be sequential
};

// File patterns that indicate test/dev context
const TEST_PATTERNS = [
  /test[s]?\//i,
  /spec[s]?\//i,
  /__test__/i,
  /\.test\./i,
  /\.spec\./i,
  /mock[s]?\//i,
  /fixture[s]?\//i,
  /example[s]?\//i,
  /sample[s]?\//i,
  /demo\//i,
];

// File patterns that indicate generated/vendored code
const GENERATED_PATTERNS = [
  /node_modules\//i,
  /vendor\//i,
  /dist\//i,
  /build\//i,
  /\.min\./i,
  /bundle\./i,
  /generated\//i,
];

// Packages known to have false positive vulnerabilities or low impact
const LOW_PRIORITY_PACKAGES = [
  'lodash', // Often has low-severity prototype pollution
  'minimist', // Prototype pollution, but rarely exploitable
  'qs', // Prototype pollution in old versions
];

export class PolicyEvaluatorAgent extends BaseAgent {
  constructor() {
    super(CONFIG, CAPABILITIES);
  }

  async execute(context: ZoneContext): Promise<AgentResult> {
    const startTime = Date.now();
    this.status = 'running';
    const processedFindings: ZoneFinding[] = [];

    try {
      context.log('info', 'Policy Evaluator analyzing findings');

      // Get findings from scanner zone (passed via memory)
      const scannerFindings = context.memory.data.get('scanner_findings') as ZoneFinding[] || [];

      if (scannerFindings.length === 0) {
        context.log('info', 'No findings to evaluate');
        this.status = 'complete';
        return {
          agentId: this.config.id,
          agentName: this.config.name,
          status: 'success',
          findings: [],
          duration: Date.now() - startTime,
        };
      }

      context.log('info', `Evaluating ${scannerFindings.length} findings`);

      for (const finding of scannerFindings) {
        const evaluation = this.evaluateFinding(finding);

        // Create annotated finding with policy metadata
        const annotatedFinding = this.createFinding('policy-evaluator', {
          ...finding,
          metadata: {
            ...finding.metadata,
            policyEvaluation: evaluation,
            originalSeverity: finding.severity,
          },
          severity: evaluation.adjustedSeverity,
        });

        // Add context notes
        if (evaluation.notes.length > 0) {
          annotatedFinding.description += `\n\nPolicy Notes:\n${evaluation.notes.map(n => `• ${n}`).join('\n')}`;
        }

        processedFindings.push(annotatedFinding);
        context.addFinding(annotatedFinding);
      }

      // Store evaluated findings for validator
      context.memory.data.set('evaluated_findings', processedFindings);

      this.status = 'complete';
      context.log(
        'info',
        `Policy evaluation complete: ${processedFindings.length} findings processed`
      );

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'success',
        findings: processedFindings,
        duration: Date.now() - startTime,
      };
    } catch (error) {
      this.status = 'error';
      const errorMsg = error instanceof Error ? error.message : String(error);
      context.log('error', `Policy evaluation error: ${errorMsg}`);

      return {
        agentId: this.config.id,
        agentName: this.config.name,
        status: 'error',
        findings: processedFindings,
        duration: Date.now() - startTime,
        error: errorMsg,
      };
    }
  }

  private evaluateFinding(finding: ZoneFinding): {
    adjustedSeverity: ZoneFinding['severity'];
    notes: string[];
    isTestContext: boolean;
    isGenerated: boolean;
    shouldSuppress: boolean;
  } {
    const notes: string[] = [];
    let adjustedSeverity = finding.severity;
    let isTestContext = false;
    let isGenerated = false;
    let shouldSuppress = false;

    const filePath = finding.file || '';

    // Check if in test context
    if (TEST_PATTERNS.some((p) => p.test(filePath))) {
      isTestContext = true;
      notes.push('Found in test/example context - lower priority');
      adjustedSeverity = this.reduceSeverity(adjustedSeverity);
    }

    // Check if generated/vendored
    if (GENERATED_PATTERNS.some((p) => p.test(filePath))) {
      isGenerated = true;
      notes.push('Found in generated/vendored code');
      shouldSuppress = true;
    }

    // Check for low-priority packages
    const pkgName = (finding.metadata?.package as string) || '';
    if (LOW_PRIORITY_PACKAGES.some((p) => pkgName.toLowerCase().includes(p))) {
      notes.push(`${pkgName} is known for low-impact vulnerabilities`);
      adjustedSeverity = this.reduceSeverity(adjustedSeverity);
    }

    // Secrets in env.example or sample files are likely intentional
    if (
      finding.type === 'secret' &&
      /\.(example|sample|template)/i.test(filePath)
    ) {
      notes.push('Secret in example/template file - likely placeholder');
      shouldSuppress = true;
    }

    // Check for fix availability
    const fixAvailable = finding.metadata?.fixAvailable as boolean | { version?: string } | undefined;
    if (fixAvailable === false) {
      notes.push('No fix available yet');
    } else if (typeof fixAvailable === 'object' && fixAvailable && 'version' in fixAvailable && fixAvailable.version) {
      notes.push(`Fix available: upgrade to ${fixAvailable.version}`);
    }

    // Direct dependencies are higher priority
    if (finding.metadata?.isDirect === true) {
      notes.push('Direct dependency - higher priority');
      if (finding.severity === 'medium') {
        adjustedSeverity = 'high';
      }
    }

    return {
      adjustedSeverity,
      notes,
      isTestContext,
      isGenerated,
      shouldSuppress,
    };
  }

  private reduceSeverity(
    severity: ZoneFinding['severity']
  ): ZoneFinding['severity'] {
    switch (severity) {
      case 'critical':
        return 'high';
      case 'high':
        return 'medium';
      case 'medium':
        return 'low';
      default:
        return 'info';
    }
  }
}
