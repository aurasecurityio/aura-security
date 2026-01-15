// Auditor Pipeline - Rule-based security analysis with fail-closed behavior

import type {
  AuditorInput,
  AuditorOutput,
  AuditEvent,
  FindingPayload,
  Severity,
  AssuranceBreak
} from '../types/events.js';
import { SchemaValidator, ValidationError } from './validator.js';
import { SlopClient, SlopConnectionError } from '../slop/client.js';

const AGENT_ID = 'exploit-reviewer';

export interface PipelineConfig {
  slopClient: SlopClient;
  strictMode?: boolean;
}

export class AuditorPipeline {
  private validator: SchemaValidator;
  private client: SlopClient;
  private strictMode: boolean;

  constructor(config: PipelineConfig) {
    this.validator = new SchemaValidator();
    this.client = config.slopClient;
    this.strictMode = config.strictMode ?? true;
  }

  // Main entry point - fail-closed on any error
  async analyze(rawInput: unknown): Promise<AuditorOutput> {
    // Fail-closed: must be connected to SLOP
    if (!this.client.connected) {
      throw new SlopConnectionError('No SLOP connection - blocking execution');
    }

    // Fail-closed: validate input
    this.validator.assertValidInput(rawInput);
    const input = rawInput as AuditorInput;

    // Start analysis
    const events: AuditEvent[] = [];
    const assumptions: string[] = [];
    const uncertainties: string[] = [];

    // Emit analysis_started
    events.push(this.createEvent('analysis_started', 'self', {
      severity: 'low',
      claim: `Analyzing ${input.change_event.type} in ${input.change_event.environment}`,
      attack_path: ['Initiated audit pipeline'],
      affected_assets: [],
      evidence_refs: [{ type: 'diff', pointer: input.change_event.id }],
      assurance_break: [],
      confidence: 1.0
    }));

    // Run analysis rules
    const findings = this.runAnalysisRules(input, assumptions, uncertainties);
    events.push(...findings);

    // Determine final state
    const hasCritical = findings.some(e => e.payload.severity === 'critical');
    const hasHigh = findings.some(e => e.payload.severity === 'high');
    const hasConflict = findings.some(e => e.event_type === 'conflict_detected');

    let agentState: AuditorOutput['agent_state'] = 'idle';
    if (hasCritical) {
      agentState = 'blocked';
    } else if (hasConflict) {
      agentState = 'conflict';
    } else if (hasHigh) {
      agentState = 'escalated';
    } else if (findings.length > 0) {
      agentState = 'analyzing';
    }

    const output: AuditorOutput = {
      agent_id: AGENT_ID,
      agent_state: agentState,
      events,
      meta: { assumptions, uncertainties }
    };

    // Fail-closed: validate output
    this.validator.assertValidOutput(output);

    // Publish to SLOP memory (audit log)
    await this.client.publishToMemory({
      key: `audit:${input.change_event.id}:${Date.now()}`,
      value: output,
      metadata: {
        commit: input.change_event.commit,
        repo: input.change_event.repo,
        environment: input.change_event.environment
      }
    });

    return output;
  }

  private runAnalysisRules(
    input: AuditorInput,
    assumptions: string[],
    uncertainties: string[]
  ): AuditEvent[] {
    const findings: AuditEvent[] = [];
    const { change_event, evidence_bundle, policy_context } = input;

    // Rule: Critical asset modification
    const criticalFiles = this.findCriticalAssetChanges(
      change_event.files_changed,
      policy_context.critical_assets
    );
    if (criticalFiles.length > 0) {
      findings.push(this.createEvent('finding_raised', 'self', {
        severity: this.getSeverityForRisk(policy_context.risk_tolerance, 'high'),
        claim: 'Critical asset files modified without explicit approval chain',
        attack_path: [
          'Attacker gains commit access',
          'Modifies critical asset configuration',
          'Changes bypass standard review due to file location'
        ],
        affected_assets: criticalFiles,
        evidence_refs: criticalFiles.map(f => ({ type: 'diff' as const, pointer: f })),
        assurance_break: ['integrity', 'access_control'],
        confidence: 0.85
      }));
    }

    // Rule: Production deployment without staging
    if (change_event.environment === 'prod' && change_event.type === 'deploy') {
      assumptions.push('Assumes staging validation is required before prod');
      findings.push(this.createEvent('finding_raised', 'self', {
        severity: this.getSeverityForRisk(policy_context.risk_tolerance, 'medium'),
        claim: 'Direct production deployment detected',
        attack_path: [
          'Change bypasses staging environment',
          'Untested code reaches production',
          'Runtime errors expose attack surface'
        ],
        affected_assets: ['production-environment'],
        evidence_refs: [{ type: 'diff', pointer: change_event.commit }],
        assurance_break: ['isolation'],
        confidence: 0.7
      }));
    }

    // Rule: Check for secrets in diff
    const secretPatterns = this.detectSecretPatterns(change_event.diff);
    if (secretPatterns.length > 0) {
      findings.push(this.createEvent('escalation_triggered', 'self', {
        severity: 'critical',
        claim: 'Potential secrets or credentials detected in diff',
        attack_path: [
          'Credentials committed to repository',
          'Secrets exposed in version history',
          'Attacker extracts credentials from git history'
        ],
        affected_assets: secretPatterns.map(p => p.file),
        evidence_refs: secretPatterns.map(p => ({ type: 'diff' as const, pointer: p.line })),
        assurance_break: ['integrity', 'access_control'],
        confidence: 0.95
      }));
    }

    // Rule: Vulnerability scan findings
    if (evidence_bundle.vuln_scan) {
      const vulnFindings = this.parseVulnScan(evidence_bundle.vuln_scan);
      if (vulnFindings.critical > 0 || vulnFindings.high > 0) {
        findings.push(this.createEvent('finding_raised', 'self', {
          severity: vulnFindings.critical > 0 ? 'critical' : 'high',
          claim: `Vulnerability scan detected ${vulnFindings.critical} critical and ${vulnFindings.high} high severity issues`,
          attack_path: [
            'Known vulnerability present in dependencies',
            'Attacker identifies CVE in deployed version',
            'Exploit executed against vulnerable component'
          ],
          affected_assets: ['dependencies'],
          evidence_refs: [{ type: 'scan', pointer: 'vuln_scan' }],
          assurance_break: ['integrity'],
          confidence: 0.9
        }));
      }
    }

    // Rule: Infrastructure changes
    if (change_event.type === 'infra_change') {
      uncertainties.push('Infrastructure change impact depends on cloud provider specifics');
      findings.push(this.createEvent('finding_raised', 'self', {
        severity: this.getSeverityForRisk(policy_context.risk_tolerance, 'medium'),
        claim: 'Infrastructure modification requires manual review',
        attack_path: [
          'IaC change modifies security boundaries',
          'Misconfiguration exposes internal services',
          'Attacker gains network access to protected resources'
        ],
        affected_assets: ['infrastructure'],
        evidence_refs: change_event.files_changed.map(f => ({ type: 'diff' as const, pointer: f })),
        assurance_break: ['isolation', 'access_control'],
        confidence: 0.6
      }));
    }

    return findings;
  }

  private findCriticalAssetChanges(files: string[], criticalAssets: string[]): string[] {
    const matches: string[] = [];
    for (const file of files) {
      const fileLower = file.toLowerCase();
      for (const asset of criticalAssets) {
        if (fileLower.includes(asset.toLowerCase())) {
          matches.push(file);
          break;
        }
      }
    }
    return matches;
  }

  private detectSecretPatterns(diff: string): Array<{ file: string; line: string }> {
    const patterns = [
      /api[_-]?key\s*[=:]\s*['"][^'"]+['"]/gi,
      /secret\s*[=:]\s*['"][^'"]+['"]/gi,
      /password\s*[=:]\s*['"][^'"]+['"]/gi,
      /bearer\s+[a-z0-9_-]+/gi,
      /-----BEGIN\s+(RSA|EC|OPENSSH)\s+PRIVATE\s+KEY-----/g,
      /aws[_-]?secret[_-]?access[_-]?key/gi
    ];

    const findings: Array<{ file: string; line: string }> = [];
    const lines = diff.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('+')) {
        for (const pattern of patterns) {
          if (pattern.test(line)) {
            findings.push({ file: 'diff', line: `line:${i + 1}` });
            break;
          }
        }
      }
    }

    return findings;
  }

  private parseVulnScan(scan: string): { critical: number; high: number } {
    // Simple parser - in production would parse actual scanner output
    const criticalMatch = scan.match(/critical[:\s]+(\d+)/i);
    const highMatch = scan.match(/high[:\s]+(\d+)/i);
    return {
      critical: criticalMatch ? parseInt(criticalMatch[1], 10) : 0,
      high: highMatch ? parseInt(highMatch[1], 10) : 0
    };
  }

  private getSeverityForRisk(tolerance: string, baseSeverity: 'low' | 'medium' | 'high'): Severity {
    if (tolerance === 'low') {
      if (baseSeverity === 'low') return 'medium';
      if (baseSeverity === 'medium') return 'high';
      return 'critical';
    }
    if (tolerance === 'high') {
      if (baseSeverity === 'high') return 'medium';
      if (baseSeverity === 'medium') return 'low';
      return 'low';
    }
    return baseSeverity;
  }

  private createEvent(
    eventType: AuditEvent['event_type'],
    target: string,
    payload: FindingPayload
  ): AuditEvent {
    return {
      event_type: eventType,
      target,
      payload,
      timestamp: new Date().toISOString()
    };
  }
}
