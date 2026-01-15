// Pipeline Framework - Extensible security analysis pipeline
// Compose multiple analysis stages with pluggable rules

import type {
  AuditorInput,
  AuditEvent,
  FindingPayload,
  Severity,
  AssuranceBreak,
  EvidenceType
} from '../types/events.js';

export interface PipelineContext {
  input: AuditorInput;
  events: AuditEvent[];
  assumptions: string[];
  uncertainties: string[];
  metadata: Map<string, unknown>;
}

export interface AnalysisStage {
  name: string;
  description: string;
  analyze(ctx: PipelineContext): Promise<void> | void;
}

export interface RuleDefinition {
  id: string;
  name: string;
  description: string;
  severity: Severity;
  category: 'secrets' | 'vulnerabilities' | 'compliance' | 'infrastructure' | 'access_control';
  check: (input: AuditorInput) => RuleResult | null;
}

export interface RuleResult {
  severity: Severity;
  claim: string;
  attackPath: string[];
  affectedAssets: string[];
  evidenceRefs: Array<{ type: EvidenceType; pointer: string }>;
  assuranceBreak: AssuranceBreak[];
  confidence: number;
}

// Built-in analysis stages
export class SecretsDetectionStage implements AnalysisStage {
  name = 'secrets-detection';
  description = 'Detect hardcoded secrets and credentials in code changes';

  private patterns = [
    { name: 'API Key', regex: /api[_-]?key\s*[=:]\s*['"][^'"]{8,}['"]/gi },
    { name: 'Secret', regex: /secret\s*[=:]\s*['"][^'"]{8,}['"]/gi },
    { name: 'Password', regex: /password\s*[=:]\s*['"][^'"]{4,}['"]/gi },
    { name: 'Bearer Token', regex: /bearer\s+[a-z0-9_-]{20,}/gi },
    { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|OPENSSH|PGP)\s+PRIVATE\s+KEY-----/g },
    { name: 'AWS Key', regex: /AKIA[0-9A-Z]{16}/g },
    { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
    { name: 'JWT', regex: /eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*/g }
  ];

  analyze(ctx: PipelineContext): void {
    const { diff } = ctx.input.change_event;
    const lines = diff.split('\n');
    const findings: Array<{ pattern: string; line: number }> = [];

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i];
      if (!line.startsWith('+')) continue;

      for (const { name, regex } of this.patterns) {
        regex.lastIndex = 0;
        if (regex.test(line)) {
          findings.push({ pattern: name, line: i + 1 });
        }
      }
    }

    if (findings.length > 0) {
      ctx.events.push(this.createEvent({
        severity: 'critical',
        claim: `Detected ${findings.length} potential secret(s): ${[...new Set(findings.map(f => f.pattern))].join(', ')}`,
        attackPath: [
          'Credentials committed to repository',
          'Secrets exposed in version control history',
          'Attacker extracts credentials from git history or logs'
        ],
        affectedAssets: findings.map(f => `line:${f.line}`),
        evidenceRefs: findings.map(f => ({ type: 'diff' as const, pointer: `line:${f.line}` })),
        assuranceBreak: ['integrity', 'access_control'],
        confidence: 0.95
      }));
    }
  }

  private createEvent(result: RuleResult): AuditEvent {
    return {
      event_type: 'escalation_triggered',
      target: 'self',
      payload: {
        severity: result.severity,
        claim: result.claim,
        attack_path: result.attackPath,
        affected_assets: result.affectedAssets,
        evidence_refs: result.evidenceRefs,
        assurance_break: result.assuranceBreak,
        confidence: result.confidence
      },
      timestamp: new Date().toISOString()
    };
  }
}

export class VulnerabilityScanStage implements AnalysisStage {
  name = 'vulnerability-scan';
  description = 'Analyze vulnerability scan results from evidence bundle';

  analyze(ctx: PipelineContext): void {
    const { vuln_scan } = ctx.input.evidence_bundle;
    if (!vuln_scan) return;

    const vulns = this.parseVulnScan(vuln_scan);

    if (vulns.critical > 0) {
      ctx.events.push({
        event_type: 'escalation_triggered',
        target: 'self',
        payload: {
          severity: 'critical',
          claim: `${vulns.critical} critical vulnerabilities detected in dependencies`,
          attack_path: [
            'Known CVE present in deployed dependencies',
            'Attacker identifies vulnerable component version',
            'Exploit executed against production system'
          ],
          affected_assets: ['dependencies'],
          evidence_refs: [{ type: 'scan', pointer: 'vuln_scan:critical' }],
          assurance_break: ['integrity'],
          confidence: 0.95
        },
        timestamp: new Date().toISOString()
      });
    }

    if (vulns.high > 0) {
      ctx.events.push({
        event_type: 'finding_raised',
        target: 'self',
        payload: {
          severity: 'high',
          claim: `${vulns.high} high severity vulnerabilities detected`,
          attack_path: [
            'Known vulnerability in dependency chain',
            'Attacker chains vulnerability with other weaknesses',
            'System compromise achieved'
          ],
          affected_assets: ['dependencies'],
          evidence_refs: [{ type: 'scan', pointer: 'vuln_scan:high' }],
          assurance_break: ['integrity'],
          confidence: 0.85
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  private parseVulnScan(scan: string): { critical: number; high: number; medium: number; low: number } {
    const criticalMatch = scan.match(/critical[:\s]+(\d+)/i);
    const highMatch = scan.match(/high[:\s]+(\d+)/i);
    const mediumMatch = scan.match(/medium[:\s]+(\d+)/i);
    const lowMatch = scan.match(/low[:\s]+(\d+)/i);

    return {
      critical: criticalMatch ? parseInt(criticalMatch[1], 10) : 0,
      high: highMatch ? parseInt(highMatch[1], 10) : 0,
      medium: mediumMatch ? parseInt(mediumMatch[1], 10) : 0,
      low: lowMatch ? parseInt(lowMatch[1], 10) : 0
    };
  }
}

export class CriticalAssetStage implements AnalysisStage {
  name = 'critical-asset-monitor';
  description = 'Monitor changes to critical asset paths';

  analyze(ctx: PipelineContext): void {
    const { files_changed } = ctx.input.change_event;
    const { critical_assets, risk_tolerance } = ctx.input.policy_context;

    const criticalChanges: string[] = [];

    for (const file of files_changed) {
      const fileLower = file.toLowerCase();
      for (const asset of critical_assets) {
        if (fileLower.includes(asset.toLowerCase())) {
          criticalChanges.push(file);
          break;
        }
      }
    }

    if (criticalChanges.length > 0) {
      const severity = this.adjustSeverity('high', risk_tolerance);

      ctx.events.push({
        event_type: 'finding_raised',
        target: 'self',
        payload: {
          severity,
          claim: `${criticalChanges.length} critical asset file(s) modified`,
          attack_path: [
            'Attacker gains commit access or compromises developer',
            'Modifies critical asset configuration or code',
            'Changes bypass review due to file location complexity'
          ],
          affected_assets: criticalChanges,
          evidence_refs: criticalChanges.map(f => ({ type: 'diff' as const, pointer: f })),
          assurance_break: ['integrity', 'access_control'],
          confidence: 0.85
        },
        timestamp: new Date().toISOString()
      });
    }
  }

  private adjustSeverity(base: Severity, tolerance: string): Severity {
    if (tolerance === 'low') {
      if (base === 'low') return 'medium';
      if (base === 'medium') return 'high';
      if (base === 'high') return 'critical';
    }
    if (tolerance === 'high') {
      if (base === 'critical') return 'high';
      if (base === 'high') return 'medium';
      if (base === 'medium') return 'low';
    }
    return base;
  }
}

export class InfrastructureChangeStage implements AnalysisStage {
  name = 'infrastructure-change';
  description = 'Analyze infrastructure-as-code changes';

  private iacPatterns = [
    /\.tf$/,           // Terraform
    /\.tfvars$/,
    /cloudformation/i,
    /\.yaml$/,
    /\.yml$/,
    /kubernetes/i,
    /helm/i,
    /docker-compose/i,
    /Dockerfile$/i
  ];

  analyze(ctx: PipelineContext): void {
    const { type, files_changed } = ctx.input.change_event;

    if (type !== 'infra_change') {
      // Check if any files look like IaC
      const iacFiles = files_changed.filter(f =>
        this.iacPatterns.some(p => p.test(f))
      );

      if (iacFiles.length === 0) return;

      ctx.uncertainties.push('Detected potential IaC files but change type is not infra_change');
    }

    ctx.events.push({
      event_type: 'finding_raised',
      target: 'self',
      payload: {
        severity: 'medium',
        claim: 'Infrastructure change requires manual security review',
        attack_path: [
          'IaC misconfiguration introduced',
          'Security boundaries or network rules modified',
          'Attacker gains access to previously protected resources'
        ],
        affected_assets: ['infrastructure'],
        evidence_refs: files_changed.map(f => ({ type: 'diff' as const, pointer: f })),
        assurance_break: ['isolation', 'access_control'],
        confidence: 0.6
      },
      timestamp: new Date().toISOString()
    });

    ctx.assumptions.push('Infrastructure changes require human approval regardless of automated checks');
  }
}

export class ProductionDeployStage implements AnalysisStage {
  name = 'production-deploy-guard';
  description = 'Guard against direct production deployments';

  analyze(ctx: PipelineContext): void {
    const { type, environment } = ctx.input.change_event;

    if (type === 'deploy' && environment === 'prod') {
      ctx.events.push({
        event_type: 'finding_raised',
        target: 'self',
        payload: {
          severity: 'medium',
          claim: 'Direct production deployment detected - verify staging validation completed',
          attack_path: [
            'Code deployed directly to production',
            'Untested changes reach production environment',
            'Runtime errors or vulnerabilities exposed to users'
          ],
          affected_assets: ['production-environment'],
          evidence_refs: [{ type: 'diff', pointer: ctx.input.change_event.commit }],
          assurance_break: ['isolation'],
          confidence: 0.7
        },
        timestamp: new Date().toISOString()
      });

      ctx.assumptions.push('Production deployments should pass through staging first');
    }
  }
}

// Pipeline executor
export class SecurityPipeline {
  private stages: AnalysisStage[] = [];

  constructor() {
    // Add default stages
    this.stages = [
      new SecretsDetectionStage(),
      new VulnerabilityScanStage(),
      new CriticalAssetStage(),
      new InfrastructureChangeStage(),
      new ProductionDeployStage()
    ];
  }

  addStage(stage: AnalysisStage): void {
    this.stages.push(stage);
  }

  removeStage(name: string): void {
    this.stages = this.stages.filter(s => s.name !== name);
  }

  getStages(): AnalysisStage[] {
    return [...this.stages];
  }

  async execute(input: AuditorInput): Promise<PipelineContext> {
    const ctx: PipelineContext = {
      input,
      events: [],
      assumptions: [],
      uncertainties: [],
      metadata: new Map()
    };

    // Add analysis started event
    ctx.events.push({
      event_type: 'analysis_started',
      target: 'self',
      payload: {
        severity: 'low',
        claim: `Pipeline started: ${this.stages.length} stages`,
        attack_path: ['Initiated security analysis'],
        affected_assets: [],
        evidence_refs: [{ type: 'diff', pointer: input.change_event.id }],
        assurance_break: [],
        confidence: 1.0
      },
      timestamp: new Date().toISOString()
    });

    // Run all stages
    for (const stage of this.stages) {
      try {
        await stage.analyze(ctx);
      } catch (err) {
        ctx.uncertainties.push(`Stage ${stage.name} failed: ${err}`);
      }
    }

    return ctx;
  }
}

export {
  PipelineContext as Context,
  AnalysisStage as Stage,
  RuleDefinition as Rule
};
