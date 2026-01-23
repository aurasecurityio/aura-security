/**
 * Analyst SLOP Agent
 *
 * SLOP-native agent that triages and analyzes findings.
 * Reduces false positives, adjusts severity, and recommends fixes.
 */

import { SLOPAgent } from './base.js';
import { SLOPAgentConfig, SLOPTool, SLOPToolCall, SLOPToolResult, Finding, TriageResult } from './types.js';

const ANALYST_TOOLS: SLOPTool[] = [
  {
    name: 'triage',
    description: 'Triage a single finding - validate, adjust severity, check for false positive',
    parameters: {
      finding: { type: 'object', description: 'The finding to triage', required: true },
      context: { type: 'object', description: 'Additional context (file content, project type, etc.)', required: false },
    },
  },
  {
    name: 'triage-batch',
    description: 'Triage multiple findings at once',
    parameters: {
      findings: { type: 'array', description: 'Array of findings to triage', required: true },
      context: { type: 'object', description: 'Additional context', required: false },
    },
  },
  {
    name: 'deduplicate',
    description: 'Remove duplicate findings',
    parameters: {
      findings: { type: 'array', description: 'Array of findings to deduplicate', required: true },
    },
  },
  {
    name: 'prioritize',
    description: 'Prioritize findings by risk and exploitability',
    parameters: {
      findings: { type: 'array', description: 'Array of findings to prioritize', required: true },
    },
  },
  {
    name: 'get-stats',
    description: 'Get triage statistics',
    parameters: {},
  },
];

// Known false positive patterns
const FALSE_POSITIVE_PATTERNS = [
  // Test files
  { pattern: /\.(test|spec)\.(js|ts|py|go|java)$/i, types: ['secret'], reason: 'Test file - likely mock data' },
  { pattern: /test[s]?\//i, types: ['secret'], reason: 'Test directory - likely mock data' },
  { pattern: /__tests__\//i, types: ['secret'], reason: 'Test directory - likely mock data' },
  // Example files
  { pattern: /example/i, types: ['secret'], reason: 'Example file - likely placeholder' },
  { pattern: /sample/i, types: ['secret'], reason: 'Sample file - likely placeholder' },
  // Documentation
  { pattern: /\.md$/i, types: ['secret'], reason: 'Documentation file' },
  { pattern: /README/i, types: ['secret'], reason: 'README file - likely example' },
  // Lock files (low severity vulns)
  { pattern: /package-lock\.json$/i, types: ['vulnerability'], reason: 'Lock file - transitive dependency' },
  { pattern: /yarn\.lock$/i, types: ['vulnerability'], reason: 'Lock file - transitive dependency' },
];

// Known low-risk patterns
const LOW_RISK_PATTERNS = [
  { cve: /^CVE-202[0-2]/, reason: 'Old CVE - likely already patched or mitigated' },
  { package: /^@types\//, reason: 'TypeScript types - dev dependency only' },
  { package: /-dev$/, reason: 'Development dependency' },
];

export class AnalystAgent extends SLOPAgent {
  private stats = {
    triaged: 0,
    falsePositives: 0,
    severityAdjusted: 0,
    deduplicated: 0,
  };

  constructor(config: Partial<SLOPAgentConfig> = {}) {
    super(
      {
        id: config.id || 'analyst-agent',
        name: config.name || 'Analyst Agent',
        port: config.port || 3011,
        description: 'Security analyst agent - triages findings, reduces false positives, prioritizes risks',
        coordinatorUrl: config.coordinatorUrl,
        peers: config.peers,
      },
      ANALYST_TOOLS
    );
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    console.log(`[Analyst] Tool call: ${call.tool}`, call.arguments);

    try {
      switch (call.tool) {
        case 'triage':
          return { result: await this.triageFinding(call.arguments.finding as Finding, call.arguments.context as Record<string, unknown>) };
        case 'triage-batch':
          return { result: await this.triageBatch(call.arguments.findings as Finding[], call.arguments.context as Record<string, unknown>) };
        case 'deduplicate':
          return { result: await this.deduplicate(call.arguments.findings as Finding[]) };
        case 'prioritize':
          return { result: await this.prioritize(call.arguments.findings as Finding[]) };
        case 'get-stats':
          return { result: this.stats };
        default:
          return { error: `Unknown tool: ${call.tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  private async triageFinding(finding: Finding, context?: Record<string, unknown>): Promise<TriageResult> {
    this.stats.triaged++;

    const result: TriageResult = {
      finding,
      validated: true,
      falsePositive: false,
      reason: 'Valid finding',
      recommendFix: true,
      confidence: 0.8,
    };

    // Check for false positives
    for (const pattern of FALSE_POSITIVE_PATTERNS) {
      if (pattern.types.includes(finding.type)) {
        if (finding.file && pattern.pattern.test(finding.file)) {
          result.validated = false;
          result.falsePositive = true;
          result.reason = pattern.reason;
          result.recommendFix = false;
          result.confidence = 0.9;
          this.stats.falsePositives++;
          break;
        }
      }
    }

    // Check for low-risk patterns (adjust severity)
    if (!result.falsePositive) {
      for (const pattern of LOW_RISK_PATTERNS) {
        if (pattern.cve && finding.cve && pattern.cve.test(finding.cve)) {
          result.adjustedSeverity = this.reduceSeverity(finding.severity);
          result.reason = pattern.reason;
          result.confidence = 0.7;
          this.stats.severityAdjusted++;
          break;
        }
        if (pattern.package && finding.package && pattern.package.test(finding.package)) {
          result.adjustedSeverity = this.reduceSeverity(finding.severity);
          result.reason = pattern.reason;
          result.confidence = 0.7;
          this.stats.severityAdjusted++;
          break;
        }
      }
    }

    // Context-aware analysis
    if (context && !result.falsePositive) {
      // Check if it's a development-only context
      if (context.environment === 'development' || context.branch?.toString().includes('dev')) {
        if (finding.severity === 'medium' || finding.severity === 'low') {
          result.adjustedSeverity = 'low';
          result.reason = 'Development environment - lower priority';
          result.confidence = 0.6;
        }
      }

      // Check if exploitable based on code path
      if (context.reachableFromUserInput === false) {
        result.adjustedSeverity = this.reduceSeverity(finding.severity);
        result.reason = 'Not reachable from user input - reduced exploitability';
        result.confidence = 0.75;
        this.stats.severityAdjusted++;
      }
    }

    // Write to shared memory
    await this.writeMemory(`triage:${finding.id}`, result);

    return result;
  }

  private async triageBatch(findings: Finding[], context?: Record<string, unknown>): Promise<{ results: TriageResult[]; summary: Record<string, number> }> {
    const results: TriageResult[] = [];

    for (const finding of findings) {
      const result = await this.triageFinding(finding, context);
      results.push(result);
    }

    const summary = {
      total: results.length,
      validated: results.filter((r) => r.validated).length,
      falsePositives: results.filter((r) => r.falsePositive).length,
      severityAdjusted: results.filter((r) => r.adjustedSeverity).length,
      recommendedForFix: results.filter((r) => r.recommendFix).length,
    };

    return { results, summary };
  }

  private async deduplicate(findings: Finding[]): Promise<{ unique: Finding[]; duplicates: Finding[]; duplicateCount: number }> {
    const seen = new Map<string, Finding>();
    const duplicates: Finding[] = [];

    for (const finding of findings) {
      // Create a fingerprint for deduplication
      const fingerprint = this.createFingerprint(finding);

      if (seen.has(fingerprint)) {
        duplicates.push(finding);
        this.stats.deduplicated++;
      } else {
        seen.set(fingerprint, finding);
      }
    }

    return {
      unique: Array.from(seen.values()),
      duplicates,
      duplicateCount: duplicates.length,
    };
  }

  private async prioritize(findings: Finding[]): Promise<Finding[]> {
    // Sort by priority score
    return [...findings].sort((a, b) => {
      const scoreA = this.calculatePriorityScore(a);
      const scoreB = this.calculatePriorityScore(b);
      return scoreB - scoreA; // Higher score = higher priority
    });
  }

  private createFingerprint(finding: Finding): string {
    // Create a unique fingerprint based on key attributes
    const parts = [
      finding.type,
      finding.severity,
      finding.file || '',
      finding.line?.toString() || '',
      finding.package || '',
      finding.cve || '',
      finding.title.substring(0, 50), // First 50 chars of title
    ];
    return parts.join('|').toLowerCase();
  }

  private calculatePriorityScore(finding: Finding): number {
    let score = 0;

    // Base score by severity
    switch (finding.severity) {
      case 'critical':
        score += 100;
        break;
      case 'high':
        score += 75;
        break;
      case 'medium':
        score += 50;
        break;
      case 'low':
        score += 25;
        break;
    }

    // Bonus for certain types
    if (finding.type === 'secret') score += 20; // Secrets are urgent
    if (finding.cve) score += 10; // Known CVEs are well-documented

    // Penalty for test files
    if (finding.file && /test|spec|mock/i.test(finding.file)) {
      score -= 30;
    }

    return score;
  }

  private reduceSeverity(severity: 'critical' | 'high' | 'medium' | 'low'): 'critical' | 'high' | 'medium' | 'low' {
    switch (severity) {
      case 'critical':
        return 'high';
      case 'high':
        return 'medium';
      case 'medium':
        return 'low';
      default:
        return 'low';
    }
  }
}

// Allow running as standalone
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3011', 10);
  const agent = new AnalystAgent({ port });
  agent.start();
}
