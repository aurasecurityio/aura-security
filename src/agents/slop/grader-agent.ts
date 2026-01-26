/**
 * Grader Agent - SLOP Native
 *
 * Intelligent scoring and attack chain analysis.
 * Takes findings from Scanner, calculates risk scores, maps attack chains.
 *
 * Tools:
 * - grade-finding: Score a single finding
 * - grade-batch: Score multiple findings
 * - map-chain: Map attack chains between findings
 * - calculate-risk: Calculate overall repository risk score
 * - get-exploitability: Get exploitability score for a finding
 */

import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
  Finding,
} from './types.js';

// Grading types
export interface GradedFinding {
  finding: Finding;
  score: number; // 0-100
  exploitability: ExploitabilityScore;
  impact: ImpactScore;
  chainPotential: number; // 0-100, how likely to be part of attack chain
  priority: number; // 1-5, higher = fix first
  reasoning: string;
  recommendations: string[];
}

export interface ExploitabilityScore {
  attackVector: 'network' | 'adjacent' | 'local' | 'physical';
  attackComplexity: 'low' | 'high';
  privilegesRequired: 'none' | 'low' | 'high';
  userInteraction: 'none' | 'required';
  score: number; // 0-10
}

export interface ImpactScore {
  confidentiality: 'none' | 'low' | 'high';
  integrity: 'none' | 'low' | 'high';
  availability: 'none' | 'low' | 'high';
  scope: 'unchanged' | 'changed';
  score: number; // 0-10
}

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  findings: string[]; // Finding IDs in order
  totalScore: number;
  likelihood: number; // 0-100
  impact: 'critical' | 'high' | 'medium' | 'low';
  steps: AttackStep[];
}

export interface AttackStep {
  order: number;
  findingId: string;
  action: string;
  outcome: string;
  requiresPrevious: boolean;
}

export interface RiskReport {
  overallScore: number; // 0-100
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  findings: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  topRisks: GradedFinding[];
  attackChains: AttackChain[];
  recommendations: string[];
  summary: string;
}

// Grader Agent Tool definitions
const GRADER_TOOLS: SLOPTool[] = [
  {
    name: 'grade-finding',
    description: 'Score and analyze a single security finding',
    parameters: {
      finding: {
        type: 'object',
        description: 'The finding to grade',
        required: true,
      },
      context: {
        type: 'object',
        description: 'Additional context (repo type, tech stack, etc.)',
        required: false,
      },
    },
  },
  {
    name: 'grade-batch',
    description: 'Score multiple findings at once',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings to grade',
        required: true,
      },
      context: {
        type: 'object',
        description: 'Additional context',
        required: false,
      },
    },
  },
  {
    name: 'map-chains',
    description: 'Identify attack chains between findings',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings to analyze for chains',
        required: true,
      },
    },
  },
  {
    name: 'calculate-risk',
    description: 'Calculate overall risk score for a repository',
    parameters: {
      findings: {
        type: 'array',
        description: 'All findings from the repository',
        required: true,
      },
      repoInfo: {
        type: 'object',
        description: 'Repository metadata (stars, forks, visibility, etc.)',
        required: false,
      },
    },
  },
  {
    name: 'get-exploitability',
    description: 'Calculate CVSS-style exploitability score',
    parameters: {
      finding: {
        type: 'object',
        description: 'The finding to analyze',
        required: true,
      },
    },
  },
  {
    name: 'prioritize',
    description: 'Get prioritized fix order for findings',
    parameters: {
      findings: {
        type: 'array',
        description: 'Findings to prioritize',
        required: true,
      },
      strategy: {
        type: 'string',
        description: 'Prioritization strategy: risk, effort, quick-wins',
        required: false,
      },
    },
  },
];

// Attack chain patterns
const CHAIN_PATTERNS: Array<{
  name: string;
  description: string;
  pattern: { type: string; severity?: string }[];
  likelihood: number;
  impact: 'critical' | 'high' | 'medium' | 'low';
}> = [
  {
    name: 'Secret to RCE',
    description: 'Exposed secret leads to remote code execution',
    pattern: [
      { type: 'secret' },
      { type: 'vulnerability', severity: 'critical' },
    ],
    likelihood: 80,
    impact: 'critical',
  },
  {
    name: 'Dependency Chain Compromise',
    description: 'Vulnerable dependency enables further exploitation',
    pattern: [
      { type: 'vulnerability', severity: 'high' },
      { type: 'code-issue' },
    ],
    likelihood: 60,
    impact: 'high',
  },
  {
    name: 'Config to Data Breach',
    description: 'Misconfiguration exposes sensitive data',
    pattern: [
      { type: 'iac' },
      { type: 'secret' },
    ],
    likelihood: 70,
    impact: 'critical',
  },
  {
    name: 'Auth Bypass Chain',
    description: 'Multiple weaknesses combine to bypass authentication',
    pattern: [
      { type: 'code-issue' },
      { type: 'vulnerability' },
    ],
    likelihood: 50,
    impact: 'high',
  },
  {
    name: 'Container Escape',
    description: 'Docker misconfig enables container escape',
    pattern: [
      { type: 'docker' },
      { type: 'vulnerability', severity: 'critical' },
    ],
    likelihood: 40,
    impact: 'critical',
  },
];

export class GraderAgent extends SLOPAgent {
  private gradingCache: Map<string, GradedFinding> = new Map();

  constructor(config: SLOPAgentConfig) {
    super(config, GRADER_TOOLS);
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    const { tool, arguments: args } = call;

    try {
      switch (tool) {
        case 'grade-finding':
          return { result: await this.gradeFinding(args.finding as Finding, args.context as Record<string, unknown> | undefined) };

        case 'grade-batch':
          return { result: await this.gradeBatch(args.findings as Finding[], args.context as Record<string, unknown> | undefined) };

        case 'map-chains':
          return { result: await this.mapChains(args.findings as Finding[]) };

        case 'calculate-risk':
          return { result: await this.calculateRisk(args.findings as Finding[], args.repoInfo as Record<string, unknown> | undefined) };

        case 'get-exploitability':
          return { result: await this.getExploitability(args.finding as Finding) };

        case 'prioritize':
          return { result: await this.prioritize(args.findings as Finding[], args.strategy as string | undefined) };

        default:
          return { error: `Unknown tool: ${tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  /**
   * Grade a single finding
   */
  private async gradeFinding(finding: Finding, context?: Record<string, unknown>): Promise<GradedFinding> {
    // Check cache
    if (this.gradingCache.has(finding.id)) {
      return this.gradingCache.get(finding.id)!;
    }

    const exploitability = this.calculateExploitability(finding);
    const impact = this.calculateImpact(finding);
    const chainPotential = this.calculateChainPotential(finding);

    // Calculate overall score (0-100)
    const baseScore = this.severityToScore(finding.severity);
    const exploitabilityFactor = exploitability.score / 10;
    const impactFactor = impact.score / 10;
    const score = Math.min(100, Math.round(baseScore * 0.4 + exploitabilityFactor * 30 + impactFactor * 30));

    // Calculate priority (1-5)
    const priority = this.calculatePriority(score, finding, context);

    const graded: GradedFinding = {
      finding,
      score,
      exploitability,
      impact,
      chainPotential,
      priority,
      reasoning: this.generateReasoning(finding, score, exploitability, impact),
      recommendations: this.generateRecommendations(finding),
    };

    this.gradingCache.set(finding.id, graded);

    // Write to shared memory
    await this.writeMemory(`grader:graded:${finding.id}`, {
      score,
      priority,
      chainPotential,
      gradedAt: Date.now(),
    });

    return graded;
  }

  /**
   * Grade multiple findings
   */
  private async gradeBatch(findings: Finding[], context?: Record<string, unknown>): Promise<{
    graded: GradedFinding[];
    summary: { avgScore: number; maxScore: number; criticalCount: number };
  }> {
    const graded = await Promise.all(
      findings.map(f => this.gradeFinding(f, context))
    );

    const scores = graded.map(g => g.score);
    const avgScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 0;
    const maxScore = scores.length > 0 ? Math.max(...scores) : 0;
    const criticalCount = graded.filter(g => g.priority === 5).length;

    return {
      graded,
      summary: { avgScore, maxScore, criticalCount },
    };
  }

  /**
   * Map attack chains between findings
   */
  private async mapChains(findings: Finding[]): Promise<{
    chains: AttackChain[];
    highestRisk: AttackChain | null;
  }> {
    const chains: AttackChain[] = [];

    // Try to match each pattern
    for (const pattern of CHAIN_PATTERNS) {
      const matchedFindings: Finding[] = [];

      for (const step of pattern.pattern) {
        const match = findings.find(f =>
          f.type === step.type &&
          !matchedFindings.includes(f) &&
          (!step.severity || f.severity === step.severity)
        );

        if (match) {
          matchedFindings.push(match);
        }
      }

      // If we matched all steps in the pattern
      if (matchedFindings.length === pattern.pattern.length) {
        const chain: AttackChain = {
          id: `chain-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
          name: pattern.name,
          description: pattern.description,
          findings: matchedFindings.map(f => f.id),
          totalScore: this.calculateChainScore(matchedFindings),
          likelihood: pattern.likelihood,
          impact: pattern.impact,
          steps: matchedFindings.map((f, i) => ({
            order: i + 1,
            findingId: f.id,
            action: this.getActionForFinding(f),
            outcome: this.getOutcomeForFinding(f, i === matchedFindings.length - 1),
            requiresPrevious: i > 0,
          })),
        };

        chains.push(chain);
      }
    }

    // Also look for custom chains based on file proximity
    const fileChains = this.findFileProximityChains(findings);
    chains.push(...fileChains);

    // Sort by total score
    chains.sort((a, b) => b.totalScore - a.totalScore);

    // Write chains to memory
    for (const chain of chains) {
      await this.writeMemory(`grader:chain:${chain.id}`, chain);
    }

    return {
      chains,
      highestRisk: chains.length > 0 ? chains[0] : null,
    };
  }

  /**
   * Calculate overall repository risk
   */
  private async calculateRisk(findings: Finding[], repoInfo?: Record<string, unknown>): Promise<RiskReport> {
    const { graded, summary } = await this.gradeBatch(findings);
    const { chains } = await this.mapChains(findings);

    // Count by severity
    const severityCounts = {
      total: findings.length,
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length,
    };

    // Calculate overall score
    let overallScore = 100;
    overallScore -= severityCounts.critical * 20;
    overallScore -= severityCounts.high * 10;
    overallScore -= severityCounts.medium * 3;
    overallScore -= severityCounts.low * 1;

    // Penalty for attack chains
    for (const chain of chains) {
      if (chain.impact === 'critical') overallScore -= 15;
      else if (chain.impact === 'high') overallScore -= 10;
      else if (chain.impact === 'medium') overallScore -= 5;
    }

    // Adjust for repo visibility (if public, more risk)
    if (repoInfo?.visibility === 'public') {
      overallScore -= 5;
    }

    overallScore = Math.max(0, Math.min(100, overallScore));

    // Determine grade
    const grade = this.scoreToGrade(overallScore);

    // Get top risks
    const topRisks = graded
      .sort((a, b) => b.score - a.score)
      .slice(0, 5);

    // Generate recommendations
    const recommendations = this.generateOverallRecommendations(graded, chains);

    // Generate summary
    const summary_text = this.generateSummary(overallScore, grade, severityCounts, chains);

    const report: RiskReport = {
      overallScore,
      grade,
      findings: severityCounts,
      topRisks,
      attackChains: chains,
      recommendations,
      summary: summary_text,
    };

    // Write report to memory
    await this.writeMemory('grader:latest-report', {
      overallScore,
      grade,
      findingsCount: findings.length,
      chainsCount: chains.length,
      generatedAt: Date.now(),
    });

    return report;
  }

  /**
   * Get exploitability score for a finding
   */
  private async getExploitability(finding: Finding): Promise<ExploitabilityScore> {
    return this.calculateExploitability(finding);
  }

  /**
   * Prioritize findings for fixing
   */
  private async prioritize(findings: Finding[], strategy = 'risk'): Promise<{
    prioritized: Array<{ finding: Finding; priority: number; reason: string }>;
    fixOrder: string[];
  }> {
    const graded = await Promise.all(findings.map(f => this.gradeFinding(f)));

    let sorted: GradedFinding[];

    switch (strategy) {
      case 'effort':
        // Easiest fixes first
        sorted = graded.sort((a, b) => {
          const effortA = this.estimateEffort(a.finding);
          const effortB = this.estimateEffort(b.finding);
          return effortA - effortB;
        });
        break;

      case 'quick-wins':
        // High impact, low effort first
        sorted = graded.sort((a, b) => {
          const ratioA = a.score / this.estimateEffort(a.finding);
          const ratioB = b.score / this.estimateEffort(b.finding);
          return ratioB - ratioA;
        });
        break;

      case 'risk':
      default:
        // Highest risk first
        sorted = graded.sort((a, b) => b.score - a.score);
    }

    return {
      prioritized: sorted.map(g => ({
        finding: g.finding,
        priority: g.priority,
        reason: g.reasoning,
      })),
      fixOrder: sorted.map(g => g.finding.id),
    };
  }

  // ===== Helper Methods =====

  private calculateExploitability(finding: Finding): ExploitabilityScore {
    // Default values based on finding type
    let attackVector: ExploitabilityScore['attackVector'] = 'network';
    let attackComplexity: ExploitabilityScore['attackComplexity'] = 'low';
    let privilegesRequired: ExploitabilityScore['privilegesRequired'] = 'none';
    let userInteraction: ExploitabilityScore['userInteraction'] = 'none';

    // Adjust based on finding type
    if (finding.type === 'secret') {
      attackVector = 'network';
      attackComplexity = 'low';
      privilegesRequired = 'none';
    } else if (finding.type === 'vulnerability') {
      // Check for known CVE patterns
      if (finding.cve) {
        attackComplexity = finding.severity === 'critical' ? 'low' : 'high';
      }
    } else if (finding.type === 'code-issue') {
      attackVector = 'local';
      privilegesRequired = 'low';
    } else if (finding.type === 'docker') {
      attackVector = 'adjacent';
    }

    // Calculate score (simplified CVSS-like)
    const vectorScore = { network: 0.85, adjacent: 0.62, local: 0.55, physical: 0.2 };
    const complexityScore = { low: 0.77, high: 0.44 };
    const privilegesScore = { none: 0.85, low: 0.62, high: 0.27 };
    const interactionScore = { none: 0.85, required: 0.62 };

    const score = 8.22 *
      vectorScore[attackVector] *
      complexityScore[attackComplexity] *
      privilegesScore[privilegesRequired] *
      interactionScore[userInteraction];

    return {
      attackVector,
      attackComplexity,
      privilegesRequired,
      userInteraction,
      score: Math.round(score * 10) / 10,
    };
  }

  private calculateImpact(finding: Finding): ImpactScore {
    let confidentiality: ImpactScore['confidentiality'] = 'low';
    let integrity: ImpactScore['integrity'] = 'low';
    let availability: ImpactScore['availability'] = 'none';
    let scope: ImpactScore['scope'] = 'unchanged';

    // Adjust based on finding type and severity
    if (finding.type === 'secret') {
      confidentiality = 'high';
      integrity = 'high';
      scope = 'changed';
    } else if (finding.type === 'vulnerability') {
      if (finding.severity === 'critical') {
        confidentiality = 'high';
        integrity = 'high';
        availability = 'high';
        scope = 'changed';
      } else if (finding.severity === 'high') {
        confidentiality = 'high';
        integrity = 'low';
        availability = 'low';
      }
    } else if (finding.type === 'docker' || finding.type === 'iac') {
      availability = 'high';
      scope = 'changed';
    }

    // Calculate score
    const impactScores = { none: 0, low: 0.22, high: 0.56 };
    const scopeMultiplier = scope === 'changed' ? 1.0 : 0.85;

    const iscBase = 1 - (
      (1 - impactScores[confidentiality]) *
      (1 - impactScores[integrity]) *
      (1 - impactScores[availability])
    );

    const score = scopeMultiplier * 10 * iscBase;

    return {
      confidentiality,
      integrity,
      availability,
      scope,
      score: Math.round(score * 10) / 10,
    };
  }

  private calculateChainPotential(finding: Finding): number {
    let potential = 30; // Base potential

    // Secrets are often chain starters
    if (finding.type === 'secret') potential += 40;

    // Critical vulns can be chain enders
    if (finding.severity === 'critical') potential += 30;
    else if (finding.severity === 'high') potential += 20;

    // Code issues are often chain links
    if (finding.type === 'code-issue') potential += 15;

    // Docker issues can enable escalation
    if (finding.type === 'docker') potential += 25;

    return Math.min(100, potential);
  }

  private calculatePriority(score: number, finding: Finding, context?: Record<string, unknown>): number {
    if (score >= 90 || finding.severity === 'critical') return 5;
    if (score >= 70 || finding.severity === 'high') return 4;
    if (score >= 50) return 3;
    if (score >= 30) return 2;
    return 1;
  }

  private severityToScore(severity: string): number {
    switch (severity) {
      case 'critical': return 100;
      case 'high': return 75;
      case 'medium': return 50;
      case 'low': return 25;
      default: return 25;
    }
  }

  private scoreToGrade(score: number): 'A' | 'B' | 'C' | 'D' | 'F' {
    if (score >= 90) return 'A';
    if (score >= 80) return 'B';
    if (score >= 70) return 'C';
    if (score >= 60) return 'D';
    return 'F';
  }

  private generateReasoning(finding: Finding, score: number, exploitability: ExploitabilityScore, impact: ImpactScore): string {
    const parts = [];

    parts.push(`${finding.type.toUpperCase()} finding with ${finding.severity} severity.`);

    if (exploitability.score >= 7) {
      parts.push(`Highly exploitable (${exploitability.attackVector} attack vector, ${exploitability.attackComplexity} complexity).`);
    }

    if (impact.scope === 'changed') {
      parts.push('Can affect resources beyond the vulnerable component.');
    }

    if (finding.cve) {
      parts.push(`Known CVE: ${finding.cve}.`);
    }

    return parts.join(' ');
  }

  private generateRecommendations(finding: Finding): string[] {
    const recs: string[] = [];

    if (finding.type === 'secret') {
      recs.push('Rotate the exposed credential immediately');
      recs.push('Add file to .gitignore to prevent future exposure');
      recs.push('Use environment variables or secret management system');
    } else if (finding.type === 'vulnerability') {
      if (finding.package && finding.version) {
        recs.push(`Update ${finding.package} from ${finding.version} to latest patched version`);
      }
      recs.push('Review dependency tree for transitive vulnerabilities');
    } else if (finding.type === 'code-issue') {
      recs.push('Review and fix the identified code pattern');
      recs.push('Consider adding static analysis to CI/CD pipeline');
    } else if (finding.type === 'docker') {
      recs.push('Use minimal base images');
      recs.push('Avoid running as root');
      recs.push('Scan images before deployment');
    }

    return recs;
  }

  private calculateChainScore(findings: Finding[]): number {
    const severityScores = findings.map(f => this.severityToScore(f.severity));
    const maxScore = Math.max(...severityScores);
    const avgScore = severityScores.reduce((a, b) => a + b, 0) / severityScores.length;

    // Chain score is amplified version of combined scores
    return Math.min(100, Math.round(maxScore * 0.6 + avgScore * 0.4 + findings.length * 5));
  }

  private getActionForFinding(finding: Finding): string {
    switch (finding.type) {
      case 'secret': return `Exploit exposed ${finding.title.toLowerCase()}`;
      case 'vulnerability': return `Leverage ${finding.cve || 'vulnerability'} in ${finding.package || 'component'}`;
      case 'code-issue': return `Exploit ${finding.title.toLowerCase()}`;
      case 'docker': return `Abuse container misconfiguration`;
      case 'iac': return `Exploit infrastructure weakness`;
      default: return `Exploit ${finding.type}`;
    }
  }

  private getOutcomeForFinding(finding: Finding, isFinal: boolean): string {
    if (isFinal) {
      switch (finding.severity) {
        case 'critical': return 'Full system compromise';
        case 'high': return 'Significant data breach';
        case 'medium': return 'Partial access gained';
        default: return 'Minor impact';
      }
    }

    switch (finding.type) {
      case 'secret': return 'Gain authenticated access';
      case 'vulnerability': return 'Execute arbitrary code';
      case 'code-issue': return 'Bypass security controls';
      default: return 'Enable further exploitation';
    }
  }

  private findFileProximityChains(findings: Finding[]): AttackChain[] {
    const chains: AttackChain[] = [];
    const fileGroups = new Map<string, Finding[]>();

    // Group findings by file
    for (const finding of findings) {
      if (finding.file) {
        const dir = finding.file.split('/').slice(0, -1).join('/');
        if (!fileGroups.has(dir)) {
          fileGroups.set(dir, []);
        }
        fileGroups.get(dir)!.push(finding);
      }
    }

    // Look for chains in same directory
    for (const [dir, group] of fileGroups) {
      if (group.length >= 2) {
        const hasSecret = group.some(f => f.type === 'secret');
        const hasVuln = group.some(f => f.type === 'vulnerability');

        if (hasSecret && hasVuln) {
          const chainFindings = group.slice(0, 3);
          chains.push({
            id: `chain-proximity-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
            name: 'File Proximity Chain',
            description: `Multiple vulnerabilities in ${dir} can be combined`,
            findings: chainFindings.map(f => f.id),
            totalScore: this.calculateChainScore(chainFindings),
            likelihood: 50,
            impact: 'high',
            steps: chainFindings.map((f, i) => ({
              order: i + 1,
              findingId: f.id,
              action: this.getActionForFinding(f),
              outcome: this.getOutcomeForFinding(f, i === chainFindings.length - 1),
              requiresPrevious: i > 0,
            })),
          });
        }
      }
    }

    return chains;
  }

  private estimateEffort(finding: Finding): number {
    // 1-10 scale, lower is easier
    switch (finding.type) {
      case 'vulnerability':
        if (finding.package) return 2; // Usually just version bump
        return 5;
      case 'secret':
        return 3; // Remove + rotate
      case 'code-issue':
        return 6; // Code changes needed
      case 'docker':
        return 4; // Config changes
      case 'iac':
        return 5; // Infrastructure changes
      default:
        return 5;
    }
  }

  private generateOverallRecommendations(graded: GradedFinding[], chains: AttackChain[]): string[] {
    const recs: string[] = [];

    // Priority recommendations
    const critical = graded.filter(g => g.priority === 5);
    if (critical.length > 0) {
      recs.push(`FIX IMMEDIATELY: ${critical.length} critical finding(s) require urgent attention`);
    }

    // Chain-specific recommendations
    if (chains.length > 0) {
      recs.push(`ATTACK CHAINS DETECTED: ${chains.length} potential attack chain(s) identified`);
      const criticalChain = chains.find(c => c.impact === 'critical');
      if (criticalChain) {
        recs.push(`Break chain "${criticalChain.name}" by fixing: ${criticalChain.findings[0]}`);
      }
    }

    // Type-specific recommendations
    const secrets = graded.filter(g => g.finding.type === 'secret');
    if (secrets.length > 0) {
      recs.push(`Rotate ${secrets.length} exposed credential(s) and implement secret scanning in CI`);
    }

    const vulns = graded.filter(g => g.finding.type === 'vulnerability');
    if (vulns.length > 0) {
      recs.push(`Update ${vulns.length} vulnerable package(s) - run 'npm audit fix' or equivalent`);
    }

    return recs;
  }

  private generateSummary(score: number, grade: string, findings: { total: number; critical: number; high: number }, chains: AttackChain[]): string {
    const parts = [];

    parts.push(`Repository security grade: ${grade} (${score}/100)`);
    parts.push(`${findings.total} finding(s): ${findings.critical} critical, ${findings.high} high`);

    if (chains.length > 0) {
      const criticalChains = chains.filter(c => c.impact === 'critical').length;
      parts.push(`${chains.length} attack chain(s) identified${criticalChains > 0 ? ` (${criticalChains} critical)` : ''}`);
    }

    if (score < 60) {
      parts.push('IMMEDIATE ACTION REQUIRED');
    } else if (score < 80) {
      parts.push('Significant security improvements needed');
    } else {
      parts.push('Good security posture with minor improvements possible');
    }

    return parts.join('. ') + '.';
  }
}

// Export factory function
export function createGraderAgent(port = 3011, coordinatorUrl?: string): GraderAgent {
  return new GraderAgent({
    id: 'grader',
    name: 'Grader Agent',
    port,
    description: 'Scores findings, calculates risk, and maps attack chains',
    coordinatorUrl,
  });
}
