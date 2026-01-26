/**
 * Chain Mapper Agent - SLOP Native
 *
 * Deep attack path analysis - traces how vulnerabilities connect
 * across the entire codebase to form exploitable attack chains.
 *
 * Tools:
 * - trace-path: Trace exploitation path from entry to impact
 * - find-pivots: Find pivot points between vulnerabilities
 * - simulate-attack: Simulate attack sequence without execution
 * - generate-report: Generate visual attack graph + narrative
 * - analyze-blast-radius: Calculate impact radius of a finding
 */

import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
  Finding,
} from './types.js';

// Chain Mapper Types
export interface AttackNode {
  id: string;
  findingId?: string;
  type: 'entry' | 'pivot' | 'escalation' | 'impact' | 'data';
  name: string;
  description: string;
  technique?: string; // MITRE ATT&CK technique
  severity: 'critical' | 'high' | 'medium' | 'low';
  exploitability: number; // 0-100
  metadata?: Record<string, unknown>;
}

export interface AttackEdge {
  from: string;
  to: string;
  action: string;
  probability: number; // 0-100
  requires?: string[]; // Prerequisites
}

export interface AttackPath {
  id: string;
  name: string;
  nodes: AttackNode[];
  edges: AttackEdge[];
  entryPoint: string;
  finalImpact: string;
  totalProbability: number;
  narrative: string;
  mitreTechniques: string[];
}

export interface BlastRadius {
  findingId: string;
  directImpact: string[];
  indirectImpact: string[];
  affectedSystems: string[];
  dataAtRisk: string[];
  estimatedDamage: 'catastrophic' | 'severe' | 'moderate' | 'limited';
  containmentSteps: string[];
}

export interface AttackSimulation {
  id: string;
  path: AttackPath;
  steps: SimulationStep[];
  success: boolean;
  blockedAt?: string;
  totalTime: string;
  detectionPoints: string[];
}

export interface SimulationStep {
  order: number;
  nodeId: string;
  action: string;
  result: 'success' | 'partial' | 'blocked';
  output: string;
  detectable: boolean;
  timeEstimate: string;
}

// MITRE ATT&CK mapping for common finding types
const MITRE_MAPPING: Record<string, { technique: string; tactic: string }[]> = {
  'secret': [
    { technique: 'T1552.001', tactic: 'Credential Access - Credentials In Files' },
    { technique: 'T1078', tactic: 'Valid Accounts' },
  ],
  'vulnerability': [
    { technique: 'T1190', tactic: 'Initial Access - Exploit Public-Facing Application' },
    { technique: 'T1203', tactic: 'Execution - Exploitation for Client Execution' },
  ],
  'code-issue': [
    { technique: 'T1059', tactic: 'Execution - Command and Scripting Interpreter' },
    { technique: 'T1055', tactic: 'Defense Evasion - Process Injection' },
  ],
  'docker': [
    { technique: 'T1611', tactic: 'Privilege Escalation - Escape to Host' },
    { technique: 'T1610', tactic: 'Execution - Deploy Container' },
  ],
  'iac': [
    { technique: 'T1538', tactic: 'Discovery - Cloud Service Dashboard' },
    { technique: 'T1580', tactic: 'Discovery - Cloud Infrastructure Discovery' },
  ],
};

// Attack chain templates
const CHAIN_TEMPLATES = [
  {
    name: 'Credential Theft to Data Exfiltration',
    pattern: ['secret', 'vulnerability', 'data'],
    narrative: 'Attacker discovers exposed credentials, uses them to access vulnerable service, exfiltrates sensitive data',
  },
  {
    name: 'Container Escape to Host Compromise',
    pattern: ['docker', 'vulnerability', 'escalation'],
    narrative: 'Attacker exploits container misconfiguration, escapes to host, escalates privileges',
  },
  {
    name: 'Supply Chain Attack',
    pattern: ['vulnerability', 'code-issue', 'impact'],
    narrative: 'Attacker exploits vulnerable dependency, injects malicious code, compromises downstream users',
  },
  {
    name: 'Cloud Infrastructure Takeover',
    pattern: ['secret', 'iac', 'escalation'],
    narrative: 'Attacker finds cloud credentials, exploits misconfigured IAM, gains admin access',
  },
  {
    name: 'API to Database Breach',
    pattern: ['code-issue', 'vulnerability', 'data'],
    narrative: 'Attacker exploits API vulnerability, bypasses authentication, accesses database directly',
  },
];

const CHAIN_MAPPER_TOOLS: SLOPTool[] = [
  {
    name: 'trace-path',
    description: 'Trace exploitation path from entry point to final impact',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings to analyze',
        required: true,
      },
      entryPoint: {
        type: 'string',
        description: 'Finding ID to start from (optional, auto-detects if not provided)',
        required: false,
      },
      maxDepth: {
        type: 'number',
        description: 'Maximum chain depth (default: 5)',
        required: false,
      },
    },
  },
  {
    name: 'find-pivots',
    description: 'Find pivot points that connect multiple vulnerabilities',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings to analyze',
        required: true,
      },
    },
  },
  {
    name: 'simulate-attack',
    description: 'Simulate attack sequence without actual execution',
    parameters: {
      path: {
        type: 'object',
        description: 'Attack path to simulate',
        required: true,
      },
      verbose: {
        type: 'boolean',
        description: 'Include detailed step output',
        required: false,
      },
    },
  },
  {
    name: 'generate-report',
    description: 'Generate attack graph and narrative report',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings',
        required: true,
      },
      format: {
        type: 'string',
        description: 'Output format: json, markdown, or mermaid',
        required: false,
      },
    },
  },
  {
    name: 'analyze-blast-radius',
    description: 'Calculate the blast radius of a specific finding',
    parameters: {
      finding: {
        type: 'object',
        description: 'The finding to analyze',
        required: true,
      },
      context: {
        type: 'object',
        description: 'Additional context (architecture info, dependencies)',
        required: false,
      },
    },
  },
  {
    name: 'map-mitre',
    description: 'Map findings to MITRE ATT&CK framework',
    parameters: {
      findings: {
        type: 'array',
        description: 'Array of findings to map',
        required: true,
      },
    },
  },
];

export class ChainMapperAgent extends SLOPAgent {
  private pathCache: Map<string, AttackPath> = new Map();

  constructor(config: SLOPAgentConfig) {
    super(config, CHAIN_MAPPER_TOOLS);
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    const { tool, arguments: args } = call;

    try {
      switch (tool) {
        case 'trace-path':
          return { result: await this.tracePath(
            args.findings as Finding[],
            args.entryPoint as string | undefined,
            args.maxDepth as number | undefined
          )};

        case 'find-pivots':
          return { result: await this.findPivots(args.findings as Finding[]) };

        case 'simulate-attack':
          return { result: await this.simulateAttack(
            args.path as AttackPath,
            args.verbose as boolean | undefined
          )};

        case 'generate-report':
          return { result: await this.generateReport(
            args.findings as Finding[],
            args.format as string | undefined
          )};

        case 'analyze-blast-radius':
          return { result: await this.analyzeBlastRadius(
            args.finding as Finding,
            args.context as Record<string, unknown> | undefined
          )};

        case 'map-mitre':
          return { result: await this.mapToMitre(args.findings as Finding[]) };

        default:
          return { error: `Unknown tool: ${tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  /**
   * Trace exploitation path through findings
   */
  private async tracePath(
    findings: Finding[],
    entryPoint?: string,
    maxDepth = 5
  ): Promise<{ paths: AttackPath[]; mostDangerous: AttackPath | null }> {
    const paths: AttackPath[] = [];

    // Find entry points (secrets and high-severity vulns are common entries)
    const entryPoints = entryPoint
      ? findings.filter(f => f.id === entryPoint)
      : findings.filter(f =>
          f.type === 'secret' ||
          (f.type === 'vulnerability' && f.severity === 'critical')
        );

    if (entryPoints.length === 0 && findings.length > 0) {
      // Use highest severity as entry
      entryPoints.push(findings.sort((a, b) =>
        this.severityScore(b.severity) - this.severityScore(a.severity)
      )[0]);
    }

    // Build paths from each entry point
    for (const entry of entryPoints) {
      const path = this.buildPath(entry, findings, maxDepth);
      if (path.nodes.length > 1) {
        paths.push(path);
        this.pathCache.set(path.id, path);
      }
    }

    // Sort by danger (probability * severity)
    paths.sort((a, b) => b.totalProbability - a.totalProbability);

    // Write to memory
    await this.writeMemory('chainmapper:paths', {
      count: paths.length,
      mostDangerous: paths[0]?.id,
      analyzedAt: Date.now(),
    });

    return {
      paths,
      mostDangerous: paths[0] || null,
    };
  }

  /**
   * Find pivot points between vulnerabilities
   */
  private async findPivots(findings: Finding[]): Promise<{
    pivots: Array<{ finding: Finding; connectsTo: string[]; pivotScore: number }>;
    criticalPivots: Finding[];
  }> {
    const pivots: Array<{ finding: Finding; connectsTo: string[]; pivotScore: number }> = [];

    for (const finding of findings) {
      const connections: string[] = [];

      // Check what this finding could lead to
      for (const other of findings) {
        if (other.id === finding.id) continue;

        if (this.canConnect(finding, other)) {
          connections.push(other.id);
        }
      }

      if (connections.length > 0) {
        pivots.push({
          finding,
          connectsTo: connections,
          pivotScore: connections.length * this.severityScore(finding.severity),
        });
      }
    }

    // Sort by pivot score
    pivots.sort((a, b) => b.pivotScore - a.pivotScore);

    // Critical pivots are those that connect 3+ findings
    const criticalPivots = pivots
      .filter(p => p.connectsTo.length >= 3)
      .map(p => p.finding);

    return { pivots, criticalPivots };
  }

  /**
   * Simulate an attack path
   */
  private async simulateAttack(path: AttackPath, verbose = false): Promise<AttackSimulation> {
    const steps: SimulationStep[] = [];
    let blocked = false;
    let blockedAt: string | undefined;
    const detectionPoints: string[] = [];

    for (let i = 0; i < path.nodes.length; i++) {
      const node = path.nodes[i];
      const edge = path.edges[i];

      // Simulate this step
      const success = Math.random() * 100 < (edge?.probability || 80);
      const detectable = node.type !== 'entry' && Math.random() > 0.5;

      if (detectable) {
        detectionPoints.push(node.name);
      }

      steps.push({
        order: i + 1,
        nodeId: node.id,
        action: edge?.action || `Exploit ${node.name}`,
        result: success ? 'success' : 'blocked',
        output: verbose ? this.generateStepOutput(node, success) : '',
        detectable,
        timeEstimate: this.estimateTime(node),
      });

      if (!success) {
        blocked = true;
        blockedAt = node.id;
        break;
      }
    }

    const simulation: AttackSimulation = {
      id: `sim-${Date.now()}`,
      path,
      steps,
      success: !blocked,
      blockedAt,
      totalTime: this.calculateTotalTime(steps),
      detectionPoints,
    };

    await this.writeMemory(`chainmapper:simulation:${simulation.id}`, simulation);

    return simulation;
  }

  /**
   * Generate attack report
   */
  private async generateReport(
    findings: Finding[],
    format: string = 'markdown'
  ): Promise<{ report: string; paths: AttackPath[]; summary: object }> {
    const { paths, mostDangerous } = await this.tracePath(findings);
    const { pivots, criticalPivots } = await this.findPivots(findings);
    const mitreMapping = await this.mapToMitre(findings);

    const summary = {
      totalFindings: findings.length,
      attackPaths: paths.length,
      criticalPivots: criticalPivots.length,
      mostDangerousPath: mostDangerous?.name,
      mitreTechniques: mitreMapping.techniques.length,
    };

    let report = '';

    if (format === 'mermaid') {
      report = this.generateMermaidGraph(paths);
    } else if (format === 'json') {
      report = JSON.stringify({ paths, pivots, mitreMapping, summary }, null, 2);
    } else {
      report = this.generateMarkdownReport(paths, pivots, mitreMapping, summary);
    }

    return { report, paths, summary };
  }

  /**
   * Analyze blast radius of a finding
   */
  private async analyzeBlastRadius(
    finding: Finding,
    context?: Record<string, unknown>
  ): Promise<BlastRadius> {
    const directImpact: string[] = [];
    const indirectImpact: string[] = [];
    const affectedSystems: string[] = [];
    const dataAtRisk: string[] = [];
    const containmentSteps: string[] = [];

    // Analyze based on finding type
    if (finding.type === 'secret') {
      directImpact.push('Credential compromise');
      directImpact.push('Unauthorized access to protected resources');
      indirectImpact.push('Lateral movement to connected systems');
      indirectImpact.push('Data exfiltration');
      affectedSystems.push('Authentication systems', 'Connected APIs', 'Cloud resources');
      dataAtRisk.push('User credentials', 'API keys', 'Service accounts');
      containmentSteps.push(
        '1. Rotate compromised credential immediately',
        '2. Audit access logs for unauthorized usage',
        '3. Revoke all sessions using this credential',
        '4. Scan for credential reuse in other systems'
      );
    } else if (finding.type === 'vulnerability') {
      directImpact.push('Service compromise');
      if (finding.severity === 'critical') {
        directImpact.push('Remote code execution');
        indirectImpact.push('Full system takeover');
        indirectImpact.push('Malware deployment');
      }
      affectedSystems.push(finding.package || 'Application server');
      dataAtRisk.push('Application data', 'Connected database records');
      containmentSteps.push(
        `1. Update ${finding.package || 'affected component'} to patched version`,
        '2. Apply WAF rules to block exploitation attempts',
        '3. Monitor for indicators of compromise'
      );
    } else if (finding.type === 'docker') {
      directImpact.push('Container escape');
      indirectImpact.push('Host system compromise');
      indirectImpact.push('Access to other containers');
      affectedSystems.push('Container host', 'Kubernetes cluster', 'Other containers');
      dataAtRisk.push('Secrets mounted in containers', 'Host filesystem');
      containmentSteps.push(
        '1. Rebuild container with secure base image',
        '2. Apply least-privilege principles',
        '3. Enable container runtime security monitoring'
      );
    }

    // Estimate damage
    let estimatedDamage: BlastRadius['estimatedDamage'] = 'limited';
    if (finding.severity === 'critical' && directImpact.length > 2) {
      estimatedDamage = 'catastrophic';
    } else if (finding.severity === 'high' || indirectImpact.length > 2) {
      estimatedDamage = 'severe';
    } else if (finding.severity === 'medium') {
      estimatedDamage = 'moderate';
    }

    return {
      findingId: finding.id,
      directImpact,
      indirectImpact,
      affectedSystems,
      dataAtRisk,
      estimatedDamage,
      containmentSteps,
    };
  }

  /**
   * Map findings to MITRE ATT&CK
   */
  private async mapToMitre(findings: Finding[]): Promise<{
    mappings: Array<{ finding: Finding; techniques: { technique: string; tactic: string }[] }>;
    techniques: string[];
    tactics: string[];
  }> {
    const mappings: Array<{ finding: Finding; techniques: { technique: string; tactic: string }[] }> = [];
    const allTechniques = new Set<string>();
    const allTactics = new Set<string>();

    for (const finding of findings) {
      const techniques = MITRE_MAPPING[finding.type] || [];
      mappings.push({ finding, techniques });

      for (const t of techniques) {
        allTechniques.add(t.technique);
        allTactics.add(t.tactic.split(' - ')[0]);
      }
    }

    return {
      mappings,
      techniques: Array.from(allTechniques),
      tactics: Array.from(allTactics),
    };
  }

  // ===== Helper Methods =====

  private buildPath(entry: Finding, findings: Finding[], maxDepth: number): AttackPath {
    const nodes: AttackNode[] = [];
    const edges: AttackEdge[] = [];
    const used = new Set<string>();
    let current = entry;
    let depth = 0;

    // Add entry node
    nodes.push(this.findingToNode(entry, 'entry'));
    used.add(entry.id);

    // Build chain
    while (depth < maxDepth) {
      const next = findings.find(f => !used.has(f.id) && this.canConnect(current, f));
      if (!next) break;

      const nodeType = depth === maxDepth - 1 ? 'impact' : 'pivot';
      nodes.push(this.findingToNode(next, nodeType));
      edges.push({
        from: current.id,
        to: next.id,
        action: this.getConnectionAction(current, next),
        probability: this.calculateProbability(current, next),
      });

      used.add(next.id);
      current = next;
      depth++;
    }

    // Calculate total probability
    const totalProbability = edges.reduce((acc, e) => acc * (e.probability / 100), 1) * 100;

    // Generate narrative
    const template = CHAIN_TEMPLATES.find(t =>
      t.pattern.some(p => nodes.some(n => n.type === p || (n as any).findingType === p))
    );

    return {
      id: `path-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      name: template?.name || `Attack Chain from ${entry.title}`,
      nodes,
      edges,
      entryPoint: entry.id,
      finalImpact: nodes[nodes.length - 1]?.id || entry.id,
      totalProbability: Math.round(totalProbability),
      narrative: this.generateNarrative(nodes, edges),
      mitreTechniques: nodes.flatMap(n =>
        MITRE_MAPPING[n.type]?.map(m => m.technique) || []
      ),
    };
  }

  private findingToNode(finding: Finding, type: AttackNode['type']): AttackNode {
    return {
      id: finding.id,
      findingId: finding.id,
      type,
      name: finding.title,
      description: finding.description,
      technique: MITRE_MAPPING[finding.type]?.[0]?.technique,
      severity: finding.severity,
      exploitability: this.severityScore(finding.severity) * 10,
    };
  }

  private canConnect(from: Finding, to: Finding): boolean {
    // Define connection rules
    const connections: Record<string, string[]> = {
      'secret': ['vulnerability', 'code-issue', 'iac'],
      'vulnerability': ['code-issue', 'docker', 'secret'],
      'code-issue': ['vulnerability', 'secret'],
      'docker': ['vulnerability', 'iac'],
      'iac': ['secret', 'vulnerability'],
    };

    return connections[from.type]?.includes(to.type) || false;
  }

  private getConnectionAction(from: Finding, to: Finding): string {
    if (from.type === 'secret' && to.type === 'vulnerability') {
      return 'Use credentials to access vulnerable service';
    }
    if (from.type === 'secret' && to.type === 'iac') {
      return 'Use cloud credentials to access infrastructure';
    }
    if (from.type === 'vulnerability' && to.type === 'code-issue') {
      return 'Exploit vulnerability to reach code execution';
    }
    if (from.type === 'docker' && to.type === 'vulnerability') {
      return 'Escape container and exploit host vulnerability';
    }
    return `Pivot from ${from.type} to ${to.type}`;
  }

  private calculateProbability(from: Finding, to: Finding): number {
    let base = 70;
    if (from.severity === 'critical') base += 15;
    if (to.severity === 'critical') base += 10;
    if (from.type === 'secret') base += 10; // Secrets are reliable entry points
    return Math.min(95, base);
  }

  private severityScore(severity: string): number {
    return { critical: 10, high: 7, medium: 4, low: 2 }[severity] || 1;
  }

  private generateNarrative(nodes: AttackNode[], edges: AttackEdge[]): string {
    if (nodes.length === 0) return 'No attack path identified.';
    if (nodes.length === 1) return `Single vulnerability: ${nodes[0].name}`;

    const parts = [`Attacker begins by exploiting "${nodes[0].name}"`];

    for (let i = 1; i < nodes.length; i++) {
      const edge = edges[i - 1];
      parts.push(`then ${edge?.action.toLowerCase() || 'pivots to'} "${nodes[i].name}"`);
    }

    parts.push(`resulting in ${nodes[nodes.length - 1].severity} severity impact.`);
    return parts.join(', ');
  }

  private generateStepOutput(node: AttackNode, success: boolean): string {
    if (success) {
      return `[+] Successfully exploited ${node.name}. Gained ${node.type === 'entry' ? 'initial access' : 'elevated privileges'}.`;
    }
    return `[-] Exploitation of ${node.name} failed. Security control blocked the attempt.`;
  }

  private estimateTime(node: AttackNode): string {
    const times: Record<string, string> = {
      entry: '5-15 minutes',
      pivot: '15-30 minutes',
      escalation: '30-60 minutes',
      impact: '1-2 hours',
      data: '2-4 hours',
    };
    return times[node.type] || '15-30 minutes';
  }

  private calculateTotalTime(steps: SimulationStep[]): string {
    const totalMinutes = steps.length * 20; // Rough estimate
    if (totalMinutes < 60) return `${totalMinutes} minutes`;
    return `${Math.round(totalMinutes / 60)} hours`;
  }

  private generateMermaidGraph(paths: AttackPath[]): string {
    let mermaid = 'graph TD\n';

    for (const path of paths.slice(0, 3)) { // Limit to 3 paths
      for (const node of path.nodes) {
        const shape = node.type === 'entry' ? '([' : node.type === 'impact' ? '{{' : '[';
        const shapeEnd = node.type === 'entry' ? '])' : node.type === 'impact' ? '}}' : ']';
        mermaid += `    ${node.id}${shape}"${node.name}"${shapeEnd}\n`;
      }

      for (const edge of path.edges) {
        mermaid += `    ${edge.from} -->|"${edge.action}"| ${edge.to}\n`;
      }
    }

    return mermaid;
  }

  private generateMarkdownReport(
    paths: AttackPath[],
    pivots: Array<{ finding: Finding; connectsTo: string[]; pivotScore: number }>,
    mitreMapping: { techniques: string[]; tactics: string[] },
    summary: object
  ): string {
    let md = '# Attack Chain Analysis Report\n\n';

    md += '## Summary\n';
    md += `- **Attack Paths Identified:** ${paths.length}\n`;
    md += `- **Critical Pivot Points:** ${pivots.filter(p => p.pivotScore > 20).length}\n`;
    md += `- **MITRE Techniques:** ${mitreMapping.techniques.join(', ') || 'None'}\n\n`;

    if (paths.length > 0) {
      md += '## Most Dangerous Attack Path\n\n';
      const top = paths[0];
      md += `**${top.name}**\n\n`;
      md += `> ${top.narrative}\n\n`;
      md += `- Probability: ${top.totalProbability}%\n`;
      md += `- Techniques: ${top.mitreTechniques.join(', ')}\n\n`;
    }

    md += '## All Attack Paths\n\n';
    for (const path of paths) {
      md += `### ${path.name}\n`;
      md += `${path.narrative}\n\n`;
    }

    return md;
  }
}

// Export factory function
export function createChainMapperAgent(port = 4005, coordinatorUrl?: string): ChainMapperAgent {
  return new ChainMapperAgent({
    id: 'chain-mapper',
    name: 'Chain Mapper Agent',
    port,
    description: 'Maps attack chains and traces exploitation paths through vulnerabilities',
    coordinatorUrl,
  });
}
