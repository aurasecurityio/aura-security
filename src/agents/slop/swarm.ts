/**
 * Aura Security Swarm - Phase 1 & 2
 *
 * Multi-agent orchestration system for autonomous security scanning.
 *
 * Phase 1 Agents: Scout, Scanner, Grader, Fixer
 * Phase 2 Agents: Chain Mapper, Red Team
 *
 * Usage:
 *   npm run swarm           # Start Phase 1 agents
 *   npm run swarm:full      # Start all agents (Phase 1 + 2)
 *   npm run swarm:phase2    # Start with Phase 2 agents
 */

import { CoordinatorAgent } from './coordinator-agent.js';
import { ScannerAgent } from './scanner-agent.js';
import { FixerAgent } from './fixer-agent.js';
import { ScoutAgent, createScoutAgent } from './scout-agent.js';
import { GraderAgent, createGraderAgent } from './grader-agent.js';
import { ChainMapperAgent, createChainMapperAgent } from './chain-mapper-agent.js';
import { RedTeamAgent, createRedTeamAgent } from './redteam-agent.js';
import { GuardianAgent, createGuardianAgent } from './guardian-agent.js';
import { IntelAgent, createIntelAgent } from './intel-agent.js';
import { SLOPAgent } from './base.js';

// Agent port assignments (starting from 4000 to avoid conflicts with Aura server on 3000/3001)
const PORTS = {
  coordinator: 4000,
  scanner: 4001,
  grader: 4002,
  fixer: 4003,
  scout: 4004,
  // Phase 2
  chainMapper: 4005,
  redTeam: 4006,
  // Phase 3
  guardian: 4007,
  intel: 4008,
};

export interface SwarmConfig {
  coordinatorPort?: number;
  scannerPort?: number;
  graderPort?: number;
  fixerPort?: number;
  scoutPort?: number;
  chainMapperPort?: number;
  redTeamPort?: number;
  guardianPort?: number;
  intelPort?: number;
  enableScout?: boolean;      // Watch repos for changes
  enableFixer?: boolean;      // Auto-generate fixes
  enableChainMapper?: boolean; // Phase 2: Attack chain analysis
  enableRedTeam?: boolean;    // Phase 2: Adversarial validation
  enableGuardian?: boolean;   // Phase 3: PR protection
  enableIntel?: boolean;      // Phase 3: Threat intelligence
  autoScan?: boolean;         // Auto-scan when scout detects changes
  verbose?: boolean;
}

export interface SwarmStatus {
  running: boolean;
  agents: {
    name: string;
    port: number;
    status: 'running' | 'stopped' | 'error';
    url: string;
  }[];
  startedAt?: number;
}

export class AuraSwarm {
  private agents: Map<string, SLOPAgent> = new Map();
  private running = false;
  private startedAt?: number;
  private config: SwarmConfig;

  constructor(config: SwarmConfig = {}) {
    this.config = {
      coordinatorPort: config.coordinatorPort ?? PORTS.coordinator,
      scannerPort: config.scannerPort ?? PORTS.scanner,
      graderPort: config.graderPort ?? PORTS.grader,
      fixerPort: config.fixerPort ?? PORTS.fixer,
      scoutPort: config.scoutPort ?? PORTS.scout,
      chainMapperPort: config.chainMapperPort ?? PORTS.chainMapper,
      redTeamPort: config.redTeamPort ?? PORTS.redTeam,
      guardianPort: config.guardianPort ?? PORTS.guardian,
      intelPort: config.intelPort ?? PORTS.intel,
      enableScout: config.enableScout ?? false,
      enableFixer: config.enableFixer ?? true,
      enableChainMapper: config.enableChainMapper ?? false,
      enableRedTeam: config.enableRedTeam ?? false,
      enableGuardian: config.enableGuardian ?? false,
      enableIntel: config.enableIntel ?? false,
      autoScan: config.autoScan ?? true,
      verbose: config.verbose ?? true,
    };
  }

  /**
   * Start all swarm agents
   */
  async start(): Promise<SwarmStatus> {
    if (this.running) {
      return this.getStatus();
    }

    const phase2Enabled = this.config.enableChainMapper || this.config.enableRedTeam;
    const phase3Enabled = this.config.enableGuardian || this.config.enableIntel;
    const phaseText = phase3Enabled ? 'FULL' : phase2Enabled ? 'PHASE 1-2' : 'PHASE 1';
    console.log(`
╔═══════════════════════════════════════════════════════════════╗
║            AURA SECURITY SWARM - ${phaseText.padEnd(10)}                  ║
║            Multi-Agent Security Orchestration                 ║
╚═══════════════════════════════════════════════════════════════╝
`);

    const coordinatorUrl = `http://localhost:${this.config.coordinatorPort}`;

    // 1. Start Coordinator (central hub)
    const coordinator = new CoordinatorAgent({
      id: 'coordinator',
      name: 'Coordinator',
      port: this.config.coordinatorPort!,
      description: 'Central orchestration hub for all agents',
    });
    this.agents.set('coordinator', coordinator);
    await coordinator.start();

    // 2. Start Scanner (detection)
    const scanner = new ScannerAgent({
      id: 'scanner',
      name: 'Scanner Agent',
      port: this.config.scannerPort!,
      description: 'Security vulnerability scanner',
      coordinatorUrl,
    });
    this.agents.set('scanner', scanner);
    await scanner.start();

    // 3. Start Grader (scoring & chains)
    const grader = createGraderAgent(this.config.graderPort!, coordinatorUrl);
    this.agents.set('grader', grader);
    await grader.start();

    // 4. Start Fixer (if enabled)
    if (this.config.enableFixer) {
      const fixer = new FixerAgent({
        id: 'fixer',
        name: 'Fixer Agent',
        port: this.config.fixerPort!,
        description: 'Auto-remediation and fix generation',
        coordinatorUrl,
      });
      this.agents.set('fixer', fixer);
      await fixer.start();
    }

    // 5. Start Scout (if enabled)
    if (this.config.enableScout) {
      const scout = createScoutAgent(this.config.scoutPort!, coordinatorUrl);
      this.agents.set('scout', scout);
      await scout.start();
    }

    // === Phase 2 Agents ===

    // 6. Start Chain Mapper (if enabled)
    if (this.config.enableChainMapper) {
      const chainMapper = createChainMapperAgent(this.config.chainMapperPort!, coordinatorUrl);
      this.agents.set('chain-mapper', chainMapper);
      await chainMapper.start();
    }

    // 7. Start Red Team (if enabled)
    if (this.config.enableRedTeam) {
      const redTeam = createRedTeamAgent(this.config.redTeamPort!, coordinatorUrl);
      this.agents.set('red-team', redTeam);
      await redTeam.start();
    }

    // === Phase 3 Agents ===

    // 8. Start Guardian (if enabled)
    if (this.config.enableGuardian) {
      const guardian = createGuardianAgent(this.config.guardianPort!, coordinatorUrl);
      this.agents.set('guardian', guardian);
      await guardian.start();
    }

    // 9. Start Intel (if enabled)
    if (this.config.enableIntel) {
      const intel = createIntelAgent(this.config.intelPort!, coordinatorUrl);
      this.agents.set('intel', intel);
      await intel.start();
    }

    this.running = true;
    this.startedAt = Date.now();

    // Print status
    this.printStatus();

    return this.getStatus();
  }

  /**
   * Stop all swarm agents
   */
  async stop(): Promise<void> {
    console.log('\n[Swarm] Shutting down agents...');

    for (const [name, agent] of this.agents) {
      try {
        await agent.stop();
        console.log(`  ✓ ${name} stopped`);
      } catch (error) {
        console.error(`  ✗ ${name} failed to stop:`, error);
      }
    }

    this.agents.clear();
    this.running = false;
    console.log('[Swarm] All agents stopped');
  }

  /**
   * Get current swarm status
   */
  getStatus(): SwarmStatus {
    const agents = Array.from(this.agents.entries()).map(([name, agent]) => ({
      name,
      port: (agent as any).config.port,
      status: 'running' as const,
      url: `http://localhost:${(agent as any).config.port}`,
    }));

    return {
      running: this.running,
      agents,
      startedAt: this.startedAt,
    };
  }

  /**
   * Run a full security scan pipeline
   */
  async runPipeline(targetPath: string): Promise<{
    scanId: string;
    findings: any[];
    grading: any;
    fixes: any[];
    chainAnalysis?: any;
    validation?: any;
    report: any;
  }> {
    const scanId = `scan-${Date.now()}`;
    const phase2Enabled = this.config.enableChainMapper || this.config.enableRedTeam;
    const totalSteps = 4 + (this.config.enableChainMapper ? 1 : 0) + (this.config.enableRedTeam ? 1 : 0);
    let step = 0;

    console.log(`\n[Swarm] Starting pipeline: ${scanId}`);
    console.log(`[Swarm] Target: ${targetPath}`);
    console.log(`[Swarm] Phase 2: ${phase2Enabled ? 'ENABLED' : 'disabled'}`);

    // Step 1: Scan
    step++;
    console.log(`\n[${step}/${totalSteps}] Scanning...`);
    const scanResult = await this.callAgent('scanner', 'scan', {
      targetPath,
      scanSecrets: true,
      scanPackages: true,
      scanCode: true,
    });

    const findings = (scanResult as any)?.raw_findings?.allFindings || [];
    console.log(`  Found ${findings.length} findings`);

    // Step 2: Grade
    step++;
    console.log(`\n[${step}/${totalSteps}] Grading findings...`);
    const gradingResult = await this.callAgent('grader', 'calculate-risk', {
      findings,
      repoInfo: { path: targetPath },
    });
    console.log(`  Risk score: ${(gradingResult as any)?.overallScore}/100 (Grade: ${(gradingResult as any)?.grade})`);

    // Step 3: Map attack chains (basic)
    step++;
    console.log(`\n[${step}/${totalSteps}] Mapping attack chains...`);
    const chainResult = await this.callAgent('grader', 'map-chains', { findings });
    const chains = (chainResult as any)?.chains || [];
    console.log(`  Found ${chains.length} attack chain(s)`);

    // Step 4: Generate fixes (if enabled)
    step++;
    let fixes: any[] = [];
    if (this.config.enableFixer && findings.length > 0) {
      console.log(`\n[${step}/${totalSteps}] Generating fixes...`);
      const fixResult = await this.callAgent('fixer', 'fix-batch', {
        findings: findings.slice(0, 10), // Limit to top 10
        autoFix: false,
      });
      fixes = (fixResult as any)?.fixes || [];
      console.log(`  Generated ${fixes.length} fix suggestions`);
    } else {
      console.log(`\n[${step}/${totalSteps}] Skipping fix generation`);
    }

    // === Phase 2 Steps ===
    let chainAnalysis: any = null;
    let validation: any = null;

    // Step 5: Deep Chain Mapping (Phase 2)
    if (this.config.enableChainMapper && findings.length > 0) {
      step++;
      console.log(`\n[${step}/${totalSteps}] [PHASE 2] Deep attack chain analysis...`);
      chainAnalysis = await this.callAgent('chain-mapper', 'generate-report', {
        findings,
        format: 'json',
      });
      const advancedChains = (chainAnalysis as any)?.paths?.length || 0;
      console.log(`  Mapped ${advancedChains} advanced attack path(s)`);
      if ((chainAnalysis as any)?.summary?.mostDangerousPath) {
        console.log(`  Most dangerous: ${(chainAnalysis as any).summary.mostDangerousPath}`);
      }
    }

    // Step 6: Red Team Validation (Phase 2)
    if (this.config.enableRedTeam && findings.length > 0) {
      step++;
      console.log(`\n[${step}/${totalSteps}] [PHASE 2] Red Team validation...`);
      const highPriorityFindings = findings
        .filter((f: any) => f.severity === 'critical' || f.severity === 'high')
        .slice(0, 5);

      if (highPriorityFindings.length > 0) {
        validation = await this.callAgent('red-team', 'bulk-validate', {
          findings: highPriorityFindings,
          maxConcurrent: 3,
        });
        const validated = (validation as any)?.summary || {};
        console.log(`  Validated ${validated.total || 0} findings`);
        console.log(`  Confirmed exploitable: ${validated.exploitable || 0}`);
        console.log(`  False positives: ${validated.falsePositives || 0}`);
      } else {
        console.log('  No high-priority findings to validate');
      }
    }

    // Build report
    const report = {
      scanId,
      timestamp: Date.now(),
      target: targetPath,
      phase2Enabled,
      summary: {
        totalFindings: findings.length,
        critical: findings.filter((f: any) => f.severity === 'critical').length,
        high: findings.filter((f: any) => f.severity === 'high').length,
        medium: findings.filter((f: any) => f.severity === 'medium').length,
        low: findings.filter((f: any) => f.severity === 'low').length,
      },
      riskScore: (gradingResult as any)?.overallScore,
      grade: (gradingResult as any)?.grade,
      attackChains: chains.length,
      advancedChains: chainAnalysis?.paths?.length || 0,
      confirmedExploitable: validation?.summary?.exploitable || 0,
      falsePositives: validation?.summary?.falsePositives || 0,
      fixableCount: fixes.filter((f: any) => f.fixable).length,
    };

    console.log('\n' + '='.repeat(60));
    console.log('PIPELINE COMPLETE');
    console.log('='.repeat(60));
    console.log(`Risk Score: ${report.riskScore}/100 (Grade: ${report.grade})`);
    console.log(`Findings: ${report.summary.totalFindings} (${report.summary.critical} critical, ${report.summary.high} high)`);
    console.log(`Attack Chains: ${report.attackChains}${report.advancedChains ? ` (${report.advancedChains} advanced)` : ''}`);
    if (phase2Enabled) {
      console.log(`Confirmed Exploitable: ${report.confirmedExploitable}`);
      console.log(`False Positives: ${report.falsePositives}`);
    }
    console.log(`Fixable: ${report.fixableCount}/${fixes.length}`);
    console.log('='.repeat(60));

    return { scanId, findings, grading: gradingResult, fixes, chainAnalysis, validation, report };
  }

  /**
   * Watch a repository for changes
   */
  async watchRepo(repoUrl: string, branch?: string): Promise<any> {
    if (!this.config.enableScout) {
      throw new Error('Scout agent is not enabled');
    }

    return this.callAgent('scout', 'watch-repo', {
      url: repoUrl,
      branch,
      pollInterval: 60,
    });
  }

  /**
   * Call an agent's tool
   */
  private async callAgent(agentName: string, tool: string, args: Record<string, unknown>): Promise<unknown> {
    const agent = this.agents.get(agentName);
    if (!agent) {
      throw new Error(`Agent ${agentName} not found`);
    }

    const port = (agent as any).config.port;
    const url = `http://localhost:${port}/tools`;

    try {
      const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, arguments: args }),
      });

      const result = await response.json();
      if (result.error) {
        throw new Error(result.error);
      }

      return result.result;
    } catch (error) {
      console.error(`[Swarm] Error calling ${agentName}.${tool}:`, error);
      throw error;
    }
  }

  private printStatus(): void {
    console.log('\n' + '─'.repeat(60));
    console.log('SWARM STATUS');
    console.log('─'.repeat(60));

    for (const [name, agent] of this.agents) {
      const port = (agent as any).config.port;
      console.log(`  ✓ ${name.padEnd(12)} http://localhost:${port}`);
    }

    console.log('─'.repeat(60));
    console.log('\nEndpoints:');
    console.log(`  Coordinator: http://localhost:${this.config.coordinatorPort}/info`);
    console.log(`  Scanner:     http://localhost:${this.config.scannerPort}/tools`);
    console.log(`  Grader:      http://localhost:${this.config.graderPort}/tools`);
    if (this.config.enableFixer) {
      console.log(`  Fixer:       http://localhost:${this.config.fixerPort}/tools`);
    }
    if (this.config.enableScout) {
      console.log(`  Scout:       http://localhost:${this.config.scoutPort}/tools`);
    }
    if (this.config.enableChainMapper) {
      console.log(`  ChainMapper: http://localhost:${this.config.chainMapperPort}/tools`);
    }
    if (this.config.enableRedTeam) {
      console.log(`  RedTeam:     http://localhost:${this.config.redTeamPort}/tools`);
    }
    if (this.config.enableGuardian) {
      console.log(`  Guardian:    http://localhost:${this.config.guardianPort}/tools`);
    }
    if (this.config.enableIntel) {
      console.log(`  Intel:       http://localhost:${this.config.intelPort}/tools`);
    }

    console.log('\nReady to scan! Use:');
    console.log(`  curl -X POST http://localhost:${this.config.scannerPort}/tools \\`);
    console.log('    -H "Content-Type: application/json" \\');
    console.log('    -d \'{"tool":"scan","arguments":{"targetPath":"/path/to/repo"}}\'');
    console.log('');
  }
}

// CLI Entry Point
async function main(): Promise<void> {
  const enablePhase2 = process.argv.includes('--phase2') || process.argv.includes('--full');
  const enablePhase3 = process.argv.includes('--phase3') || process.argv.includes('--full');

  const swarm = new AuraSwarm({
    enableScout: process.argv.includes('--scout') || process.argv.includes('--full'),
    enableFixer: !process.argv.includes('--no-fixer'),
    enableChainMapper: enablePhase2,
    enableRedTeam: enablePhase2,
    enableGuardian: enablePhase3,
    enableIntel: enablePhase3,
    verbose: true,
  });

  // Handle shutdown
  process.on('SIGINT', async () => {
    await swarm.stop();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    await swarm.stop();
    process.exit(0);
  });

  await swarm.start();

  // If a target path is provided, run the pipeline
  const targetIndex = process.argv.indexOf('--scan');
  if (targetIndex !== -1 && process.argv[targetIndex + 1]) {
    const targetPath = process.argv[targetIndex + 1];
    await swarm.runPipeline(targetPath);
  }

  // Keep running
  console.log('\nSwarm is running. Press Ctrl+C to stop.\n');
}

// Run if executed directly
const isMainModule = import.meta.url === `file://${process.argv[1]}`;
if (isMainModule) {
  main().catch(console.error);
}

export { AuraSwarm as default };
