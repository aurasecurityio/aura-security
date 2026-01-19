/**
 * Aura Protocol - Parallel Orchestrator
 *
 * Orchestrates parallel execution of zones and manages data flow between them.
 * This is the main entry point for running security scans using the Aura architecture.
 */

import { EventEmitter } from 'events';
import { ZoneManager, zoneManager } from '../zones/manager.js';
import { Zone, ZoneConfig, ZoneResult, ZoneFinding } from '../zones/types.js';
import { createAllAgents } from '../agents/index.js';
import { Agent } from '../agents/types.js';

export interface OrchestratorConfig {
  // Target path to scan
  targetPath: string;
  // Which zones to run (default: all)
  zones?: string[];
  // Whether to run policy zone after scanner zone
  runPolicyZone?: boolean;
  // Custom zone configurations
  customZones?: ZoneConfig[];
}

export interface OrchestratorResult {
  success: boolean;
  duration: number;
  targetPath: string;
  zoneResults: Map<string, ZoneResult>;
  findings: ZoneFinding[];
  summary: {
    totalFindings: number;
    byType: Record<string, number>;
    bySeverity: Record<string, number>;
    byZone: Record<string, number>;
    agentsUsed: string[];
  };
}

export class ParallelOrchestrator extends EventEmitter {
  private manager: ZoneManager;
  private agents: Agent[] = [];
  private initialized = false;

  constructor(manager?: ZoneManager) {
    super();
    this.manager = manager || zoneManager;
  }

  /**
   * Initialize the orchestrator with all agents
   */
  async initialize(): Promise<void> {
    if (this.initialized) return;

    // Create and register all agents
    this.agents = createAllAgents();

    for (const agent of this.agents) {
      this.manager.registerAgent(agent);
    }

    // Listen to manager events and forward them
    this.manager.on('zone:started', (data) => this.emit('zone:started', data));
    this.manager.on('zone:completed', (data) => this.emit('zone:completed', data));
    this.manager.on('zone:error', (data) => this.emit('zone:error', data));
    this.manager.on('agent:started', (data) => this.emit('agent:started', data));
    this.manager.on('agent:completed', (data) => this.emit('agent:completed', data));
    this.manager.on('finding:added', (data) => this.emit('finding:added', data));

    this.initialized = true;
    this.emit('initialized', { agentCount: this.agents.length });
  }

  /**
   * Run a full security scan using Aura Protocol
   *
   * Execution flow:
   * 1. Scanner Zone - Run all scanners in parallel
   * 2. Policy Zone - Evaluate and validate findings (sequential)
   */
  async scan(config: OrchestratorConfig): Promise<OrchestratorResult> {
    const startTime = Date.now();

    // Ensure initialized
    await this.initialize();

    this.emit('scan:started', { targetPath: config.targetPath });

    const zoneResults = new Map<string, ZoneResult>();
    let allFindings: ZoneFinding[] = [];

    try {
      // Phase 1: Run Scanner Zone
      this.emit('phase:started', { phase: 'scanner', zones: ['scanner-zone'] });

      const scannerResult = await this.manager.executeZone(
        'scanner-zone',
        config.targetPath
      );
      zoneResults.set('scanner-zone', scannerResult);

      // Collect scanner findings
      const scannerFindings = scannerResult.findings;
      this.emit('phase:completed', {
        phase: 'scanner',
        findingCount: scannerFindings.length,
      });

      // Phase 2: Run Policy Zone (if enabled)
      if (config.runPolicyZone !== false) {
        this.emit('phase:started', { phase: 'policy', zones: ['policy-zone'] });

        // Pass scanner findings to policy zone via memory
        const policyZone = this.manager.getZone('policy-zone');
        if (policyZone) {
          policyZone.memory.data.set('scanner_findings', scannerFindings);
        }

        const policyResult = await this.manager.executeZone(
          'policy-zone',
          config.targetPath
        );
        zoneResults.set('policy-zone', policyResult);

        // Use validated findings as final results
        const validatedFindings =
          (policyZone?.memory.data.get('validated_findings') as ZoneFinding[]) ||
          policyResult.findings;
        allFindings = validatedFindings;

        this.emit('phase:completed', {
          phase: 'policy',
          findingCount: allFindings.length,
        });
      } else {
        allFindings = scannerFindings;
      }

      // Build summary
      const summary = this.buildSummary(allFindings, zoneResults);

      const result: OrchestratorResult = {
        success: true,
        duration: Date.now() - startTime,
        targetPath: config.targetPath,
        zoneResults,
        findings: allFindings,
        summary,
      };

      this.emit('scan:completed', result);
      return result;
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      this.emit('scan:error', { error: errorMsg });

      return {
        success: false,
        duration: Date.now() - startTime,
        targetPath: config.targetPath,
        zoneResults,
        findings: allFindings,
        summary: this.buildSummary(allFindings, zoneResults),
      };
    }
  }

  /**
   * Run only the scanner zone (faster, no policy evaluation)
   */
  async quickScan(targetPath: string): Promise<OrchestratorResult> {
    return this.scan({
      targetPath,
      runPolicyZone: false,
    });
  }

  /**
   * Run a full scan with policy evaluation
   */
  async fullScan(targetPath: string): Promise<OrchestratorResult> {
    return this.scan({
      targetPath,
      runPolicyZone: true,
    });
  }

  /**
   * Get available agents
   */
  async getAvailableAgents(): Promise<Agent[]> {
    await this.initialize();
    const available: Agent[] = [];

    for (const agent of this.agents) {
      if (await agent.isAvailable()) {
        available.push(agent);
      }
    }

    return available;
  }

  /**
   * Get current state for visualization
   */
  getState(): ReturnType<ZoneManager['exportState']> {
    return this.manager.exportState();
  }

  /**
   * Reset all zones
   */
  reset(): void {
    for (const zone of this.manager.getAllZones()) {
      this.manager.resetZone(zone.config.id);
    }
  }

  private buildSummary(
    findings: ZoneFinding[],
    zoneResults: Map<string, ZoneResult>
  ): OrchestratorResult['summary'] {
    const byType: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};
    const byZone: Record<string, number> = {};
    const agentsUsed = new Set<string>();

    for (const finding of findings) {
      byType[finding.type] = (byType[finding.type] || 0) + 1;
      bySeverity[finding.severity] = (bySeverity[finding.severity] || 0) + 1;
    }

    for (const [zoneId, result] of zoneResults) {
      byZone[zoneId] = result.findings.length;
      for (const agentResult of result.agentResults) {
        if (agentResult.status === 'success') {
          agentsUsed.add(agentResult.agentName);
        }
      }
    }

    return {
      totalFindings: findings.length,
      byType,
      bySeverity,
      byZone,
      agentsUsed: Array.from(agentsUsed),
    };
  }
}

// Export singleton instance
export const orchestrator = new ParallelOrchestrator();

// Export zones
export * from '../zones/types.js';
export * from '../zones/manager.js';
