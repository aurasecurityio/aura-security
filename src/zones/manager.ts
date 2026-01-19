/**
 * Aura Protocol - Zone Manager
 *
 * Manages creation, execution, and lifecycle of zones.
 * Zones are isolated execution environments that contain agents.
 */

import { EventEmitter } from 'events';
import {
  Zone,
  ZoneConfig,
  ZoneContext,
  ZoneFinding,
  ZoneLog,
  ZoneMemory,
  ZoneResult,
  ZoneStatus,
  DEFAULT_ZONES,
} from './types.js';
import { Agent, AgentResult } from '../agents/types.js';

export class ZoneManager extends EventEmitter {
  private zones: Map<string, Zone> = new Map();
  private agents: Map<string, Agent> = new Map();

  constructor() {
    super();
    // Initialize default zones
    this.initializeDefaultZones();
  }

  private initializeDefaultZones(): void {
    for (const config of DEFAULT_ZONES) {
      this.createZone(config);
    }
  }

  /**
   * Create a new zone
   */
  createZone(config: ZoneConfig): Zone {
    const zone: Zone = {
      config,
      status: 'idle',
      memory: {
        data: new Map(),
        findings: [],
        logs: [],
      },
    };
    this.zones.set(config.id, zone);
    this.emit('zone:created', { zoneId: config.id, zone });
    return zone;
  }

  /**
   * Get a zone by ID
   */
  getZone(zoneId: string): Zone | undefined {
    return this.zones.get(zoneId);
  }

  /**
   * Get all zones
   */
  getAllZones(): Zone[] {
    return Array.from(this.zones.values());
  }

  /**
   * Register an agent
   */
  registerAgent(agent: Agent): void {
    this.agents.set(agent.config.id, agent);
    this.emit('agent:registered', { agentId: agent.config.id, agent });
  }

  /**
   * Get an agent by ID
   */
  getAgent(agentId: string): Agent | undefined {
    return this.agents.get(agentId);
  }

  /**
   * Get all agents
   */
  getAllAgents(): Agent[] {
    return Array.from(this.agents.values());
  }

  /**
   * Get agents for a specific zone
   */
  getZoneAgents(zoneId: string): Agent[] {
    const zone = this.zones.get(zoneId);
    if (!zone) return [];

    return zone.config.agentIds
      .map((id) => this.agents.get(id))
      .filter((agent): agent is Agent => agent !== undefined);
  }

  /**
   * Assign an agent to a zone
   */
  assignAgentToZone(agentId: string, zoneId: string): void {
    const zone = this.zones.get(zoneId);
    if (!zone) throw new Error(`Zone ${zoneId} not found`);

    if (!zone.config.agentIds.includes(agentId)) {
      zone.config.agentIds.push(agentId);
      this.emit('agent:assigned', { agentId, zoneId });
    }
  }

  /**
   * Remove an agent from a zone
   */
  removeAgentFromZone(agentId: string, zoneId: string): void {
    const zone = this.zones.get(zoneId);
    if (!zone) return;

    const index = zone.config.agentIds.indexOf(agentId);
    if (index > -1) {
      zone.config.agentIds.splice(index, 1);
      this.emit('agent:removed', { agentId, zoneId });
    }
  }

  /**
   * Create a zone context for agent execution
   */
  private createZoneContext(zone: Zone, targetPath: string): ZoneContext {
    return {
      zoneId: zone.config.id,
      zoneName: zone.config.name,
      zoneType: zone.config.type,
      targetPath,
      memory: zone.memory,
      config: zone.config.config || {},
      addFinding: (finding) => {
        const fullFinding: ZoneFinding = {
          ...finding,
          id: `${zone.config.id}-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
          timestamp: Date.now(),
        };
        zone.memory.findings.push(fullFinding);
        this.emit('finding:added', { zoneId: zone.config.id, finding: fullFinding });
      },
      log: (level, message) => {
        const log: ZoneLog = {
          level,
          message,
          timestamp: Date.now(),
        };
        zone.memory.logs.push(log);
        this.emit('zone:log', { zoneId: zone.config.id, log });
      },
    };
  }

  /**
   * Execute a single zone
   */
  async executeZone(zoneId: string, targetPath: string): Promise<ZoneResult> {
    const zone = this.zones.get(zoneId);
    if (!zone) throw new Error(`Zone ${zoneId} not found`);

    // Update zone status
    zone.status = 'running';
    zone.startTime = Date.now();
    zone.memory.findings = [];
    zone.memory.logs = [];
    this.emit('zone:started', { zoneId });

    const context = this.createZoneContext(zone, targetPath);
    const agentResults: AgentResult[] = [];

    try {
      // Get agents for this zone
      const agents = this.getZoneAgents(zoneId);

      // Execute all agents in parallel within the zone
      const results = await Promise.all(
        agents.map(async (agent) => {
          const agentStartTime = Date.now();
          try {
            // Check if agent is available
            const isAvailable = await agent.isAvailable();
            if (!isAvailable) {
              context.log('warn', `Agent ${agent.config.name} not available, skipping`);
              return {
                agentId: agent.config.id,
                agentName: agent.config.name,
                status: 'skipped' as const,
                findings: [],
                duration: Date.now() - agentStartTime,
              };
            }

            this.emit('agent:started', { zoneId, agentId: agent.config.id });
            context.log('info', `Starting agent: ${agent.config.name}`);

            const result = await agent.execute(context);

            this.emit('agent:completed', { zoneId, agentId: agent.config.id, result });
            context.log('info', `Agent ${agent.config.name} completed with ${result.findings.length} findings`);

            return result;
          } catch (error) {
            const errorMsg = error instanceof Error ? error.message : String(error);
            context.log('error', `Agent ${agent.config.name} failed: ${errorMsg}`);
            this.emit('agent:error', { zoneId, agentId: agent.config.id, error: errorMsg });

            return {
              agentId: agent.config.id,
              agentName: agent.config.name,
              status: 'error' as const,
              findings: [],
              duration: Date.now() - agentStartTime,
              error: errorMsg,
            };
          }
        })
      );

      agentResults.push(...results);

      zone.status = 'complete';
      zone.endTime = Date.now();
      this.emit('zone:completed', { zoneId });
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : String(error);
      zone.status = 'error';
      zone.error = errorMsg;
      zone.endTime = Date.now();
      this.emit('zone:error', { zoneId, error: errorMsg });
    }

    return {
      zoneId: zone.config.id,
      zoneName: zone.config.name,
      zoneType: zone.config.type,
      status: zone.status,
      findings: zone.memory.findings,
      logs: zone.memory.logs,
      duration: (zone.endTime || Date.now()) - (zone.startTime || Date.now()),
      agentResults,
      error: zone.error,
    };
  }

  /**
   * Execute multiple zones in parallel
   */
  async executeZonesParallel(zoneIds: string[], targetPath: string): Promise<Map<string, ZoneResult>> {
    this.emit('execution:started', { zoneIds, targetPath });

    const results = await Promise.all(
      zoneIds.map((zoneId) => this.executeZone(zoneId, targetPath))
    );

    const resultMap = new Map<string, ZoneResult>();
    for (const result of results) {
      resultMap.set(result.zoneId, result);
    }

    this.emit('execution:completed', { results: resultMap });
    return resultMap;
  }

  /**
   * Execute all zones in parallel
   */
  async executeAllZones(targetPath: string): Promise<Map<string, ZoneResult>> {
    const zoneIds = Array.from(this.zones.keys());
    return this.executeZonesParallel(zoneIds, targetPath);
  }

  /**
   * Reset a zone to idle state
   */
  resetZone(zoneId: string): void {
    const zone = this.zones.get(zoneId);
    if (!zone) return;

    zone.status = 'idle';
    zone.startTime = undefined;
    zone.endTime = undefined;
    zone.error = undefined;
    zone.memory = {
      data: new Map(),
      findings: [],
      logs: [],
    };
    this.emit('zone:reset', { zoneId });
  }

  /**
   * Get zone status
   */
  getZoneStatus(zoneId: string): ZoneStatus | undefined {
    return this.zones.get(zoneId)?.status;
  }

  /**
   * Get all findings from all zones
   */
  getAllFindings(): ZoneFinding[] {
    const findings: ZoneFinding[] = [];
    for (const zone of this.zones.values()) {
      findings.push(...zone.memory.findings);
    }
    return findings;
  }

  /**
   * Export zone state for visualization
   */
  exportState(): {
    zones: Array<{
      id: string;
      name: string;
      type: string;
      color: string;
      status: ZoneStatus;
      agentCount: number;
      findingCount: number;
    }>;
    agents: Array<{
      id: string;
      name: string;
      role: string;
      zoneId: string | null;
      status: string;
    }>;
  } {
    const zones = Array.from(this.zones.values()).map((zone) => ({
      id: zone.config.id,
      name: zone.config.name,
      type: zone.config.type,
      color: zone.config.color,
      status: zone.status,
      agentCount: zone.config.agentIds.length,
      findingCount: zone.memory.findings.length,
    }));

    const agents = Array.from(this.agents.values()).map((agent) => {
      // Find which zone this agent belongs to
      let zoneId: string | null = null;
      for (const zone of this.zones.values()) {
        if (zone.config.agentIds.includes(agent.config.id)) {
          zoneId = zone.config.id;
          break;
        }
      }
      return {
        id: agent.config.id,
        name: agent.config.name,
        role: agent.config.role,
        zoneId,
        status: agent.getStatus(),
      };
    });

    return { zones, agents };
  }
}

// Export singleton instance
export const zoneManager = new ZoneManager();
