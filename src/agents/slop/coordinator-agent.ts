/**
 * Coordinator SLOP Agent
 *
 * SLOP-native agent that orchestrates all other agents.
 * Manages pipelines, shared memory, and agent communication.
 */

import { SLOPAgent } from './base.js';
import { SLOPAgentConfig, SLOPTool, SLOPToolCall, SLOPToolResult, Finding, TriageResult, PipelineResult } from './types.js';

interface RegisteredAgent {
  id: string;
  name: string;
  url: string;
  status: 'online' | 'offline' | 'busy';
  lastSeen: number;
  tools: string[];
}

const COORDINATOR_TOOLS: SLOPTool[] = [
  {
    name: 'register-agent',
    description: 'Register an agent with the coordinator',
    parameters: {
      id: { type: 'string', description: 'Agent ID', required: true },
      name: { type: 'string', description: 'Agent name', required: true },
      url: { type: 'string', description: 'Agent URL', required: true },
      tools: { type: 'array', description: 'List of tool names', required: false },
    },
  },
  {
    name: 'list-agents',
    description: 'List all registered agents',
    parameters: {},
  },
  {
    name: 'run-pipeline',
    description: 'Run a full security scan pipeline: scan → triage → prioritize',
    parameters: {
      target: { type: 'string', description: 'Target to scan', required: true },
      options: { type: 'object', description: 'Pipeline options', required: false },
    },
  },
  {
    name: 'call-agent',
    description: 'Call a specific agent tool',
    parameters: {
      agentId: { type: 'string', description: 'Agent to call', required: true },
      tool: { type: 'string', description: 'Tool to invoke', required: true },
      arguments: { type: 'object', description: 'Tool arguments', required: false },
    },
  },
  {
    name: 'broadcast',
    description: 'Broadcast a message to all agents',
    parameters: {
      message: { type: 'string', description: 'Message to broadcast', required: true },
    },
  },
  {
    name: 'get-pipeline-history',
    description: 'Get history of pipeline runs',
    parameters: {
      limit: { type: 'number', description: 'Number of results to return', required: false },
    },
  },
];

export class CoordinatorAgent extends SLOPAgent {
  private agents: Map<string, RegisteredAgent> = new Map();
  private pipelineHistory: PipelineResult[] = [];

  constructor(config: Partial<SLOPAgentConfig> = {}) {
    super(
      {
        id: config.id || 'coordinator',
        name: config.name || 'Coordinator Agent',
        port: config.port || 3009,
        description: 'Central coordinator - orchestrates all security agents, manages pipelines',
        peers: config.peers,
      },
      COORDINATOR_TOOLS
    );
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    console.log(`[Coordinator] Tool call: ${call.tool}`, call.arguments);

    try {
      switch (call.tool) {
        case 'register-agent':
          return { result: await this.registerAgent(call.arguments as unknown as RegisteredAgent) };
        case 'list-agents':
          return { result: await this.listAgents() };
        case 'run-pipeline':
          return { result: await this.runPipeline(call.arguments.target as string, call.arguments.options as Record<string, unknown>) };
        case 'call-agent':
          return { result: await this.callAgentTool(call.arguments.agentId as string, call.arguments.tool as string, call.arguments.arguments as Record<string, unknown>) };
        case 'broadcast':
          return { result: await this.broadcast(call.arguments.message as string) };
        case 'get-pipeline-history':
          return { result: this.pipelineHistory.slice(-(call.arguments.limit as number || 10)) };
        default:
          return { error: `Unknown tool: ${call.tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  private async registerAgent(agent: RegisteredAgent): Promise<{ success: boolean; agent: RegisteredAgent }> {
    // Verify agent is reachable
    try {
      const response = await fetch(`${agent.url}/info`);
      if (response.ok) {
        const info = await response.json();
        agent.tools = info.tools?.map((t: { name: string }) => t.name) || [];
        agent.status = 'online';
        agent.lastSeen = Date.now();
        this.agents.set(agent.id, agent);
        console.log(`[Coordinator] Registered agent: ${agent.name} at ${agent.url}`);
        return { success: true, agent };
      }
    } catch (error) {
      agent.status = 'offline';
      this.agents.set(agent.id, agent);
      console.log(`[Coordinator] Registered agent (offline): ${agent.name}`);
    }

    return { success: false, agent };
  }

  private async listAgents(): Promise<{ agents: RegisteredAgent[]; online: number; offline: number }> {
    // Update status for all agents
    for (const [id, agent] of this.agents) {
      try {
        const response = await fetch(`${agent.url}/info`, { signal: AbortSignal.timeout(2000) });
        if (response.ok) {
          agent.status = 'online';
          agent.lastSeen = Date.now();
        } else {
          agent.status = 'offline';
        }
      } catch {
        agent.status = 'offline';
      }
      this.agents.set(id, agent);
    }

    const agentList = Array.from(this.agents.values());
    return {
      agents: agentList,
      online: agentList.filter((a) => a.status === 'online').length,
      offline: agentList.filter((a) => a.status === 'offline').length,
    };
  }

  private async callAgentTool(agentId: string, tool: string, args?: Record<string, unknown>): Promise<unknown> {
    const agent = this.agents.get(agentId);
    if (!agent) {
      throw new Error(`Agent not found: ${agentId}`);
    }

    return this.callAgent(agent.url, tool, args || {});
  }

  private async runPipeline(target: string, options?: Record<string, unknown>): Promise<PipelineResult> {
    const startTime = Date.now();
    const stages: PipelineResult['stages'] = [];

    console.log(`\n[Coordinator] ═══════════════════════════════════════════`);
    console.log(`[Coordinator] Starting security pipeline for: ${target}`);
    console.log(`[Coordinator] ═══════════════════════════════════════════\n`);

    try {
      // Stage 1: Scan
      console.log(`[Coordinator] Stage 1: SCANNING...`);
      const scannerAgent = this.findAgentWithTool('scan');
      if (!scannerAgent) {
        throw new Error('No scanner agent available');
      }

      const stageStartScan = Date.now();
      const scanResult = (await this.callAgent(scannerAgent.url, 'scan', { target })) as { findings: Finding[]; summary: Record<string, number> };

      stages.push({
        agent: scannerAgent.id,
        tool: 'scan',
        result: scanResult,
        duration: Date.now() - stageStartScan,
      });

      console.log(`[Coordinator] ✓ Scan complete: ${scanResult.findings.length} findings`);
      console.log(`[Coordinator]   Critical: ${scanResult.summary.critical}, High: ${scanResult.summary.high}, Medium: ${scanResult.summary.medium}, Low: ${scanResult.summary.low}`);

      if (scanResult.findings.length === 0) {
        console.log(`[Coordinator] No findings to triage. Pipeline complete.`);
        const result: PipelineResult = {
          stages,
          totalDuration: Date.now() - startTime,
          success: true,
        };
        this.pipelineHistory.push(result);
        return result;
      }

      // Stage 2: Triage
      console.log(`\n[Coordinator] Stage 2: TRIAGING...`);
      const analystAgent = this.findAgentWithTool('triage-batch');
      if (!analystAgent) {
        console.log(`[Coordinator] ⚠ No analyst agent available, skipping triage`);
      } else {
        const stageStartTriage = Date.now();
        const triageResult = (await this.callAgent(analystAgent.url, 'triage-batch', { findings: scanResult.findings })) as {
          results: TriageResult[];
          summary: Record<string, number>;
        };

        stages.push({
          agent: analystAgent.id,
          tool: 'triage-batch',
          result: triageResult,
          duration: Date.now() - stageStartTriage,
        });

        console.log(`[Coordinator] ✓ Triage complete:`);
        console.log(`[Coordinator]   Validated: ${triageResult.summary.validated}, False positives: ${triageResult.summary.falsePositives}`);

        // Stage 3: Deduplicate
        console.log(`\n[Coordinator] Stage 3: DEDUPLICATING...`);
        const validatedFindings = triageResult.results.filter((r) => r.validated && !r.falsePositive).map((r) => r.finding);

        const stageStartDedup = Date.now();
        const dedupResult = (await this.callAgent(analystAgent.url, 'deduplicate', { findings: validatedFindings })) as {
          unique: Finding[];
          duplicates: Finding[];
          duplicateCount: number;
        };

        stages.push({
          agent: analystAgent.id,
          tool: 'deduplicate',
          result: dedupResult,
          duration: Date.now() - stageStartDedup,
        });

        console.log(`[Coordinator] ✓ Deduplication complete: ${dedupResult.duplicateCount} duplicates removed`);

        // Stage 4: Prioritize
        console.log(`\n[Coordinator] Stage 4: PRIORITIZING...`);
        const stageStartPrioritize = Date.now();
        const prioritizedFindings = (await this.callAgent(analystAgent.url, 'prioritize', { findings: dedupResult.unique })) as Finding[];

        stages.push({
          agent: analystAgent.id,
          tool: 'prioritize',
          result: prioritizedFindings,
          duration: Date.now() - stageStartPrioritize,
        });

        console.log(`[Coordinator] ✓ Prioritization complete: ${prioritizedFindings.length} findings prioritized`);

        // Show top findings
        if (prioritizedFindings.length > 0) {
          console.log(`\n[Coordinator] Top priority findings:`);
          for (const finding of prioritizedFindings.slice(0, 5)) {
            console.log(`[Coordinator]   [${finding.severity.toUpperCase()}] ${finding.title}`);
            if (finding.file) console.log(`[Coordinator]     └─ ${finding.file}${finding.line ? ':' + finding.line : ''}`);
          }
        }
      }

      // Write final results to memory
      const finalResult = {
        target,
        timestamp: Date.now(),
        stages: stages.map((s) => ({ agent: s.agent, tool: s.tool, duration: s.duration })),
        totalDuration: Date.now() - startTime,
      };
      await this.writeMemory(`pipeline:${target}:${Date.now()}`, finalResult);

      console.log(`\n[Coordinator] ═══════════════════════════════════════════`);
      console.log(`[Coordinator] Pipeline complete in ${Date.now() - startTime}ms`);
      console.log(`[Coordinator] ═══════════════════════════════════════════\n`);

      const result: PipelineResult = {
        stages,
        totalDuration: Date.now() - startTime,
        success: true,
      };
      this.pipelineHistory.push(result);
      return result;
    } catch (error) {
      console.error(`[Coordinator] Pipeline error:`, error);
      const result: PipelineResult = {
        stages,
        totalDuration: Date.now() - startTime,
        success: false,
        error: String(error),
      };
      this.pipelineHistory.push(result);
      return result;
    }
  }

  private findAgentWithTool(toolName: string): RegisteredAgent | undefined {
    for (const agent of this.agents.values()) {
      if (agent.status === 'online' && agent.tools.includes(toolName)) {
        return agent;
      }
    }
    return undefined;
  }

  private async broadcast(message: string): Promise<{ sent: number; failed: number }> {
    let sent = 0;
    let failed = 0;

    for (const agent of this.agents.values()) {
      try {
        await fetch(`${agent.url}/memory`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            key: `broadcast:${Date.now()}`,
            value: { from: 'coordinator', message, timestamp: Date.now() },
            timestamp: Date.now(),
            agent: 'coordinator',
          }),
        });
        sent++;
      } catch {
        failed++;
      }
    }

    return { sent, failed };
  }

  /**
   * Auto-discover and register agents on common ports
   */
  async discoverAgents(): Promise<void> {
    const commonPorts = [3010, 3011, 3012, 3013, 3014];
    const agentTypes = ['scanner', 'analyst', 'fixer', 'compliance', 'reviewer'];

    console.log(`[Coordinator] Discovering agents...`);

    for (let i = 0; i < commonPorts.length; i++) {
      const port = commonPorts[i];
      const url = `http://localhost:${port}`;

      try {
        const response = await fetch(`${url}/info`, { signal: AbortSignal.timeout(1000) });
        if (response.ok) {
          const info = await response.json();
          await this.registerAgent({
            id: info.name?.toLowerCase().replace(/\s+/g, '-') || `agent-${port}`,
            name: info.name || `Agent ${port}`,
            url,
            status: 'online',
            lastSeen: Date.now(),
            tools: info.tools?.map((t: { name: string }) => t.name) || [],
          });
        }
      } catch {
        // Agent not running on this port
      }
    }

    const agentCount = Array.from(this.agents.values()).filter((a) => a.status === 'online').length;
    console.log(`[Coordinator] Discovered ${agentCount} agents`);
  }
}

// Allow running as standalone
if (import.meta.url === `file://${process.argv[1]}`) {
  const port = parseInt(process.env.PORT || '3009', 10);
  const agent = new CoordinatorAgent({ port });
  agent.start().then(() => {
    // Auto-discover agents after starting
    setTimeout(() => agent.discoverAgents(), 1000);
  });
}
