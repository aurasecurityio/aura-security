/**
 * SLOP Agents Index
 *
 * Export all SLOP-native agents for the Aura Security Swarm
 */

export * from './types.js';
export * from './base.js';

// Core Agents
export { ScannerAgent } from './scanner-agent.js';
export { AnalystAgent } from './analyst-agent.js';
export { CoordinatorAgent } from './coordinator-agent.js';
export { FixerAgent } from './fixer-agent.js';

// Phase 1 Swarm Agents
export { ScoutAgent, createScoutAgent } from './scout-agent.js';
export { GraderAgent, createGraderAgent } from './grader-agent.js';

// Phase 2 Swarm Agents
export { ChainMapperAgent, createChainMapperAgent } from './chain-mapper-agent.js';
export { RedTeamAgent, createRedTeamAgent } from './redteam-agent.js';

// Phase 3 Swarm Agents
export { GuardianAgent, createGuardianAgent } from './guardian-agent.js';
export { IntelAgent, createIntelAgent } from './intel-agent.js';

// Swarm Orchestration
export { AuraSwarm } from './swarm.js';
