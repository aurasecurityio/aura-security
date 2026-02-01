/**
 * AI Jail System
 *
 * Agent trust scoring, bot farm detection, and containment for Moltbook.
 */

export { AgentScorer } from './scorer.js';
export { BotFarmDetector } from './network.js';
export { JailEnforcer } from './actions.js';
export type {
  AgentTrustScore,
  IdentitySignal,
  BehaviorSignal,
  NetworkSignal,
  ContentSignal,
  JailLevel,
  JailAction,
  BotCluster,
  ClusterSignal,
  CompoundEvidence,
} from './types.js';
