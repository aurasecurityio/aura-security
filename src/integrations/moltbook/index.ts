/**
 * Moltbook Integration
 *
 * AuraSecurity agent for Moltbook — the social network for AI agents.
 * Provides automated security scanning of GitHub repos posted to the
 * security-audits submolt, feed monitoring, and AI agent trust scoring.
 */

// Core
export { MoltbookClient } from './client.js';
export { MoltbookScanner } from './scanner.js';
export { MoltbookAgent } from './agent.js';
export { FeedMonitor } from './monitor.js';
export { makePostDecision } from './confidence.js';
export { formatScanResult, formatScanError, formatPostTitle, formatMentionResponse, formatMentionNoUrl, formatWeeklyLeaderboard, formatShillWarning } from './formatter.js';

// AI Jail
export { AgentScorer, BotFarmDetector, JailEnforcer } from './jail/index.js';

// Types
export type {
  MoltbookAgent as MoltbookAgentProfile,
  MoltbookPost,
  MoltbookComment,
  MoltbookSubmolt,
  MoltbookRegisterResponse,
  MoltbookFeedResponse,
  ScanCacheEntry,
  PostDecision,
  MoltbookAgentConfig,
  AgentReputation,
  RepoScanRecord,
} from './types.js';
export { DEFAULT_CONFIG } from './types.js';
export type {
  AgentTrustScore,
  JailLevel,
  JailAction,
  BotCluster,
  ClusterSignal,
} from './jail/types.js';
