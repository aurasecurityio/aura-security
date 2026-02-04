/**
 * Clawstr Integration
 *
 * Nostr-based social network integration for AuraSecurity.
 * Monitors Clawstr subclaws for GitHub URLs and posts security scan results.
 *
 * Similar to Moltbook integration but for the Clawstr/Nostr ecosystem.
 */

// Main agent
export { ClawstrAgent, type ClawstrAgentStatus } from './agent.js';

// Client for direct Nostr operations
export { ClawstrClient, type NostrFilter } from './client.js';

// Monitor for watching feeds
export { ClawstrMonitor, type ScanRequest, type MentionRequest } from './monitor.js';

// Formatting utilities
export {
  formatScanResult,
  formatBriefScanResult,
  formatScanError,
  formatMentionResponse,
  formatMentionNoUrl,
  formatWeeklyLeaderboard,
  formatShillWarning,
  formatTrendingReport,
  makePostDecision,
  type ScanResultData,
  type PostDecision,
  type VerdictType,
} from './formatter.js';

// Key management
export {
  generateKeyPair,
  loadKeyPair,
  getPublicKey,
  signEvent,
  getEventHash,
  verifySignature,
  createSignedEvent,
  type NostrKeyPair,
} from './keys.js';

// Types
export {
  type NostrEvent,
  type UnsignedEvent,
  type ClawstrPost,
  type ClawstrComment,
  type ClawstrAgentConfig,
  type CommentTags,
  type Subclaw,
  type AgentReputation,
  type RepoScanRecord,
  EVENT_KINDS,
  DEFAULT_CONFIG,
  GITHUB_URL_REGEX,
  extractGitHubUrls,
  getSubclawFromTags,
  isAIAgentPost,
  calculateReputationScore,
} from './types.js';

/**
 * Quick start helper - creates and starts a Clawstr agent
 *
 * @example
 * ```typescript
 * import { startClawstrAgent } from './integrations/clawstr';
 *
 * const agent = await startClawstrAgent({
 *   privateKey: process.env.CLAWSTR_PRIVATE_KEY,
 *   subclaws: ['/c/ai-freedom', '/c/builds'],
 * });
 *
 * // Get status
 * console.log(agent.getStatus());
 *
 * // Stop when done
 * agent.stop();
 * ```
 */
export async function startClawstrAgent(
  config: Partial<import('./types.js').ClawstrAgentConfig>
): Promise<import('./agent.js').ClawstrAgent> {
  const { ClawstrAgent } = await import('./agent.js');
  const agent = new ClawstrAgent({
    enabled: true,
    ...config,
  });
  await agent.start();
  return agent;
}

/**
 * Generate a new keypair for Clawstr
 *
 * @example
 * ```typescript
 * import { generateClawstrKeys } from './integrations/clawstr';
 *
 * const keys = generateClawstrKeys();
 * console.log('Private key (keep secret!):', keys.privateKey);
 * console.log('Public key:', keys.publicKey);
 * ```
 */
export { generateKeyPair as generateClawstrKeys } from './keys.js';
