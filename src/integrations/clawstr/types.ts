/**
 * Clawstr Types
 *
 * Nostr event types and Clawstr-specific interfaces.
 * Built on NIPs: NIP-01 (events), NIP-22 (comments), NIP-32 (labels), NIP-73 (web identifiers)
 */

// === Nostr Core Types ===

export interface NostrEvent {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
}

export interface UnsignedEvent {
  kind: number;
  created_at: number;
  tags: string[][];
  content: string;
}

// === Nostr Event Kinds ===

export const EVENT_KINDS = {
  TEXT_NOTE: 1,           // Regular post (NIP-01)
  COMMENT: 1111,          // NIP-22 comment
  LABEL: 1985,            // NIP-32 label
} as const;

// === Clawstr-Specific Types ===

export interface ClawstrPost {
  id: string;
  pubkey: string;
  authorName?: string;
  content: string;
  subclaw: string;         // e.g., "/c/ai-freedom"
  createdAt: number;
  tags: string[][];
  replyCount?: number;
}

export interface ClawstrComment {
  id: string;
  pubkey: string;
  authorName?: string;
  content: string;
  rootPostId: string;
  parentId?: string;       // For threaded replies
  createdAt: number;
}

// === Agent Configuration ===

export interface ClawstrAgentConfig {
  // Identity
  privateKey: string;      // nsec or hex format

  // Relays
  relays: string[];        // WebSocket URLs

  // Monitoring
  subclaws: string[];      // Subclaws to monitor (e.g., ["/c/ai-freedom", "/c/builds"])
  pollIntervalMs: number;  // How often to check for new events

  // Behavior
  enabled: boolean;
  autoScan: boolean;       // Auto-scan GitHub URLs
  replyToMentions: boolean;

  // Rate limiting
  maxScansPerHour: number;
  minSecondsBetweenPosts: number;
}

export const DEFAULT_CONFIG: ClawstrAgentConfig = {
  privateKey: '',
  relays: [
    'wss://relay.ditto.pub',
    'wss://nos.lol',
    'wss://relay.primal.net',
    'wss://relay.damus.io',
  ],
  subclaws: [
    // AI & Agent communities
    '/c/ai-freedom',
    '/c/ai-thoughts',
    '/c/agent-economy',
    '/c/smart-accounts',
    // Developer communities
    '/c/builds',
    '/c/coding-help',
    '/c/tech',
    // Crypto/protocol communities
    '/c/bitcoin',
    '/c/nostr',
    // Social
    '/c/introductions',
  ],
  pollIntervalMs: 60_000,  // 1 minute
  enabled: false,
  autoScan: true,
  replyToMentions: true,
  maxScansPerHour: 30,
  minSecondsBetweenPosts: 30,
};

// === NIP-22 Comment Tags ===

export interface CommentTags {
  // Uppercase = root scope
  rootKind: string;        // K tag
  rootId: string;          // E, A, or I tag
  rootPubkey?: string;     // P tag (optional)

  // Lowercase = parent item
  parentKind: string;      // k tag
  parentId: string;        // e, a, or i tag
  parentPubkey?: string;   // p tag (optional)
}

// === Clawstr Subclaw (Community) ===

export interface Subclaw {
  name: string;            // e.g., "ai-freedom"
  displayName: string;     // e.g., "AI Freedom"
  description: string;
  webIdentifier: string;   // e.g., "https://clawstr.com/c/ai-freedom"
}

// === GitHub Detection ===

export const GITHUB_URL_REGEX = /https?:\/\/github\.com\/([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+)/gi;

// === Helper Functions ===

export function extractGitHubUrls(content: string): string[] {
  const matches = content.match(GITHUB_URL_REGEX);
  if (!matches) return [];

  // Dedupe and clean
  const unique = new Set<string>();
  for (const match of matches) {
    // Normalize: remove trailing slashes, .git, etc.
    const cleaned = match
      .replace(/\.git$/, '')
      .replace(/\/$/, '')
      .toLowerCase();
    unique.add(cleaned);
  }

  return Array.from(unique);
}

export function getSubclawFromTags(tags: string[][]): string | null {
  // Look for I or i tag with clawstr.com URL
  for (const tag of tags) {
    if ((tag[0] === 'I' || tag[0] === 'i') && tag[1]?.includes('clawstr.com/c/')) {
      const match = tag[1].match(/\/c\/([a-zA-Z0-9_-]+)/);
      if (match) return `/c/${match[1]}`;
    }
  }
  return null;
}

export function isAIAgentPost(tags: string[][]): boolean {
  // Check for NIP-32 AI label
  for (const tag of tags) {
    if (tag[0] === 'L' && tag[1] === 'agent') return true;
    if (tag[0] === 'l' && tag[1] === 'ai' && tag[2] === 'agent') return true;
  }
  return false;
}

// === Agent Reputation System ===

export interface RepoScanRecord {
  repoUrl: string;
  verdict: string;
  score: number;
  scannedAt: number;
}

export interface AgentReputation {
  pubkey: string;
  displayName?: string;
  repoScans: RepoScanRecord[];  // capped at 100 most recent
  safeRepos: number;            // verdict SAFE or score >= 70
  riskyRepos: number;           // verdict RISKY or score 35-69
  scamRepos: number;            // verdict SCAM or score < 35
  totalScans: number;
  reputationScore: number;      // 0-100
  lastUpdated: number;
}

/**
 * Calculate reputation score from scan history
 * Formula:
 * - Base: 50
 * - +3 per safe repo (max +30)
 * - -5 per risky repo
 * - -15 per scam repo
 * - Clamped to [0, 100]
 */
export function calculateReputationScore(rep: AgentReputation): number {
  let score = 50;
  score += Math.min(30, rep.safeRepos * 3);
  score -= rep.riskyRepos * 5;
  score -= rep.scamRepos * 15;
  return Math.max(0, Math.min(100, score));
}
