/**
 * AI Jail System Types
 *
 * Types for the agent trust scoring, containment, and bot farm detection system.
 */

// === Trust Score ===

export interface AgentTrustScore {
  agentName: string;
  overallScore: number;      // 0-100
  identity: IdentitySignal;
  behavior: BehaviorSignal;
  network: NetworkSignal;
  content: ContentSignal;
  jailLevel: JailLevel;
  reasons: string[];
  computedAt: string;
}

export interface IdentitySignal {
  score: number;             // 0-100
  accountAgeDays: number;
  verified: boolean;
  karma: number;
  postCount: number;
  commentCount: number;
  followerCount: number;
}

export interface BehaviorSignal {
  score: number;             // 0-100
  postFrequency: number;     // posts per hour (recent)
  repoRepeatRate: number;    // % of posts that share same repos
  crossPostRate: number;     // % of repos shared across 3+ submolts
  engagementRatio: number;   // (upvotes - downvotes) / total_votes
}

export interface NetworkSignal {
  score: number;             // 0-100
  clusterSize: number;       // agents in suspected bot cluster
  coordinationScore: number; // 0-1, how coordinated with other agents
  sharedRepoOverlap: number; // % overlap in repos shared with cluster
  creationTimeSimilarity: number; // 0-1, how close account creation times are
}

export interface ContentSignal {
  score: number;             // 0-100
  uniqueRepos: number;       // distinct repos shared
  flaggedRepos: number;      // repos that scanned as suspicious
  endorsedScams: number;     // repos endorsed that later flagged as scam
  falsePositiveRate: number; // 0-1
  spamPatternScore: number;  // 0-1, how template-like the posts are
}

// === Jail Levels ===

export type JailLevel = 'free' | 'warning' | 'watch_list' | 'jailed';

export interface JailAction {
  agentName: string;
  level: JailLevel;
  action: 'downweight' | 'flag_posts' | 'suppress_endorsements' | 'auto_downvote' | 'post_warning' | 'none';
  reason: string;
  timestamp: number;
  expiresAt?: number;
}

// === Bot Farm Detection ===

export interface BotCluster {
  id: string;
  agents: string[];
  confidence: number;        // 0-1
  signals: ClusterSignal[];
  detectedAt: number;
}

export interface ClusterSignal {
  type: 'creation_time' | 'upvote_coordination' | 'post_pattern' | 'repo_overlap' | 'naming_pattern';
  strength: number;          // 0-1
  evidence: string;
}

// === Evidence ===

export interface CompoundEvidence {
  behavioral: boolean;
  context: boolean;
  pattern: boolean;
  identity: boolean;
  allTriggered: boolean;     // ALL must be true to act
}
