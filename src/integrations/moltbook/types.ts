/**
 * Moltbook Integration Types
 */

// === API Response Types ===

export interface MoltbookAgent {
  name: string;
  display_name?: string;
  description?: string;
  karma: number;
  post_count: number;
  comment_count: number;
  verified: boolean;
  follower_count: number;
  following_count: number;
  owner?: string;
  created_at: string;
}

export interface MoltbookPost {
  id: string;
  title: string;
  content?: string;
  url?: string;
  submolt: string;
  author: string;
  upvotes: number;
  downvotes: number;
  comment_count: number;
  created_at: string;
}

export interface MoltbookComment {
  id: string;
  post_id: string;
  content: string;
  author: string;
  parent_id?: string;
  upvotes: number;
  created_at: string;
}

export interface MoltbookSubmolt {
  id: string;
  name: string;
  display_name: string;
  description: string;
  subscriber_count: number;
  created_at: string;
}

export interface MoltbookRegisterResponse {
  api_key: string;
  claim_url: string;
  verification_code: string;
  agent: MoltbookAgent;
}

export interface MoltbookFeedResponse {
  success: boolean;
  posts: MoltbookPost[];
}

export interface MoltbookSubmoltsResponse {
  success: boolean;
  submolts: MoltbookSubmolt[];
}

// === Scan Cache ===

export interface ScanCacheEntry {
  repo_url: string;
  scam_result: any;
  trust_result: any;
  scanned_at: string;
  posted: boolean;
  post_id?: string;
}

// === Confidence Gate ===

export interface PostDecision {
  shouldPost: boolean;
  confidence: 'high' | 'medium' | 'low';
  postType: 'warning' | 'report' | 'endorsement' | 'skip';
  caveats: string[];
  suppressedFlags: string[];
}

// === Agent Config ===

export interface MoltbookAgentConfig {
  apiKey?: string;
  agentName: string;
  scannerApiUrl: string;
  submoltName: string;
  pollIntervalMs: number;
  feedPollIntervalMs: number;
  scanCacheTtlMs: number;
}

export const DEFAULT_CONFIG: MoltbookAgentConfig = {
  agentName: 'AuraSecurity',
  scannerApiUrl: 'http://127.0.0.1:3000',
  submoltName: 'security-audits',
  pollIntervalMs: 30_000,       // 30 seconds
  feedPollIntervalMs: 60_000,   // 60 seconds
  scanCacheTtlMs: 6 * 60 * 60 * 1000, // 6 hours
};
