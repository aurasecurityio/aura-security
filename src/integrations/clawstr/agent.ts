/**
 * Clawstr Agent
 *
 * Main bot that monitors Clawstr subclaws for GitHub URLs,
 * runs security scans, and posts results as comments.
 *
 * Shares reputation database with Moltbook integration.
 */

import { ClawstrClient } from './client.js';
import { ClawstrMonitor, type ScanRequest, type MentionRequest } from './monitor.js';
import {
  formatScanResult,
  formatBriefScanResult,
  formatScanError,
  formatMentionResponse,
  formatMentionNoUrl,
  formatWeeklyLeaderboard,
  formatShillWarning,
  makePostDecision,
  type ScanResultData,
} from './formatter.js';
import type { ClawstrAgentConfig, AgentReputation, RepoScanRecord } from './types.js';
import { DEFAULT_CONFIG, calculateReputationScore } from './types.js';

// Import shared scanners (same as Moltbook) - using functions, not classes
import { performEnhancedTrustScan, type EnhancedTrustResult } from '../enhanced-scanner.js';
import type { ScamDetectionResult } from '../scam-detector.js';

export interface ClawstrAgentStatus {
  enabled: boolean;
  connected: boolean;
  publicKey: string;
  connectedRelays: string[];
  monitorStatus: {
    isRunning: boolean;
    processedCount: number;
    scannedReposCount: number;
    scansThisHour: number;
  };
  stats: {
    totalScans: number;
    postsCreated: number;
    repliesCreated: number;
    errorsCount: number;
  };
  reputation: {
    trackedAgents: number;
    totalRepoScans: number;
    shillWarningQueue: number;
    lastLeaderboardPost: string | null;
  };
}

export class ClawstrAgent {
  private client: ClawstrClient;
  private monitor: ClawstrMonitor;
  private config: ClawstrAgentConfig;

  // Stats
  private stats = {
    totalScans: 0,
    postsCreated: 0,
    repliesCreated: 0,
    errorsCount: 0,
  };

  // Track posts we've commented on (for threading)
  private commentedPosts: Map<string, string> = new Map(); // repoUrl -> postId

  // Agent reputation tracking
  private agentReputations: Map<string, AgentReputation> = new Map();
  private shillWarningQueue: Set<string> = new Set(); // pubkeys pending warning
  private lastLeaderboardPost: number = 0;
  private leaderboardTimer?: ReturnType<typeof setInterval>;

  constructor(config?: Partial<ClawstrAgentConfig>) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Initialize client
    this.client = new ClawstrClient(this.config);

    // Initialize monitor with callbacks
    this.monitor = new ClawstrMonitor(this.client, this.config, {
      onScanRequest: (request) => this.handleScanRequest(request),
      onMentionRequest: (request) => this.handleMentionRequest(request),
    });

    console.log('[CLAWSTR-AGENT] Initialized');
  }

  /**
   * Start the agent
   */
  async start(): Promise<void> {
    if (!this.config.enabled) {
      console.log('[CLAWSTR-AGENT] Disabled in config, not starting');
      return;
    }

    if (!this.config.privateKey) {
      console.error('[CLAWSTR-AGENT] No private key configured');
      return;
    }

    console.log('[CLAWSTR-AGENT] Starting...');

    try {
      // Connect to relays
      await this.client.connect();

      if (!this.client.isConnected()) {
        console.error('[CLAWSTR-AGENT] Failed to connect to any relays');
        return;
      }

      // Start monitoring
      this.monitor.start();

      // Start weekly leaderboard timer (check every 6 hours)
      this.leaderboardTimer = setInterval(() => {
        this.checkWeeklyLeaderboard();
      }, 6 * 60 * 60 * 1000);

      console.log('[CLAWSTR-AGENT] Started successfully');
      console.log(`[CLAWSTR-AGENT] Monitoring subclaws: ${this.config.subclaws.join(', ')}`);
    } catch (error: any) {
      console.error('[CLAWSTR-AGENT] Failed to start:', error.message);
    }
  }

  /**
   * Stop the agent
   */
  stop(): void {
    console.log('[CLAWSTR-AGENT] Stopping...');
    this.monitor.stop();
    this.client.disconnect();
    if (this.leaderboardTimer) {
      clearInterval(this.leaderboardTimer);
      this.leaderboardTimer = undefined;
    }
    console.log('[CLAWSTR-AGENT] Stopped');
  }

  /**
   * Handle scan request from monitor (GitHub URL detected)
   */
  private async handleScanRequest(request: ScanRequest): Promise<void> {
    console.log(`[CLAWSTR-AGENT] Scan requested: ${request.repoUrl} from ${request.subclaw}`);

    try {
      // Parse repo URL
      const match = request.repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/i);
      if (!match) {
        console.log(`[CLAWSTR-AGENT] Invalid GitHub URL: ${request.repoUrl}`);
        return;
      }

      const [, owner, repoName] = match;
      const cleanRepoName = repoName.replace(/\.git$/, '');

      // Run scans
      const { trustResult, scamResult } = await this.runScans(owner, cleanRepoName);

      // Make decision
      const decision = makePostDecision(trustResult, scamResult);

      if (!decision.shouldPost) {
        console.log(`[CLAWSTR-AGENT] Not posting (${decision.reason})`);
        return;
      }

      // Format result
      const scanData: ScanResultData = {
        repoUrl: request.repoUrl,
        repoName: cleanRepoName,
        owner,
        trustResult,
        scamResult,
      };

      const content = formatScanResult(scanData, decision);

      // Post as reply to the original post
      const eventId = await this.client.replyToPost(
        request.postId,
        request.authorPubkey,
        content
      );

      // Track that we commented on this post
      this.commentedPosts.set(request.repoUrl, request.postId);

      // Prune old tracked posts
      if (this.commentedPosts.size > 500) {
        const entries = Array.from(this.commentedPosts.entries());
        entries.slice(0, 250).forEach(([url]) => this.commentedPosts.delete(url));
      }

      // Record for reputation tracking
      const score = trustResult?.trustScore ?? 50;
      this.recordScanForReputation(
        request.authorPubkey,
        request.repoUrl,
        decision.verdict,
        score,
        request.authorName
      );

      // Check for shill warning
      await this.checkShillWarning(request.authorPubkey, request.postId);

      this.stats.totalScans++;
      this.stats.repliesCreated++;

      console.log(`[CLAWSTR-AGENT] Posted scan result: ${eventId.slice(0, 8)} (${decision.verdict})`);

    } catch (error: any) {
      console.error(`[CLAWSTR-AGENT] Scan failed for ${request.repoUrl}:`, error.message);
      this.stats.errorsCount++;

      // Optionally post error message
      try {
        const errorContent = formatScanError(request.repoUrl, error.message);
        await this.client.replyToPost(request.postId, request.authorPubkey, errorContent);
      } catch {
        // Ignore error posting failure
      }
    }
  }

  /**
   * Handle mention request (someone tagged @AuraSecurity)
   */
  private async handleMentionRequest(request: MentionRequest): Promise<void> {
    console.log(`[CLAWSTR-AGENT] Mention from ${request.authorPubkey.slice(0, 8)}`);

    try {
      // If no repo URL, ask for one
      if (!request.repoUrl) {
        const content = formatMentionNoUrl(request.authorName || request.authorPubkey.slice(0, 8));
        await this.client.replyToPost(request.postId, request.authorPubkey, content);
        this.stats.repliesCreated++;
        return;
      }

      // Parse repo URL
      const match = request.repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/i);
      if (!match) {
        const content = `@${request.authorName || request.authorPubkey.slice(0, 8)} That doesn't look like a valid GitHub repo URL. Try something like: github.com/owner/repo`;
        await this.client.replyToPost(request.postId, request.authorPubkey, content);
        return;
      }

      const [, owner, repoName] = match;
      const cleanRepoName = repoName.replace(/\.git$/, '');

      // Run scans
      const { trustResult, scamResult } = await this.runScans(owner, cleanRepoName);

      // Make decision
      const decision = makePostDecision(trustResult, scamResult);

      // Format mention response
      const scanData: ScanResultData = {
        repoUrl: request.repoUrl,
        repoName: cleanRepoName,
        owner,
        trustResult,
        scamResult,
      };

      const content = formatMentionResponse(
        request.authorName || request.authorPubkey.slice(0, 8),
        scanData,
        decision
      );

      await this.client.replyToPost(request.postId, request.authorPubkey, content);

      // Record for reputation tracking
      const score = trustResult?.trustScore ?? 50;
      this.recordScanForReputation(
        request.authorPubkey,
        request.repoUrl,
        decision.verdict,
        score,
        request.authorName
      );

      this.stats.totalScans++;
      this.stats.repliesCreated++;

      console.log(`[CLAWSTR-AGENT] Replied to mention: ${decision.verdict}`);

    } catch (error: any) {
      console.error(`[CLAWSTR-AGENT] Mention handling failed:`, error.message);
      this.stats.errorsCount++;
    }
  }

  /**
   * Run trust scan on a repo
   * Note: Scam detection requires fetched file data, so we rely on
   * the enhanced trust scanner which includes rug database checks
   */
  private async runScans(
    owner: string,
    repo: string
  ): Promise<{ trustResult?: EnhancedTrustResult; scamResult?: ScamDetectionResult }> {
    let trustResult: EnhancedTrustResult | undefined;
    // ScamDetectionResult requires file content - trust scanner is sufficient for now
    const scamResult: ScamDetectionResult | undefined = undefined;

    const gitUrl = `https://github.com/${owner}/${repo}`;

    try {
      trustResult = await performEnhancedTrustScan(gitUrl);
    } catch (error: any) {
      console.error(`[CLAWSTR-AGENT] Trust scan failed:`, error.message);
    }

    return { trustResult, scamResult };
  }

  /**
   * Manually post to a subclaw (for testing or announcements)
   */
  async postToSubclaw(subclaw: string, content: string): Promise<string> {
    const eventId = await this.client.postToSubclaw(subclaw, content);
    this.stats.postsCreated++;
    return eventId;
  }

  /**
   * Manually scan and post result for a repo
   */
  async scanAndPost(repoUrl: string, subclaw: string): Promise<string | null> {
    const match = repoUrl.match(/github\.com\/([^/]+)\/([^/]+)/i);
    if (!match) {
      throw new Error('Invalid GitHub URL');
    }

    const [, owner, repoName] = match;
    const cleanRepoName = repoName.replace(/\.git$/, '');

    // Run scans
    const { trustResult, scamResult } = await this.runScans(owner, cleanRepoName);

    // Make decision
    const decision = makePostDecision(trustResult, scamResult);

    // Format result
    const scanData: ScanResultData = {
      repoUrl,
      repoName: cleanRepoName,
      owner,
      trustResult,
      scamResult,
    };

    const content = formatScanResult(scanData, decision);

    // Post to subclaw
    const eventId = await this.client.postToSubclaw(subclaw, content);

    this.stats.totalScans++;
    this.stats.postsCreated++;

    return eventId;
  }

  /**
   * Get agent status
   */
  getStatus(): ClawstrAgentStatus {
    const reputations = Array.from(this.agentReputations.values());
    const totalRepoScans = reputations.reduce((sum, r) => sum + r.totalScans, 0);

    return {
      enabled: this.config.enabled,
      connected: this.client.isConnected(),
      publicKey: this.client.getPublicKey(),
      connectedRelays: this.client.getConnectedRelays(),
      monitorStatus: this.monitor.getStatus(),
      stats: { ...this.stats },
      reputation: {
        trackedAgents: this.agentReputations.size,
        totalRepoScans,
        shillWarningQueue: this.shillWarningQueue.size,
        lastLeaderboardPost: this.lastLeaderboardPost ? new Date(this.lastLeaderboardPost).toISOString() : null,
      },
    };
  }

  /**
   * Get the Nostr client (for advanced usage)
   */
  getClient(): ClawstrClient {
    return this.client;
  }

  // === Agent Reputation System ===

  /**
   * Record a scan result for reputation tracking
   */
  private recordScanForReputation(
    pubkey: string,
    repoUrl: string,
    verdict: string,
    score: number,
    displayName?: string
  ): void {
    let rep = this.agentReputations.get(pubkey);

    if (!rep) {
      rep = {
        pubkey,
        displayName,
        repoScans: [],
        safeRepos: 0,
        riskyRepos: 0,
        scamRepos: 0,
        totalScans: 0,
        reputationScore: 50,
        lastUpdated: Date.now(),
      };
      this.agentReputations.set(pubkey, rep);
    }

    // Update display name if provided
    if (displayName) {
      rep.displayName = displayName;
    }

    // Add scan record
    const record: RepoScanRecord = {
      repoUrl,
      verdict,
      score,
      scannedAt: Date.now(),
    };

    rep.repoScans.push(record);

    // Cap at 100 records
    if (rep.repoScans.length > 100) {
      rep.repoScans = rep.repoScans.slice(-100);
    }

    // Update counts
    if (verdict === 'SAFE' || score >= 70) {
      rep.safeRepos++;
    } else if (verdict === 'SCAM' || score < 35) {
      rep.scamRepos++;
    } else {
      rep.riskyRepos++;
    }

    rep.totalScans++;
    rep.lastUpdated = Date.now();

    // Recalculate reputation score
    rep.reputationScore = calculateReputationScore(rep);

    // Check for shill warning threshold
    if (rep.scamRepos >= 3 && rep.reputationScore < 30) {
      this.shillWarningQueue.add(pubkey);
      console.log(`[CLAWSTR-AGENT] Added ${pubkey.slice(0, 8)} to shill warning queue`);
    }

    console.log(`[CLAWSTR-AGENT] Reputation updated for ${pubkey.slice(0, 8)}: score=${rep.reputationScore}, safe=${rep.safeRepos}, risky=${rep.riskyRepos}, scam=${rep.scamRepos}`);
  }

  /**
   * Check if weekly leaderboard should be posted
   */
  private async checkWeeklyLeaderboard(): Promise<void> {
    const now = Date.now();
    const oneWeek = 7 * 24 * 60 * 60 * 1000;

    // Check if a week has passed since last post
    if (now - this.lastLeaderboardPost < oneWeek) {
      return;
    }

    // Need at least 5 agents with scans to post
    if (this.agentReputations.size < 5) {
      console.log('[CLAWSTR-AGENT] Not enough agents for leaderboard yet');
      return;
    }

    await this.postLeaderboard();
  }

  /**
   * Post the weekly leaderboard
   */
  async postLeaderboard(): Promise<string | null> {
    try {
      const reputations = Array.from(this.agentReputations.values());
      const totalScans = reputations.reduce((sum, r) => sum + r.totalScans, 0);

      const content = formatWeeklyLeaderboard(reputations, totalScans);

      // Post to /c/builds
      const eventId = await this.client.postToSubclaw('/c/builds', content);

      this.lastLeaderboardPost = Date.now();
      this.stats.postsCreated++;

      console.log(`[CLAWSTR-AGENT] Posted weekly leaderboard: ${eventId.slice(0, 8)}`);

      return eventId;
    } catch (error: any) {
      console.error('[CLAWSTR-AGENT] Failed to post leaderboard:', error.message);
      return null;
    }
  }

  /**
   * Get agent reputation by pubkey
   */
  getAgentReputation(pubkey: string): AgentReputation | null {
    return this.agentReputations.get(pubkey) || null;
  }

  /**
   * Get all reputations (for external access)
   */
  getAllReputations(): AgentReputation[] {
    return Array.from(this.agentReputations.values());
  }

  /**
   * Post shill warning if agent is in queue
   */
  private async checkShillWarning(pubkey: string, postId: string): Promise<void> {
    if (!this.shillWarningQueue.has(pubkey)) {
      return;
    }

    const rep = this.agentReputations.get(pubkey);
    if (!rep) return;

    try {
      const warning = formatShillWarning(rep);
      await this.client.replyToPost(postId, pubkey, warning);

      // Remove from queue (only warn once)
      this.shillWarningQueue.delete(pubkey);
      this.stats.repliesCreated++;

      console.log(`[CLAWSTR-AGENT] Posted shill warning for ${pubkey.slice(0, 8)}`);
    } catch (error: any) {
      console.error('[CLAWSTR-AGENT] Failed to post shill warning:', error.message);
    }
  }
}
