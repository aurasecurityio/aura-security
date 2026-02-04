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
  makePostDecision,
  type ScanResultData,
} from './formatter.js';
import type { ClawstrAgentConfig } from './types.js';
import { DEFAULT_CONFIG } from './types.js';

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
    return {
      enabled: this.config.enabled,
      connected: this.client.isConnected(),
      publicKey: this.client.getPublicKey(),
      connectedRelays: this.client.getConnectedRelays(),
      monitorStatus: this.monitor.getStatus(),
      stats: { ...this.stats },
    };
  }

  /**
   * Get the Nostr client (for advanced usage)
   */
  getClient(): ClawstrClient {
    return this.client;
  }
}
