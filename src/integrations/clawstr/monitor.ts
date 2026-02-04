/**
 * Clawstr Feed Monitor
 *
 * Subscribes to Clawstr subclaws and detects:
 * - GitHub URLs for scanning
 * - Mentions of @AuraSecurity
 * - Suspicious patterns
 */

import { ClawstrClient, type NostrFilter } from './client.js';
import type { NostrEvent, ClawstrAgentConfig, ClawstrPost } from './types.js';
import { extractGitHubUrls, getSubclawFromTags, isAIAgentPost, EVENT_KINDS } from './types.js';

export interface ScanRequest {
  repoUrl: string;
  postId: string;
  authorPubkey: string;
  authorName?: string;
  subclaw: string;
  context: string;
}

export interface MentionRequest {
  postId: string;
  authorPubkey: string;
  authorName?: string;
  repoUrl: string | null;
  content: string;
}

export class ClawstrMonitor {
  private client: ClawstrClient;
  private config: ClawstrAgentConfig;
  private subscriptionId: string | null = null;

  // Tracking
  private processedEvents: Set<string> = new Set();
  private scannedRepos: Set<string> = new Set();

  // Callbacks
  private onScanRequest?: (request: ScanRequest) => void;
  private onMentionRequest?: (request: MentionRequest) => void;

  // Rate limiting
  private lastScanTime: number = 0;
  private scansThisHour: number = 0;
  private hourStart: number = Date.now();

  constructor(
    client: ClawstrClient,
    config: ClawstrAgentConfig,
    callbacks?: {
      onScanRequest?: (request: ScanRequest) => void;
      onMentionRequest?: (request: MentionRequest) => void;
    }
  ) {
    this.client = client;
    this.config = config;
    this.onScanRequest = callbacks?.onScanRequest;
    this.onMentionRequest = callbacks?.onMentionRequest;
  }

  /**
   * Start monitoring subclaws
   */
  start(): void {
    if (this.subscriptionId) {
      console.log('[CLAWSTR-MONITOR] Already running');
      return;
    }

    console.log(`[CLAWSTR-MONITOR] Starting monitor for subclaws: ${this.config.subclaws.join(', ')}`);

    // Build filters for each subclaw
    const filters: NostrFilter[] = [];

    // Filter for comments in our subclaws (kind 1111)
    for (const subclaw of this.config.subclaws) {
      const webId = `https://clawstr.com${subclaw}`;
      filters.push({
        kinds: [EVENT_KINDS.COMMENT],
        '#I': [webId],
        since: Math.floor(Date.now() / 1000) - 3600, // Last hour
        limit: 50,
      });
      filters.push({
        kinds: [EVENT_KINDS.COMMENT],
        '#i': [webId],
        since: Math.floor(Date.now() / 1000) - 3600,
        limit: 50,
      });
    }

    // Also subscribe to mentions (posts containing "AuraSecurity" or tagging our pubkey)
    if (this.client.getPublicKey()) {
      filters.push({
        kinds: [EVENT_KINDS.COMMENT, EVENT_KINDS.TEXT_NOTE],
        '#p': [this.client.getPublicKey()],
        since: Math.floor(Date.now() / 1000) - 3600,
        limit: 20,
      });
    }

    // Subscribe
    this.subscriptionId = this.client.subscribe(
      filters,
      (event, relay) => this.handleEvent(event, relay),
      (relay, subId) => {
        console.log(`[CLAWSTR-MONITOR] EOSE from ${relay}`);
      }
    );

    console.log(`[CLAWSTR-MONITOR] Subscribed with ID: ${this.subscriptionId}`);
  }

  /**
   * Stop monitoring
   */
  stop(): void {
    if (this.subscriptionId) {
      this.client.unsubscribe(this.subscriptionId);
      this.subscriptionId = null;
      console.log('[CLAWSTR-MONITOR] Stopped');
    }
  }

  /**
   * Handle incoming event
   */
  private handleEvent(event: NostrEvent, relay: string): void {
    // Skip if already processed
    if (this.processedEvents.has(event.id)) {
      return;
    }
    this.processedEvents.add(event.id);

    // Prune old processed events (keep last 5000)
    if (this.processedEvents.size > 5000) {
      const entries = Array.from(this.processedEvents);
      entries.slice(0, 2500).forEach(id => this.processedEvents.delete(id));
    }

    // Skip our own posts
    if (event.pubkey === this.client.getPublicKey()) {
      return;
    }

    // Check for mentions first
    if (this.isMention(event)) {
      this.handleMention(event);
      return;
    }

    // Check for GitHub URLs
    const githubUrls = extractGitHubUrls(event.content);
    if (githubUrls.length > 0 && this.config.autoScan) {
      this.handleGitHubUrls(event, githubUrls);
    }
  }

  /**
   * Check if event mentions us
   */
  private isMention(event: NostrEvent): boolean {
    // Check p tags
    for (const tag of event.tags) {
      if (tag[0] === 'p' && tag[1] === this.client.getPublicKey()) {
        return true;
      }
    }

    // Check content for "AuraSecurity" (case insensitive)
    if (event.content.toLowerCase().includes('aurasecurity')) {
      return true;
    }

    return false;
  }

  /**
   * Handle mention
   */
  private handleMention(event: NostrEvent): void {
    if (!this.config.replyToMentions || !this.onMentionRequest) {
      return;
    }

    console.log(`[CLAWSTR-MONITOR] Mention detected from ${event.pubkey.slice(0, 8)}`);

    // Extract GitHub URL if present
    const githubUrls = extractGitHubUrls(event.content);
    const repoUrl = githubUrls.length > 0 ? githubUrls[0] : null;

    this.onMentionRequest({
      postId: event.id,
      authorPubkey: event.pubkey,
      repoUrl,
      content: event.content,
    });
  }

  /**
   * Handle GitHub URLs found in post
   */
  private handleGitHubUrls(event: NostrEvent, urls: string[]): void {
    if (!this.onScanRequest) {
      return;
    }

    // Rate limiting
    if (!this.checkRateLimit()) {
      console.log('[CLAWSTR-MONITOR] Rate limit reached, skipping scan');
      return;
    }

    const subclaw = getSubclawFromTags(event.tags) || 'unknown';

    for (const repoUrl of urls) {
      // Skip if already scanned recently
      if (this.scannedRepos.has(repoUrl)) {
        continue;
      }
      this.scannedRepos.add(repoUrl);

      // Prune old scanned repos (keep last 1000)
      if (this.scannedRepos.size > 1000) {
        const entries = Array.from(this.scannedRepos);
        entries.slice(0, 500).forEach(url => this.scannedRepos.delete(url));
      }

      console.log(`[CLAWSTR-MONITOR] GitHub URL detected: ${repoUrl} in ${subclaw}`);

      this.onScanRequest({
        repoUrl,
        postId: event.id,
        authorPubkey: event.pubkey,
        subclaw,
        context: `Posted in ${subclaw}`,
      });

      // Only scan first URL per post
      break;
    }
  }

  /**
   * Check and update rate limit
   */
  private checkRateLimit(): boolean {
    const now = Date.now();

    // Reset hourly counter
    if (now - this.hourStart > 3600_000) {
      this.hourStart = now;
      this.scansThisHour = 0;
    }

    // Check hourly limit
    if (this.scansThisHour >= this.config.maxScansPerHour) {
      return false;
    }

    // Check minimum time between scans
    if (now - this.lastScanTime < this.config.minSecondsBetweenPosts * 1000) {
      return false;
    }

    this.scansThisHour++;
    this.lastScanTime = now;
    return true;
  }

  /**
   * Mark a repo as scanned (to avoid re-scanning)
   */
  markScanned(repoUrl: string): void {
    this.scannedRepos.add(repoUrl);
  }

  /**
   * Get monitoring status
   */
  getStatus(): {
    isRunning: boolean;
    processedCount: number;
    scannedReposCount: number;
    scansThisHour: number;
  } {
    return {
      isRunning: this.subscriptionId !== null,
      processedCount: this.processedEvents.size,
      scannedReposCount: this.scannedRepos.size,
      scansThisHour: this.scansThisHour,
    };
  }
}
