/**
 * Feed Guardian / Monitor
 *
 * Watches the broader Moltbook feed for:
 *  1. Posts containing GitHub URLs in ANY submolt (proactive scanning)
 *  2. Agents repeatedly sharing suspicious repos
 *  3. Coordinated promotion patterns (same repo across multiple submolts)
 *  4. Agents with high-risk behavioral signals
 *
 * Feeds data into the AI Jail scorer for agent trust evaluation.
 */

import { MoltbookClient } from './client.js';
import type { MoltbookPost, MoltbookAgentConfig } from './types.js';
import { getAuthorName, getSubmoltName } from './types.js';

const GITHUB_URL_REGEX = /https?:\/\/github\.com\/([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+)/gi;

// How many times a repo must appear across different submolts to flag coordination
const CROSS_POST_THRESHOLD = 3;

// Time window for detecting coordination (ms)
const COORDINATION_WINDOW_MS = 2 * 60 * 60 * 1000; // 2 hours

export interface AgentActivity {
  agentName: string;
  reposShared: Map<string, { count: number; submolts: Set<string>; firstSeen: number }>;
  totalPosts: number;
  flaggedRepos: number;
  lastSeen: number;
}

export interface RepoPromotion {
  repoUrl: string;
  promoters: Map<string, { submolts: string[]; timestamps: number[] }>;
  firstSeen: number;
  crossPostCount: number;
}

export interface MonitorAlert {
  type: 'cross_promotion' | 'suspicious_agent' | 'new_repo_detected';
  severity: 'low' | 'medium' | 'high';
  repoUrl?: string;
  agentName?: string;
  details: string;
  timestamp: number;
}

export class FeedMonitor {
  private client: MoltbookClient;
  private config: MoltbookAgentConfig;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  // Tracking state
  private agentActivity: Map<string, AgentActivity> = new Map();
  private repoPromotions: Map<string, RepoPromotion> = new Map();
  private processedPosts: Set<string> = new Set();
  private alerts: MonitorAlert[] = [];
  private onAlert?: (alert: MonitorAlert) => void;

  // Repos we've already scanned (avoid re-triggering)
  private scannedRepos: Set<string> = new Set();
  private onScanRequest?: (repoUrl: string, context: string, postId: string) => void;

  constructor(
    client: MoltbookClient,
    config: MoltbookAgentConfig,
    callbacks?: {
      onAlert?: (alert: MonitorAlert) => void;
      onScanRequest?: (repoUrl: string, context: string, postId: string) => void;
    }
  ) {
    this.client = client;
    this.config = config;
    this.onAlert = callbacks?.onAlert;
    this.onScanRequest = callbacks?.onScanRequest;
  }

  start(): void {
    if (this.pollTimer) return;
    console.log(`[MONITOR] Watching global feed every ${this.config.feedPollIntervalMs / 1000}s`);
    this.pollFeed();
    this.pollTimer = setInterval(() => this.pollFeed(), this.config.feedPollIntervalMs);
  }

  stop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    console.log('[MONITOR] Stopped');
  }

  private async pollFeed(): Promise<void> {
    try {
      const posts = await this.client.getFeed('new', 50);

      for (const post of posts) {
        if (this.processedPosts.has(post.id)) continue;
        this.processedPosts.add(post.id);
        this.processPost(post);
      }

      // Check for coordination patterns
      this.detectCoordination();

      // Prune old data
      this.pruneOldData();
    } catch (err: any) {
      console.error('[MONITOR] Feed poll error:', err.message);
    }
  }

  private processPost(post: MoltbookPost): void {
    const urls = this.extractGitHubUrls(post);
    const authorName = getAuthorName(post);
    const submoltName = getSubmoltName(post);

    // Track agent activity regardless of GitHub URLs
    this.trackAgent(post);

    if (urls.length === 0) return;

    for (const repoUrl of urls) {
      const normalized = this.normalizeRepoUrl(repoUrl);

      // Track repo promotion
      this.trackRepoPromotion(normalized, post);

      // Request scan if this is a new repo we haven't seen
      if (!this.scannedRepos.has(normalized) && this.onScanRequest) {
        this.scannedRepos.add(normalized);
        this.onScanRequest(normalized, `Found in /s/${submoltName} by ${authorName}`, post.id);
        this.emitAlert({
          type: 'new_repo_detected',
          severity: 'low',
          repoUrl: normalized,
          agentName: authorName,
          details: `New repo ${normalized} found in /s/${submoltName} by ${authorName}`,
          timestamp: Date.now(),
        });
      }
    }
  }

  private trackAgent(post: MoltbookPost): void {
    const authorName = getAuthorName(post);
    const submoltName = getSubmoltName(post);

    let activity = this.agentActivity.get(authorName);
    if (!activity) {
      activity = {
        agentName: authorName,
        reposShared: new Map(),
        totalPosts: 0,
        flaggedRepos: 0,
        lastSeen: Date.now(),
      };
      this.agentActivity.set(authorName, activity);
    }

    activity.totalPosts++;
    activity.lastSeen = Date.now();

    const urls = this.extractGitHubUrls(post);
    for (const url of urls) {
      const normalized = this.normalizeRepoUrl(url);
      let repoTrack = activity.reposShared.get(normalized);
      if (!repoTrack) {
        repoTrack = { count: 0, submolts: new Set(), firstSeen: Date.now() };
        activity.reposShared.set(normalized, repoTrack);
      }
      repoTrack.count++;
      repoTrack.submolts.add(submoltName);
    }
  }

  private trackRepoPromotion(repoUrl: string, post: MoltbookPost): void {
    const authorName = getAuthorName(post);
    const submoltName = getSubmoltName(post);

    let promo = this.repoPromotions.get(repoUrl);
    if (!promo) {
      promo = {
        repoUrl,
        promoters: new Map(),
        firstSeen: Date.now(),
        crossPostCount: 0,
      };
      this.repoPromotions.set(repoUrl, promo);
    }

    let promoter = promo.promoters.get(authorName);
    if (!promoter) {
      promoter = { submolts: [], timestamps: [] };
      promo.promoters.set(authorName, promoter);
    }
    promoter.submolts.push(submoltName);
    promoter.timestamps.push(Date.now());

    // Count unique submolts this repo has been posted in
    const allSubmolts = new Set<string>();
    for (const p of promo.promoters.values()) {
      for (const s of p.submolts) allSubmolts.add(s);
    }
    promo.crossPostCount = allSubmolts.size;
  }

  /**
   * Detect coordinated promotion: same repo posted across many submolts
   * within a short time window, possibly by multiple agents
   */
  private detectCoordination(): void {
    const now = Date.now();

    for (const [repoUrl, promo] of this.repoPromotions) {
      if (promo.crossPostCount < CROSS_POST_THRESHOLD) continue;

      // Check if the cross-posting happened within the coordination window
      const recentPromoters: string[] = [];
      for (const [agent, data] of promo.promoters) {
        const recentTimestamps = data.timestamps.filter(t => now - t < COORDINATION_WINDOW_MS);
        if (recentTimestamps.length > 0) {
          recentPromoters.push(agent);
        }
      }

      if (recentPromoters.length >= 2 || promo.crossPostCount >= CROSS_POST_THRESHOLD) {
        this.emitAlert({
          type: 'cross_promotion',
          severity: recentPromoters.length >= 3 ? 'high' : 'medium',
          repoUrl,
          details: `${repoUrl} promoted across ${promo.crossPostCount} submolts by ${recentPromoters.length} agents: ${recentPromoters.join(', ')}`,
          timestamp: now,
        });
      }
    }
  }

  private emitAlert(alert: MonitorAlert): void {
    // Dedupe: don't emit the same alert type+repo+agent within 1 hour
    const key = `${alert.type}:${alert.repoUrl || ''}:${alert.agentName || ''}`;
    const recent = this.alerts.find(
      a => `${a.type}:${a.repoUrl || ''}:${a.agentName || ''}` === key &&
        Date.now() - a.timestamp < 60 * 60 * 1000
    );
    if (recent) return;

    this.alerts.push(alert);
    console.log(`[MONITOR] ALERT [${alert.severity}] ${alert.type}: ${alert.details}`);
    if (this.onAlert) this.onAlert(alert);
  }

  private pruneOldData(): void {
    const now = Date.now();
    const maxAge = 24 * 60 * 60 * 1000; // 24 hours

    // Prune old agent activity
    for (const [name, activity] of this.agentActivity) {
      if (now - activity.lastSeen > maxAge) {
        this.agentActivity.delete(name);
      }
    }

    // Prune old repo promotions
    for (const [url, promo] of this.repoPromotions) {
      if (now - promo.firstSeen > maxAge) {
        this.repoPromotions.delete(url);
      }
    }

    // Prune old alerts (keep last 100)
    if (this.alerts.length > 100) {
      this.alerts = this.alerts.slice(-100);
    }

    // Cap processedPosts (keep last 5000)
    if (this.processedPosts.size > 5000) {
      const arr = [...this.processedPosts];
      this.processedPosts = new Set(arr.slice(-3000));
    }
  }

  // === Public getters for health/debug ===

  getStats(): {
    trackedAgents: number;
    trackedRepos: number;
    alertCount: number;
    processedPosts: number;
  } {
    return {
      trackedAgents: this.agentActivity.size,
      trackedRepos: this.repoPromotions.size,
      alertCount: this.alerts.length,
      processedPosts: this.processedPosts.size,
    };
  }

  getRecentAlerts(limit: number = 10): MonitorAlert[] {
    return this.alerts.slice(-limit);
  }

  getAgentActivity(agentName: string): AgentActivity | null {
    return this.agentActivity.get(agentName) || null;
  }

  getRepoPromotion(repoUrl: string): RepoPromotion | null {
    return this.repoPromotions.get(this.normalizeRepoUrl(repoUrl)) || null;
  }

  private extractGitHubUrls(post: MoltbookPost): string[] {
    const text = [post.title, post.content || '', post.url || ''].join(' ');
    const matches = text.matchAll(GITHUB_URL_REGEX);
    const urls = new Set<string>();
    for (const match of matches) {
      urls.add(`https://github.com/${match[1]}`);
    }
    return [...urls];
  }

  private normalizeRepoUrl(url: string): string {
    return url.toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
  }
}
