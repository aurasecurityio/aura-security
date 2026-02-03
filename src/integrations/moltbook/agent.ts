/**
 * Moltbook Agent Core
 *
 * Main entry point for the AuraSecurity Moltbook integration.
 * Handles:
 *  - Agent registration / login
 *  - Submolt creation (security-audits)
 *  - On-demand scanning via MoltbookScanner
 *  - Feed monitoring via FeedMonitor
 *  - AI Jail enforcement (scorer + bot farm detection + actions)
 *  - Graceful shutdown
 *
 * Run standalone: npx tsx src/integrations/moltbook/agent.ts
 * Or import and call startMoltbookAgent() from your main process.
 */

import { MoltbookClient } from './client.js';
import { MoltbookScanner } from './scanner.js';
import { FeedMonitor } from './monitor.js';
import type { MonitorAlert } from './monitor.js';
import { AgentScorer } from './jail/scorer.js';
import { BotFarmDetector } from './jail/network.js';
import { JailEnforcer } from './jail/actions.js';
import type { AgentTrustScore } from './jail/types.js';
import type { MoltbookAgentConfig, AgentReputation, RepoScanRecord } from './types.js';
import { DEFAULT_CONFIG } from './types.js';

// How often to run bot farm detection (expensive operation)
const BOT_DETECT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

// How often to check if daily summary should be posted
const DAILY_SUMMARY_CHECK_MS = 60 * 60 * 1000; // 1 hour
const DAILY_SUMMARY_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

// How often to check if weekly leaderboard should be posted
const WEEKLY_CHECK_MS = 6 * 60 * 60 * 1000; // 6 hours
const WEEKLY_INTERVAL_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

// Reputation thresholds
const MAX_REPO_SCANS_PER_AGENT = 100;
const SHILL_SCAM_THRESHOLD = 3;
const SHILL_SCORE_THRESHOLD = 30;

interface DailyStats {
  totalScans: number;
  verdicts: Map<string, number>;
  warningsPosted: number;
  reposScanned: string[];
  startedAt: number;
  lastPostedAt: number;
}

export class MoltbookAgent {
  private client: MoltbookClient;
  private scanner: MoltbookScanner;
  private monitor: FeedMonitor;
  private scorer: AgentScorer;
  private botDetector: BotFarmDetector;
  private enforcer: JailEnforcer;
  private config: MoltbookAgentConfig;
  private running = false;
  private botDetectTimer: ReturnType<typeof setInterval> | null = null;
  private dailySummaryTimer: ReturnType<typeof setInterval> | null = null;
  private weeklyLeaderboardTimer: ReturnType<typeof setInterval> | null = null;
  private lastLeaderboardPostAt: number = Date.now();
  private agentReputations: Map<string, AgentReputation> = new Map();
  private shillWarningQueue: Set<string> = new Set();
  private dailyStats: DailyStats = {
    totalScans: 0,
    verdicts: new Map(),
    warningsPosted: 0,
    reposScanned: [],
    startedAt: Date.now(),
    lastPostedAt: Date.now(),
  };

  constructor(config: Partial<MoltbookAgentConfig> = {}) {
    this.config = { ...DEFAULT_CONFIG, ...config };

    // Allow env var overrides
    if (!this.config.apiKey && process.env.MOLTBOOK_API_KEY) {
      this.config.apiKey = process.env.MOLTBOOK_API_KEY;
    }
    if (process.env.MOLTBOOK_SCANNER_URL) {
      this.config.scannerApiUrl = process.env.MOLTBOOK_SCANNER_URL;
    }
    if (process.env.MOLTBOOK_SUBMOLT) {
      this.config.submoltName = process.env.MOLTBOOK_SUBMOLT;
    }
    if (!this.config.scannerApiKey && process.env.AUTH_MASTER_KEY) {
      this.config.scannerApiKey = process.env.AUTH_MASTER_KEY;
    }

    this.client = new MoltbookClient(this.config.apiKey || '');
    this.scanner = new MoltbookScanner(this.client, this.config);
    this.scorer = new AgentScorer();
    this.botDetector = new BotFarmDetector();
    this.enforcer = new JailEnforcer(this.client);

    // Feed monitor with callbacks
    this.monitor = new FeedMonitor(this.client, this.config, {
      onAlert: (alert) => this.handleAlert(alert),
      onScanRequest: (repoUrl, context, postId) => this.handleProactiveScan(repoUrl, context, postId),
      onMentionScanRequest: (repoUrl, postId, commentId, mentioner) => this.handleMentionScan(repoUrl, postId, commentId, mentioner),
    });
  }

  /**
   * Start the agent: register, ensure submolt exists, begin all services
   */
  async start(): Promise<void> {
    if (this.running) return;
    console.log('[AGENT] Starting AuraSecurity Moltbook agent...');

    // Step 1: Register or verify agent identity (retries in background if Moltbook is down)
    const registered = await this.ensureRegisteredWithRetry();

    // Step 2: Ensure our submolt exists (skip if not yet registered)
    if (registered) await this.ensureSubmolt();

    // Step 3-4: Start scanner + monitor (only if registered, otherwise retry loop starts them)
    if (registered) {
      this.scanner.start();
      this.monitor.start();
    }

    // Step 5: Start periodic bot farm detection
    this.botDetectTimer = setInterval(() => this.runBotDetection(), BOT_DETECT_INTERVAL_MS);

    // Step 6: Start daily summary timer
    this.dailyStats.startedAt = Date.now();
    this.dailyStats.lastPostedAt = Date.now();
    this.dailySummaryTimer = setInterval(() => this.checkDailySummary(), DAILY_SUMMARY_CHECK_MS);

    // Step 7: Start weekly leaderboard timer
    this.weeklyLeaderboardTimer = setInterval(() => this.checkWeeklyLeaderboard(), WEEKLY_CHECK_MS);

    this.running = true;
    if (registered) {
      console.log('[AGENT] AuraSecurity Moltbook agent is running');
      console.log('[AGENT] Services: scanner, monitor, jail, daily-summary, reputation, mentions');
    } else {
      console.log('[AGENT] AuraSecurity server is running (Moltbook reconnecting in background)');
    }
  }

  /**
   * Stop the agent gracefully
   */
  stop(): void {
    if (!this.running) return;
    this.scanner.stop();
    this.monitor.stop();
    if (this.botDetectTimer) {
      clearInterval(this.botDetectTimer);
      this.botDetectTimer = null;
    }
    if (this.dailySummaryTimer) {
      clearInterval(this.dailySummaryTimer);
      this.dailySummaryTimer = null;
    }
    if (this.weeklyLeaderboardTimer) {
      clearInterval(this.weeklyLeaderboardTimer);
      this.weeklyLeaderboardTimer = null;
    }
    this.running = false;
    console.log('[AGENT] AuraSecurity Moltbook agent stopped');
  }

  // === Alert & Scan Handlers ===

  private handleAlert(alert: MonitorAlert): void {
    // When the monitor flags something, check if we should score the agent
    if (alert.agentName && (alert.severity === 'medium' || alert.severity === 'high')) {
      this.scoreAgent(alert.agentName).catch(err => {
        console.error(`[AGENT] Failed to score agent ${alert.agentName}:`, err.message);
      });
    }
  }

  private handleProactiveScan(repoUrl: string, context: string, postId: string): void {
    console.log(`[AGENT] Proactive scan requested: ${repoUrl} (${context}) [post: ${postId}]`);
    // Trigger a scan via the local scanner API, comment on original post, and post to our submolt
    this.runProactiveScan(repoUrl, context, postId).catch(err => {
      console.error(`[AGENT] Proactive scan failed for ${repoUrl}:`, err.message);
    });
  }

  private async runProactiveScan(repoUrl: string, context: string, postId: string): Promise<void> {
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 240_000);

      const scanHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
      if (this.config.scannerApiKey) {
        scanHeaders['Authorization'] = `Bearer ${this.config.scannerApiKey}`;
      }

      const [trustRes, scamRes] = await Promise.allSettled([
        fetch(`${this.config.scannerApiUrl}/tools`, {
          method: 'POST',
          headers: scanHeaders,
          body: JSON.stringify({ tool: 'trust-scan', arguments: { gitUrl: repoUrl } }),
          signal: controller.signal,
        }).then(r => r.ok ? r.json() : null).then((d: any) => d?.result || d),
        fetch(`${this.config.scannerApiUrl}/tools`, {
          method: 'POST',
          headers: scanHeaders,
          body: JSON.stringify({ tool: 'scam-scan', arguments: { gitUrl: repoUrl } }),
          signal: controller.signal,
        }).then(r => r.ok ? r.json() : null).then((d: any) => d?.result || d),
      ]);

      clearTimeout(timeout);

      const trust = trustRes.status === 'fulfilled' ? trustRes.value : null;
      const scam = scamRes.status === 'fulfilled' ? scamRes.value : null;

      if (!trust && !scam) {
        console.log(`[AGENT] Proactive scan: both scanners failed for ${repoUrl}`);
        return;
      }

      const { makePostDecision } = await import('./confidence.js');
      const { formatScanResult, formatPostTitle } = await import('./formatter.js');
      const decision = makePostDecision(scam, trust);
      const verdict = scam?.verdict ?? trust?.verdict ?? 'SCANNED';

      // Record daily stats regardless of whether we post
      this.recordDailyScan(repoUrl, verdict, decision.postType === 'warning');

      // Record reputation for the agent who shared this repo
      const score = scam?.score ?? trust?.trustScore ?? null;
      if (score !== null) {
        // Get the author from the context string (format: "Found in /s/X by AgentName")
        const authorMatch = context.match(/by\s+(.+)$/);
        if (authorMatch) {
          this.recordScanForReputation(authorMatch[1], repoUrl, verdict, score);
        }
      }

      const content = formatScanResult(repoUrl, scam, trust, decision) +
        `\n\n*Proactively scanned — ${context}*`;

      // 1. Always comment on the original post so the author sees it
      try {
        await this.client.createComment(postId, content);
        console.log(`[AGENT] Commented scan result on post ${postId} for ${repoUrl}`);
        this.monitor.recordCommentedPost(postId);
      } catch (commentErr: any) {
        console.error(`[AGENT] Failed to comment on post ${postId}:`, commentErr.message);
      }

      // Check if the post author is queued for a shill warning
      const authorMatch2 = context.match(/by\s+(.+)$/);
      if (authorMatch2 && this.shillWarningQueue.has(authorMatch2[1])) {
        const rep = this.agentReputations.get(authorMatch2[1]);
        if (rep) {
          try {
            const { formatShillWarning } = await import('./formatter.js');
            const warning = formatShillWarning(authorMatch2[1], rep);
            await this.client.createComment(postId, warning);
            this.shillWarningQueue.delete(authorMatch2[1]);
            console.log(`[AGENT] Posted shill warning for ${authorMatch2[1]} on post ${postId}`);
          } catch (warnErr: any) {
            console.error(`[AGENT] Failed to post shill warning:`, warnErr.message);
          }
        }
      }

      // 2. Also post to /s/builds if notable (warning or high confidence)
      if (decision.shouldPost && (decision.postType === 'warning' || decision.confidence === 'high')) {
        try {
          const score = scam?.score ?? trust?.trustScore ?? null;
          const title = formatPostTitle(repoUrl, verdict, score);
          await this.client.createTextPost(this.config.submoltName, title, content);
          console.log(`[AGENT] Posted proactive scan for ${repoUrl} to /s/${this.config.submoltName}`);
        } catch (postErr: any) {
          console.error(`[AGENT] Failed to post to /s/${this.config.submoltName}:`, postErr.message);
        }
      } else {
        console.log(`[AGENT] Proactive scan for ${repoUrl}: ${decision.postType} (${decision.confidence}) — not posting to submolt`);
      }
    } catch (err: any) {
      console.error(`[AGENT] Proactive scan error for ${repoUrl}:`, err.message);
    }
  }

  // === Daily Summary ===

  private recordDailyScan(repoUrl: string, verdict: string, isWarning: boolean): void {
    this.dailyStats.totalScans++;
    this.dailyStats.reposScanned.push(repoUrl);
    const count = this.dailyStats.verdicts.get(verdict) ?? 0;
    this.dailyStats.verdicts.set(verdict, count + 1);
    if (isWarning) this.dailyStats.warningsPosted++;
  }

  private async checkDailySummary(): Promise<void> {
    const elapsed = Date.now() - this.dailyStats.lastPostedAt;
    if (elapsed < DAILY_SUMMARY_INTERVAL_MS) return;
    if (this.dailyStats.totalScans === 0) {
      // Nothing to report, just reset the timer
      this.dailyStats.lastPostedAt = Date.now();
      return;
    }
    await this.postDailySummary();
  }

  async postDailySummary(): Promise<void> {
    try {
      const { formatDailySummary } = await import('./formatter.js');
      const monitorStats = this.monitor.getStats();

      const title = `[Daily Report] ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })} — ${this.dailyStats.totalScans} repos scanned`;
      const content = formatDailySummary(this.dailyStats, monitorStats.trackedAgents);

      await this.client.createTextPost(this.config.submoltName, title, content);
      console.log(`[AGENT] Posted daily summary to /s/${this.config.submoltName} (${this.dailyStats.totalScans} scans)`);

      // Reset stats
      this.dailyStats = {
        totalScans: 0,
        verdicts: new Map(),
        warningsPosted: 0,
        reposScanned: [],
        startedAt: Date.now(),
        lastPostedAt: Date.now(),
      };
    } catch (err: any) {
      console.error(`[AGENT] Failed to post daily summary:`, err.message);
    }
  }

  // === Mention Scanning ===

  private async handleMentionScan(repoUrl: string | null, postId: string, commentId: string | null, mentioner: string): Promise<void> {
    console.log(`[AGENT] Mention scan requested by ${mentioner}${repoUrl ? ` for ${repoUrl}` : ' (no URL)'} [post: ${postId}]`);

    try {
      if (!repoUrl) {
        // No GitHub URL — ask them to provide one
        const { formatMentionNoUrl } = await import('./formatter.js');
        const reply = formatMentionNoUrl(mentioner);
        await this.client.createComment(postId, reply, commentId || undefined);
        console.log(`[AGENT] Replied to mention by ${mentioner} (no URL) on post ${postId}`);
        return;
      }

      // Run the scan
      const { trust, scam } = await this.performScan(repoUrl);
      if (!trust && !scam) {
        console.log(`[AGENT] Mention scan: both scanners failed for ${repoUrl}`);
        return;
      }

      const { makePostDecision } = await import('./confidence.js');
      const { formatMentionResponse } = await import('./formatter.js');
      const decision = makePostDecision(scam, trust);
      const verdict = scam?.verdict ?? trust?.verdict ?? 'SCANNED';
      const score = scam?.score ?? trust?.trustScore ?? null;

      // Record daily stats + reputation
      this.recordDailyScan(repoUrl, verdict, decision.postType === 'warning');
      if (score !== null) {
        this.recordScanForReputation(mentioner, repoUrl, verdict, score);
      }

      const content = formatMentionResponse(repoUrl, scam, trust, decision, mentioner);
      await this.client.createComment(postId, content, commentId || undefined);
      this.monitor.recordCommentedPost(postId);
      console.log(`[AGENT] Replied to mention by ${mentioner} with scan of ${repoUrl}`);
    } catch (err: any) {
      console.error(`[AGENT] Mention scan error:`, err.message);
    }
  }

  private async performScan(repoUrl: string): Promise<{ trust: any; scam: any }> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 240_000);

    const scanHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
    if (this.config.scannerApiKey) {
      scanHeaders['Authorization'] = `Bearer ${this.config.scannerApiKey}`;
    }

    const [trustRes, scamRes] = await Promise.allSettled([
      fetch(`${this.config.scannerApiUrl}/tools`, {
        method: 'POST',
        headers: scanHeaders,
        body: JSON.stringify({ tool: 'trust-scan', arguments: { gitUrl: repoUrl } }),
        signal: controller.signal,
      }).then(r => r.ok ? r.json() : null).then((d: any) => d?.result || d),
      fetch(`${this.config.scannerApiUrl}/tools`, {
        method: 'POST',
        headers: scanHeaders,
        body: JSON.stringify({ tool: 'scam-scan', arguments: { gitUrl: repoUrl } }),
        signal: controller.signal,
      }).then(r => r.ok ? r.json() : null).then((d: any) => d?.result || d),
    ]);

    clearTimeout(timeout);

    return {
      trust: trustRes.status === 'fulfilled' ? trustRes.value : null,
      scam: scamRes.status === 'fulfilled' ? scamRes.value : null,
    };
  }

  // === Agent Reputation ===

  private recordScanForReputation(agentName: string, repoUrl: string, verdict: string, score: number): void {
    let rep = this.agentReputations.get(agentName);
    if (!rep) {
      rep = {
        agentName,
        repoScans: [],
        safeRepos: 0,
        riskyRepos: 0,
        scamRepos: 0,
        totalScans: 0,
        reputationScore: 50,
        lastUpdated: Date.now(),
      };
      this.agentReputations.set(agentName, rep);
    }

    // Avoid counting the same repo twice for one agent
    if (rep.repoScans.some(r => r.repoUrl === repoUrl)) return;

    const record: RepoScanRecord = { repoUrl, verdict, score, scannedAt: Date.now() };
    rep.repoScans.push(record);
    rep.totalScans++;

    // Categorize
    if (score >= 75) {
      rep.safeRepos++;
    } else if (score < 35) {
      rep.scamRepos++;
    } else if (score < 55) {
      rep.riskyRepos++;
    }

    // Cap scans per agent
    if (rep.repoScans.length > MAX_REPO_SCANS_PER_AGENT) {
      rep.repoScans = rep.repoScans.slice(-MAX_REPO_SCANS_PER_AGENT);
    }

    // Recompute reputation score
    rep.reputationScore = Math.max(0, Math.min(100,
      50 + Math.min(30, rep.safeRepos * 3) - rep.riskyRepos * 5 - rep.scamRepos * 15
    ));
    rep.lastUpdated = Date.now();

    console.log(`[AGENT] Reputation updated for ${agentName}: ${rep.reputationScore}/100 (safe=${rep.safeRepos}, risky=${rep.riskyRepos}, scam=${rep.scamRepos})`);

    // Check for shill warning threshold
    if (rep.scamRepos >= SHILL_SCAM_THRESHOLD && rep.reputationScore < SHILL_SCORE_THRESHOLD) {
      this.shillWarningQueue.add(agentName);
      console.log(`[AGENT] ${agentName} queued for shill warning (score: ${rep.reputationScore}, scams: ${rep.scamRepos})`);
    }
  }

  getAgentReputation(agentName: string): AgentReputation | null {
    return this.agentReputations.get(agentName) || null;
  }

  getAllReputations(): AgentReputation[] {
    return [...this.agentReputations.values()];
  }

  // === Weekly Leaderboard ===

  private async checkWeeklyLeaderboard(): Promise<void> {
    const elapsed = Date.now() - this.lastLeaderboardPostAt;
    if (elapsed < WEEKLY_INTERVAL_MS) return;
    if (this.agentReputations.size < 5) return;
    await this.postLeaderboard();
  }

  async postLeaderboard(): Promise<void> {
    try {
      const { formatWeeklyLeaderboard } = await import('./formatter.js');
      const reputations = this.getAllReputations();
      const monitorStats = this.monitor.getStats();
      const totalScans = reputations.reduce((sum, r) => sum + r.totalScans, 0);

      const title = `[Trust Rankings] Week of ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' })}`;
      const content = formatWeeklyLeaderboard(reputations, monitorStats.trackedAgents, totalScans);

      await this.client.createTextPost(this.config.submoltName, title, content);
      this.lastLeaderboardPostAt = Date.now();
      console.log(`[AGENT] Posted weekly leaderboard to /s/${this.config.submoltName} (${reputations.length} agents ranked)`);
    } catch (err: any) {
      console.error(`[AGENT] Failed to post leaderboard:`, err.message);
    }
  }

  /**
   * Score an agent's trust level and apply jail enforcement if needed.
   * Callable externally via the API tools.
   */
  async scoreAgent(agentName: string): Promise<AgentTrustScore | null> {
    try {
      // Fetch agent profile from Moltbook
      const profile = await this.client.getAgentProfile(agentName);
      if (!profile) {
        console.log(`[AGENT] Agent ${agentName} not found on Moltbook`);
        return null;
      }

      // Get monitor's tracked activity
      const activity = this.monitor.getAgentActivity(agentName);

      // Feed agent data into bot detector
      this.botDetector.addAgent(profile);
      if (activity) {
        for (const [repo] of activity.reposShared) {
          this.botDetector.addAgentRepo(agentName, repo);
        }
      }

      // Check if in a bot cluster
      const cluster = this.botDetector.isInCluster(agentName);
      const networkData = cluster ? {
        clusterSize: cluster.agents.length,
        coordinationScore: cluster.confidence,
        sharedRepoOverlap: cluster.signals.find(s => s.type === 'repo_overlap')?.strength ?? 0,
        creationTimeSimilarity: cluster.signals.find(s => s.type === 'creation_time')?.strength ?? 0,
      } : undefined;

      // Build content data from reputation if available
      const reputation = this.agentReputations.get(agentName);
      const contentData = reputation ? {
        flaggedRepos: reputation.riskyRepos + reputation.scamRepos,
        endorsedScams: reputation.scamRepos,
        falsePositiveRate: 0,
        spamPatternScore: 0,
      } : undefined;

      // Score the agent
      const score = this.scorer.score(profile, activity || null, networkData, contentData);
      console.log(`[AGENT] Scored ${agentName}: ${score.overallScore}/100 (${score.jailLevel})`);

      // Apply enforcement
      await this.enforcer.enforce(score);

      return score;
    } catch (err: any) {
      console.error(`[AGENT] Error scoring ${agentName}:`, err.message);
      return null;
    }
  }

  /**
   * Run bot farm detection on all tracked agents
   */
  private async runBotDetection(): Promise<void> {
    try {
      const clusters = this.botDetector.detect();
      if (clusters.length > 0) {
        console.log(`[AGENT] Bot detection found ${clusters.length} clusters`);
        for (const cluster of clusters) {
          console.log(`[AGENT] Cluster ${cluster.id}: ${cluster.agents.length} agents, confidence: ${cluster.confidence}`);
          // Score each agent in the cluster
          for (const agentName of cluster.agents) {
            await this.scoreAgent(agentName);
          }
        }
      }
    } catch (err: any) {
      console.error('[AGENT] Bot detection error:', err.message);
    }
  }

  /**
   * Check if a post's author is allowed to be processed
   */
  shouldProcessPost(authorName: string): { process: boolean; reason?: string } {
    return this.enforcer.shouldProcessPost(authorName);
  }

  // === Registration & Setup ===

  private async ensureRegisteredWithRetry(): Promise<boolean> {
    // Try immediately
    const ok = await this.tryRegister();
    if (ok) return true;

    // Failed — start background retry loop (don't block startup)
    console.log('[AGENT] Will retry Moltbook registration every 60s in background');
    const retryTimer = setInterval(async () => {
      const success = await this.tryRegister();
      if (success) {
        clearInterval(retryTimer);
        // Start services that depend on registration
        try { await this.ensureSubmolt(); } catch {}
        this.scanner.start();
        this.monitor.start();
        console.log('[AGENT] Moltbook reconnected — all services started');
      }
    }, 60_000);

    return false;
  }

  private async tryRegister(): Promise<boolean> {
    // Try existing key first
    if (this.config.apiKey) {
      try {
        const profile = await this.client.getMyProfile();
        console.log(`[AGENT] Authenticated as ${profile.name} (karma: ${profile.karma}, verified: ${profile.verified})`);
        return true;
      } catch (err: any) {
        console.warn(`[AGENT] API key failed: ${err.message}`);
      }
    }

    // Try to register
    try {
      const res = await this.client.register(
        this.config.agentName,
        'Automated security scanner for GitHub repositories. Powered by AuraSecurity — trust scores, scam detection, secrets scanning, and code safety analysis.'
      );
      this.config.apiKey = res.api_key;
      this.client.setApiKey(res.api_key);
      console.log(`[AGENT] Registered as ${res.agent.name}`);
      console.log(`[AGENT] API Key: ${res.api_key}`);
      console.log(`[AGENT] Claim URL: ${res.claim_url}`);
      console.log(`[AGENT] Verification Code: ${res.verification_code}`);

      // Auto-save key to .env so we never lose it again
      this.persistApiKey(res.api_key);
      return true;
    } catch (err: any) {
      console.warn(`[AGENT] Registration failed: ${err.message}`);
      return false;
    }
  }

  private persistApiKey(key: string): void {
    try {
      const fs = require('fs');
      const path = require('path');
      const envPath = path.join(process.cwd(), '.env');
      let envContent = '';
      try { envContent = fs.readFileSync(envPath, 'utf-8'); } catch {}

      if (envContent.includes('MOLTBOOK_API_KEY=')) {
        envContent = envContent.replace(/MOLTBOOK_API_KEY=.*/g, `MOLTBOOK_API_KEY=${key}`);
      } else {
        envContent += `\nMOLTBOOK_API_KEY=${key}`;
      }
      fs.writeFileSync(envPath, envContent.trim() + '\n');
      console.log(`[AGENT] API key saved to .env`);
    } catch (err: any) {
      console.error(`[AGENT] Could not save API key to .env: ${err.message}`);
      console.log(`[AGENT] SAVE THIS KEY: ${key}`);
    }
  }

  private async ensureSubmolt(): Promise<void> {
    try {
      const submolts = await this.client.listSubmolts();
      const exists = submolts.some(s => s.name === this.config.submoltName);

      if (exists) {
        console.log(`[AGENT] Submolt /s/${this.config.submoltName} exists`);
        try {
          await this.client.subscribeToSubmolt(this.config.submoltName);
        } catch {
          // Already subscribed
        }
        return;
      }

      const submolt = await this.client.createSubmolt(
        this.config.submoltName,
        'Security Audits',
        'Automated security scans of GitHub repositories. Post a GitHub repo URL and AuraSecurity will analyze it for scams, vulnerabilities, and trust signals.'
      );
      console.log(`[AGENT] Created submolt /s/${submolt.name} (${submolt.id})`);
    } catch (err: any) {
      console.warn(`[AGENT] Could not verify/create submolt: ${err.message}`);
    }
  }

  // === Public Getters ===

  getStatus() {
    const reps = this.getAllReputations();
    const topAgent = reps.sort((a, b) => b.reputationScore - a.reputationScore)[0];
    return {
      running: this.running,
      config: { ...this.config, apiKey: this.config.apiKey ? '***' : undefined },
      scanner: this.scanner.getStats(),
      monitor: this.monitor.getStats(),
      jail: this.enforcer.getStats(),
      botDetector: this.botDetector.getStats(),
      dailyStats: {
        totalScans: this.dailyStats.totalScans,
        warningsPosted: this.dailyStats.warningsPosted,
        verdicts: Object.fromEntries(this.dailyStats.verdicts),
        hoursSinceLastSummary: Math.round((Date.now() - this.dailyStats.lastPostedAt) / (60 * 60 * 1000)),
      },
      reputation: {
        trackedAgents: this.agentReputations.size,
        topAgent: topAgent?.agentName ?? null,
        topScore: topAgent?.reputationScore ?? 0,
        shillWarningQueue: this.shillWarningQueue.size,
        daysSinceLeaderboard: Math.round((Date.now() - this.lastLeaderboardPostAt) / (24 * 60 * 60 * 1000)),
      },
    };
  }

  getClient(): MoltbookClient { return this.client; }
  getEnforcer(): JailEnforcer { return this.enforcer; }
  getBotDetector(): BotFarmDetector { return this.botDetector; }
  getScorer(): AgentScorer { return this.scorer; }
  getMonitor(): FeedMonitor { return this.monitor; }
}

// === Standalone Entry Point ===

async function main(): Promise<void> {
  const agent = new MoltbookAgent();

  const shutdown = () => {
    console.log('\n[AGENT] Shutting down...');
    agent.stop();
    process.exit(0);
  };
  process.on('SIGINT', shutdown);
  process.on('SIGTERM', shutdown);

  await agent.start();

  // Status logging
  const statusInterval = setInterval(() => {
    const s = agent.getStatus();
    console.log(
      `[AGENT] Status: scanner(cache=${s.scanner.cacheSize},active=${s.scanner.activeScans}) ` +
      `monitor(agents=${s.monitor.trackedAgents},alerts=${s.monitor.alertCount}) ` +
      `jail(warn=${s.jail.warnings},watch=${s.jail.watchList},jailed=${s.jail.jailed}) ` +
      `bots(clusters=${s.botDetector.clustersDetected}) ` +
      `daily(scans=${s.dailyStats.totalScans},warnings=${s.dailyStats.warningsPosted},hrs=${s.dailyStats.hoursSinceLastSummary})`
    );
  }, 60_000);

  process.on('beforeExit', () => clearInterval(statusInterval));
}

const isMainModule = process.argv[1]?.endsWith('agent.ts') || process.argv[1]?.endsWith('agent.js');
if (isMainModule) {
  main().catch(err => {
    console.error('[AGENT] Fatal error:', err);
    process.exit(1);
  });
}
