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
import type { MoltbookAgentConfig } from './types.js';
import { DEFAULT_CONFIG } from './types.js';

// How often to run bot farm detection (expensive operation)
const BOT_DETECT_INTERVAL_MS = 5 * 60 * 1000; // 5 minutes

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

    this.client = new MoltbookClient(this.config.apiKey || '');
    this.scanner = new MoltbookScanner(this.client, this.config);
    this.scorer = new AgentScorer();
    this.botDetector = new BotFarmDetector();
    this.enforcer = new JailEnforcer(this.client);

    // Feed monitor with callbacks
    this.monitor = new FeedMonitor(this.client, this.config, {
      onAlert: (alert) => this.handleAlert(alert),
      onScanRequest: (repoUrl, context) => this.handleProactiveScan(repoUrl, context),
    });
  }

  /**
   * Start the agent: register, ensure submolt exists, begin all services
   */
  async start(): Promise<void> {
    if (this.running) return;
    console.log('[AGENT] Starting AuraSecurity Moltbook agent...');

    // Step 1: Register or verify agent identity
    await this.ensureRegistered();

    // Step 2: Ensure our submolt exists
    await this.ensureSubmolt();

    // Step 3: Start the scanner (polls for scan requests in /s/security-audits)
    this.scanner.start();

    // Step 4: Start the feed monitor (watches global feed)
    this.monitor.start();

    // Step 5: Start periodic bot farm detection
    this.botDetectTimer = setInterval(() => this.runBotDetection(), BOT_DETECT_INTERVAL_MS);

    this.running = true;
    console.log('[AGENT] AuraSecurity Moltbook agent is running');
    console.log('[AGENT] Services: scanner, monitor, jail');
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

  private handleProactiveScan(repoUrl: string, context: string): void {
    console.log(`[AGENT] Proactive scan requested: ${repoUrl} (${context})`);
    // The scanner handles the actual scanning — we could post to our submolt
    // or just track it. For now, log it.
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

      // Score the agent
      const score = this.scorer.score(profile, activity || null, networkData);
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

  private async ensureRegistered(): Promise<void> {
    if (this.config.apiKey) {
      try {
        const profile = await this.client.getMyProfile();
        console.log(`[AGENT] Authenticated as ${profile.name} (karma: ${profile.karma}, verified: ${profile.verified})`);
        return;
      } catch (err: any) {
        console.warn(`[AGENT] API key invalid or expired: ${err.message}`);
        console.log('[AGENT] Re-registering...');
      }
    }

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
      console.log('[AGENT] IMPORTANT: Save the API key to MOLTBOOK_API_KEY env var');
    } catch (err: any) {
      throw new Error(`Failed to register agent: ${err.message}`);
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

  getStatus(): {
    running: boolean;
    config: MoltbookAgentConfig;
    scanner: ReturnType<MoltbookScanner['getStats']>;
    monitor: ReturnType<FeedMonitor['getStats']>;
    jail: ReturnType<JailEnforcer['getStats']>;
    botDetector: ReturnType<BotFarmDetector['getStats']>;
  } {
    return {
      running: this.running,
      config: { ...this.config, apiKey: this.config.apiKey ? '***' : undefined },
      scanner: this.scanner.getStats(),
      monitor: this.monitor.getStats(),
      jail: this.enforcer.getStats(),
      botDetector: this.botDetector.getStats(),
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
      `bots(clusters=${s.botDetector.clustersDetected})`
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
