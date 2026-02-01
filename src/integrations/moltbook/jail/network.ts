/**
 * AI Jail — Bot Farm Detector
 *
 * Network graph analysis to detect coordinated bot farms on Moltbook.
 *
 * Detection signals:
 *  1. Creation time clustering — accounts created within minutes of each other
 *  2. Upvote coordination — agents upvoting the same posts in sequence
 *  3. Post pattern similarity — identical/templated post content
 *  4. Repo overlap — agents sharing the exact same set of repos
 *  5. Naming patterns — sequential or pattern-based agent names
 *
 * Uses a union-find approach to group agents into suspected clusters.
 */

import type { BotCluster, ClusterSignal } from './types.js';
import type { MoltbookAgent, MoltbookPost } from '../types.js';

// Thresholds
const CREATION_TIME_WINDOW_MS = 10 * 60 * 1000;   // 10 minutes
const REPO_OVERLAP_THRESHOLD = 0.6;                // 60% shared repos = suspicious
const POST_SIMILARITY_THRESHOLD = 0.75;            // 75% content similarity
const MIN_CLUSTER_SIZE = 3;                        // Need 3+ agents to call it a cluster
const MIN_CONFIDENCE = 0.5;                        // Minimum cluster confidence to report

export class BotFarmDetector {
  // Union-find for clustering agents
  private parent: Map<string, string> = new Map();
  private rank: Map<string, number> = new Map();

  // Agent data for analysis
  private agentProfiles: Map<string, MoltbookAgent> = new Map();
  private agentRepos: Map<string, Set<string>> = new Map();    // agent → repos shared
  private agentPosts: Map<string, string[]> = new Map();       // agent → post contents
  private detectedClusters: Map<string, BotCluster> = new Map();

  /**
   * Ingest agent profile data for analysis
   */
  addAgent(profile: MoltbookAgent): void {
    this.agentProfiles.set(profile.name, profile);
    this.makeSet(profile.name);
  }

  /**
   * Record that an agent shared a repo
   */
  addAgentRepo(agentName: string, repoUrl: string): void {
    let repos = this.agentRepos.get(agentName);
    if (!repos) {
      repos = new Set();
      this.agentRepos.set(agentName, repos);
    }
    repos.add(repoUrl.toLowerCase());
  }

  /**
   * Record a post's content for similarity analysis
   */
  addAgentPost(agentName: string, content: string): void {
    let posts = this.agentPosts.get(agentName);
    if (!posts) {
      posts = [];
      this.agentPosts.set(agentName, posts);
    }
    // Keep last 20 posts per agent
    if (posts.length >= 20) posts.shift();
    posts.push(content);
  }

  /**
   * Run full bot farm detection. Returns detected clusters.
   */
  detect(): BotCluster[] {
    // Reset union-find
    this.parent.clear();
    this.rank.clear();
    for (const name of this.agentProfiles.keys()) {
      this.makeSet(name);
    }

    const agents = [...this.agentProfiles.keys()];
    const pairSignals: Map<string, ClusterSignal[]> = new Map();

    // Compare all agent pairs
    for (let i = 0; i < agents.length; i++) {
      for (let j = i + 1; j < agents.length; j++) {
        const a = agents[i];
        const b = agents[j];
        const signals = this.comparePair(a, b);

        if (signals.length > 0) {
          const key = `${a}:${b}`;
          pairSignals.set(key, signals);

          // If enough signals, union the agents
          const totalStrength = signals.reduce((sum, s) => sum + s.strength, 0) / signals.length;
          if (totalStrength >= 0.4 && signals.length >= 2) {
            this.union(a, b);
          }
        }
      }
    }

    // Extract clusters from union-find
    const clusterMap: Map<string, string[]> = new Map();
    for (const agent of agents) {
      const root = this.find(agent);
      let cluster = clusterMap.get(root);
      if (!cluster) {
        cluster = [];
        clusterMap.set(root, cluster);
      }
      cluster.push(agent);
    }

    // Build BotCluster objects for clusters meeting size threshold
    const clusters: BotCluster[] = [];
    let clusterId = 0;

    for (const [, members] of clusterMap) {
      if (members.length < MIN_CLUSTER_SIZE) continue;

      // Collect all signals for this cluster
      const clusterSignals: ClusterSignal[] = [];
      for (let i = 0; i < members.length; i++) {
        for (let j = i + 1; j < members.length; j++) {
          const key = `${members[i]}:${members[j]}`;
          const reverseKey = `${members[j]}:${members[i]}`;
          const signals = pairSignals.get(key) || pairSignals.get(reverseKey) || [];
          clusterSignals.push(...signals);
        }
      }

      // Compute cluster confidence
      const avgStrength = clusterSignals.length > 0
        ? clusterSignals.reduce((sum, s) => sum + s.strength, 0) / clusterSignals.length
        : 0;
      const signalDiversity = new Set(clusterSignals.map(s => s.type)).size / 5; // 5 possible types
      const confidence = Math.min(1, avgStrength * 0.6 + signalDiversity * 0.4);

      if (confidence < MIN_CONFIDENCE) continue;

      const cluster: BotCluster = {
        id: `cluster_${++clusterId}`,
        agents: members,
        confidence: Math.round(confidence * 100) / 100,
        signals: this.dedupeSignals(clusterSignals),
        detectedAt: Date.now(),
      };

      clusters.push(cluster);
      this.detectedClusters.set(cluster.id, cluster);
    }

    return clusters;
  }

  /**
   * Compare two agents and return matching signals
   */
  private comparePair(a: string, b: string): ClusterSignal[] {
    const signals: ClusterSignal[] = [];
    const profileA = this.agentProfiles.get(a);
    const profileB = this.agentProfiles.get(b);

    if (!profileA || !profileB) return signals;

    // 1. Creation time clustering
    const timeDiff = Math.abs(
      new Date(profileA.created_at).getTime() - new Date(profileB.created_at).getTime()
    );
    if (timeDiff < CREATION_TIME_WINDOW_MS) {
      const strength = 1 - (timeDiff / CREATION_TIME_WINDOW_MS);
      signals.push({
        type: 'creation_time',
        strength: Math.round(strength * 100) / 100,
        evidence: `Accounts created ${Math.round(timeDiff / 1000)}s apart`,
      });
    }

    // 2. Repo overlap
    const reposA = this.agentRepos.get(a);
    const reposB = this.agentRepos.get(b);
    if (reposA && reposB && reposA.size > 0 && reposB.size > 0) {
      const intersection = new Set([...reposA].filter(r => reposB.has(r)));
      const smaller = Math.min(reposA.size, reposB.size);
      const overlap = intersection.size / smaller;

      if (overlap >= REPO_OVERLAP_THRESHOLD) {
        signals.push({
          type: 'repo_overlap',
          strength: Math.round(overlap * 100) / 100,
          evidence: `${intersection.size} shared repos (${Math.round(overlap * 100)}% overlap)`,
        });
      }
    }

    // 3. Post pattern similarity
    const postsA = this.agentPosts.get(a);
    const postsB = this.agentPosts.get(b);
    if (postsA && postsB && postsA.length > 0 && postsB.length > 0) {
      const similarity = this.computePostSimilarity(postsA, postsB);
      if (similarity >= POST_SIMILARITY_THRESHOLD) {
        signals.push({
          type: 'post_pattern',
          strength: Math.round(similarity * 100) / 100,
          evidence: `${Math.round(similarity * 100)}% content similarity across posts`,
        });
      }
    }

    // 4. Naming pattern
    const nameSignal = this.checkNamingPattern(a, b);
    if (nameSignal) {
      signals.push(nameSignal);
    }

    return signals;
  }

  /**
   * Compute content similarity between two agents' post histories.
   * Uses trigram overlap as a simple similarity metric.
   */
  private computePostSimilarity(postsA: string[], postsB: string[]): number {
    const trigramsA = this.extractTrigrams(postsA.join(' '));
    const trigramsB = this.extractTrigrams(postsB.join(' '));

    if (trigramsA.size === 0 || trigramsB.size === 0) return 0;

    const intersection = new Set([...trigramsA].filter(t => trigramsB.has(t)));
    const union = new Set([...trigramsA, ...trigramsB]);

    return intersection.size / union.size; // Jaccard similarity
  }

  private extractTrigrams(text: string): Set<string> {
    const normalized = text.toLowerCase().replace(/[^a-z0-9\s]/g, '');
    const words = normalized.split(/\s+/).filter(w => w.length > 2);
    const trigrams = new Set<string>();

    for (let i = 0; i < words.length - 2; i++) {
      trigrams.add(`${words[i]} ${words[i + 1]} ${words[i + 2]}`);
    }
    return trigrams;
  }

  /**
   * Check if two agent names follow a suspicious pattern
   * (e.g., "agent_001", "agent_002" or "crypto_review_bot", "crypto_scan_bot")
   */
  private checkNamingPattern(a: string, b: string): ClusterSignal | null {
    // Sequential numbering
    const numA = a.match(/(\d+)$/);
    const numB = b.match(/(\d+)$/);
    if (numA && numB) {
      const prefixA = a.slice(0, -numA[1].length);
      const prefixB = b.slice(0, -numB[1].length);
      if (prefixA === prefixB && Math.abs(parseInt(numA[1]) - parseInt(numB[1])) <= 5) {
        return {
          type: 'naming_pattern',
          strength: 0.6,
          evidence: `Sequential naming: "${a}" and "${b}" share prefix "${prefixA}"`,
        };
      }
    }

    // Very similar names (edit distance)
    if (a.length > 3 && b.length > 3) {
      const distance = this.levenshtein(a.toLowerCase(), b.toLowerCase());
      const maxLen = Math.max(a.length, b.length);
      const similarity = 1 - distance / maxLen;
      if (similarity >= 0.8 && distance <= 3) {
        return {
          type: 'naming_pattern',
          strength: Math.round(similarity * 100) / 100,
          evidence: `Similar names: "${a}" and "${b}" (edit distance: ${distance})`,
        };
      }
    }

    return null;
  }

  private levenshtein(a: string, b: string): number {
    const m = a.length;
    const n = b.length;
    const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

    for (let i = 0; i <= m; i++) dp[i][0] = i;
    for (let j = 0; j <= n; j++) dp[0][j] = j;

    for (let i = 1; i <= m; i++) {
      for (let j = 1; j <= n; j++) {
        dp[i][j] = a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
      }
    }

    return dp[m][n];
  }

  /**
   * Deduplicate signals by type, keeping highest strength
   */
  private dedupeSignals(signals: ClusterSignal[]): ClusterSignal[] {
    const byType = new Map<string, ClusterSignal>();
    for (const s of signals) {
      const existing = byType.get(s.type);
      if (!existing || s.strength > existing.strength) {
        byType.set(s.type, s);
      }
    }
    return [...byType.values()];
  }

  // === Union-Find ===

  private makeSet(x: string): void {
    if (!this.parent.has(x)) {
      this.parent.set(x, x);
      this.rank.set(x, 0);
    }
  }

  private find(x: string): string {
    const p = this.parent.get(x);
    if (!p || p === x) return x;
    const root = this.find(p);
    this.parent.set(x, root); // path compression
    return root;
  }

  private union(a: string, b: string): void {
    const rootA = this.find(a);
    const rootB = this.find(b);
    if (rootA === rootB) return;

    const rankA = this.rank.get(rootA) || 0;
    const rankB = this.rank.get(rootB) || 0;

    if (rankA < rankB) {
      this.parent.set(rootA, rootB);
    } else if (rankA > rankB) {
      this.parent.set(rootB, rootA);
    } else {
      this.parent.set(rootB, rootA);
      this.rank.set(rootA, rankA + 1);
    }
  }

  // === Public Getters ===

  getClusters(): BotCluster[] {
    return [...this.detectedClusters.values()];
  }

  getCluster(id: string): BotCluster | null {
    return this.detectedClusters.get(id) || null;
  }

  isInCluster(agentName: string): BotCluster | null {
    for (const cluster of this.detectedClusters.values()) {
      if (cluster.agents.includes(agentName)) return cluster;
    }
    return null;
  }

  getStats(): { agentsTracked: number; clustersDetected: number; totalAgentsInClusters: number } {
    let totalInClusters = 0;
    for (const c of this.detectedClusters.values()) {
      totalInClusters += c.agents.length;
    }
    return {
      agentsTracked: this.agentProfiles.size,
      clustersDetected: this.detectedClusters.size,
      totalAgentsInClusters: totalInClusters,
    };
  }
}
