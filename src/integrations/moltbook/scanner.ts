/**
 * Moltbook Scan Request Handler
 *
 * Watches the security-audits submolt for posts containing GitHub URLs.
 * When found, runs trust-scan + scam-scan via the local scanner API,
 * then posts formatted results as a comment reply.
 *
 * Deduplicates using an in-memory cache with configurable TTL.
 */

import { MoltbookClient } from './client.js';
import { formatScanResult, formatScanError } from './formatter.js';
import { makePostDecision } from './confidence.js';
import type { MoltbookPost, MoltbookAgentConfig, ScanCacheEntry } from './types.js';

const GITHUB_URL_REGEX = /https?:\/\/github\.com\/([a-zA-Z0-9_.-]+\/[a-zA-Z0-9_.-]+)/gi;
const MAX_CONCURRENT_SCANS = 2;
const SCAN_TIMEOUT_MS = 240_000; // 4 minutes per scan

export class MoltbookScanner {
  private client: MoltbookClient;
  private config: MoltbookAgentConfig;
  private scanCache: Map<string, ScanCacheEntry> = new Map();
  private processedPosts: Set<string> = new Set();
  private activeScans = 0;
  private pollTimer: ReturnType<typeof setInterval> | null = null;

  constructor(client: MoltbookClient, config: MoltbookAgentConfig) {
    this.client = client;
    this.config = config;
  }

  /**
   * Start polling the submolt for new scan requests
   */
  start(): void {
    if (this.pollTimer) return;
    console.log(`[SCANNER] Polling /s/${this.config.submoltName} every ${this.config.pollIntervalMs / 1000}s`);
    this.poll(); // immediate first poll
    this.pollTimer = setInterval(() => this.poll(), this.config.pollIntervalMs);
  }

  /**
   * Stop polling
   */
  stop(): void {
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = null;
    }
    console.log('[SCANNER] Stopped');
  }

  /**
   * Single poll cycle: fetch recent posts, extract GitHub URLs, scan them
   */
  private async poll(): Promise<void> {
    try {
      const posts = await this.client.getSubmoltPosts(this.config.submoltName, 'new', 25);

      for (const post of posts) {
        if (this.processedPosts.has(post.id)) continue;
        if (this.activeScans >= MAX_CONCURRENT_SCANS) break;

        const urls = this.extractGitHubUrls(post);
        if (urls.length === 0) {
          this.processedPosts.add(post.id);
          continue;
        }

        // Process the first GitHub URL found in the post
        const repoUrl = urls[0];
        const normalizedUrl = this.normalizeRepoUrl(repoUrl);

        // Check cache
        const cached = this.getCachedScan(normalizedUrl);
        if (cached) {
          // Already scanned recently — post cached result as comment
          this.processedPosts.add(post.id);
          if (!cached.posted) {
            await this.postCachedResult(post, cached);
          }
          continue;
        }

        // Run scan in background (don't block the poll loop)
        this.processedPosts.add(post.id);
        this.scanAndReply(post, normalizedUrl).catch(err => {
          console.error(`[SCANNER] Scan failed for ${normalizedUrl}:`, err.message);
        });
      }

      // Prune expired cache entries
      this.pruneCache();
    } catch (err: any) {
      console.error('[SCANNER] Poll error:', err.message);
    }
  }

  /**
   * Run trust-scan + scam-scan on a repo, then post results as comment
   */
  private async scanAndReply(post: MoltbookPost, repoUrl: string): Promise<void> {
    this.activeScans++;
    console.log(`[SCANNER] Scanning ${repoUrl} (requested by ${post.author})`);

    try {
      const [trustResult, scamResult] = await Promise.allSettled([
        this.callScannerApi('trust-scan', { repoUrl }),
        this.callScannerApi('scam-scan', { repoUrl }),
      ]);

      const trust = trustResult.status === 'fulfilled' ? trustResult.value : null;
      const scam = scamResult.status === 'fulfilled' ? scamResult.value : null;

      if (!trust && !scam) {
        // Both scans failed
        const errorMsg = formatScanError(repoUrl, 'Both trust-scan and scam-scan failed. The repo may be invalid or temporarily unavailable.');
        await this.client.createComment(post.id, errorMsg);
        return;
      }

      // Decide what to post via confidence gate
      const decision = makePostDecision(scam, trust);

      // Cache the result
      const cacheEntry: ScanCacheEntry = {
        repo_url: repoUrl,
        scam_result: scam,
        trust_result: trust,
        scanned_at: new Date().toISOString(),
        posted: true,
      };

      // Format and post
      const content = formatScanResult(repoUrl, scam, trust, decision);
      const comment = await this.client.createComment(post.id, content);
      cacheEntry.post_id = comment.id;
      this.scanCache.set(repoUrl, cacheEntry);

      console.log(`[SCANNER] Posted scan result for ${repoUrl} (comment ${comment.id})`);
    } catch (err: any) {
      console.error(`[SCANNER] Error scanning ${repoUrl}:`, err.message);
      try {
        const errorMsg = formatScanError(repoUrl, err.message);
        await this.client.createComment(post.id, errorMsg);
      } catch (commentErr: any) {
        console.error(`[SCANNER] Failed to post error comment:`, commentErr.message);
      }
    } finally {
      this.activeScans--;
    }
  }

  /**
   * Post a cached scan result as a comment reply
   */
  private async postCachedResult(post: MoltbookPost, cached: ScanCacheEntry): Promise<void> {
    try {
      const decision = makePostDecision(cached.scam_result, cached.trust_result);
      const content = formatScanResult(cached.repo_url, cached.scam_result, cached.trust_result, decision) +
        '\n\n*Cached result from ' + new Date(cached.scanned_at).toLocaleString() + '*';
      const comment = await this.client.createComment(post.id, content);
      cached.posted = true;
      cached.post_id = comment.id;
      console.log(`[SCANNER] Posted cached result for ${cached.repo_url}`);
    } catch (err: any) {
      console.error(`[SCANNER] Failed to post cached result:`, err.message);
    }
  }

  /**
   * Call the local scanner API (trust-scan or scam-scan)
   */
  private async callScannerApi(tool: string, args: Record<string, any>): Promise<any> {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), SCAN_TIMEOUT_MS);

    try {
      const response = await fetch(`${this.config.scannerApiUrl}/tools`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, arguments: args }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`Scanner API ${response.status}: ${text.slice(0, 200)}`);
      }

      const data = await response.json() as any;
      return data.result || data;
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error(`${tool} timed out (${SCAN_TIMEOUT_MS / 1000}s limit)`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  /**
   * Extract GitHub repo URLs from a post's title, content, and URL fields
   */
  private extractGitHubUrls(post: MoltbookPost): string[] {
    const text = [post.title, post.content || '', post.url || ''].join(' ');
    const matches = text.matchAll(GITHUB_URL_REGEX);
    const urls = new Set<string>();
    for (const match of matches) {
      urls.add(`https://github.com/${match[1]}`);
    }
    return [...urls];
  }

  /**
   * Normalize repo URL: lowercase, strip trailing slashes and .git suffix
   */
  private normalizeRepoUrl(url: string): string {
    return url.toLowerCase().replace(/\/+$/, '').replace(/\.git$/, '');
  }

  /**
   * Get a cached scan result if it exists and hasn't expired
   */
  private getCachedScan(repoUrl: string): ScanCacheEntry | null {
    const entry = this.scanCache.get(repoUrl);
    if (!entry) return null;

    const age = Date.now() - new Date(entry.scanned_at).getTime();
    if (age > this.config.scanCacheTtlMs) {
      this.scanCache.delete(repoUrl);
      return null;
    }
    return entry;
  }

  /**
   * Remove expired entries from the cache
   */
  private pruneCache(): void {
    const now = Date.now();
    for (const [url, entry] of this.scanCache) {
      const age = now - new Date(entry.scanned_at).getTime();
      if (age > this.config.scanCacheTtlMs) {
        this.scanCache.delete(url);
      }
    }
  }

  /**
   * Get scan cache stats (for health/debug)
   */
  getStats(): { cacheSize: number; processedPosts: number; activeScans: number } {
    return {
      cacheSize: this.scanCache.size,
      processedPosts: this.processedPosts.size,
      activeScans: this.activeScans,
    };
  }
}
