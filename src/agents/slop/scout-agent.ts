/**
 * Scout Agent - SLOP Native
 *
 * Watches GitHub/GitLab for PRs and commits in real-time.
 * Triggers security scans automatically when code changes are detected.
 *
 * Tools:
 * - watch-repo: Start watching a repository for changes
 * - unwatch-repo: Stop watching a repository
 * - list-watched: List all watched repositories
 * - get-events: Get recent code change events
 * - parse-webhook: Parse incoming GitHub/GitLab webhook
 * - poll-repo: Manually poll a repo for changes
 */

import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
} from './types.js';

// Types for Scout Agent
export interface WatchedRepo {
  id: string;
  url: string;
  provider: 'github' | 'gitlab' | 'bitbucket';
  owner: string;
  repo: string;
  branch?: string;
  lastCommit?: string;
  lastChecked?: number;
  watchSince: number;
  events: CodeEvent[];
}

export interface CodeEvent {
  id: string;
  type: 'push' | 'pull_request' | 'merge_request' | 'tag';
  repo: string;
  branch: string;
  commit: string;
  author: string;
  message: string;
  filesChanged: string[];
  additions: number;
  deletions: number;
  timestamp: number;
  url?: string;
  prNumber?: number;
  prTitle?: string;
  prState?: 'open' | 'closed' | 'merged';
  metadata?: Record<string, unknown>;
}

export interface WebhookPayload {
  provider: 'github' | 'gitlab';
  event: string;
  payload: Record<string, unknown>;
}

// Scout Agent Tool definitions
const SCOUT_TOOLS: SLOPTool[] = [
  {
    name: 'watch-repo',
    description: 'Start watching a repository for code changes',
    parameters: {
      url: {
        type: 'string',
        description: 'Repository URL (e.g., https://github.com/owner/repo)',
        required: true,
      },
      branch: {
        type: 'string',
        description: 'Branch to watch (default: all branches)',
        required: false,
      },
      pollInterval: {
        type: 'number',
        description: 'Poll interval in seconds (default: 60)',
        required: false,
      },
    },
  },
  {
    name: 'unwatch-repo',
    description: 'Stop watching a repository',
    parameters: {
      repoId: {
        type: 'string',
        description: 'Repository ID to stop watching',
        required: true,
      },
    },
  },
  {
    name: 'list-watched',
    description: 'List all watched repositories',
    parameters: {},
  },
  {
    name: 'get-events',
    description: 'Get recent code change events',
    parameters: {
      repoId: {
        type: 'string',
        description: 'Filter by repository ID',
        required: false,
      },
      since: {
        type: 'number',
        description: 'Get events since timestamp (ms)',
        required: false,
      },
      limit: {
        type: 'number',
        description: 'Max number of events to return (default: 50)',
        required: false,
      },
    },
  },
  {
    name: 'parse-webhook',
    description: 'Parse incoming GitHub/GitLab webhook payload',
    parameters: {
      provider: {
        type: 'string',
        description: 'Webhook provider (github or gitlab)',
        required: true,
      },
      event: {
        type: 'string',
        description: 'Event type header (e.g., push, pull_request)',
        required: true,
      },
      payload: {
        type: 'object',
        description: 'Raw webhook payload',
        required: true,
      },
    },
  },
  {
    name: 'poll-repo',
    description: 'Manually poll a repository for changes',
    parameters: {
      repoId: {
        type: 'string',
        description: 'Repository ID to poll',
        required: true,
      },
    },
  },
  {
    name: 'trigger-scan',
    description: 'Trigger a security scan for a code event',
    parameters: {
      eventId: {
        type: 'string',
        description: 'Code event ID to scan',
        required: true,
      },
    },
  },
];

export class ScoutAgent extends SLOPAgent {
  private watchedRepos: Map<string, WatchedRepo> = new Map();
  private allEvents: CodeEvent[] = [];
  private pollTimers: Map<string, NodeJS.Timeout> = new Map();
  private githubToken?: string;
  private gitlabToken?: string;
  private scannerUrl?: string;

  constructor(config: SLOPAgentConfig) {
    super(config, SCOUT_TOOLS);
    this.githubToken = process.env.GITHUB_TOKEN;
    this.gitlabToken = process.env.GITLAB_TOKEN;
    this.scannerUrl = process.env.SCANNER_URL || 'http://localhost:3001';
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    const { tool, arguments: args } = call;

    try {
      switch (tool) {
        case 'watch-repo':
          return { result: await this.watchRepo(args.url as string, args.branch as string | undefined, args.pollInterval as number | undefined) };

        case 'unwatch-repo':
          return { result: await this.unwatchRepo(args.repoId as string) };

        case 'list-watched':
          return { result: await this.listWatched() };

        case 'get-events':
          return { result: await this.getEvents(args.repoId as string | undefined, args.since as number | undefined, args.limit as number | undefined) };

        case 'parse-webhook':
          return { result: await this.parseWebhook({
            provider: args.provider as 'github' | 'gitlab',
            event: args.event as string,
            payload: args.payload as Record<string, unknown>,
          }) };

        case 'poll-repo':
          return { result: await this.pollRepo(args.repoId as string) };

        case 'trigger-scan':
          return { result: await this.triggerScan(args.eventId as string) };

        default:
          return { error: `Unknown tool: ${tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  /**
   * Start watching a repository
   */
  private async watchRepo(url: string, branch?: string, pollInterval = 60): Promise<WatchedRepo> {
    const parsed = this.parseRepoUrl(url);
    if (!parsed) {
      throw new Error(`Invalid repository URL: ${url}`);
    }

    const repoId = `${parsed.provider}:${parsed.owner}/${parsed.repo}`;

    if (this.watchedRepos.has(repoId)) {
      return this.watchedRepos.get(repoId)!;
    }

    const watched: WatchedRepo = {
      id: repoId,
      url,
      provider: parsed.provider,
      owner: parsed.owner,
      repo: parsed.repo,
      branch,
      watchSince: Date.now(),
      events: [],
    };

    // Get current HEAD commit
    try {
      const latestCommit = await this.getLatestCommit(watched);
      watched.lastCommit = latestCommit;
      watched.lastChecked = Date.now();
    } catch (error) {
      console.log(`[Scout] Could not get latest commit for ${repoId}: ${error}`);
    }

    this.watchedRepos.set(repoId, watched);

    // Set up polling
    const timer = setInterval(() => this.pollRepo(repoId), pollInterval * 1000);
    this.pollTimers.set(repoId, timer);

    console.log(`[Scout] Now watching ${repoId} (poll every ${pollInterval}s)`);

    // Write to shared memory
    await this.writeMemory(`scout:watching:${repoId}`, {
      status: 'watching',
      since: watched.watchSince,
      branch: branch || 'all',
    });

    return watched;
  }

  /**
   * Stop watching a repository
   */
  private async unwatchRepo(repoId: string): Promise<{ success: boolean; message: string }> {
    const timer = this.pollTimers.get(repoId);
    if (timer) {
      clearInterval(timer);
      this.pollTimers.delete(repoId);
    }

    const existed = this.watchedRepos.delete(repoId);

    if (existed) {
      await this.writeMemory(`scout:watching:${repoId}`, {
        status: 'stopped',
        stoppedAt: Date.now(),
      });
    }

    return {
      success: existed,
      message: existed ? `Stopped watching ${repoId}` : `Repository ${repoId} was not being watched`,
    };
  }

  /**
   * List all watched repositories
   */
  private async listWatched(): Promise<{ repos: WatchedRepo[]; count: number }> {
    const repos = Array.from(this.watchedRepos.values());
    return { repos, count: repos.length };
  }

  /**
   * Get recent code events
   */
  private async getEvents(repoId?: string, since?: number, limit = 50): Promise<{ events: CodeEvent[]; count: number }> {
    let events = this.allEvents;

    if (repoId) {
      events = events.filter(e => e.repo === repoId);
    }

    if (since) {
      events = events.filter(e => e.timestamp >= since);
    }

    events = events.slice(-limit);

    return { events, count: events.length };
  }

  /**
   * Parse incoming webhook
   */
  private async parseWebhook(webhook: WebhookPayload): Promise<CodeEvent | null> {
    const { provider, event, payload } = webhook;

    let codeEvent: CodeEvent | null = null;

    if (provider === 'github') {
      codeEvent = this.parseGitHubWebhook(event, payload);
    } else if (provider === 'gitlab') {
      codeEvent = this.parseGitLabWebhook(event, payload);
    }

    if (codeEvent) {
      this.allEvents.push(codeEvent);

      // Update watched repo if we're tracking it
      const repoId = codeEvent.repo;
      const watched = this.watchedRepos.get(repoId);
      if (watched) {
        watched.events.push(codeEvent);
        watched.lastCommit = codeEvent.commit;
        watched.lastChecked = Date.now();
      }

      // Write event to shared memory
      await this.writeMemory(`scout:event:${codeEvent.id}`, codeEvent);

      console.log(`[Scout] New ${codeEvent.type} event: ${codeEvent.repo} (${codeEvent.filesChanged.length} files)`);
    }

    return codeEvent;
  }

  /**
   * Poll a repository for changes
   */
  private async pollRepo(repoId: string): Promise<{ hasChanges: boolean; events: CodeEvent[] }> {
    const watched = this.watchedRepos.get(repoId);
    if (!watched) {
      throw new Error(`Repository ${repoId} is not being watched`);
    }

    const newEvents: CodeEvent[] = [];

    try {
      const latestCommit = await this.getLatestCommit(watched);

      if (latestCommit && latestCommit !== watched.lastCommit) {
        // There are new commits
        const commits = await this.getCommitsSince(watched, watched.lastCommit);

        for (const commit of commits) {
          const event: CodeEvent = {
            id: `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
            type: 'push',
            repo: repoId,
            branch: watched.branch || 'main',
            commit: commit.sha,
            author: commit.author,
            message: commit.message,
            filesChanged: commit.files,
            additions: commit.additions,
            deletions: commit.deletions,
            timestamp: commit.timestamp,
            url: commit.url,
          };

          newEvents.push(event);
          this.allEvents.push(event);
          watched.events.push(event);

          await this.writeMemory(`scout:event:${event.id}`, event);
        }

        watched.lastCommit = latestCommit;
        console.log(`[Scout] Found ${newEvents.length} new commits in ${repoId}`);
      }

      watched.lastChecked = Date.now();
    } catch (error) {
      console.error(`[Scout] Error polling ${repoId}:`, error);
    }

    return { hasChanges: newEvents.length > 0, events: newEvents };
  }

  /**
   * Trigger a security scan for an event
   */
  private async triggerScan(eventId: string): Promise<{ triggered: boolean; scanId?: string; error?: string }> {
    const event = this.allEvents.find(e => e.id === eventId);
    if (!event) {
      return { triggered: false, error: `Event ${eventId} not found` };
    }

    // If we have a scanner URL configured, call it via SLOP
    if (this.scannerUrl) {
      try {
        const result = await this.callAgent(this.scannerUrl, 'scan', {
          targetPath: event.repo,
          commit: event.commit,
          filesChanged: event.filesChanged,
          eventId: event.id,
        }) as { scanId: string };

        await this.writeMemory(`scout:scan:${eventId}`, {
          triggered: true,
          scanId: result.scanId,
          triggeredAt: Date.now(),
        });

        console.log(`[Scout] Triggered scan ${result.scanId} for event ${eventId}`);
        return { triggered: true, scanId: result.scanId };
      } catch (error) {
        return { triggered: false, error: String(error) };
      }
    }

    // No scanner configured, just record the intent
    await this.writeMemory(`scout:pending-scan:${eventId}`, {
      event,
      requestedAt: Date.now(),
    });

    return { triggered: false, error: 'No scanner URL configured' };
  }

  // ===== Helper Methods =====

  private parseRepoUrl(url: string): { provider: 'github' | 'gitlab' | 'bitbucket'; owner: string; repo: string } | null {
    // GitHub
    let match = url.match(/github\.com[\/:]([^\/]+)\/([^\/\.]+)/);
    if (match) {
      return { provider: 'github', owner: match[1], repo: match[2] };
    }

    // GitLab
    match = url.match(/gitlab\.com[\/:]([^\/]+)\/([^\/\.]+)/);
    if (match) {
      return { provider: 'gitlab', owner: match[1], repo: match[2] };
    }

    // Bitbucket
    match = url.match(/bitbucket\.org[\/:]([^\/]+)\/([^\/\.]+)/);
    if (match) {
      return { provider: 'bitbucket', owner: match[1], repo: match[2] };
    }

    return null;
  }

  private async getLatestCommit(repo: WatchedRepo): Promise<string | undefined> {
    if (repo.provider === 'github') {
      return this.getGitHubLatestCommit(repo);
    } else if (repo.provider === 'gitlab') {
      return this.getGitLabLatestCommit(repo);
    }
    return undefined;
  }

  private async getGitHubLatestCommit(repo: WatchedRepo): Promise<string | undefined> {
    const branch = repo.branch || 'main';
    const url = `https://api.github.com/repos/${repo.owner}/${repo.repo}/commits/${branch}`;

    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'AuraSecurity-Scout',
    };

    if (this.githubToken) {
      headers['Authorization'] = `token ${this.githubToken}`;
    }

    try {
      const response = await fetch(url, { headers });
      if (!response.ok) return undefined;

      const data = await response.json() as { sha: string };
      return data.sha;
    } catch {
      return undefined;
    }
  }

  private async getGitLabLatestCommit(repo: WatchedRepo): Promise<string | undefined> {
    const projectId = encodeURIComponent(`${repo.owner}/${repo.repo}`);
    const branch = repo.branch || 'main';
    const url = `https://gitlab.com/api/v4/projects/${projectId}/repository/branches/${branch}`;

    const headers: Record<string, string> = {};
    if (this.gitlabToken) {
      headers['PRIVATE-TOKEN'] = this.gitlabToken;
    }

    try {
      const response = await fetch(url, { headers });
      if (!response.ok) return undefined;

      const data = await response.json() as { commit: { id: string } };
      return data.commit?.id;
    } catch {
      return undefined;
    }
  }

  private async getCommitsSince(repo: WatchedRepo, sinceCommit?: string): Promise<Array<{
    sha: string;
    author: string;
    message: string;
    files: string[];
    additions: number;
    deletions: number;
    timestamp: number;
    url: string;
  }>> {
    if (repo.provider === 'github') {
      return this.getGitHubCommitsSince(repo, sinceCommit);
    }
    return [];
  }

  private async getGitHubCommitsSince(repo: WatchedRepo, sinceCommit?: string): Promise<Array<{
    sha: string;
    author: string;
    message: string;
    files: string[];
    additions: number;
    deletions: number;
    timestamp: number;
    url: string;
  }>> {
    const branch = repo.branch || 'main';
    let url = `https://api.github.com/repos/${repo.owner}/${repo.repo}/commits?sha=${branch}&per_page=10`;

    const headers: Record<string, string> = {
      'Accept': 'application/vnd.github.v3+json',
      'User-Agent': 'AuraSecurity-Scout',
    };

    if (this.githubToken) {
      headers['Authorization'] = `token ${this.githubToken}`;
    }

    try {
      const response = await fetch(url, { headers });
      if (!response.ok) return [];

      const commits = await response.json() as Array<{
        sha: string;
        commit: { author: { name: string; date: string }; message: string };
        html_url: string;
        stats?: { additions: number; deletions: number };
        files?: Array<{ filename: string }>;
      }>;

      const results = [];
      for (const commit of commits) {
        if (sinceCommit && commit.sha === sinceCommit) break;

        results.push({
          sha: commit.sha,
          author: commit.commit.author.name,
          message: commit.commit.message,
          files: commit.files?.map(f => f.filename) || [],
          additions: commit.stats?.additions || 0,
          deletions: commit.stats?.deletions || 0,
          timestamp: new Date(commit.commit.author.date).getTime(),
          url: commit.html_url,
        });
      }

      return results;
    } catch {
      return [];
    }
  }

  private parseGitHubWebhook(event: string, payload: Record<string, unknown>): CodeEvent | null {
    const eventId = `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    if (event === 'push') {
      const repository = payload.repository as { full_name: string; html_url: string } | undefined;
      const commits = payload.commits as Array<{
        id: string;
        message: string;
        author: { name: string };
        added: string[];
        modified: string[];
        removed: string[];
      }> | undefined;
      const ref = payload.ref as string | undefined;

      if (!repository || !commits || commits.length === 0) return null;

      const latestCommit = commits[commits.length - 1];
      const allFiles = new Set<string>();
      for (const commit of commits) {
        commit.added?.forEach(f => allFiles.add(f));
        commit.modified?.forEach(f => allFiles.add(f));
        commit.removed?.forEach(f => allFiles.add(f));
      }

      return {
        id: eventId,
        type: 'push',
        repo: `github:${repository.full_name}`,
        branch: ref?.replace('refs/heads/', '') || 'unknown',
        commit: latestCommit.id,
        author: latestCommit.author.name,
        message: latestCommit.message,
        filesChanged: Array.from(allFiles),
        additions: 0,
        deletions: 0,
        timestamp: Date.now(),
        url: `${repository.html_url}/commit/${latestCommit.id}`,
      };
    }

    if (event === 'pull_request') {
      const action = payload.action as string;
      const pr = payload.pull_request as {
        number: number;
        title: string;
        state: string;
        merged: boolean;
        head: { sha: string; ref: string };
        user: { login: string };
        html_url: string;
        additions: number;
        deletions: number;
        changed_files: number;
      } | undefined;
      const repository = payload.repository as { full_name: string } | undefined;

      if (!pr || !repository) return null;
      if (!['opened', 'synchronize', 'reopened'].includes(action)) return null;

      return {
        id: eventId,
        type: 'pull_request',
        repo: `github:${repository.full_name}`,
        branch: pr.head.ref,
        commit: pr.head.sha,
        author: pr.user.login,
        message: pr.title,
        filesChanged: [],
        additions: pr.additions,
        deletions: pr.deletions,
        timestamp: Date.now(),
        url: pr.html_url,
        prNumber: pr.number,
        prTitle: pr.title,
        prState: pr.merged ? 'merged' : pr.state as 'open' | 'closed',
      };
    }

    return null;
  }

  private parseGitLabWebhook(event: string, payload: Record<string, unknown>): CodeEvent | null {
    const eventId = `evt-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;

    if (event === 'Push Hook') {
      const project = payload.project as { path_with_namespace: string; web_url: string } | undefined;
      const commits = payload.commits as Array<{
        id: string;
        message: string;
        author: { name: string };
        added: string[];
        modified: string[];
        removed: string[];
      }> | undefined;
      const ref = payload.ref as string | undefined;

      if (!project || !commits || commits.length === 0) return null;

      const latestCommit = commits[commits.length - 1];
      const allFiles = new Set<string>();
      for (const commit of commits) {
        commit.added?.forEach(f => allFiles.add(f));
        commit.modified?.forEach(f => allFiles.add(f));
        commit.removed?.forEach(f => allFiles.add(f));
      }

      return {
        id: eventId,
        type: 'push',
        repo: `gitlab:${project.path_with_namespace}`,
        branch: ref?.replace('refs/heads/', '') || 'unknown',
        commit: latestCommit.id,
        author: latestCommit.author.name,
        message: latestCommit.message,
        filesChanged: Array.from(allFiles),
        additions: 0,
        deletions: 0,
        timestamp: Date.now(),
        url: `${project.web_url}/-/commit/${latestCommit.id}`,
      };
    }

    if (event === 'Merge Request Hook') {
      const action = (payload.object_attributes as { action?: string })?.action;
      const mr = payload.object_attributes as {
        iid: number;
        title: string;
        state: string;
        last_commit: { id: string };
        source_branch: string;
        url: string;
      } | undefined;
      const user = payload.user as { name: string } | undefined;
      const project = payload.project as { path_with_namespace: string } | undefined;

      if (!mr || !user || !project) return null;
      if (!['open', 'reopen', 'update'].includes(action || '')) return null;

      return {
        id: eventId,
        type: 'merge_request',
        repo: `gitlab:${project.path_with_namespace}`,
        branch: mr.source_branch,
        commit: mr.last_commit.id,
        author: user.name,
        message: mr.title,
        filesChanged: [],
        additions: 0,
        deletions: 0,
        timestamp: Date.now(),
        url: mr.url,
        prNumber: mr.iid,
        prTitle: mr.title,
        prState: mr.state as 'open' | 'closed' | 'merged',
      };
    }

    return null;
  }

  /**
   * Clean up on shutdown
   */
  async stop(): Promise<void> {
    // Clear all polling timers
    for (const timer of this.pollTimers.values()) {
      clearInterval(timer);
    }
    this.pollTimers.clear();

    await super.stop();
  }
}

// Export factory function
export function createScoutAgent(port = 3010, coordinatorUrl?: string): ScoutAgent {
  return new ScoutAgent({
    id: 'scout',
    name: 'Scout Agent',
    port,
    description: 'Watches repositories for code changes and triggers security scans',
    coordinatorUrl,
  });
}
