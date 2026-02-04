/**
 * Moltbook API Client
 *
 * Wraps the Moltbook REST API for agent registration, posting, commenting,
 * feed reading, and submolt management.
 *
 * API Base: https://www.moltbook.com/api/v1
 * Auth: Bearer token from agent registration
 */

import type {
  MoltbookAgent,
  MoltbookPost,
  MoltbookComment,
  MoltbookSubmolt,
  MoltbookRegisterResponse,
  MoltbookFeedResponse,
} from './types.js';

const BASE_URL = 'https://www.moltbook.com/api/v1';
const USER_AGENT = 'AuraSecurityBot/1.0';
const REQUEST_TIMEOUT = 15_000; // 15 seconds

export class MoltbookClient {
  private apiKey: string;
  private rateLimitResetAt: number = 0;
  private postQueue: Array<{ fn: () => Promise<any>; resolve: (v: any) => void; reject: (e: any) => void }> = [];
  private isProcessingQueue: boolean = false;
  private minPostIntervalMs: number = 5_000; // 5s between posts
  private lastPostTime: number = 0;

  constructor(apiKey: string = '') {
    this.apiKey = apiKey;
  }

  setApiKey(key: string): void {
    this.apiKey = key;
  }

  // === Core Request Method ===

  private async request<T>(
    method: string,
    path: string,
    body?: Record<string, any>,
    requiresAuth: boolean = true
  ): Promise<T> {
    // Respect rate limits
    if (this.rateLimitResetAt > Date.now()) {
      const waitMs = this.rateLimitResetAt - Date.now();
      console.log(`[MOLTBOOK] Rate limited, waiting ${Math.ceil(waitMs / 1000)}s`);
      await new Promise(r => setTimeout(r, waitMs));
    }

    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': USER_AGENT,
    };

    if (requiresAuth && this.apiKey) {
      headers['Authorization'] = `Bearer ${this.apiKey}`;
    }

    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT);

    try {
      const response = await fetch(`${BASE_URL}${path}`, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        signal: controller.signal,
      });

      // Handle rate limiting - wait and retry once
      if (response.status === 429) {
        const retryAfter = parseInt(response.headers.get('retry-after') || '60');
        this.rateLimitResetAt = Date.now() + retryAfter * 1000;
        console.log(`[MOLTBOOK] Rate limited, backing off ${retryAfter}s before retry`);
        await new Promise(r => setTimeout(r, retryAfter * 1000));
        // Retry once after waiting
        const retryResponse = await fetch(`${BASE_URL}${path}`, {
          method,
          headers,
          body: body ? JSON.stringify(body) : undefined,
          signal: AbortSignal.timeout(REQUEST_TIMEOUT),
        });
        if (!retryResponse.ok) {
          const text = await retryResponse.text().catch(() => '');
          throw new Error(`Moltbook API ${retryResponse.status} after retry: ${text.slice(0, 200)}`);
        }
        this.lastPostTime = Date.now();
        return await retryResponse.json() as T;
      }

      if (!response.ok) {
        const text = await response.text().catch(() => '');
        throw new Error(`Moltbook API ${response.status}: ${text.slice(0, 200)}`);
      }

      return await response.json() as T;
    } catch (err: any) {
      if (err.name === 'AbortError') {
        throw new Error(`Moltbook API timeout (${REQUEST_TIMEOUT}ms)`);
      }
      throw err;
    } finally {
      clearTimeout(timeout);
    }
  }

  // === Agent Management ===

  async register(name: string, description: string): Promise<MoltbookRegisterResponse> {
    return this.request<MoltbookRegisterResponse>('POST', '/agents/register', {
      name,
      description,
    }, false);
  }

  async getMyProfile(): Promise<MoltbookAgent> {
    const res = await this.request<{ agent: MoltbookAgent }>('GET', '/agents/me');
    return res.agent;
  }

  async getAgentProfile(name: string): Promise<MoltbookAgent | null> {
    try {
      const res = await this.request<{ agent: MoltbookAgent }>('GET', `/agents/profile?name=${encodeURIComponent(name)}`);
      return res.agent;
    } catch {
      return null;
    }
  }

  // === Posts ===

  private async throttlePost(): Promise<void> {
    const elapsed = Date.now() - this.lastPostTime;
    if (elapsed < this.minPostIntervalMs) {
      const wait = this.minPostIntervalMs - elapsed;
      await new Promise(r => setTimeout(r, wait));
    }
    this.lastPostTime = Date.now();
  }

  async createTextPost(submolt: string, title: string, content: string): Promise<MoltbookPost> {
    await this.throttlePost();
    const res = await this.request<{ post: MoltbookPost }>('POST', '/posts', {
      submolt,
      title,
      content,
    });
    return res.post;
  }

  async createLinkPost(submolt: string, title: string, url: string): Promise<MoltbookPost> {
    const res = await this.request<{ post: MoltbookPost }>('POST', '/posts', {
      submolt,
      title,
      url,
    });
    return res.post;
  }

  async getPost(postId: string): Promise<MoltbookPost | null> {
    try {
      const res = await this.request<{ post: MoltbookPost }>('GET', `/posts/${postId}`, undefined, false);
      return res.post;
    } catch {
      return null;
    }
  }

  // === Comments ===

  async createComment(postId: string, content: string, parentId?: string): Promise<MoltbookComment> {
    await this.throttlePost();
    const body: Record<string, string> = { content };
    if (parentId) body.parent_id = parentId;

    const res = await this.request<{ comment: MoltbookComment }>('POST', `/posts/${postId}/comments`, body);
    return res.comment;
  }

  async getComments(postId: string, sort: string = 'new'): Promise<MoltbookComment[]> {
    const res = await this.request<{ comments: MoltbookComment[] }>(
      'GET', `/posts/${postId}/comments?sort=${sort}`, undefined, false
    );
    return res.comments || [];
  }

  // === Voting ===

  async upvotePost(postId: string): Promise<void> {
    await this.request<any>('POST', `/posts/${postId}/upvote`);
  }

  async downvotePost(postId: string): Promise<void> {
    await this.request<any>('POST', `/posts/${postId}/downvote`);
  }

  // === Submolts ===

  async createSubmolt(name: string, displayName: string, description: string): Promise<MoltbookSubmolt> {
    const res = await this.request<{ submolt: MoltbookSubmolt }>('POST', '/submolts', {
      name,
      display_name: displayName,
      description,
    });
    return res.submolt;
  }

  async listSubmolts(): Promise<MoltbookSubmolt[]> {
    const res = await this.request<{ submolts: MoltbookSubmolt[] }>('GET', '/submolts', undefined, false);
    return res.submolts || [];
  }

  async subscribeToSubmolt(name: string): Promise<void> {
    await this.request<any>('POST', `/submolts/${encodeURIComponent(name)}/subscribe`);
  }

  // === Feed & Search ===

  async getFeed(sort: string = 'new', limit: number = 25): Promise<MoltbookPost[]> {
    const res = await this.request<MoltbookFeedResponse>(
      'GET', `/feed?sort=${sort}&limit=${limit}`
    );
    return res.posts || [];
  }

  async getSubmoltPosts(submoltName: string, sort: string = 'new', limit: number = 25): Promise<MoltbookPost[]> {
    try {
      const res = await this.request<{ posts: MoltbookPost[] }>(
        'GET', `/submolts/${encodeURIComponent(submoltName)}/posts?sort=${sort}&limit=${limit}`,
        undefined, false
      );
      return res.posts || [];
    } catch {
      return [];
    }
  }

  async search(query: string, limit: number = 25): Promise<MoltbookPost[]> {
    const res = await this.request<{ posts: MoltbookPost[] }>(
      'GET', `/search?q=${encodeURIComponent(query)}&limit=${limit}`,
      undefined, false
    );
    return res.posts || [];
  }

  // === Social ===

  async followAgent(name: string): Promise<void> {
    await this.request<any>('POST', `/agents/${encodeURIComponent(name)}/follow`);
  }

  async unfollowAgent(name: string): Promise<void> {
    await this.request<any>('DELETE', `/agents/${encodeURIComponent(name)}/follow`);
  }
}
