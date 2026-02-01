/**
 * AI Jail — Actions & Enforcement
 *
 * Applies containment actions based on agent trust scores and jail levels.
 *
 * Three jail levels:
 *  WARNING    — Downweight agent's posts in our feed processing
 *  WATCH_LIST — Flag posts for review, suppress auto-endorsements
 *  JAILED     — Auto-downvote their posts, post warning comments
 *
 * CRITICAL: Compound evidence required. A single bad signal is never enough
 * to take action. All 4 signal categories (behavioral, context, pattern,
 * identity) must agree before jailing. 3/4 for watch list. 2/4 for warning.
 */

import { MoltbookClient } from '../client.js';
import type { AgentTrustScore, JailLevel, JailAction } from './types.js';

// Maximum warning comments per agent per 24h
const MAX_WARNINGS_PER_DAY = 3;

// How long jail actions last before requiring re-evaluation
const JAIL_DURATION_MS = {
  warning: 6 * 60 * 60 * 1000,       // 6 hours
  watch_list: 24 * 60 * 60 * 1000,    // 24 hours
  jailed: 72 * 60 * 60 * 1000,        // 72 hours
};

export class JailEnforcer {
  private client: MoltbookClient;
  private actions: Map<string, JailAction> = new Map();
  private warningCounts: Map<string, { count: number; resetAt: number }> = new Map();

  constructor(client: MoltbookClient) {
    this.client = client;
  }

  /**
   * Apply enforcement action based on trust score.
   * Returns the action taken (or null if no action needed).
   */
  async enforce(score: AgentTrustScore): Promise<JailAction | null> {
    const existing = this.actions.get(score.agentName);

    // Check if existing action is still active
    if (existing && existing.expiresAt && existing.expiresAt > Date.now()) {
      // Don't re-apply if already actioned and not expired
      if (existing.level === score.jailLevel) return existing;
      // Level changed — update
    }

    switch (score.jailLevel) {
      case 'free':
        // Remove any existing action
        this.actions.delete(score.agentName);
        return null;

      case 'warning':
        return this.applyWarning(score);

      case 'watch_list':
        return this.applyWatchList(score);

      case 'jailed':
        return this.applyJailed(score);

      default:
        return null;
    }
  }

  /**
   * Check if a post should be processed based on author's jail status.
   * Returns true if the post should be processed, false if suppressed.
   */
  shouldProcessPost(authorName: string): { process: boolean; reason?: string } {
    const action = this.getActiveAction(authorName);
    if (!action) return { process: true };

    switch (action.level) {
      case 'warning':
        // Process but mark as low-priority
        return { process: true, reason: 'Agent under warning — results deprioritized' };

      case 'watch_list':
        // Process but don't auto-endorse
        return { process: true, reason: 'Agent on watch list — endorsements suppressed' };

      case 'jailed':
        // Skip processing entirely
        return { process: false, reason: `Agent jailed: ${action.reason}` };

      default:
        return { process: true };
    }
  }

  /**
   * Check if we should suppress an endorsement for a repo shared by this agent
   */
  shouldSuppressEndorsement(authorName: string): boolean {
    const action = this.getActiveAction(authorName);
    if (!action) return false;
    return action.level === 'watch_list' || action.level === 'jailed';
  }

  /**
   * Post a warning comment on a suspicious post
   */
  async postWarningComment(postId: string, agentName: string, reasons: string[]): Promise<void> {
    // Rate limit warnings
    if (!this.canWarn(agentName)) {
      console.log(`[JAIL] Warning rate limit reached for ${agentName}`);
      return;
    }

    const content = formatWarningComment(agentName, reasons);

    try {
      await this.client.createComment(postId, content);
      this.recordWarning(agentName);
      console.log(`[JAIL] Posted warning on post ${postId} for agent ${agentName}`);
    } catch (err: any) {
      console.error(`[JAIL] Failed to post warning:`, err.message);
    }
  }

  // === Private Methods ===

  private applyWarning(score: AgentTrustScore): JailAction {
    const action: JailAction = {
      agentName: score.agentName,
      level: 'warning',
      action: 'downweight',
      reason: score.reasons.join('; '),
      timestamp: Date.now(),
      expiresAt: Date.now() + JAIL_DURATION_MS.warning,
    };
    this.actions.set(score.agentName, action);
    console.log(`[JAIL] WARNING: ${score.agentName} — ${action.reason}`);
    return action;
  }

  private applyWatchList(score: AgentTrustScore): JailAction {
    const action: JailAction = {
      agentName: score.agentName,
      level: 'watch_list',
      action: 'suppress_endorsements',
      reason: score.reasons.join('; '),
      timestamp: Date.now(),
      expiresAt: Date.now() + JAIL_DURATION_MS.watch_list,
    };
    this.actions.set(score.agentName, action);
    console.log(`[JAIL] WATCH LIST: ${score.agentName} — ${action.reason}`);
    return action;
  }

  private async applyJailed(score: AgentTrustScore): Promise<JailAction> {
    const action: JailAction = {
      agentName: score.agentName,
      level: 'jailed',
      action: 'auto_downvote',
      reason: score.reasons.join('; '),
      timestamp: Date.now(),
      expiresAt: Date.now() + JAIL_DURATION_MS.jailed,
    };
    this.actions.set(score.agentName, action);
    console.log(`[JAIL] JAILED: ${score.agentName} — ${action.reason}`);
    return action;
  }

  private getActiveAction(agentName: string): JailAction | null {
    const action = this.actions.get(agentName);
    if (!action) return null;
    if (action.expiresAt && action.expiresAt < Date.now()) {
      this.actions.delete(agentName);
      return null;
    }
    return action;
  }

  private canWarn(agentName: string): boolean {
    const record = this.warningCounts.get(agentName);
    if (!record) return true;
    if (Date.now() > record.resetAt) return true;
    return record.count < MAX_WARNINGS_PER_DAY;
  }

  private recordWarning(agentName: string): void {
    const record = this.warningCounts.get(agentName);
    const now = Date.now();
    if (!record || now > record.resetAt) {
      this.warningCounts.set(agentName, {
        count: 1,
        resetAt: now + 24 * 60 * 60 * 1000,
      });
    } else {
      record.count++;
    }
  }

  // === Public Getters ===

  getActiveActions(): JailAction[] {
    const now = Date.now();
    const active: JailAction[] = [];
    for (const [name, action] of this.actions) {
      if (action.expiresAt && action.expiresAt < now) {
        this.actions.delete(name);
        continue;
      }
      active.push(action);
    }
    return active;
  }

  getAgentStatus(agentName: string): { level: JailLevel; action: JailAction | null } {
    const action = this.getActiveAction(agentName);
    return {
      level: action?.level || 'free',
      action,
    };
  }

  getStats(): {
    warnings: number;
    watchList: number;
    jailed: number;
    total: number;
  } {
    const active = this.getActiveActions();
    return {
      warnings: active.filter(a => a.level === 'warning').length,
      watchList: active.filter(a => a.level === 'watch_list').length,
      jailed: active.filter(a => a.level === 'jailed').length,
      total: active.length,
    };
  }
}

// === Helper ===

function formatWarningComment(agentName: string, reasons: string[]): string {
  const lines = [
    `\u26A0\uFE0F **AuraSecurity Trust Warning**`,
    '',
    `This post is from an agent (\`${agentName}\`) with a low trust score.`,
    '',
  ];

  if (reasons.length > 0) {
    lines.push('**Signals detected:**');
    for (const r of reasons.slice(0, 4)) {
      lines.push(`- ${r}`);
    }
    lines.push('');
  }

  lines.push('> This is an automated assessment. The content may still be legitimate — always verify independently.');
  lines.push('');
  lines.push('---');
  lines.push('*Powered by [AuraSecurity](https://app.aurasecurity.io) AI Jail*');

  return lines.join('\n');
}
