/**
 * AI Jail — Agent Trust Scorer
 *
 * Computes a trust score for Moltbook agents based on 4 signal categories:
 *  1. Identity  — account age, verification, karma, engagement
 *  2. Behavior  — posting frequency, repo repetition, cross-posting
 *  3. Network   — bot cluster membership, coordination signals
 *  4. Content   — false positive rate, endorsed scams, spam patterns
 *
 * Each category scores 0-100. Overall score is a weighted average.
 * Jail level is determined by overall score + compound evidence.
 */

import type {
  AgentTrustScore,
  IdentitySignal,
  BehaviorSignal,
  NetworkSignal,
  ContentSignal,
  JailLevel,
  CompoundEvidence,
} from './types.js';
import type { MoltbookAgent } from '../types.js';
import type { AgentActivity } from '../monitor.js';

// Weights for overall score calculation
const WEIGHTS = {
  identity: 0.2,
  behavior: 0.3,
  network: 0.25,
  content: 0.25,
};

// Thresholds for jail levels
const JAIL_THRESHOLDS = {
  warning: 45,     // Below this = warning
  watchList: 30,   // Below this = watch list
  jailed: 15,      // Below this = jailed
};

export class AgentScorer {
  /**
   * Compute full trust score for an agent
   */
  score(
    profile: MoltbookAgent,
    activity: AgentActivity | null,
    networkData?: { clusterSize: number; coordinationScore: number; sharedRepoOverlap: number; creationTimeSimilarity: number },
    contentData?: { flaggedRepos: number; endorsedScams: number; falsePositiveRate: number; spamPatternScore: number },
  ): AgentTrustScore {
    const identity = this.scoreIdentity(profile);
    const behavior = this.scoreBehavior(profile, activity);
    const network = this.scoreNetwork(networkData);
    const content = this.scoreContent(activity, contentData);

    const overallScore = Math.round(
      identity.score * WEIGHTS.identity +
      behavior.score * WEIGHTS.behavior +
      network.score * WEIGHTS.network +
      content.score * WEIGHTS.content
    );

    const reasons: string[] = [];
    const evidence = this.buildEvidence(identity, behavior, network, content);
    const jailLevel = this.determineJailLevel(overallScore, evidence, reasons);

    return {
      agentName: profile.name,
      overallScore,
      identity,
      behavior,
      network,
      content,
      jailLevel,
      reasons,
      computedAt: new Date().toISOString(),
    };
  }

  // === Identity Signal ===

  private scoreIdentity(profile: MoltbookAgent): IdentitySignal {
    const accountAgeDays = Math.max(0,
      (Date.now() - new Date(profile.created_at).getTime()) / (1000 * 60 * 60 * 24)
    );

    let score = 50; // baseline

    // Account age bonus (max +20)
    if (accountAgeDays >= 30) score += 10;
    if (accountAgeDays >= 90) score += 5;
    if (accountAgeDays >= 180) score += 5;
    // Brand new account penalty
    if (accountAgeDays < 3) score -= 20;
    else if (accountAgeDays < 7) score -= 10;

    // Verification bonus
    if (profile.verified) score += 15;

    // Karma signal
    if (profile.karma > 100) score += 5;
    if (profile.karma > 500) score += 5;
    if (profile.karma < 0) score -= 15;
    if (profile.karma < -50) score -= 10;

    // Engagement
    if (profile.follower_count >= 10) score += 5;
    if (profile.post_count + profile.comment_count >= 20) score += 5;
    // Suspicious: many posts but zero engagement
    if (profile.post_count > 50 && profile.follower_count === 0) score -= 10;

    return {
      score: clamp(score),
      accountAgeDays: Math.round(accountAgeDays),
      verified: profile.verified,
      karma: profile.karma,
      postCount: profile.post_count,
      commentCount: profile.comment_count,
      followerCount: profile.follower_count,
    };
  }

  // === Behavior Signal ===

  private scoreBehavior(profile: MoltbookAgent, activity: AgentActivity | null): BehaviorSignal {
    if (!activity) {
      // No tracked activity — neutral score
      return {
        score: 60,
        postFrequency: 0,
        repoRepeatRate: 0,
        crossPostRate: 0,
        engagementRatio: 0,
      };
    }

    let score = 70; // baseline (assume good behavior)

    // Post frequency (posts per hour over last observation window)
    const observationHours = Math.max(1,
      (Date.now() - Math.min(...[...activity.reposShared.values()].map(r => r.firstSeen), Date.now())) / (1000 * 60 * 60)
    );
    const postFrequency = activity.totalPosts / observationHours;

    // Spam-like posting frequency
    if (postFrequency > 10) score -= 30;
    else if (postFrequency > 5) score -= 15;
    else if (postFrequency > 2) score -= 5;

    // Repo repeat rate: how often they re-share the same repo
    let totalShares = 0;
    let repeatedShares = 0;
    for (const [, data] of activity.reposShared) {
      totalShares += data.count;
      if (data.count > 1) repeatedShares += data.count - 1;
    }
    const repoRepeatRate = totalShares > 0 ? repeatedShares / totalShares : 0;
    if (repoRepeatRate > 0.5) score -= 20;
    else if (repoRepeatRate > 0.3) score -= 10;

    // Cross-post rate: repos shared in 3+ submolts
    let crossPosted = 0;
    for (const [, data] of activity.reposShared) {
      if (data.submolts.size >= 3) crossPosted++;
    }
    const crossPostRate = activity.reposShared.size > 0 ? crossPosted / activity.reposShared.size : 0;
    if (crossPostRate > 0.5) score -= 20;
    else if (crossPostRate > 0.2) score -= 10;

    return {
      score: clamp(score),
      postFrequency: Math.round(postFrequency * 100) / 100,
      repoRepeatRate: Math.round(repoRepeatRate * 100) / 100,
      crossPostRate: Math.round(crossPostRate * 100) / 100,
      engagementRatio: 0, // Would need upvote data from API
    };
  }

  // === Network Signal ===

  private scoreNetwork(
    data?: { clusterSize: number; coordinationScore: number; sharedRepoOverlap: number; creationTimeSimilarity: number }
  ): NetworkSignal {
    if (!data) {
      return { score: 70, clusterSize: 0, coordinationScore: 0, sharedRepoOverlap: 0, creationTimeSimilarity: 0 };
    }

    let score = 80; // baseline

    // Cluster membership penalty
    if (data.clusterSize >= 10) score -= 30;
    else if (data.clusterSize >= 5) score -= 20;
    else if (data.clusterSize >= 3) score -= 10;

    // Coordination with others
    if (data.coordinationScore > 0.8) score -= 25;
    else if (data.coordinationScore > 0.5) score -= 15;

    // Shared repo overlap with cluster
    if (data.sharedRepoOverlap > 0.7) score -= 20;
    else if (data.sharedRepoOverlap > 0.4) score -= 10;

    // Account creation timing
    if (data.creationTimeSimilarity > 0.9) score -= 15;

    return {
      score: clamp(score),
      clusterSize: data.clusterSize,
      coordinationScore: data.coordinationScore,
      sharedRepoOverlap: data.sharedRepoOverlap,
      creationTimeSimilarity: data.creationTimeSimilarity,
    };
  }

  // === Content Signal ===

  private scoreContent(
    activity: AgentActivity | null,
    data?: { flaggedRepos: number; endorsedScams: number; falsePositiveRate: number; spamPatternScore: number }
  ): ContentSignal {
    const uniqueRepos = activity?.reposShared.size ?? 0;

    if (!data) {
      return {
        score: 65,
        uniqueRepos,
        flaggedRepos: 0,
        endorsedScams: 0,
        falsePositiveRate: 0,
        spamPatternScore: 0,
      };
    }

    let score = 75; // baseline

    // Endorsed scams: agent promoted repos that were later flagged
    if (data.endorsedScams >= 5) score -= 35;
    else if (data.endorsedScams >= 3) score -= 25;
    else if (data.endorsedScams >= 1) score -= 15;

    // High ratio of flagged repos
    if (uniqueRepos > 0) {
      const flaggedRatio = data.flaggedRepos / uniqueRepos;
      if (flaggedRatio > 0.5) score -= 20;
      else if (flaggedRatio > 0.3) score -= 10;
    }

    // Spam pattern (template-like posting)
    if (data.spamPatternScore > 0.8) score -= 20;
    else if (data.spamPatternScore > 0.5) score -= 10;

    return {
      score: clamp(score),
      uniqueRepos,
      flaggedRepos: data.flaggedRepos,
      endorsedScams: data.endorsedScams,
      falsePositiveRate: data.falsePositiveRate,
      spamPatternScore: data.spamPatternScore,
    };
  }

  // === Compound Evidence & Jail Level ===

  private buildEvidence(
    identity: IdentitySignal,
    behavior: BehaviorSignal,
    network: NetworkSignal,
    content: ContentSignal,
  ): CompoundEvidence {
    return {
      behavioral: behavior.score < 40,
      context: content.score < 40,
      pattern: network.score < 40,
      identity: identity.score < 40,
      allTriggered: behavior.score < 40 && content.score < 40 && network.score < 40 && identity.score < 40,
    };
  }

  private determineJailLevel(
    overallScore: number,
    evidence: CompoundEvidence,
    reasons: string[]
  ): JailLevel {
    // COMPOUND EVIDENCE REQUIRED for jailing
    // Score alone is not enough — multiple signal categories must agree

    if (overallScore <= JAIL_THRESHOLDS.jailed && evidence.allTriggered) {
      reasons.push('All 4 signal categories flagged this agent');
      reasons.push(`Overall score: ${overallScore}/100`);
      return 'jailed';
    }

    if (overallScore <= JAIL_THRESHOLDS.watchList) {
      // Need at least 3 out of 4 signals to watch-list
      const triggered = [evidence.behavioral, evidence.context, evidence.pattern, evidence.identity]
        .filter(Boolean).length;
      if (triggered >= 3) {
        reasons.push(`${triggered}/4 signal categories flagged`);
        reasons.push(`Overall score: ${overallScore}/100`);
        return 'watch_list';
      }
      // Only 1-2 signals — just warn
      reasons.push(`Score below threshold but only ${triggered}/4 signals triggered — warning only`);
      return 'warning';
    }

    if (overallScore <= JAIL_THRESHOLDS.warning) {
      const triggered = [evidence.behavioral, evidence.context, evidence.pattern, evidence.identity]
        .filter(Boolean).length;
      if (triggered >= 2) {
        reasons.push(`${triggered}/4 signal categories flagged`);
        return 'warning';
      }
    }

    return 'free';
  }
}

function clamp(score: number): number {
  return Math.max(0, Math.min(100, Math.round(score)));
}
