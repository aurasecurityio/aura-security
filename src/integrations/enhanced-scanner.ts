/**
 * Enhanced Scanner - Wraps existing scanners with rug database intelligence
 *
 * This layer ADDS to existing scans without modifying original logic.
 * If rug database fails, original scan still works.
 */

import { performTrustScan, type TrustScanResult, type TrustCheck } from './trust-scanner.js';
import {
  isKnownRug,
  hasOwnerRuggedBefore,
  isDevFlagged,
  isForkedFromScam,
  recordScan,
  getDevReputation,
  updateDevReputation,
  type DevReputation
} from './rug-database.js';

export interface EnhancedTrustResult extends TrustScanResult {
  // Additional intelligence from rug database
  rugDbEnhanced: boolean;
  knownRug: boolean;
  ownerHistory: {
    hasRuggedBefore: boolean;
    rugCount: number;
    previousRugs: string[];
  };
  devReputation: DevReputation | null;
  forkedFromScam: boolean;
  forkedScamRepo?: string;
  // Adjusted score after rug database checks
  adjustedScore: number;
  adjustedVerdict: string;
  adjustedVerdictEmoji: string;
  // New checks added by rug database
  rugDbChecks: TrustCheck[];
}

/**
 * Run trust scan with rug database enhancement
 *
 * This runs the original scan, then enhances it with rug database intelligence.
 * If rug database fails at any point, returns original scan unchanged.
 */
export async function performEnhancedTrustScan(gitUrl: string): Promise<EnhancedTrustResult> {
  // Step 1: Run original scan (this never changes)
  const originalResult = await performTrustScan(gitUrl);

  // Step 2: Try to enhance with rug database (graceful failure)
  try {
    return await enhanceWithRugDb(originalResult);
  } catch (err) {
    console.error('[ENHANCED] Rug database enhancement failed, using original scan:', err);
    // Return original result with enhancement flags set to false
    return {
      ...originalResult,
      rugDbEnhanced: false,
      knownRug: false,
      ownerHistory: { hasRuggedBefore: false, rugCount: 0, previousRugs: [] },
      devReputation: null,
      forkedFromScam: false,
      adjustedScore: originalResult.trustScore,
      adjustedVerdict: originalResult.verdict,
      adjustedVerdictEmoji: originalResult.verdictEmoji,
      rugDbChecks: []
    };
  }
}

/**
 * Enhance scan result with rug database intelligence
 */
async function enhanceWithRugDb(result: TrustScanResult): Promise<EnhancedTrustResult> {
  const rugDbChecks: TrustCheck[] = [];
  let scoreAdjustment = 0;

  // 1. Check if this exact repo is a known rug
  const knownRugCheck = isKnownRug(result.url);
  const knownRug = knownRugCheck.isRug;

  if (knownRug) {
    rugDbChecks.push({
      id: 'known_rug',
      name: 'Known Rug',
      status: 'bad',
      points: -100,
      explanation: `CONFIRMED RUG: This repo was reported as a rug pull`
    });
    scoreAdjustment -= 100; // Instant fail
  }

  // 2. Check if owner has rugged before
  const ownerHistoryRaw = hasOwnerRuggedBefore(result.owner);
  const ownerHistory = {
    hasRuggedBefore: ownerHistoryRaw.hasRugged,
    rugCount: ownerHistoryRaw.rugCount,
    previousRugs: ownerHistoryRaw.repos
  };

  if (ownerHistory.hasRuggedBefore) {
    const severity = ownerHistory.rugCount >= 2 ? 'bad' : 'warn';
    const points = ownerHistory.rugCount >= 2 ? -50 : -25;

    rugDbChecks.push({
      id: 'owner_history',
      name: 'Owner History',
      status: severity,
      points,
      explanation: `Owner has ${ownerHistory.rugCount} previous rug(s): ${ownerHistory.previousRugs.slice(0, 2).join(', ')}`
    });
    scoreAdjustment += points;
  }

  // 3. Check if developer is flagged
  const devFlagged = isDevFlagged(result.owner);

  if (devFlagged.flagged) {
    rugDbChecks.push({
      id: 'dev_flagged',
      name: 'Flagged Developer',
      status: 'bad',
      points: -40,
      explanation: `Developer flagged: ${devFlagged.reason || 'Known bad actor'}`
    });
    scoreAdjustment -= 40;
  }

  // 4. Check if forked from known scam
  let forkedFromScam = false;
  let forkedScamRepo: string | undefined;

  if (result.metrics.isFork && result.metrics.forkParentRepo) {
    const forkCheck = isForkedFromScam(`https://github.com/${result.metrics.forkParentRepo}`);
    if (forkCheck.isScam) {
      forkedFromScam = true;
      forkedScamRepo = result.metrics.forkParentRepo;

      rugDbChecks.push({
        id: 'forked_from_scam',
        name: 'Forked From Scam',
        status: 'bad',
        points: -60,
        explanation: `Forked from known scam repo: ${forkedScamRepo}`
      });
      scoreAdjustment -= 60;
    }
  }

  // 5. Get developer reputation (for info, positive signals too)
  const devReputation = getDevReputation(result.owner);

  if (devReputation) {
    if (devReputation.safeRepos >= 3 && devReputation.ruggedRepos === 0) {
      rugDbChecks.push({
        id: 'dev_reputation_good',
        name: 'Developer Track Record',
        status: 'good',
        points: 10,
        explanation: `Developer has ${devReputation.safeRepos} safe repos, no rugs`
      });
      scoreAdjustment += 10;
    } else if (devReputation.reputationScore < 30) {
      rugDbChecks.push({
        id: 'dev_reputation_bad',
        name: 'Developer Track Record',
        status: 'warn',
        points: -15,
        explanation: `Low developer reputation score: ${devReputation.reputationScore}/100`
      });
      scoreAdjustment -= 15;
    }
  }

  // Calculate adjusted score
  let adjustedScore = Math.max(0, Math.min(100, result.trustScore + scoreAdjustment));

  // If known rug, force score to 0
  if (knownRug) {
    adjustedScore = 0;
  }

  // Determine adjusted verdict
  let adjustedVerdict: string;
  let adjustedVerdictEmoji: string;

  if (knownRug) {
    adjustedVerdict = 'CONFIRMED RUG';
    adjustedVerdictEmoji = '💀';
  } else if (adjustedScore >= 80) {
    adjustedVerdict = 'SAFU';
    adjustedVerdictEmoji = '🟢';
  } else if (adjustedScore >= 60) {
    adjustedVerdict = 'DYOR';
    adjustedVerdictEmoji = '🟡';
  } else if (adjustedScore >= 35) {
    adjustedVerdict = 'RISKY';
    adjustedVerdictEmoji = '🟠';
  } else {
    adjustedVerdict = 'RUG ALERT';
    adjustedVerdictEmoji = '🔴';
  }

  // Record this scan for future feedback
  recordScan(result.url, adjustedScore, adjustedVerdict);

  // Track this developer (just scanned, outcome unknown yet)
  updateDevReputation(result.owner, 'scanned');

  return {
    ...result,
    rugDbEnhanced: true,
    knownRug,
    ownerHistory,
    devReputation,
    forkedFromScam,
    forkedScamRepo,
    adjustedScore,
    adjustedVerdict,
    adjustedVerdictEmoji,
    rugDbChecks,
    // Override the main score/verdict with adjusted values
    trustScore: adjustedScore,
    verdict: adjustedVerdict as any,
    verdictEmoji: adjustedVerdictEmoji,
    // Merge rug database checks into main checks
    checks: [...result.checks, ...rugDbChecks]
  };
}

/**
 * Quick check if a repo/owner has red flags in rug database
 * Use this for fast pre-checks without running full scan
 */
export function quickRugDbCheck(owner: string, repoUrl?: string): {
  hasRedFlags: boolean;
  flags: string[];
} {
  const flags: string[] = [];

  try {
    // Check owner history
    const ownerHistory = hasOwnerRuggedBefore(owner);
    if (ownerHistory.hasRugged) {
      flags.push(`Owner rugged ${ownerHistory.rugCount} time(s) before`);
    }

    // Check if dev is flagged
    const devFlagged = isDevFlagged(owner);
    if (devFlagged.flagged) {
      flags.push(`Developer flagged: ${devFlagged.reason}`);
    }

    // Check if this specific repo is known rug
    if (repoUrl) {
      const knownRug = isKnownRug(repoUrl);
      if (knownRug.isRug) {
        flags.push('Repo is a confirmed rug');
      }
    }
  } catch {
    // Silently fail - rug database is optional enhancement
  }

  return {
    hasRedFlags: flags.length > 0,
    flags
  };
}
