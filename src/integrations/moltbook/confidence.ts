/**
 * Confidence Gate
 *
 * Decides whether and how to post scan results based on cross-validation
 * between trust-scan and scam-scan. Prevents false positives from reaching
 * Moltbook by requiring agreement between scanners.
 *
 * Decision matrix:
 *   Both scanners agree bad  → HIGH confidence WARNING
 *   Both scanners agree good → HIGH confidence ENDORSEMENT
 *   Scanners disagree        → MEDIUM confidence REPORT with caveats
 *   Only one scanner ran     → LOW confidence REPORT with caveat
 *   Both failed              → SKIP (don't post)
 */

import type { PostDecision } from './types.js';

// Thresholds for score interpretation
const SCORE_BAD = 35;       // Below this = likely dangerous
const SCORE_CAUTION = 55;   // Below this = needs caution
const SCORE_GOOD = 75;      // Above this = looks safe
const SCORE_EXCELLENT = 90; // Above this = highly trusted

// How far apart scores can be before we call it "disagreement"
const DISAGREEMENT_THRESHOLD = 25;

// Red flags that should always suppress endorsement
const HARD_BLOCK_FLAGS = [
  'wallet drainer',
  'rug pull',
  'honeypot',
  'private key exfiltration',
  'obfuscated eval',
  'hidden admin',
  'backdoor',
];

// Flags that are often false positives — suppress in low-confidence posts
const NOISY_FLAGS = [
  'no license file',
  'low star count',
  'new repository',
  'few contributors',
];

export function makePostDecision(scamResult: any, trustResult: any): PostDecision {
  const caveats: string[] = [];
  const suppressedFlags: string[] = [];

  // Both scanners failed
  if (!scamResult && !trustResult) {
    return {
      shouldPost: false,
      confidence: 'low',
      postType: 'skip',
      caveats: ['Both scanners failed — no data to report.'],
      suppressedFlags: [],
    };
  }

  const scamScore = scamResult?.score ?? null;
  const trustScore = trustResult?.trustScore ?? null;
  const hasScam = scamScore !== null;
  const hasTrust = trustScore !== null;

  // Only one scanner produced a score
  if (!hasScam || !hasTrust) {
    const singleScore = scamScore ?? trustScore;
    const source = hasScam ? 'scam-scan' : 'trust-scan';
    caveats.push(`Only ${source} produced results — cross-validation unavailable.`);

    if (hasScam) suppressNoisyFlags(trustResult, suppressedFlags);
    if (hasTrust) suppressNoisyFlags(scamResult, suppressedFlags);

    return {
      shouldPost: true,
      confidence: 'low',
      postType: classifySingleScore(singleScore!),
      caveats,
      suppressedFlags,
    };
  }

  // Both scanners produced scores — cross-validate
  const avgScore = (scamScore + trustScore) / 2;
  const scoreDiff = Math.abs(scamScore - trustScore);
  const scannersAgree = scoreDiff <= DISAGREEMENT_THRESHOLD;

  // Check for hard-block flags (always override endorsement)
  const hardBlockFound = checkHardBlockFlags(scamResult, trustResult);

  // === HIGH CONFIDENCE: Scanners agree ===
  if (scannersAgree) {
    // Both say bad
    if (avgScore <= SCORE_BAD) {
      return {
        shouldPost: true,
        confidence: 'high',
        postType: 'warning',
        caveats,
        suppressedFlags,
      };
    }

    // Both say caution
    if (avgScore <= SCORE_CAUTION) {
      caveats.push('Score is in the caution range — manual review recommended.');
      return {
        shouldPost: true,
        confidence: 'high',
        postType: 'warning',
        caveats,
        suppressedFlags,
      };
    }

    // Both say good
    if (avgScore >= SCORE_EXCELLENT && !hardBlockFound) {
      return {
        shouldPost: true,
        confidence: 'high',
        postType: 'endorsement',
        caveats,
        suppressedFlags,
      };
    }

    // Both say decent but not excellent
    if (avgScore >= SCORE_GOOD && !hardBlockFound) {
      return {
        shouldPost: true,
        confidence: 'high',
        postType: 'report',
        caveats,
        suppressedFlags,
      };
    }

    // Middle ground
    return {
      shouldPost: true,
      confidence: 'medium',
      postType: 'report',
      caveats,
      suppressedFlags,
    };
  }

  // === MEDIUM CONFIDENCE: Scanners disagree ===
  caveats.push(
    `Scanners disagree: scam-scan=${scamScore}/100, trust-scan=${trustScore}/100 (diff: ${scoreDiff}).`
  );

  // If one says scam and other says legit, be conservative
  if ((scamScore <= SCORE_BAD && trustScore >= SCORE_GOOD) ||
      (trustScore <= SCORE_BAD && scamScore >= SCORE_GOOD)) {
    caveats.push('Significant disagreement between scanners — treat with caution.');
    // Suppress noisy flags to reduce noise in mixed-signal posts
    suppressNoisyFlags(scamResult, suppressedFlags);
    suppressNoisyFlags(trustResult, suppressedFlags);

    return {
      shouldPost: true,
      confidence: 'low',
      postType: 'report',
      caveats,
      suppressedFlags,
    };
  }

  // Moderate disagreement — use the lower score to be safe
  const conservativeScore = Math.min(scamScore, trustScore);

  if (conservativeScore <= SCORE_CAUTION) {
    return {
      shouldPost: true,
      confidence: 'medium',
      postType: 'warning',
      caveats,
      suppressedFlags,
    };
  }

  // Hard block found but scores look okay — still don't endorse
  if (hardBlockFound) {
    caveats.push('Critical security pattern detected — endorsement withheld.');
    return {
      shouldPost: true,
      confidence: 'medium',
      postType: 'report',
      caveats,
      suppressedFlags,
    };
  }

  return {
    shouldPost: true,
    confidence: 'medium',
    postType: 'report',
    caveats,
    suppressedFlags,
  };
}

/**
 * Classify a single score into a post type (when only one scanner is available)
 */
function classifySingleScore(score: number): PostDecision['postType'] {
  if (score <= SCORE_BAD) return 'warning';
  if (score <= SCORE_CAUTION) return 'warning';
  if (score >= SCORE_EXCELLENT) return 'endorsement';
  return 'report';
}

/**
 * Check if any hard-block red flags are present in scan results.
 * These flags prevent endorsement regardless of scores.
 */
function checkHardBlockFlags(scamResult: any, trustResult: any): boolean {
  const allFlags: string[] = [];

  if (scamResult?.redFlags) allFlags.push(...scamResult.redFlags);
  if (scamResult?.matches) {
    for (const m of scamResult.matches) {
      if (m.severity === 'critical') allFlags.push(m.signatureName || '');
    }
  }
  if (trustResult?.checks) {
    for (const c of trustResult.checks) {
      if (c.status === 'fail') allFlags.push(c.description || '');
    }
  }

  const lowerFlags = allFlags.map(f => f.toLowerCase());
  return HARD_BLOCK_FLAGS.some(hb => lowerFlags.some(f => f.includes(hb)));
}

/**
 * Move noisy/low-signal flags to the suppressed list so they don't
 * appear in the post. Reduces false positive noise.
 */
function suppressNoisyFlags(result: any, suppressed: string[]): void {
  if (!result) return;

  const allFlags: string[] = [];
  if (result.redFlags) allFlags.push(...result.redFlags);
  if (result.checks) {
    for (const c of result.checks) {
      if (c.status === 'fail' || c.status === 'warning') {
        allFlags.push(c.description || c.name || '');
      }
    }
  }

  for (const flag of allFlags) {
    const lower = flag.toLowerCase();
    if (NOISY_FLAGS.some(nf => lower.includes(nf))) {
      suppressed.push(flag);
    }
  }
}
