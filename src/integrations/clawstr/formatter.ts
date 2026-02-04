/**
 * Clawstr Formatter
 *
 * Formats security scan results for posting on Clawstr.
 * Follows Nostr conventions (plain text content, no markdown).
 */

import type { EnhancedTrustResult } from '../enhanced-scanner.js';
import type { ScamDetectionResult } from '../scam-detector.js';

export interface ScanResultData {
  repoUrl: string;
  repoName: string;
  owner: string;
  trustResult?: EnhancedTrustResult;
  scamResult?: ScamDetectionResult;
}

export type VerdictType = 'SAFE' | 'RISKY' | 'SCAM' | 'UNKNOWN';

export interface PostDecision {
  shouldPost: boolean;
  verdict: VerdictType;
  confidence: number;
  reason: string;
}

/**
 * Format a security scan result for Clawstr
 */
export function formatScanResult(data: ScanResultData, decision: PostDecision): string {
  const { repoUrl, repoName, owner, trustResult, scamResult } = data;

  const lines: string[] = [];

  // Header with verdict
  const emoji = getVerdictEmoji(decision.verdict);
  lines.push(`${emoji} SECURITY SCAN: ${owner}/${repoName}`);
  lines.push('');

  // Score and verdict
  if (trustResult) {
    lines.push(`Score: ${trustResult.trustScore}/100 - ${decision.verdict}`);
    lines.push(`Grade: ${trustResult.grade}`);
  }
  lines.push('');

  // Red flags
  const redFlags = collectRedFlags(trustResult, scamResult);
  if (redFlags.length > 0) {
    lines.push('RED FLAGS:');
    redFlags.slice(0, 5).forEach(flag => {
      lines.push(`- ${flag}`);
    });
    if (redFlags.length > 5) {
      lines.push(`- ...and ${redFlags.length - 5} more`);
    }
    lines.push('');
  }

  // Green flags
  const greenFlags = collectGreenFlags(trustResult);
  if (greenFlags.length > 0) {
    lines.push('GOOD SIGNS:');
    greenFlags.slice(0, 3).forEach(flag => {
      lines.push(`+ ${flag}`);
    });
    lines.push('');
  }

  // Summary
  if (trustResult?.summary) {
    lines.push(trustResult.summary);
    lines.push('');
  }

  // Footer
  lines.push(`Repo: ${repoUrl}`);
  lines.push('');
  lines.push('-- AuraSecurity Bot');

  return lines.join('\n');
}

/**
 * Format a brief scan result (for comments/replies)
 */
export function formatBriefScanResult(data: ScanResultData, decision: PostDecision): string {
  const { repoName, owner, trustResult } = data;

  const emoji = getVerdictEmoji(decision.verdict);
  const score = trustResult?.trustScore ?? '?';
  const grade = trustResult?.grade ?? '?';

  let result = `${emoji} ${owner}/${repoName}: ${decision.verdict} (${score}/100, Grade ${grade})`;

  // Add top red flag if any
  const redFlags = collectRedFlags(trustResult, data.scamResult);
  if (redFlags.length > 0 && decision.verdict !== 'SAFE') {
    result += `\n⚠️ ${redFlags[0]}`;
  }

  return result;
}

/**
 * Format error message
 */
export function formatScanError(repoUrl: string, error: string): string {
  return `❌ Failed to scan ${repoUrl}\nError: ${error}\n\n-- AuraSecurity Bot`;
}

/**
 * Format mention response (when someone tags @AuraSecurity)
 */
export function formatMentionResponse(
  mentioner: string,
  data: ScanResultData,
  decision: PostDecision
): string {
  const brief = formatBriefScanResult(data, decision);
  return `@${mentioner} Here's the scan result:\n\n${brief}`;
}

/**
 * Format response when mention has no GitHub URL
 */
export function formatMentionNoUrl(mentioner: string): string {
  return `@${mentioner} I'd be happy to scan a repo! Please include a GitHub URL and I'll analyze it for security issues.`;
}

/**
 * Get emoji for verdict
 */
function getVerdictEmoji(verdict: string): string {
  switch (verdict) {
    case 'SAFE':
      return '✅';
    case 'RISKY':
      return '⚠️';
    case 'SCAM':
      return '🚨';
    default:
      return '🔍';
  }
}

/**
 * Collect red flags from scan results
 */
function collectRedFlags(
  trustResult?: EnhancedTrustResult,
  scamResult?: ScamDetectionResult
): string[] {
  const flags: string[] = [];

  // From trust result checks
  if (trustResult?.checks) {
    for (const check of trustResult.checks) {
      if (check.status === 'bad' || check.status === 'warn') {
        flags.push(check.explanation || check.name);
      }
    }
  }

  // From scam result warnings
  if (scamResult?.warnings) {
    flags.push(...scamResult.warnings);
  }

  // From enhanced scanner rug db checks
  if (trustResult?.knownRug) {
    flags.push('KNOWN RUG - Listed in rug database');
  }
  if (trustResult?.ownerHistory?.hasRuggedBefore) {
    flags.push('Owner has rugged before');
  }

  return flags;
}

/**
 * Collect green flags from scan results
 */
function collectGreenFlags(trustResult?: EnhancedTrustResult): string[] {
  const flags: string[] = [];

  if (trustResult?.checks) {
    for (const check of trustResult.checks) {
      if (check.status === 'good') {
        flags.push(check.explanation || check.name);
      }
    }
  }

  return flags;
}

/**
 * Make a decision about whether to post/respond
 */
export function makePostDecision(
  trustResult?: EnhancedTrustResult,
  scamResult?: ScamDetectionResult
): PostDecision {
  // Default unknown
  let verdict: PostDecision['verdict'] = 'UNKNOWN';
  let confidence = 50;
  let reason = 'Unable to determine';

  if (!trustResult && !scamResult) {
    return { shouldPost: false, verdict, confidence, reason: 'No scan results' };
  }

  const score = trustResult?.trustScore ?? 50;
  const isLikelyScam = scamResult?.isLikelyScam ?? false;
  const scamScore = scamResult?.scamScore ?? 0;

  // Determine verdict
  if (score >= 70 && !isLikelyScam) {
    verdict = 'SAFE';
    confidence = Math.min(95, score);
    reason = 'High trust score, no red flags';
  } else if (score < 30 || scamScore > 70 || trustResult?.knownRug) {
    verdict = 'SCAM';
    confidence = Math.max(80, 100 - score);
    reason = score < 30 ? 'Very low trust score' :
             trustResult?.knownRug ? 'Known rug in database' :
             'High scam indicators detected';
  } else if (score < 50 || isLikelyScam || scamScore > 40) {
    verdict = 'RISKY';
    confidence = 60;
    reason = 'Moderate concerns detected';
  } else {
    verdict = 'SAFE';
    confidence = score;
    reason = 'Acceptable trust score';
  }

  // Should post if we have confidence in our assessment
  const shouldPost = confidence >= 50;

  return { shouldPost, verdict, confidence, reason };
}
