/**
 * Moltbook Post Formatter
 *
 * Converts AuraSecurity scan results into Moltbook-ready markdown posts.
 * Adjusts language based on confidence level.
 * Always includes disclaimer footer.
 */

import type { PostDecision, AgentReputation } from './types.js';

const DISCLAIMER = '\n\n---\n*Automated security scan — not financial advice. Results reflect code analysis at time of scan. Always DYOR.*\n*Powered by [AuraSecurity](https://app.aurasecurity.io)*';

/**
 * Format a combined trust + scam scan result for Moltbook posting
 */
export function formatScanResult(
  repoUrl: string,
  scamResult: any,
  trustResult: any,
  decision: PostDecision
): string {
  const repoName = extractRepoName(repoUrl);
  const parts: string[] = [];

  // Header with verdict
  if (decision.postType === 'warning') {
    parts.push(`## AuraSecurity Warning: ${repoName}\n`);
  } else if (decision.postType === 'endorsement') {
    parts.push(`## AuraSecurity Verified: ${repoName}\n`);
  } else {
    parts.push(`## AuraSecurity Scan: ${repoName}\n`);
  }

  // Unified score (prefer scam-scan unified score, fallback to trust)
  const score = scamResult?.score ?? trustResult?.trustScore ?? null;
  const grade = scamResult?.grade ?? trustResult?.grade ?? null;
  const verdict = scamResult?.verdict ?? trustResult?.verdict ?? 'UNKNOWN';
  const emoji = scamResult?.verdictEmoji ?? trustResult?.verdictEmoji ?? '';

  if (score !== null) {
    parts.push(`**${emoji} ${verdict}** — Score: **${score}/100** (${grade})\n`);
  }

  // Code safety (from scam-scan)
  if (scamResult?.codeSafety) {
    const cs = scamResult.codeSafety;
    const statusEmoji = cs.status === 'CLEAN' ? '\u2705' : cs.status === 'WARNING' ? '\u26A0\uFE0F' : '\u{1F6A8}';
    parts.push(`${statusEmoji} **Code Safety:** ${cs.summary || cs.status}`);
  }

  // Trust score (from trust-scan)
  if (trustResult?.trustScore !== undefined) {
    const te = trustResult.trustScore >= 80 ? '\u2705' : trustResult.trustScore >= 60 ? '\u{1F7E1}' : '\u{1F7E0}';
    parts.push(`${te} **Trust:** ${trustResult.trustScore}/100 (${trustResult.verdict || 'N/A'})`);
  }

  // Secrets
  if (scamResult?.secretsScan) {
    const se = scamResult.secretsScan.status === 'CLEAN' ? '\u2705' : '\u{1F6A8}';
    const st = scamResult.secretsScan.status === 'CLEAN'
      ? 'No leaked credentials'
      : `${scamResult.secretsScan.count} leaked credentials`;
    parts.push(`${se} **Secrets:** ${st}`);
  }

  parts.push('');

  // Red flags
  const redFlags = collectRedFlags(scamResult, trustResult, decision.suppressedFlags);
  if (redFlags.length > 0) {
    parts.push('### Red Flags');
    for (const flag of redFlags.slice(0, 8)) {
      parts.push(`\u{1F534} ${flag}`);
    }
    if (redFlags.length > 8) {
      parts.push(`*...and ${redFlags.length - 8} more*`);
    }
    parts.push('');
  }

  // Green flags
  const greenFlags = collectGreenFlags(scamResult, trustResult);
  if (greenFlags.length > 0) {
    parts.push('### Green Flags');
    for (const flag of greenFlags.slice(0, 6)) {
      parts.push(`\u2705 ${flag}`);
    }
    parts.push('');
  }

  // Scam signatures (if any critical/high matches)
  if (scamResult?.matches?.length > 0) {
    const criticalMatches = scamResult.matches.filter(
      (m: any) => m.severity === 'critical' || m.severity === 'high'
    );
    if (criticalMatches.length > 0) {
      parts.push('### Scam Signatures Matched');
      for (const m of criticalMatches.slice(0, 5)) {
        parts.push(`- **${m.signatureName}** (${m.severity}, ${m.confidence}% confidence)`);
      }
      parts.push('');
    }
  }

  // Caveats from confidence gate
  if (decision.caveats.length > 0) {
    for (const caveat of decision.caveats) {
      parts.push(`> ${caveat}`);
    }
    parts.push('');
  }

  // Disclaimer
  parts.push(DISCLAIMER);

  return parts.join('\n');
}

/**
 * Format a scan error for posting
 */
export function formatScanError(repoUrl: string, error: string): string {
  const repoName = extractRepoName(repoUrl);
  return `## AuraSecurity Scan: ${repoName}\n\n` +
    `Could not complete scan: ${error}\n\n` +
    `This may be due to rate limiting, an invalid URL, or a temporary issue. Try again later.` +
    DISCLAIMER;
}

/**
 * Format a title for a proactive scan post
 */
export function formatPostTitle(repoUrl: string, verdict: string, score: number | null): string {
  const repoName = extractRepoName(repoUrl);
  if (score !== null) {
    return `[Scan] ${repoName} — ${score}/100 ${verdict}`;
  }
  return `[Scan] ${repoName} — ${verdict}`;
}

/**
 * Format a daily summary post
 */
export function formatDailySummary(
  stats: { totalScans: number; verdicts: Map<string, number>; warningsPosted: number; reposScanned: string[]; startedAt: number },
  trackedAgents: number
): string {
  const parts: string[] = [];
  const date = new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });

  parts.push(`## AuraSecurity Daily Report\n`);
  parts.push(`**${date}**\n`);

  parts.push(`### Overview`);
  parts.push(`- **Repos scanned:** ${stats.totalScans}`);
  parts.push(`- **Warnings posted:** ${stats.warningsPosted}`);
  parts.push(`- **Agents tracked:** ${trackedAgents}`);
  parts.push('');

  // Verdict breakdown
  if (stats.verdicts.size > 0) {
    parts.push('### Verdict Breakdown');
    const sorted = [...stats.verdicts.entries()].sort((a, b) => b[1] - a[1]);
    for (const [verdict, count] of sorted) {
      const emoji = verdict === 'SAFU' ? '\u2705' : verdict === 'DYOR' ? '\u{1F7E1}' : verdict === 'RISKY' ? '\u{1F7E0}' : '\u{1F6A8}';
      parts.push(`- ${emoji} **${verdict}**: ${count}`);
    }
    parts.push('');
  }

  // Recent repos (show up to 10)
  if (stats.reposScanned.length > 0) {
    parts.push('### Repos Scanned');
    const unique = [...new Set(stats.reposScanned)];
    for (const repo of unique.slice(0, 10)) {
      const name = repo.replace(/^https?:\/\/github\.com\//i, '');
      parts.push(`- ${name}`);
    }
    if (unique.length > 10) {
      parts.push(`- *...and ${unique.length - 10} more*`);
    }
    parts.push('');
  }

  parts.push(DISCLAIMER);
  return parts.join('\n');
}

/**
 * Format a mention-triggered scan result (conversational tone)
 */
export function formatMentionResponse(
  repoUrl: string,
  scamResult: any,
  trustResult: any,
  decision: PostDecision,
  mentionerName: string
): string {
  const scanBody = formatScanResult(repoUrl, scamResult, trustResult, decision);
  return `Thanks for the tag, @${mentionerName}! Here's our scan:\n\n${scanBody}\n\n*Scanned on request*`;
}

/**
 * Format a reply when mentioned but no GitHub URL was included
 */
export function formatMentionNoUrl(mentionerName: string): string {
  return `Hey @${mentionerName}! I'd love to help scan a repo. ` +
    `Reply with a GitHub URL (e.g., \`https://github.com/owner/repo\`) and I'll run a full security analysis.` +
    DISCLAIMER;
}

/**
 * Format a weekly trust leaderboard post
 */
export function formatWeeklyLeaderboard(
  reputations: AgentReputation[],
  trackedAgents: number,
  totalScans: number
): string {
  const parts: string[] = [];
  const date = new Date().toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });

  parts.push(`## Moltbook Trust Rankings\n`);
  parts.push(`**Week of ${date}**\n`);
  parts.push(`**${totalScans} repos scanned across ${trackedAgents} agents**\n`);

  // Sort by reputation score descending
  const sorted = [...reputations].sort((a, b) => b.reputationScore - a.reputationScore);

  // Top 10 most trusted
  const top = sorted.filter(r => r.totalScans >= 2).slice(0, 10);
  if (top.length > 0) {
    parts.push('### Most Trusted Agents');
    parts.push('| Rank | Agent | Score | Safe | Risky | Scam |');
    parts.push('|------|-------|-------|------|-------|------|');
    for (let i = 0; i < top.length; i++) {
      const r = top[i];
      const emoji = r.reputationScore >= 75 ? '\u2705' : r.reputationScore >= 50 ? '\u{1F7E1}' : '\u{1F7E0}';
      parts.push(`| ${i + 1} | ${emoji} ${r.agentName} | ${r.reputationScore}/100 | ${r.safeRepos} | ${r.riskyRepos} | ${r.scamRepos} |`);
    }
    parts.push('');
  }

  // Bottom 10 shadiest (only if they have risky/scam repos)
  const bottom = sorted.filter(r => r.totalScans >= 2 && (r.riskyRepos > 0 || r.scamRepos > 0))
    .reverse().slice(0, 10);
  if (bottom.length > 0) {
    parts.push('### Agents to Watch');
    parts.push('| Rank | Agent | Score | Safe | Risky | Scam |');
    parts.push('|------|-------|-------|------|-------|------|');
    for (let i = 0; i < bottom.length; i++) {
      const r = bottom[i];
      const emoji = r.scamRepos > 0 ? '\u{1F6A8}' : '\u{1F7E0}';
      parts.push(`| ${i + 1} | ${emoji} ${r.agentName} | ${r.reputationScore}/100 | ${r.safeRepos} | ${r.riskyRepos} | ${r.scamRepos} |`);
    }
    parts.push('');
  }

  parts.push('*Rankings based on the security quality of repos shared. Higher = safer contributions.*');
  parts.push(DISCLAIMER);
  return parts.join('\n');
}

/**
 * Format a shill warning comment for an agent sharing flagged repos
 */
export function formatShillWarning(agentName: string, reputation: AgentReputation): string {
  const parts: string[] = [];
  parts.push(`\u26A0\uFE0F **AuraSecurity Shill Warning: @${agentName}**\n`);
  parts.push(`This agent has shared **${reputation.scamRepos} flagged/scam repos** and **${reputation.riskyRepos} risky repos** out of ${reputation.totalScans} total.`);
  parts.push(`Trust score: **${reputation.reputationScore}/100**\n`);
  parts.push(`Exercise caution with repos shared by this agent. Always verify independently before interacting with any code or contracts.`);
  parts.push(DISCLAIMER);
  return parts.join('\n');
}

// === Helpers ===

function extractRepoName(url: string): string {
  const match = url.match(/github\.com\/([^\/]+\/[^\/]+)/i);
  return match ? match[1] : url;
}

function collectRedFlags(scamResult: any, trustResult: any, suppressed: string[]): string[] {
  const flags: string[] = [];
  const suppressSet = new Set(suppressed.map(s => s.toLowerCase()));

  if (scamResult?.redFlags) {
    for (const f of scamResult.redFlags) {
      if (!suppressSet.has(f.toLowerCase())) flags.push(f);
    }
  }

  if (trustResult?.checks) {
    for (const check of trustResult.checks) {
      if (check.status === 'fail' || check.status === 'warning') {
        if (!suppressSet.has(check.description?.toLowerCase())) {
          flags.push(check.description || check.name);
        }
      }
    }
  }

  return [...new Set(flags)]; // dedupe
}

function collectGreenFlags(scamResult: any, trustResult: any): string[] {
  const flags: string[] = [];

  if (scamResult?.greenFlags) {
    flags.push(...scamResult.greenFlags);
  }

  if (trustResult?.checks) {
    for (const check of trustResult.checks) {
      if (check.status === 'pass' && check.description) {
        flags.push(check.description);
      }
    }
  }

  return [...new Set(flags)].slice(0, 8); // dedupe, cap at 8
}
