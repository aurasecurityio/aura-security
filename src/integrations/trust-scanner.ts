/**
 * Trust Scanner - Rug Check for Crypto Investors
 *
 * Analyzes GitHub repositories to detect potential rug pulls and scams.
 * Returns a trust score (0-100) with plain English explanations.
 */

export interface TrustCheck {
  id: string;
  name: string;
  status: 'good' | 'warn' | 'bad' | 'info';
  points: number;
  explanation: string;
}

export interface TrustMetrics {
  repoAgeDays: number;
  daysSinceLastPush: number;
  commitCount: number;
  contributorCount: number;
  stars: number;
  forks: number;
  watchers: number;
  openIssues: number;
  codeFileCount: number;
  hasTests: boolean;
  hasReadme: boolean;
  hasDependencies: boolean;
  hasLicense: boolean;
  isFork: boolean;
  isArchived: boolean;
  language: string | null;
  topics: string[];
  secretsFound: number;
  // Enhanced metrics
  forkChangedLines?: number;
  forkParentRepo?: string;
  ownerAccountAgeDays?: number;
  ownerPublicRepos?: number;
  ownerTotalContributions?: number;
  readmeRedFlags?: string[];
  codeRedFlags?: string[];
}

export interface TrustScanResult {
  url: string;
  repoName: string;
  owner: string;
  trustScore: number;
  grade: 'A' | 'B' | 'C' | 'F';
  verdict: 'SAFU' | 'DYOR' | 'RISKY' | 'RUG ALERT';
  verdictEmoji: string;
  summary: string;
  checks: TrustCheck[];
  metrics: TrustMetrics;
  scannedAt: string;
}

/**
 * Parse GitHub URL to extract owner and repo
 */
function parseGitHubUrl(url: string): { owner: string; repo: string } | null {
  // Handle various GitHub URL formats
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/\?\#]+)/,
    /^([^\/]+)\/([^\/]+)$/  // owner/repo format
  ];

  for (const pattern of patterns) {
    const match = url.match(pattern);
    if (match) {
      return {
        owner: match[1],
        repo: match[2].replace(/\.git$/, '')
      };
    }
  }

  return null;
}

/**
 * Run all trust checks on the metrics
 */
function runTrustChecks(metrics: TrustMetrics): TrustCheck[] {
  const checks: TrustCheck[] = [];

  // 1. Repo Age Check
  if (metrics.repoAgeDays < 7) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'bad',
      points: -15,
      explanation: 'Brand new project (less than a week old) - major red flag!'
    });
  } else if (metrics.repoAgeDays < 30) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'warn',
      points: 2,
      explanation: `Very new project (${metrics.repoAgeDays} days old) - be cautious`
    });
  } else if (metrics.repoAgeDays < 180) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'info',
      points: 5,
      explanation: `Project is ${Math.floor(metrics.repoAgeDays / 30)} months old`
    });
  } else if (metrics.repoAgeDays < 365) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'good',
      points: 8,
      explanation: `Established project (${Math.floor(metrics.repoAgeDays / 30)} months old)`
    });
  } else {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'good',
      points: 10,
      explanation: `Well-established project (${Math.floor(metrics.repoAgeDays / 365)} years old)`
    });
  }

  // 2. Commit Count Check
  if (metrics.commitCount < 5) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'bad',
      points: 0,
      explanation: `Only ${metrics.commitCount} commits - looks like a placeholder or copy`
    });
  } else if (metrics.commitCount < 20) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'warn',
      points: 3,
      explanation: `Low commit count (${metrics.commitCount}) - limited development`
    });
  } else if (metrics.commitCount < 100) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'info',
      points: 6,
      explanation: `${metrics.commitCount} commits - moderate development activity`
    });
  } else {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'good',
      points: 10,
      explanation: `${metrics.commitCount} commits - active development`
    });
  }

  // 3. Contributor Check
  if (metrics.contributorCount === 1) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'warn',
      points: -5,
      explanation: 'Only 1 contributor - single person project (higher risk)'
    });
  } else if (metrics.contributorCount < 3) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'info',
      points: 3,
      explanation: `Small team (${metrics.contributorCount} contributors)`
    });
  } else if (metrics.contributorCount < 10) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'good',
      points: 7,
      explanation: `Good team size (${metrics.contributorCount} contributors)`
    });
  } else {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'good',
      points: 10,
      explanation: `Large team (${metrics.contributorCount}+ contributors)`
    });
  }

  // 4. Star Pattern Check (detect fake stars)
  const starForkRatio = metrics.stars / Math.max(metrics.forks, 1);
  if (metrics.stars > 100 && starForkRatio > 100) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'bad',
      points: -20,
      explanation: `Suspicious! ${metrics.stars} stars but only ${metrics.forks} forks - likely bought stars`
    });
  } else if (metrics.stars > 50 && starForkRatio > 50) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'warn',
      points: -10,
      explanation: `Unusual star pattern (${metrics.stars} stars, ${metrics.forks} forks) - could be inflated`
    });
  } else if (metrics.stars > 10) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'good',
      points: 5,
      explanation: `Natural engagement (${metrics.stars} stars, ${metrics.forks} forks)`
    });
  } else {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'info',
      points: 0,
      explanation: `Low visibility (${metrics.stars} stars) - newer or niche project`
    });
  }

  // 5. Code Files Check
  if (metrics.codeFileCount === 0) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'bad',
      points: -10,
      explanation: 'No code files found! This is just a README - major red flag'
    });
  } else if (metrics.codeFileCount < 5) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'warn',
      points: 2,
      explanation: `Very few code files (${metrics.codeFileCount}) - might be a placeholder`
    });
  } else if (metrics.codeFileCount < 20) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'info',
      points: 6,
      explanation: `${metrics.codeFileCount} code files - small but real codebase`
    });
  } else {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'good',
      points: 10,
      explanation: `${metrics.codeFileCount} code files - substantial codebase`
    });
  }

  // 6. Tests Check
  if (!metrics.hasTests) {
    checks.push({
      id: 'tests',
      name: 'Test Coverage',
      status: 'warn',
      points: 0,
      explanation: 'No tests found - harder to verify code quality'
    });
  } else {
    checks.push({
      id: 'tests',
      name: 'Test Coverage',
      status: 'good',
      points: 10,
      explanation: 'Has test files - shows quality effort'
    });
  }

  // 7. Recent Activity Check
  if (metrics.daysSinceLastPush > 365) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'bad',
      points: -10,
      explanation: `No updates in ${Math.floor(metrics.daysSinceLastPush / 365)} year(s) - project may be abandoned`
    });
  } else if (metrics.daysSinceLastPush > 180) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'warn',
      points: 0,
      explanation: `No updates in ${Math.floor(metrics.daysSinceLastPush / 30)} months - possibly inactive`
    });
  } else if (metrics.daysSinceLastPush > 30) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'info',
      points: 5,
      explanation: `Last update ${Math.floor(metrics.daysSinceLastPush / 30)} month(s) ago`
    });
  } else {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'good',
      points: 10,
      explanation: `Recently updated (${metrics.daysSinceLastPush} days ago) - actively maintained`
    });
  }

  // 8. Fork Check
  if (metrics.isFork) {
    checks.push({
      id: 'fork',
      name: 'Original Project',
      status: 'warn',
      points: -5,
      explanation: 'This is a fork of another project - not original work'
    });
  } else {
    checks.push({
      id: 'fork',
      name: 'Original Project',
      status: 'good',
      points: 5,
      explanation: 'Original repository (not a fork)'
    });
  }

  // 9. License Check
  if (metrics.hasLicense) {
    checks.push({
      id: 'license',
      name: 'License',
      status: 'good',
      points: 5,
      explanation: 'Has a proper open-source license'
    });
  } else {
    checks.push({
      id: 'license',
      name: 'License',
      status: 'info',
      points: 0,
      explanation: 'No license specified'
    });
  }

  // 10. Dependencies Check
  if (metrics.hasDependencies) {
    checks.push({
      id: 'dependencies',
      name: 'Dependencies',
      status: 'good',
      points: 5,
      explanation: 'Has package management (real project structure)'
    });
  } else {
    checks.push({
      id: 'dependencies',
      name: 'Dependencies',
      status: 'info',
      points: 0,
      explanation: 'No dependency file found'
    });
  }

  // 11. Secrets Check
  if (metrics.secretsFound > 0) {
    checks.push({
      id: 'secrets',
      name: 'Security',
      status: 'bad',
      points: -10 * metrics.secretsFound,
      explanation: `Found ${metrics.secretsFound} leaked secret(s) - major security red flag!`
    });
  } else {
    checks.push({
      id: 'secrets',
      name: 'Security',
      status: 'good',
      points: 5,
      explanation: 'No leaked credentials found'
    });
  }

  // 12. Archived Check
  if (metrics.isArchived) {
    checks.push({
      id: 'archived',
      name: 'Project Status',
      status: 'bad',
      points: -15,
      explanation: 'Project is ARCHIVED - no longer maintained!'
    });
  }

  // 13. Language Check
  if (metrics.language) {
    checks.push({
      id: 'language',
      name: 'Tech Stack',
      status: 'info',
      points: 0,
      explanation: `Built with ${metrics.language}`
    });
  }

  // 14. Enhanced Fork Analysis
  if (metrics.isFork && metrics.forkChangedLines !== undefined) {
    if (metrics.forkChangedLines < 50) {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'bad',
        points: -25,
        explanation: `Copy-paste alert! Only ${metrics.forkChangedLines} lines changed from original`
      });
    } else if (metrics.forkChangedLines < 200) {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'warn',
        points: -10,
        explanation: `Minimal changes (${metrics.forkChangedLines} lines) from forked repo`
      });
    } else {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'info',
        points: 0,
        explanation: `Substantial modifications (${metrics.forkChangedLines}+ lines changed)`
      });
    }
  }

  // 15. Owner Account Age Check (softer if there's real code)
  const hasRealCode = metrics.codeFileCount >= 20;
  const hasRealActivity = metrics.commitCount >= 20;

  if (metrics.ownerAccountAgeDays !== undefined) {
    if (metrics.ownerAccountAgeDays < 30) {
      // Softer penalty if they're actually building something
      const points = (hasRealCode && hasRealActivity) ? -8 : -15;
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'warn',
        points,
        explanation: `New developer account (${metrics.ownerAccountAgeDays} days old)`
      });
    } else if (metrics.ownerAccountAgeDays < 180) {
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'warn',
        points: -5,
        explanation: `New developer account (${Math.floor(metrics.ownerAccountAgeDays / 30)} months old)`
      });
    } else if (metrics.ownerAccountAgeDays >= 365) {
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'good',
        points: 5,
        explanation: `Established developer (${Math.floor(metrics.ownerAccountAgeDays / 365)}+ years on GitHub)`
      });
    }
  }

  // 16. Owner Repo Count Check (softer if building real code)
  if (metrics.ownerPublicRepos !== undefined) {
    if (metrics.ownerPublicRepos === 1) {
      // Softer penalty if the repo shows real effort
      const points = (hasRealCode && hasRealActivity) ? -5 : -10;
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'warn',
        points,
        explanation: 'First repo - new to GitHub'
      });
    } else if (metrics.ownerPublicRepos < 5) {
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'warn',
        points: -5,
        explanation: `Limited history (only ${metrics.ownerPublicRepos} repos)`
      });
    } else if (metrics.ownerPublicRepos >= 10) {
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'good',
        points: 5,
        explanation: `Active developer (${metrics.ownerPublicRepos} public repos)`
      });
    }
  }

  // 17. README Red Flags
  if (metrics.readmeRedFlags && metrics.readmeRedFlags.length > 0) {
    const flagCount = metrics.readmeRedFlags.length;
    checks.push({
      id: 'readme_flags',
      name: 'README Analysis',
      status: flagCount >= 2 ? 'bad' : 'warn',
      points: flagCount >= 2 ? -20 : -10,
      explanation: `Scam signals: ${metrics.readmeRedFlags.slice(0, 2).join(', ')}`
    });
  }

  // 18. Code Red Flags (Honeypot patterns)
  if (metrics.codeRedFlags && metrics.codeRedFlags.length > 0) {
    const flagCount = metrics.codeRedFlags.length;
    checks.push({
      id: 'code_flags',
      name: 'Code Analysis',
      status: flagCount >= 2 ? 'bad' : 'warn',
      points: flagCount >= 2 ? -25 : -10,
      explanation: `Risky code: ${metrics.codeRedFlags.slice(0, 2).join(', ')}`
    });
  }

  // 19. Builder Bonus - reward real development effort
  const builderSignals = [
    metrics.codeFileCount >= 20,      // Substantial codebase
    metrics.hasTests,                  // Has tests
    metrics.commitCount >= 30,         // Active commits
    metrics.daysSinceLastPush < 30,    // Recent activity
    metrics.contributorCount >= 2,     // Team effort
  ].filter(Boolean).length;

  if (builderSignals >= 4) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'good',
      points: 15,
      explanation: 'Strong development signals - actively building!'
    });
  } else if (builderSignals >= 3) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'good',
      points: 10,
      explanation: 'Good development activity detected'
    });
  } else if (builderSignals >= 2) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'info',
      points: 5,
      explanation: 'Some development effort shown'
    });
  }

  return checks;
}

/**
 * Calculate trust score from checks
 */
function calculateScore(checks: TrustCheck[]): { score: number; grade: 'A' | 'B' | 'C' | 'F'; verdict: 'SAFU' | 'DYOR' | 'RISKY' | 'RUG ALERT'; verdictEmoji: string } {
  const baseScore = 40; // Lowered from 50
  const totalPoints = checks.reduce((sum, check) => sum + check.points, 0);
  let score = Math.max(0, Math.min(100, baseScore + totalPoints));

  // Count critical issues
  const badChecks = checks.filter(c => c.status === 'bad');
  const hasSecrets = checks.some(c => c.id === 'secrets' && c.status === 'bad');
  const hasNoCode = checks.some(c => c.id === 'code' && c.status === 'bad');
  const isAbandoned = checks.some(c => c.id === 'activity' && c.status === 'bad');

  // Apply caps based on critical issues
  if (hasSecrets) {
    // Leaked secrets = max score 50 (RISKY)
    score = Math.min(score, 50);
  }
  if (hasNoCode) {
    // No code = max score 40 (RISKY)
    score = Math.min(score, 40);
  }
  if (badChecks.length >= 3) {
    // 3+ bad checks = max score 50 (RISKY)
    score = Math.min(score, 50);
  } else if (badChecks.length >= 2) {
    // 2 bad checks = max score 60 (DYOR)
    score = Math.min(score, 60);
  } else if (badChecks.length >= 1) {
    // 1 bad check = max score 75 (DYOR)
    score = Math.min(score, 75);
  }

  let grade: 'A' | 'B' | 'C' | 'F';
  let verdict: 'SAFU' | 'DYOR' | 'RISKY' | 'RUG ALERT';
  let verdictEmoji: string;

  if (score >= 80) {
    grade = 'A';
    verdict = 'SAFU';
    verdictEmoji = '🟢';
  } else if (score >= 60) {
    grade = 'B';
    verdict = 'DYOR';
    verdictEmoji = '🟡';
  } else if (score >= 35) {
    grade = 'C';
    verdict = 'RISKY';
    verdictEmoji = '🟠';
  } else {
    // RUG ALERT only for really bad scores (<35)
    grade = 'F';
    verdict = 'RUG ALERT';
    verdictEmoji = '🔴';
  }

  return { score, grade, verdict, verdictEmoji };
}

/**
 * Generate plain English summary
 */
function generateSummary(checks: TrustCheck[], score: number, verdict: string): string {
  const good = checks.filter(c => c.status === 'good');
  const bad = checks.filter(c => c.status === 'bad');
  const warn = checks.filter(c => c.status === 'warn');

  let summary = '';

  if (verdict === 'SAFU') {
    summary = 'This project looks legitimate! ';
    if (good.length > 0) {
      summary += `Strong points: ${good.slice(0, 3).map(c => c.name.toLowerCase()).join(', ')}. `;
    }
    if (warn.length > 0) {
      summary += `Minor note: ${warn[0].explanation.toLowerCase()}.`;
    }
  } else if (verdict === 'DYOR') {
    summary = 'Do your own research before investing. ';
    if (warn.length > 0) {
      summary += `Concerns: ${warn.slice(0, 2).map(c => c.explanation.toLowerCase()).join('; ')}. `;
    }
    summary += 'Verify the team and roadmap independently.';
  } else if (verdict === 'RISKY') {
    summary = 'Proceed with extreme caution! ';
    const concerns = [...bad, ...warn].slice(0, 3);
    summary += `Red flags: ${concerns.map(c => c.explanation.toLowerCase()).join('; ')}. `;
    summary += 'High risk of losing your investment.';
  } else {
    summary = 'WARNING: High probability of rug pull! ';
    summary += `Critical issues: ${bad.map(c => c.explanation.toLowerCase()).join('; ')}. `;
    summary += 'We strongly recommend NOT investing.';
  }

  return summary;
}

/**
 * Scan a single file for secrets (basic patterns)
 */
function scanForSecrets(content: string): number {
  const secretPatterns = [
    /AKIA[0-9A-Z]{16}/,                    // AWS Access Key
    /[a-zA-Z0-9+\/]{40}/,                   // Generic 40-char key
    /ghp_[A-Za-z0-9_]{36}/,                // GitHub Token
    /sk_live_[A-Za-z0-9]{24,}/,            // Stripe Key
    /-----BEGIN.*PRIVATE KEY-----/,         // Private Key
    /password\s*[:=]\s*['""][^'""]+['""]/, // Hardcoded password
  ];

  let count = 0;
  for (const pattern of secretPatterns) {
    if (pattern.test(content)) {
      count++;
    }
  }
  return count;
}

/**
 * Scan README for scam red flags
 */
function scanReadmeForRedFlags(content: string): string[] {
  const redFlags: string[] = [];
  const lowerContent = content.toLowerCase();

  // Check for scam language
  if (/100x|1000x|guaranteed.*return|moonshot|get rich/i.test(content)) {
    redFlags.push('Promises unrealistic returns');
  }
  if (/🚀{3,}|💰{3,}|💎{3,}/u.test(content)) {
    redFlags.push('Excessive hype emojis');
  }
  if (/whitelist.*limited|presale.*ending|act.*fast|don.?t.*miss/i.test(content)) {
    redFlags.push('FOMO/urgency language');
  }
  if (/t\.me\/|telegram\.me\//i.test(content) && !/docs|documentation|wiki/i.test(content)) {
    redFlags.push('Only Telegram links, no documentation');
  }
  if (lowerContent.includes('airdrop') && lowerContent.includes('connect wallet')) {
    redFlags.push('Airdrop + connect wallet = phishing risk');
  }
  if (/stealth.*launch|fair.*launch.*no.*team/i.test(content)) {
    redFlags.push('Suspicious launch claims');
  }

  return redFlags;
}

/**
 * Scan Solidity code for honeypot patterns
 */
function scanCodeForRedFlags(files: Array<{ path: string; content?: string }>): string[] {
  const redFlags: string[] = [];

  for (const file of files) {
    if (!file.content) continue;
    const content = file.content;

    // Only scan Solidity files for smart contract red flags
    if (file.path.endsWith('.sol')) {
      // Check for honeypot patterns
      if (/onlyOwner.*withdraw|withdraw.*onlyOwner/is.test(content)) {
        redFlags.push('Owner-only withdraw function');
      }
      if (/function\s+_?mint.*onlyOwner|onlyOwner.*function\s+_?mint/is.test(content)) {
        redFlags.push('Hidden mint function (owner can create tokens)');
      }
      if (/blacklist|blocklist|isBlocked|_blocked/i.test(content)) {
        redFlags.push('Blacklist function (can block selling)');
      }
      if (/selfdestruct|delegatecall/i.test(content)) {
        redFlags.push('Dangerous functions (selfdestruct/delegatecall)');
      }
      if (/maxTx|maxWallet|_maxTxAmount/i.test(content) && /onlyOwner/i.test(content)) {
        redFlags.push('Owner-controlled transaction limits');
      }
      if (/pause|unpause|whenNotPaused/i.test(content)) {
        redFlags.push('Pausable transfers (can freeze trading)');
      }
      if (/fee.*[5-9]\d|fee.*100|taxRate.*[2-9]\d/i.test(content)) {
        redFlags.push('High fee/tax configuration');
      }
    }
  }

  // Dedupe
  return [...new Set(redFlags)];
}

/**
 * Main trust scan function
 */
export async function performTrustScan(gitUrl: string): Promise<TrustScanResult> {
  // Security: Validate URL doesn't contain dangerous characters
  if (/[;&|`$(){}[\]<>\s]/.test(gitUrl)) {
    throw new Error('Invalid characters in URL');
  }

  const parsed = parseGitHubUrl(gitUrl);
  if (!parsed) {
    throw new Error('Invalid GitHub URL. Use format: https://github.com/owner/repo');
  }

  const { owner, repo } = parsed;

  // Security: Validate owner/repo names are alphanumeric with hyphens/underscores only
  if (!/^[\w\-\.]+$/.test(owner) || !/^[\w\-\.]+$/.test(repo)) {
    throw new Error('Invalid repository name');
  }
  const headers: Record<string, string> = {
    'User-Agent': 'AuraSecurity-RugCheck',
    'Accept': 'application/vnd.github.v3+json',
  };

  // Add GitHub token if available for higher rate limits
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
  }

  // Fetch repo info
  const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
  if (!repoRes.ok) {
    if (repoRes.status === 404) {
      throw new Error('Repository not found. Check the URL and make sure it\'s a public repo.');
    }
    if (repoRes.status === 403) {
      throw new Error('GitHub API rate limit exceeded. Try again later or add a GITHUB_TOKEN.');
    }
    throw new Error(`GitHub API error: ${repoRes.status}`);
  }
  const repoData = await repoRes.json();

  // Fetch contributor count (from Link header pagination)
  let contributorCount = 1;
  try {
    const contribRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contributors?per_page=1&anon=true`, { headers });
    if (contribRes.ok) {
      const linkHeader = contribRes.headers.get('Link');
      if (linkHeader) {
        const lastMatch = linkHeader.match(/page=(\d+)>; rel="last"/);
        if (lastMatch) {
          contributorCount = parseInt(lastMatch[1], 10);
        }
      } else {
        const contribs = await contribRes.json();
        contributorCount = Array.isArray(contribs) ? contribs.length : 1;
      }
    }
  } catch {
    // Default to 1 if we can't fetch
  }

  // Fetch commit count (from Link header pagination)
  let commitCount = 1;
  try {
    const commitsRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/commits?per_page=1`, { headers });
    if (commitsRes.ok) {
      const linkHeader = commitsRes.headers.get('Link');
      if (linkHeader) {
        const lastMatch = linkHeader.match(/page=(\d+)>; rel="last"/);
        if (lastMatch) {
          commitCount = parseInt(lastMatch[1], 10);
        }
      }
    }
  } catch {
    // Default to 1 if we can't fetch
  }

  // Fetch owner profile for enhanced checks
  let ownerAccountAgeDays: number | undefined;
  let ownerPublicRepos: number | undefined;
  let ownerTotalContributions: number | undefined;

  try {
    const ownerRes = await fetch(`https://api.github.com/users/${owner}`, { headers });
    if (ownerRes.ok) {
      const ownerData = await ownerRes.json();
      const ownerCreatedAt = new Date(ownerData.created_at);
      ownerAccountAgeDays = Math.floor((new Date().getTime() - ownerCreatedAt.getTime()) / (1000 * 60 * 60 * 24));
      ownerPublicRepos = ownerData.public_repos || 0;
    }
  } catch {
    // Continue without owner data
  }

  // Fetch fork comparison if this is a fork
  let forkChangedLines: number | undefined;
  let forkParentRepo: string | undefined;

  if (repoData.fork && repoData.parent) {
    forkParentRepo = repoData.parent.full_name;
    try {
      const compareRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/compare/${repoData.parent.default_branch}...${repoData.default_branch}`, { headers });
      if (compareRes.ok) {
        const compareData = await compareRes.json();
        // Sum up additions and deletions
        forkChangedLines = (compareData.files || []).reduce((sum: number, f: { additions?: number; deletions?: number }) =>
          sum + (f.additions || 0) + (f.deletions || 0), 0);
      }
    } catch {
      // Continue without fork comparison
    }
  }

  // Fetch file tree to analyze code structure
  let codeFileCount = 0;
  let hasTests = false;
  let hasReadme = false;
  let hasDependencies = false;
  let secretsFound = 0;
  let readmeRedFlags: string[] = [];
  let codeRedFlags: string[] = [];

  try {
    const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${repoData.default_branch}?recursive=1`, { headers });
    if (treeRes.ok) {
      const treeData = await treeRes.json();
      const files = treeData.tree?.filter((f: { type: string }) => f.type === 'blob') || [];

      // Code file extensions
      const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.sol', '.java', '.c', '.cpp', '.rb', '.php', '.swift', '.kt'];
      codeFileCount = files.filter((f: { path: string }) =>
        codeExtensions.some(ext => f.path.endsWith(ext))
      ).length;

      // Check for tests
      hasTests = files.some((f: { path: string }) =>
        f.path.includes('test') || f.path.includes('spec') || f.path.includes('__tests__')
      );

      // Check for readme
      const readmeFile = files.find((f: { path: string }) =>
        f.path.toLowerCase().includes('readme')
      );
      hasReadme = !!readmeFile;

      // Check for dependencies
      hasDependencies = files.some((f: { path: string }) =>
        f.path === 'package.json' ||
        f.path === 'requirements.txt' ||
        f.path === 'Cargo.toml' ||
        f.path === 'go.mod' ||
        f.path === 'Gemfile'
      );

      // Scan README for red flags
      if (readmeFile) {
        try {
          const readmeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${readmeFile.path}`, { headers });
          if (readmeRes.ok) {
            const readmeData = await readmeRes.json();
            if (readmeData.content) {
              const readmeContent = Buffer.from(readmeData.content, 'base64').toString('utf-8');
              readmeRedFlags = scanReadmeForRedFlags(readmeContent);
            }
          }
        } catch {
          // Skip if can't read README
        }
      }

      // Scan Solidity files for honeypot patterns (limit to 3 files)
      const solidityFiles = files.filter((f: { path: string }) => f.path.endsWith('.sol')).slice(0, 3);
      const scannedFiles: Array<{ path: string; content?: string }> = [];

      for (const file of solidityFiles) {
        try {
          const fileRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`, { headers });
          if (fileRes.ok) {
            const fileData = await fileRes.json();
            if (fileData.content) {
              scannedFiles.push({
                path: file.path,
                content: Buffer.from(fileData.content, 'base64').toString('utf-8')
              });
            }
          }
        } catch {
          // Skip files we can't read
        }
      }
      codeRedFlags = scanCodeForRedFlags(scannedFiles);

      // Quick secret scan on key files (config files, env examples)
      const sensitiveFiles = files.filter((f: { path: string }) =>
        f.path.includes('config') ||
        f.path.includes('.env') ||
        f.path.endsWith('.json') ||
        f.path.endsWith('.yml')
      ).slice(0, 5);

      for (const file of sensitiveFiles) {
        try {
          const fileRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`, { headers });
          if (fileRes.ok) {
            const fileData = await fileRes.json();
            if (fileData.content) {
              const content = Buffer.from(fileData.content, 'base64').toString('utf-8');
              secretsFound += scanForSecrets(content);
            }
          }
        } catch {
          // Skip files we can't read
        }
      }
    }
  } catch {
    // If we can't fetch tree, continue with defaults
  }

  // Calculate metrics
  const now = new Date();
  const createdAt = new Date(repoData.created_at);
  const pushedAt = new Date(repoData.pushed_at);
  const repoAgeDays = Math.floor((now.getTime() - createdAt.getTime()) / (1000 * 60 * 60 * 24));
  const daysSinceLastPush = Math.floor((now.getTime() - pushedAt.getTime()) / (1000 * 60 * 60 * 24));

  const metrics: TrustMetrics = {
    repoAgeDays,
    daysSinceLastPush,
    commitCount,
    contributorCount,
    stars: repoData.stargazers_count || 0,
    forks: repoData.forks_count || 0,
    watchers: repoData.watchers_count || 0,
    openIssues: repoData.open_issues_count || 0,
    codeFileCount,
    hasTests,
    hasReadme,
    hasDependencies,
    hasLicense: !!repoData.license,
    isFork: repoData.fork || false,
    isArchived: repoData.archived || false,
    language: repoData.language,
    topics: repoData.topics || [],
    secretsFound,
    // Enhanced metrics
    forkChangedLines,
    forkParentRepo,
    ownerAccountAgeDays,
    ownerPublicRepos,
    ownerTotalContributions,
    readmeRedFlags,
    codeRedFlags,
  };

  // Run trust checks
  const checks = runTrustChecks(metrics);

  // Calculate score
  const { score, grade, verdict, verdictEmoji } = calculateScore(checks);

  // Generate summary
  const summary = generateSummary(checks, score, verdict);

  return {
    url: gitUrl,
    repoName: repo,
    owner,
    trustScore: Math.round(score),
    grade,
    verdict,
    verdictEmoji,
    summary,
    checks,
    metrics,
    scannedAt: new Date().toISOString(),
  };
}
