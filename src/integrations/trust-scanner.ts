/**
 * Trust Scanner - Rug Check for Crypto Investors
 *
 * Analyzes GitHub repositories to detect potential rug pulls and scams.
 * Returns a trust score (0-100) with plain English explanations.
 *
 * Scoring weights and thresholds are loaded from private config (config/trust-weights.json).
 * If config is missing, built-in defaults are used.
 */

import { loadConfig, toRegExp } from '../config/loader.js';

// Config types
interface TrustWeightsConfig {
  baseScore: number;
  repoAge: {
    brandNewDays: number; brandNewPoints: number;
    veryNewDays: number; veryNewPoints: number;
    moderateDays: number; moderatePoints: number;
    establishedDays: number; establishedPoints: number;
    wellEstablishedPoints: number;
  };
  commits: {
    veryLowMax: number; veryLowPoints: number;
    lowMax: number; lowPoints: number;
    moderateMax: number; moderatePoints: number;
    activePoints: number;
  };
  historySuspicious: {
    minCodeFiles: number; minCommitsForCheck: number;
    extremeRatio: number; extremePoints: number;
    suspiciousRatio: number; suspiciousPoints: number;
  };
  contributors: {
    soloMax: number; soloPoints: number;
    smallMax: number; smallPoints: number;
    goodMax: number; goodPoints: number;
    largePoints: number;
  };
  stars: {
    boughtMinStars: number; boughtRatio: number; boughtPoints: number;
    inflatedMinStars: number; inflatedRatio: number; inflatedPoints: number;
    naturalMinStars: number; naturalPoints: number;
    lowPoints: number;
  };
  codeFiles: {
    noneMax: number; nonePoints: number;
    fewMax: number; fewPoints: number;
    smallMax: number; smallPoints: number;
    substantialPoints: number;
  };
  tests: { absentPoints: number; presentPoints: number };
  activity: {
    abandonedDays: number; abandonedPoints: number;
    inactiveDays: number; inactivePoints: number;
    moderateDays: number; moderatePoints: number;
    activePoints: number;
  };
  fork: { isForkPoints: number; isOriginalPoints: number };
  license: { presentPoints: number; absentPoints: number };
  dependencies: { presentPoints: number; absentPoints: number };
  secrets: { perSecretPoints: number; cleanPoints: number };
  archived: { points: number };
  forkAnalysis: {
    copyPasteMax: number; copyPastePoints: number;
    minimalMax: number; minimalPoints: number;
    substantialPoints: number;
  };
  ownerAge: {
    veryNewDays: number; veryNewPointsDefault: number; veryNewPointsWithCode: number;
    newDays: number; newPoints: number;
    establishedDays: number; establishedPoints: number;
  };
  ownerRepos: {
    firstMax: number; firstPointsDefault: number; firstPointsWithCode: number;
    limitedMax: number; limitedPoints: number;
    activeMin: number; activePoints: number;
  };
  readmeFlags: { manyMin: number; manyPoints: number; somePoints: number };
  codeFlags: { manyMin: number; manyPoints: number; somePoints: number };
  builderBonus: {
    strongMin: number; strongPoints: number;
    goodMin: number; goodPoints: number;
    someMin: number; somePoints: number;
    thresholds: {
      minCodeFiles: number; minCommits: number;
      maxDaysSinceUpdate: number; minContributors: number;
    };
  };
  grades: { A: number; B: number; C: number };
  scoreCaps: {
    secrets5plus: number; secrets3plus: number; secrets1plus: number;
    noCode: number; bad3plus: number; bad2: number; bad1: number;
  };
  realCodeThresholds: { minCodeFiles: number; minCommits: number };
  secretPatterns?: Array<{ pattern: [string, string?]; name: string }>;
  readmeRedFlagPatterns?: Array<{ pattern: [string, string?]; flag: string; excludePattern?: [string, string?] }>;
  codeRedFlagPatterns?: Array<{ pattern: [string, string?]; flag: string; fileExt: string }>;
}

// Default weights (used when config file is not found)
const DEFAULT_WEIGHTS: TrustWeightsConfig = {
  baseScore: 40,
  repoAge: { brandNewDays: 7, brandNewPoints: -15, veryNewDays: 30, veryNewPoints: 2, moderateDays: 180, moderatePoints: 5, establishedDays: 365, establishedPoints: 8, wellEstablishedPoints: 10 },
  commits: { veryLowMax: 5, veryLowPoints: 0, lowMax: 20, lowPoints: 3, moderateMax: 100, moderatePoints: 6, activePoints: 10 },
  historySuspicious: { minCodeFiles: 20, minCommitsForCheck: 3, extremeRatio: 30, extremePoints: -25, suspiciousRatio: 15, suspiciousPoints: -15 },
  contributors: { soloMax: 1, soloPoints: -5, smallMax: 3, smallPoints: 3, goodMax: 10, goodPoints: 7, largePoints: 10 },
  stars: { boughtMinStars: 100, boughtRatio: 100, boughtPoints: -20, inflatedMinStars: 50, inflatedRatio: 50, inflatedPoints: -10, naturalMinStars: 10, naturalPoints: 5, lowPoints: 0 },
  codeFiles: { noneMax: 0, nonePoints: -10, fewMax: 5, fewPoints: 2, smallMax: 20, smallPoints: 6, substantialPoints: 10 },
  tests: { absentPoints: 0, presentPoints: 10 },
  activity: { abandonedDays: 365, abandonedPoints: -10, inactiveDays: 180, inactivePoints: 0, moderateDays: 30, moderatePoints: 5, activePoints: 10 },
  fork: { isForkPoints: -5, isOriginalPoints: 5 },
  license: { presentPoints: 5, absentPoints: 0 },
  dependencies: { presentPoints: 5, absentPoints: 0 },
  secrets: { perSecretPoints: -10, cleanPoints: 5 },
  archived: { points: -15 },
  forkAnalysis: { copyPasteMax: 50, copyPastePoints: -25, minimalMax: 200, minimalPoints: -10, substantialPoints: 0 },
  ownerAge: { veryNewDays: 30, veryNewPointsDefault: -15, veryNewPointsWithCode: -8, newDays: 180, newPoints: -5, establishedDays: 365, establishedPoints: 5 },
  ownerRepos: { firstMax: 1, firstPointsDefault: -10, firstPointsWithCode: -5, limitedMax: 5, limitedPoints: -5, activeMin: 10, activePoints: 5 },
  readmeFlags: { manyMin: 2, manyPoints: -20, somePoints: -10 },
  codeFlags: { manyMin: 2, manyPoints: -25, somePoints: -10 },
  builderBonus: { strongMin: 4, strongPoints: 15, goodMin: 3, goodPoints: 10, someMin: 2, somePoints: 5, thresholds: { minCodeFiles: 20, minCommits: 30, maxDaysSinceUpdate: 30, minContributors: 2 } },
  grades: { A: 80, B: 60, C: 35 },
  scoreCaps: { secrets5plus: 40, secrets3plus: 50, secrets1plus: 65, noCode: 40, bad3plus: 50, bad2: 60, bad1: 75 },
  realCodeThresholds: { minCodeFiles: 20, minCommits: 20 },
};

// Load weights from config
const W = loadConfig<TrustWeightsConfig>('trust-weights.json', DEFAULT_WEIGHTS);

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
  const patterns = [
    /github\.com\/([^\/]+)\/([^\/\?\#]+)/,
    /^([^\/]+)\/([^\/]+)$/
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
  if (metrics.repoAgeDays < W.repoAge.brandNewDays) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'bad',
      points: W.repoAge.brandNewPoints,
      explanation: 'Brand new project (less than a week old) - major red flag!'
    });
  } else if (metrics.repoAgeDays < W.repoAge.veryNewDays) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'warn',
      points: W.repoAge.veryNewPoints,
      explanation: `Very new project (${metrics.repoAgeDays} days old) - be cautious`
    });
  } else if (metrics.repoAgeDays < W.repoAge.moderateDays) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'info',
      points: W.repoAge.moderatePoints,
      explanation: `Project is ${Math.floor(metrics.repoAgeDays / 30)} months old`
    });
  } else if (metrics.repoAgeDays < W.repoAge.establishedDays) {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'good',
      points: W.repoAge.establishedPoints,
      explanation: `Established project (${Math.floor(metrics.repoAgeDays / 30)} months old)`
    });
  } else {
    checks.push({
      id: 'repo_age',
      name: 'Project Age',
      status: 'good',
      points: W.repoAge.wellEstablishedPoints,
      explanation: `Well-established project (${Math.floor(metrics.repoAgeDays / 365)} years old)`
    });
  }

  // 2. Commit Count Check
  if (metrics.commitCount < W.commits.veryLowMax) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'bad',
      points: W.commits.veryLowPoints,
      explanation: `Only ${metrics.commitCount} commits - looks like a placeholder or copy`
    });
  } else if (metrics.commitCount < W.commits.lowMax) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'warn',
      points: W.commits.lowPoints,
      explanation: `Low commit count (${metrics.commitCount}) - limited development`
    });
  } else if (metrics.commitCount < W.commits.moderateMax) {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'info',
      points: W.commits.moderatePoints,
      explanation: `${metrics.commitCount} commits - moderate development activity`
    });
  } else {
    checks.push({
      id: 'commits',
      name: 'Development Activity',
      status: 'good',
      points: W.commits.activePoints,
      explanation: `${metrics.commitCount} commits - active development`
    });
  }

  // 2b. Files-to-Commits Ratio Check
  if (metrics.codeFileCount > W.historySuspicious.minCodeFiles && metrics.commitCount <= W.historySuspicious.minCommitsForCheck) {
    const ratio = metrics.codeFileCount / Math.max(metrics.commitCount, 1);
    if (ratio > W.historySuspicious.extremeRatio) {
      checks.push({
        id: 'history-suspicious',
        name: 'Suspicious History',
        status: 'bad',
        points: W.historySuspicious.extremePoints,
        explanation: `${metrics.codeFileCount} files in only ${metrics.commitCount} commit(s) - likely copied/forked with squashed history`
      });
    } else if (ratio > W.historySuspicious.suspiciousRatio) {
      checks.push({
        id: 'history-suspicious',
        name: 'Suspicious History',
        status: 'warn',
        points: W.historySuspicious.suspiciousPoints,
        explanation: `High files-to-commits ratio (${metrics.codeFileCount} files, ${metrics.commitCount} commits) - unusual development pattern`
      });
    }
  }

  // 3. Contributor Check
  if (metrics.contributorCount === W.contributors.soloMax) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'warn',
      points: W.contributors.soloPoints,
      explanation: 'Only 1 contributor - single person project (higher risk)'
    });
  } else if (metrics.contributorCount < W.contributors.smallMax) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'info',
      points: W.contributors.smallPoints,
      explanation: `Small team (${metrics.contributorCount} contributors)`
    });
  } else if (metrics.contributorCount < W.contributors.goodMax) {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'good',
      points: W.contributors.goodPoints,
      explanation: `Good team size (${metrics.contributorCount} contributors)`
    });
  } else {
    checks.push({
      id: 'contributors',
      name: 'Team Size',
      status: 'good',
      points: W.contributors.largePoints,
      explanation: `Large team (${metrics.contributorCount}+ contributors)`
    });
  }

  // 4. Star Pattern Check
  const starForkRatio = metrics.stars / Math.max(metrics.forks, 1);
  if (metrics.stars > W.stars.boughtMinStars && starForkRatio > W.stars.boughtRatio) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'bad',
      points: W.stars.boughtPoints,
      explanation: `Suspicious! ${metrics.stars} stars but only ${metrics.forks} forks - likely bought stars`
    });
  } else if (metrics.stars > W.stars.inflatedMinStars && starForkRatio > W.stars.inflatedRatio) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'warn',
      points: W.stars.inflatedPoints,
      explanation: `Unusual star pattern (${metrics.stars} stars, ${metrics.forks} forks) - could be inflated`
    });
  } else if (metrics.stars > W.stars.naturalMinStars) {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'good',
      points: W.stars.naturalPoints,
      explanation: `Natural engagement (${metrics.stars} stars, ${metrics.forks} forks)`
    });
  } else {
    checks.push({
      id: 'stars',
      name: 'Star Pattern',
      status: 'info',
      points: W.stars.lowPoints,
      explanation: `Low visibility (${metrics.stars} stars) - newer or niche project`
    });
  }

  // 5. Code Files Check
  if (metrics.codeFileCount === W.codeFiles.noneMax) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'bad',
      points: W.codeFiles.nonePoints,
      explanation: 'No code files found! This is just a README - major red flag'
    });
  } else if (metrics.codeFileCount < W.codeFiles.fewMax) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'warn',
      points: W.codeFiles.fewPoints,
      explanation: `Very few code files (${metrics.codeFileCount}) - might be a placeholder`
    });
  } else if (metrics.codeFileCount < W.codeFiles.smallMax) {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'info',
      points: W.codeFiles.smallPoints,
      explanation: `${metrics.codeFileCount} code files - small but real codebase`
    });
  } else {
    checks.push({
      id: 'code',
      name: 'Actual Code',
      status: 'good',
      points: W.codeFiles.substantialPoints,
      explanation: `${metrics.codeFileCount} code files - substantial codebase`
    });
  }

  // 6. Tests Check
  if (!metrics.hasTests) {
    checks.push({
      id: 'tests',
      name: 'Test Coverage',
      status: 'warn',
      points: W.tests.absentPoints,
      explanation: 'No tests found - harder to verify code quality'
    });
  } else {
    checks.push({
      id: 'tests',
      name: 'Test Coverage',
      status: 'good',
      points: W.tests.presentPoints,
      explanation: 'Has test files - shows quality effort'
    });
  }

  // 7. Recent Activity Check
  if (metrics.daysSinceLastPush > W.activity.abandonedDays) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'bad',
      points: W.activity.abandonedPoints,
      explanation: `No updates in ${Math.floor(metrics.daysSinceLastPush / 365)} year(s) - project may be abandoned`
    });
  } else if (metrics.daysSinceLastPush > W.activity.inactiveDays) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'warn',
      points: W.activity.inactivePoints,
      explanation: `No updates in ${Math.floor(metrics.daysSinceLastPush / 30)} months - possibly inactive`
    });
  } else if (metrics.daysSinceLastPush > W.activity.moderateDays) {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'info',
      points: W.activity.moderatePoints,
      explanation: `Last update ${Math.floor(metrics.daysSinceLastPush / 30)} month(s) ago`
    });
  } else {
    checks.push({
      id: 'activity',
      name: 'Recent Activity',
      status: 'good',
      points: W.activity.activePoints,
      explanation: `Recently updated (${metrics.daysSinceLastPush} days ago) - actively maintained`
    });
  }

  // 8. Fork Check
  if (metrics.isFork) {
    checks.push({
      id: 'fork',
      name: 'Original Project',
      status: 'warn',
      points: W.fork.isForkPoints,
      explanation: 'This is a fork of another project - not original work'
    });
  } else {
    checks.push({
      id: 'fork',
      name: 'Original Project',
      status: 'good',
      points: W.fork.isOriginalPoints,
      explanation: 'Original repository (not a fork)'
    });
  }

  // 9. License Check
  if (metrics.hasLicense) {
    checks.push({
      id: 'license',
      name: 'License',
      status: 'good',
      points: W.license.presentPoints,
      explanation: 'Has a proper open-source license'
    });
  } else {
    checks.push({
      id: 'license',
      name: 'License',
      status: 'info',
      points: W.license.absentPoints,
      explanation: 'No license specified'
    });
  }

  // 10. Dependencies Check
  if (metrics.hasDependencies) {
    checks.push({
      id: 'dependencies',
      name: 'Dependencies',
      status: 'good',
      points: W.dependencies.presentPoints,
      explanation: 'Has package management (real project structure)'
    });
  } else {
    checks.push({
      id: 'dependencies',
      name: 'Dependencies',
      status: 'info',
      points: W.dependencies.absentPoints,
      explanation: 'No dependency file found'
    });
  }

  // 11. Secrets Check
  if (metrics.secretsFound > 0) {
    checks.push({
      id: 'secrets',
      name: 'Security',
      status: 'bad',
      points: W.secrets.perSecretPoints * metrics.secretsFound,
      explanation: `Found ${metrics.secretsFound} leaked secret(s) - major security red flag!`
    });
  } else {
    checks.push({
      id: 'secrets',
      name: 'Security',
      status: 'good',
      points: W.secrets.cleanPoints,
      explanation: 'No leaked credentials found'
    });
  }

  // 12. Archived Check
  if (metrics.isArchived) {
    checks.push({
      id: 'archived',
      name: 'Project Status',
      status: 'bad',
      points: W.archived.points,
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
    if (metrics.forkChangedLines < W.forkAnalysis.copyPasteMax) {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'bad',
        points: W.forkAnalysis.copyPastePoints,
        explanation: `Copy-paste alert! Only ${metrics.forkChangedLines} lines changed from original`
      });
    } else if (metrics.forkChangedLines < W.forkAnalysis.minimalMax) {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'warn',
        points: W.forkAnalysis.minimalPoints,
        explanation: `Minimal changes (${metrics.forkChangedLines} lines) from forked repo`
      });
    } else {
      checks.push({
        id: 'fork_analysis',
        name: 'Fork Quality',
        status: 'info',
        points: W.forkAnalysis.substantialPoints,
        explanation: `Substantial modifications (${metrics.forkChangedLines}+ lines changed)`
      });
    }
  }

  // 15. Owner Account Age Check
  const hasRealCode = metrics.codeFileCount >= W.realCodeThresholds.minCodeFiles;
  const hasRealActivity = metrics.commitCount >= W.realCodeThresholds.minCommits;

  if (metrics.ownerAccountAgeDays !== undefined) {
    if (metrics.ownerAccountAgeDays < W.ownerAge.veryNewDays) {
      const points = (hasRealCode && hasRealActivity) ? W.ownerAge.veryNewPointsWithCode : W.ownerAge.veryNewPointsDefault;
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'warn',
        points,
        explanation: `New developer account (${metrics.ownerAccountAgeDays} days old)`
      });
    } else if (metrics.ownerAccountAgeDays < W.ownerAge.newDays) {
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'warn',
        points: W.ownerAge.newPoints,
        explanation: `New developer account (${Math.floor(metrics.ownerAccountAgeDays / 30)} months old)`
      });
    } else if (metrics.ownerAccountAgeDays >= W.ownerAge.establishedDays) {
      checks.push({
        id: 'owner_age',
        name: 'Developer Account',
        status: 'good',
        points: W.ownerAge.establishedPoints,
        explanation: `Established developer (${Math.floor(metrics.ownerAccountAgeDays / 365)}+ years on GitHub)`
      });
    }
  }

  // 16. Owner Repo Count Check
  if (metrics.ownerPublicRepos !== undefined) {
    if (metrics.ownerPublicRepos === W.ownerRepos.firstMax) {
      const points = (hasRealCode && hasRealActivity) ? W.ownerRepos.firstPointsWithCode : W.ownerRepos.firstPointsDefault;
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'warn',
        points,
        explanation: 'First repo - new to GitHub'
      });
    } else if (metrics.ownerPublicRepos < W.ownerRepos.limitedMax) {
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'warn',
        points: W.ownerRepos.limitedPoints,
        explanation: `Limited history (only ${metrics.ownerPublicRepos} repos)`
      });
    } else if (metrics.ownerPublicRepos >= W.ownerRepos.activeMin) {
      checks.push({
        id: 'owner_repos',
        name: 'Developer History',
        status: 'good',
        points: W.ownerRepos.activePoints,
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
      status: flagCount >= W.readmeFlags.manyMin ? 'bad' : 'warn',
      points: flagCount >= W.readmeFlags.manyMin ? W.readmeFlags.manyPoints : W.readmeFlags.somePoints,
      explanation: `Scam signals: ${metrics.readmeRedFlags.slice(0, 2).join(', ')}`
    });
  }

  // 18. Code Red Flags
  if (metrics.codeRedFlags && metrics.codeRedFlags.length > 0) {
    const flagCount = metrics.codeRedFlags.length;
    checks.push({
      id: 'code_flags',
      name: 'Code Analysis',
      status: flagCount >= W.codeFlags.manyMin ? 'bad' : 'warn',
      points: flagCount >= W.codeFlags.manyMin ? W.codeFlags.manyPoints : W.codeFlags.somePoints,
      explanation: `Risky code: ${metrics.codeRedFlags.slice(0, 2).join(', ')}`
    });
  }

  // 19. Builder Bonus
  const builderSignals = [
    metrics.codeFileCount >= W.builderBonus.thresholds.minCodeFiles,
    metrics.hasTests,
    metrics.commitCount >= W.builderBonus.thresholds.minCommits,
    metrics.daysSinceLastPush < W.builderBonus.thresholds.maxDaysSinceUpdate,
    metrics.contributorCount >= W.builderBonus.thresholds.minContributors,
  ].filter(Boolean).length;

  if (builderSignals >= W.builderBonus.strongMin) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'good',
      points: W.builderBonus.strongPoints,
      explanation: 'Strong development signals - actively building!'
    });
  } else if (builderSignals >= W.builderBonus.goodMin) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'good',
      points: W.builderBonus.goodPoints,
      explanation: 'Good development activity detected'
    });
  } else if (builderSignals >= W.builderBonus.someMin) {
    checks.push({
      id: 'builder_bonus',
      name: 'Builder Score',
      status: 'info',
      points: W.builderBonus.somePoints,
      explanation: 'Some development effort shown'
    });
  }

  return checks;
}

/**
 * Calculate trust score from checks
 */
function calculateScore(checks: TrustCheck[]): { score: number; grade: 'A' | 'B' | 'C' | 'F'; verdict: 'SAFU' | 'DYOR' | 'RISKY' | 'RUG ALERT'; verdictEmoji: string } {
  const totalPoints = checks.reduce((sum, check) => sum + check.points, 0);
  let score = Math.max(0, Math.min(100, W.baseScore + totalPoints));

  // Count critical issues
  const badChecks = checks.filter(c => c.status === 'bad');
  const hasSecrets = checks.some(c => c.id === 'secrets' && c.status === 'bad');
  const hasNoCode = checks.some(c => c.id === 'code' && c.status === 'bad');

  // Apply caps based on critical issues
  if (hasSecrets) {
    const secretsCheck = checks.find(c => c.id === 'secrets');
    const secretCount = secretsCheck ? Math.abs(secretsCheck.points) / Math.abs(W.secrets.perSecretPoints) : 1;
    if (secretCount >= 5) {
      score = Math.min(score, W.scoreCaps.secrets5plus);
    } else if (secretCount >= 3) {
      score = Math.min(score, W.scoreCaps.secrets3plus);
    } else {
      score = Math.min(score, W.scoreCaps.secrets1plus);
    }
  }
  if (hasNoCode) {
    score = Math.min(score, W.scoreCaps.noCode);
  }
  if (badChecks.length >= 3) {
    score = Math.min(score, W.scoreCaps.bad3plus);
  } else if (badChecks.length >= 2) {
    score = Math.min(score, W.scoreCaps.bad2);
  } else if (badChecks.length >= 1) {
    score = Math.min(score, W.scoreCaps.bad1);
  }

  let grade: 'A' | 'B' | 'C' | 'F';
  let verdict: 'SAFU' | 'DYOR' | 'RISKY' | 'RUG ALERT';
  let verdictEmoji: string;

  if (score >= W.grades.A) {
    grade = 'A';
    verdict = 'SAFU';
    verdictEmoji = '🟢';
  } else if (score >= W.grades.B) {
    grade = 'B';
    verdict = 'DYOR';
    verdictEmoji = '🟡';
  } else if (score >= W.grades.C) {
    grade = 'C';
    verdict = 'RISKY';
    verdictEmoji = '🟠';
  } else {
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
 * Compile secret patterns from config
 */
function getSecretPatterns(): Array<{ pattern: RegExp; name: string }> {
  if (W.secretPatterns && W.secretPatterns.length > 0) {
    return W.secretPatterns.map(p => ({
      pattern: toRegExp(p.pattern),
      name: p.name,
    }));
  }
  // Minimal fallback
  return [
    { pattern: /AKIA[0-9A-Z]{16}/, name: 'AWS Access Key' },
    { pattern: /gh[pousr]_[A-Za-z0-9_]{36,}/, name: 'GitHub Token' },
    { pattern: /-----BEGIN\s*(?:RSA|EC|DSA|OPENSSH)?\s*PRIVATE KEY-----/, name: 'Private Key' },
  ];
}

/**
 * Scan a single file for secrets (basic patterns)
 */
function scanForSecrets(content: string): number {
  const secretPatterns = getSecretPatterns();

  // Skip data files (token lists, address registries)
  if (/["'](tokens|addresses|mints|constituents|verified)["']\s*:/i.test(content)) {
    return 0;
  }

  // Placeholder/example values are not real secrets
  const placeholderPattern = /your[_-]?api[_-]?key|REPLACE[_-]?ME|TODO|CHANGEME|xxxx|placeholder|example|sample|dummy|test|fake|mock/i;

  // Public/client-side API keys that are intentionally embedded in frontend code
  const publicKeyContext = /(?:inkeep|algolia|segment|analytics|gtag|ga4|google.*analytics|mapbox|stripe.*publishable|pk_(?:live|test)|posthog|amplitude|mixpanel|sentry.*dsn|bugsnag|datadog.*rum|hotjar|intercom.*app)/i;

  // Known blockchain addresses, program IDs, and public values
  const blockchainPattern = /^(?:0x[0-9a-fA-F]{10,}|[1-9A-HJ-NP-Za-km-z]{32,44})$/;

  let count = 0;
  for (const { pattern } of secretPatterns) {
    const match = content.match(pattern);
    if (match && !placeholderPattern.test(match[0])) {
      const valueMatch = match[0].match(/["']([^"']+)["']/);
      if (valueMatch && blockchainPattern.test(valueMatch[1])) {
        continue;
      }
      if (publicKeyContext.test(content.substring(Math.max(0, content.indexOf(match[0]) - 200), content.indexOf(match[0]) + match[0].length + 200))) {
        continue;
      }
      count++;
    }
  }
  return count;
}

/**
 * Compile README red flag patterns from config
 */
function getReadmeRedFlagPatterns(): Array<{ pattern: RegExp; flag: string; excludePattern?: RegExp }> {
  if (W.readmeRedFlagPatterns && W.readmeRedFlagPatterns.length > 0) {
    return W.readmeRedFlagPatterns.map(p => ({
      pattern: toRegExp(p.pattern),
      flag: p.flag,
      excludePattern: p.excludePattern ? toRegExp(p.excludePattern) : undefined,
    }));
  }
  // Minimal fallback
  return [
    { pattern: /100x|1000x|guaranteed.*return|moonshot|get rich/i, flag: 'Promises unrealistic returns' },
    { pattern: /whitelist.*limited|presale.*ending|act.*fast|don.?t.*miss/i, flag: 'FOMO/urgency language' },
  ];
}

/**
 * Scan README for scam red flags
 */
function scanReadmeForRedFlags(content: string): string[] {
  const redFlags: string[] = [];
  const patterns = getReadmeRedFlagPatterns();

  for (const { pattern, flag, excludePattern } of patterns) {
    if (pattern.test(content)) {
      if (excludePattern && excludePattern.test(content)) {
        continue;
      }
      redFlags.push(flag);
    }
  }

  // Airdrop + connect wallet check (composite check, kept inline)
  const lowerContent = content.toLowerCase();
  if (lowerContent.includes('airdrop') && lowerContent.includes('connect wallet')) {
    redFlags.push('Airdrop + connect wallet = phishing risk');
  }

  return redFlags;
}

/**
 * Compile code red flag patterns from config
 */
function getCodeRedFlagPatterns(): Array<{ pattern: RegExp; flag: string; fileExt: string }> {
  if (W.codeRedFlagPatterns && W.codeRedFlagPatterns.length > 0) {
    return W.codeRedFlagPatterns.map(p => ({
      pattern: toRegExp(p.pattern),
      flag: p.flag,
      fileExt: p.fileExt,
    }));
  }
  // Minimal fallback
  return [
    { pattern: /onlyOwner.*withdraw|withdraw.*onlyOwner/is, flag: 'Owner-only withdraw function', fileExt: '.sol' },
    { pattern: /selfdestruct|delegatecall/i, flag: 'Dangerous functions (selfdestruct/delegatecall)', fileExt: '.sol' },
  ];
}

/**
 * Scan code for honeypot patterns
 */
function scanCodeForRedFlags(files: Array<{ path: string; content?: string }>): string[] {
  const redFlags: string[] = [];
  const patterns = getCodeRedFlagPatterns();

  for (const file of files) {
    if (!file.content) continue;

    for (const { pattern, flag, fileExt } of patterns) {
      if (file.path.endsWith(fileExt) && pattern.test(file.content)) {
        redFlags.push(flag);
      }
    }
  }

  // Dedupe
  return [...new Set(redFlags)];
}

/**
 * Lightweight check if a GitHub repo exists
 */
export async function validateGitHubRepo(gitUrl: string): Promise<boolean> {
  try {
    const parsed = parseGitHubUrl(gitUrl);
    if (!parsed) return false;

    const { owner, repo } = parsed;
    if (!/^[\w\-\.]+$/.test(owner) || !/^[\w\-\.]+$/.test(repo)) return false;

    const headers: Record<string, string> = {
      'User-Agent': 'AuraSecurity-RugCheck',
      'Accept': 'application/vnd.github.v3+json',
    };
    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
    }

    const res = await fetch(`https://api.github.com/repos/${owner}/${repo}`, {
      headers,
      signal: AbortSignal.timeout(5000),
    });

    return res.ok;
  } catch {
    return false;
  }
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

  // Fetch contributor count
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
    // Default to 1
  }

  // Fetch commit count
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
    // Default to 1
  }

  // Fetch owner profile
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

  // Fetch fork comparison
  let forkChangedLines: number | undefined;
  let forkParentRepo: string | undefined;

  if (repoData.fork && repoData.parent) {
    forkParentRepo = repoData.parent.full_name;
    try {
      const compareRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/compare/${repoData.parent.default_branch}...${repoData.default_branch}`, { headers });
      if (compareRes.ok) {
        const compareData = await compareRes.json();
        forkChangedLines = (compareData.files || []).reduce((sum: number, f: { additions?: number; deletions?: number }) =>
          sum + (f.additions || 0) + (f.deletions || 0), 0);
      }
    } catch {
      // Continue without fork comparison
    }
  }

  // Fetch file tree
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

      const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.sol', '.java', '.c', '.cpp', '.rb', '.php', '.swift', '.kt'];
      codeFileCount = files.filter((f: { path: string }) =>
        codeExtensions.some(ext => f.path.endsWith(ext))
      ).length;

      hasTests = files.some((f: { path: string }) =>
        f.path.includes('test') || f.path.includes('spec') || f.path.includes('__tests__')
      );

      const readmeFile = files.find((f: { path: string }) =>
        f.path.toLowerCase().includes('readme')
      );
      hasReadme = !!readmeFile;

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
          // Skip
        }
      }

      // Scan Solidity files for honeypot patterns
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
          // Skip
        }
      }
      codeRedFlags = scanCodeForRedFlags(scannedFiles);

      // Quick secret scan
      const sensitiveFiles = files.filter((f: { path: string }) => {
        const p = f.path.toLowerCase();
        const isSensitive = p.includes('.env') ||
          /(?:^|\/)(?:config|settings|credentials|secrets)\.(json|yml|yaml|toml|ini)$/i.test(p) ||
          /(?:^|\/)application\.(yml|yaml|properties)$/i.test(p) ||
          p.endsWith('.env.local') ||
          p.endsWith('.env.production');
        const isSafe = p === 'package.json' ||
          p === 'package-lock.json' ||
          p.includes('tsconfig') ||
          p.includes('eslint') ||
          p.includes('prettier') ||
          p.endsWith('.lock') ||
          p.includes('token-list') ||
          p.includes('tokenlist') ||
          p.includes('/test') ||
          p.includes('/example') ||
          p.includes('/fixture') ||
          /\.env\.(example|sample|template|defaults|development|test)$/i.test(p) ||
          p.includes('docker-compose') ||
          p.includes('.github/');
        return isSensitive && !isSafe;
      }).slice(0, 5);

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
          // Skip
        }
      }
    }
  } catch {
    // Continue with defaults
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
    forkChangedLines,
    forkParentRepo,
    ownerAccountAgeDays,
    ownerPublicRepos,
    ownerTotalContributions,
    readmeRedFlags,
    codeRedFlags,
  };

  const checks = runTrustChecks(metrics);
  const { score, grade, verdict, verdictEmoji } = calculateScore(checks);
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
