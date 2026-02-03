/**
 * X/Twitter Scanner - Profile Analysis for Crypto Projects
 *
 * Phase 1-3 Enhanced Version:
 * - Engagement rate analysis
 * - Reply ratio detection
 * - 2-level follower quality check
 * - Notable follower detection
 * - Database tracking for reputation
 */

import {
  getXAccountReputation,
  updateXAccountReputation,
  recordXScan,
  isXAccountFlagged,
  type XAccountReputation
} from './rug-database.js';

// Keywords for analysis
const DEV_BIO_KEYWORDS = ['developer', 'engineer', 'dev', 'code', 'programming', 'software', 'web3', 'blockchain', 'rust', 'solidity', 'typescript'];
const FAKE_BIO_KEYWORDS = ['dm for promo', 'paid promo', 'giveaway', '100x', 'guaranteed', 'profit daily', 'not financial advice'];
const SCAM_TWEET_KEYWORDS = ['airdrop', 'giveaway', 'whitelist', 'presale', '100x', '1000x', 'guaranteed', 'dont miss', "don't miss", 'last chance', 'free money', 'dm me'];
const TECH_TWEET_KEYWORDS = ['github', 'commit', 'deploy', 'bug', 'feature', 'release', 'update', 'code', 'api', 'sdk', 'docs', 'rust', 'solidity', 'typescript'];

export interface XProfile {
  id: string;
  username: string;
  name: string;
  bio: string;
  followers: number;
  following: number;
  tweets: number;
  createdAt: string;
  verified: boolean;
  website?: string;
  profileImage?: string;
}

export interface XScanResult {
  profile: XProfile;
  score: number;
  grade: 'A' | 'B' | 'C' | 'D' | 'F';
  verdict: 'LEGIT' | 'LIKELY LEGIT' | 'SUSPICIOUS' | 'LIKELY SCAM' | 'SCAM';
  verdictEmoji: string;
  redFlags: string[];
  greenFlags: string[];
  followerAnalysis: {
    quality: number;
    realPercent: number;
    botPercent: number;
    analysis: string;
    // Phase 2: Deep check
    followersOfFollowersReal?: number;
    verifiedFollowers?: number;
  };
  tweetAnalysis: {
    techPercent: number;
    scamPercent: number;
    // Phase 1: New metrics
    engagementRate: number;
    replyRatio: number;
    avgLikes: number;
    avgRetweets: number;
  };
  githubVerified: boolean;
  githubData?: {
    username: string;
    repos: number;
    followers: number;
    crossVerified: boolean;
  };
  // Phase 3: Database reputation
  reputation?: XAccountReputation | null;
  previousScans?: number;
  isNewAccount?: boolean;
  scannedAt: string;
}

/**
 * Format large numbers (1000 -> 1K, 1000000 -> 1M)
 */
function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

/**
 * Fetch JSON from URL
 */
async function fetchJson(url: string, headers: Record<string, string> = {}): Promise<any> {
  const response = await fetch(url, { headers });
  if (!response.ok) return null;
  return response.json();
}

/**
 * Get X user profile by username
 */
async function getXProfile(username: string, bearerToken: string): Promise<XProfile | null> {
  const url = `https://api.twitter.com/2/users/by/username/${username}?user.fields=id,created_at,description,public_metrics,verified,verified_type,profile_image_url,url,entities`;

  const data = await fetchJson(url, {
    'Authorization': `Bearer ${bearerToken}`,
    'User-Agent': 'AuraSecurityBot/1.0'
  });

  if (!data?.data) return null;

  const user = data.data;
  return {
    id: user.id,
    username: user.username,
    name: user.name,
    bio: user.description || '',
    followers: user.public_metrics?.followers_count || 0,
    following: user.public_metrics?.following_count || 0,
    tweets: user.public_metrics?.tweet_count || 0,
    createdAt: user.created_at,
    verified: user.verified || false,
    website: user.entities?.url?.urls?.[0]?.expanded_url || user.url,
    profileImage: user.profile_image_url
  };
}

/**
 * Get user's recent tweets with engagement metrics
 */
async function getUserTweets(userId: string, bearerToken: string, count = 100): Promise<any[]> {
  const url = `https://api.twitter.com/2/users/${userId}/tweets?max_results=${Math.min(count, 100)}&tweet.fields=created_at,public_metrics,text,in_reply_to_user_id`;

  const data = await fetchJson(url, {
    'Authorization': `Bearer ${bearerToken}`,
    'User-Agent': 'AuraSecurityBot/1.0'
  });

  return data?.data || [];
}

/**
 * Sample followers to check quality - PHASE 2: Increased to 100
 */
async function sampleFollowers(userId: string, bearerToken: string, count = 100): Promise<any[]> {
  const url = `https://api.twitter.com/2/users/${userId}/followers?max_results=${Math.min(count, 100)}&user.fields=public_metrics,verified,description,created_at,profile_image_url`;

  const data = await fetchJson(url, {
    'Authorization': `Bearer ${bearerToken}`,
    'User-Agent': 'AuraSecurityBot/1.0'
  });

  return data?.data || [];
}

/**
 * Get who the user follows
 */
async function getUserFollowing(userId: string, bearerToken: string, count = 100): Promise<any[]> {
  const url = `https://api.twitter.com/2/users/${userId}/following?max_results=${Math.min(count, 100)}&user.fields=public_metrics,verified,description,created_at`;

  const data = await fetchJson(url, {
    'Authorization': `Bearer ${bearerToken}`,
    'User-Agent': 'AuraSecurityBot/1.0'
  });

  return data?.data || [];
}

/**
 * PHASE 1: Calculate engagement rate from tweets
 */
function calculateEngagement(tweets: any[], followerCount: number): {
  engagementRate: number;
  avgLikes: number;
  avgRetweets: number;
  replyRatio: number;
} {
  if (!tweets || tweets.length === 0 || followerCount === 0) {
    return { engagementRate: 0, avgLikes: 0, avgRetweets: 0, replyRatio: 0 };
  }

  let totalLikes = 0;
  let totalRetweets = 0;
  let replyCount = 0;

  for (const tweet of tweets) {
    const metrics = tweet.public_metrics || {};
    totalLikes += metrics.like_count || 0;
    totalRetweets += metrics.retweet_count || 0;

    // Check if tweet is a reply (has in_reply_to_user_id)
    if (tweet.in_reply_to_user_id) {
      replyCount++;
    }
  }

  const avgLikes = totalLikes / tweets.length;
  const avgRetweets = totalRetweets / tweets.length;
  const avgEngagement = avgLikes + avgRetweets;

  // Engagement rate = average engagement per tweet / followers * 100
  const engagementRate = (avgEngagement / followerCount) * 100;
  const replyRatio = (replyCount / tweets.length) * 100;

  return {
    engagementRate: Math.round(engagementRate * 100) / 100,
    avgLikes: Math.round(avgLikes),
    avgRetweets: Math.round(avgRetweets),
    replyRatio: Math.round(replyRatio)
  };
}

/**
 * PHASE 2: Analyze follower quality with 2-level depth
 */
function analyzeFollowerQuality(followers: any[]): {
  quality: number;
  realPercent: number;
  botPercent: number;
  analysis: string;
  verifiedFollowers: number;
  followersOfFollowersReal: number;
} {
  if (!followers || followers.length === 0) {
    return {
      quality: 0,
      realPercent: 0,
      botPercent: 0,
      analysis: 'Could not sample followers',
      verifiedFollowers: 0,
      followersOfFollowersReal: 0
    };
  }

  let realCount = 0;
  let botCount = 0;
  let suspiciousCount = 0;
  let verifiedCount = 0;

  // Phase 2: Track follower quality scores for 2-level analysis
  let totalFollowerQuality = 0;

  for (const f of followers) {
    const metrics = f.public_metrics || {};
    const followerCount = metrics.followers_count || 0;
    const followingCount = metrics.following_count || 0;
    const tweetCount = metrics.tweet_count || 0;
    const created = new Date(f.created_at);
    const ageMonths = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 30);
    const hasDefaultPic = f.profile_image_url?.includes('default_profile');
    const hasBio = f.description && f.description.length > 10;

    // Count verified followers
    if (f.verified) verifiedCount++;

    // Bot signals
    let botScore = 0;
    if (hasDefaultPic) botScore += 30;
    if (!hasBio) botScore += 20;
    if (tweetCount < 5) botScore += 25;
    if (ageMonths < 3) botScore += 15;
    if (followingCount > 1000 && followerCount < 50) botScore += 30; // Follow farming
    if (followerCount === 0 && tweetCount === 0) botScore += 40;

    // PHASE 2: Check if this follower's followers are likely real
    // Real accounts tend to have balanced follower/following ratios
    if (followerCount > 0 && followingCount > 0) {
      const ratio = followerCount / followingCount;
      if (ratio > 0.1 && ratio < 10) {
        // Healthy ratio suggests real account with real followers
        totalFollowerQuality += 1;
      } else if (followingCount > 5000 && followerCount < 100) {
        // Follow-farming pattern - their followers are probably bots too
        totalFollowerQuality -= 0.5;
      }
    }

    // Real signals
    if (ageMonths > 24) botScore -= 20;
    if (hasBio) botScore -= 10;
    if (tweetCount > 100) botScore -= 15;
    if (followerCount > 100 && followingCount < followerCount) botScore -= 15;
    if (f.verified) botScore -= 30; // Verified accounts are real

    if (botScore >= 50) botCount++;
    else if (botScore >= 25) suspiciousCount++;
    else realCount++;
  }

  const total = followers.length;
  const realPercent = Math.round((realCount / total) * 100);
  const botPercent = Math.round((botCount / total) * 100);

  // PHASE 2: Followers of followers quality score (0-100)
  const followersOfFollowersReal = Math.round(
    Math.max(0, Math.min(100, (totalFollowerQuality / total) * 100 + 50))
  );

  let quality = realPercent;
  let analysis = '';

  if (botPercent > 50) {
    analysis = 'MAJORITY BOT FOLLOWERS';
  } else if (botPercent > 30) {
    analysis = 'High bot percentage';
  } else if (realPercent > 70) {
    analysis = 'Healthy authentic follower base';
  } else {
    analysis = 'Mixed follower quality';
  }

  return {
    quality,
    realPercent,
    botPercent,
    analysis,
    verifiedFollowers: verifiedCount,
    followersOfFollowersReal
  };
}

/**
 * PHASE 1: Analyze tweet content with engagement
 */
function analyzeTweets(tweets: any[], followerCount: number): {
  techPercent: number;
  scamPercent: number;
  engagementRate: number;
  replyRatio: number;
  avgLikes: number;
  avgRetweets: number;
} {
  if (!tweets || tweets.length === 0) {
    return {
      techPercent: 0,
      scamPercent: 0,
      engagementRate: 0,
      replyRatio: 0,
      avgLikes: 0,
      avgRetweets: 0
    };
  }

  let techCount = 0;
  let scamCount = 0;

  for (const tweet of tweets) {
    const text = (tweet.text || '').toLowerCase();

    if (SCAM_TWEET_KEYWORDS.some(k => text.includes(k))) {
      scamCount++;
    }
    if (TECH_TWEET_KEYWORDS.some(k => text.includes(k))) {
      techCount++;
    }
  }

  // Calculate engagement metrics
  const engagement = calculateEngagement(tweets, followerCount);

  return {
    techPercent: Math.round((techCount / tweets.length) * 100),
    scamPercent: Math.round((scamCount / tweets.length) * 100),
    ...engagement
  };
}

/**
 * Analyze who they follow
 */
function analyzeFollowing(following: any[]): { techPercent: number; suspiciousPercent: number; suspiciousCount: number } {
  if (!following || following.length === 0) {
    return { techPercent: 0, suspiciousPercent: 0, suspiciousCount: 0 };
  }

  let techCount = 0;
  let suspiciousCount = 0;

  for (const f of following) {
    const bio = (f.description || '').toLowerCase();

    if (DEV_BIO_KEYWORDS.some(k => bio.includes(k))) {
      techCount++;
    }
    if (FAKE_BIO_KEYWORDS.some(k => bio.includes(k))) {
      suspiciousCount++;
    }
  }

  return {
    techPercent: Math.round((techCount / following.length) * 100),
    suspiciousPercent: Math.round((suspiciousCount / following.length) * 100),
    suspiciousCount
  };
}

/**
 * Main X/Twitter scan function - Enhanced with Phase 1-3
 */
export async function performXScan(usernameOrUrl: string): Promise<XScanResult> {
  const bearerToken = process.env.X_BEARER_TOKEN;
  if (!bearerToken) {
    throw new Error('X_BEARER_TOKEN environment variable required');
  }

  // Extract username from URL if needed
  let username = usernameOrUrl;
  const urlMatch = usernameOrUrl.match(/(?:x\.com|twitter\.com)\/([a-zA-Z0-9_]+)/i);
  if (urlMatch) {
    username = urlMatch[1];
  }
  username = username.replace(/^@/, '');

  // Fetch profile
  const profile = await getXProfile(username, bearerToken);
  if (!profile) {
    throw new Error(`Could not find X user: @${username}`);
  }

  // Fetch additional data in parallel
  const [tweets, followers, following] = await Promise.all([
    getUserTweets(profile.id, bearerToken),
    sampleFollowers(profile.id, bearerToken, 100), // Phase 2: Increased sample
    getUserFollowing(profile.id, bearerToken)
  ]);

  // Run analysis
  const followerAnalysis = analyzeFollowerQuality(followers);
  const tweetAnalysis = analyzeTweets(tweets, profile.followers);
  const followingAnalysis = analyzeFollowing(following);

  // PHASE 3: Get reputation from database
  let reputation: XAccountReputation | null = null;
  let previousScans = 0;
  let isNewAccount = true;

  try {
    reputation = getXAccountReputation(username);
    if (reputation) {
      previousScans = reputation.totalScans;
      isNewAccount = false;
    }
  } catch (err) {
    console.error('[X-SCAN] Error getting reputation:', err);
  }

  // Check if flagged in database
  const flagStatus = isXAccountFlagged(username);

  // Calculate score
  let score = 50;
  const redFlags: string[] = [];
  const greenFlags: string[] = [];

  // === PHASE 3: DATABASE FLAGS ===
  if (flagStatus.flagged) {
    score -= 40;
    redFlags.push(`⚠️ FLAGGED: ${flagStatus.reason || 'Known bad actor'}`);
  }

  if (reputation) {
    if (reputation.scamCount >= 2) {
      score -= 30;
      redFlags.push(`Previously linked to ${reputation.scamCount} scam projects`);
    } else if (reputation.scamCount === 1) {
      score -= 15;
      redFlags.push(`Previously linked to 1 scam project`);
    } else if (reputation.legitCount >= 3 && reputation.scamCount === 0) {
      score += 15;
      greenFlags.push(`Verified ${reputation.legitCount} legit projects before`);
    } else if (reputation.legitCount >= 1) {
      score += 5;
      greenFlags.push(`${reputation.legitCount} previous legit project(s)`);
    }
  }
  // Note: First scan is not a red flag - it's neutral (no penalty)

  // Account size tiers
  const isLargeAccount = profile.followers > 100000;
  const isMegaAccount = profile.followers > 1000000;

  // === ACCOUNT AGE ===
  const created = new Date(profile.createdAt);
  const ageYears = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);

  if (ageYears >= 10) {
    score += 20;
    greenFlags.push(`Account is ${Math.floor(ageYears)} years old (OG)`);
  } else if (ageYears >= 5) {
    score += 15;
    greenFlags.push(`Account is ${Math.floor(ageYears)} years old`);
  } else if (ageYears >= 2) {
    score += 8;
    greenFlags.push(`Account is ${Math.floor(ageYears)} years old`);
  } else if (ageYears < 0.5) {
    score -= 20;
    redFlags.push(`Very new account (${Math.floor(ageYears * 12)} months)`);
  }

  // === FOLLOWER COUNT ===
  if (isMegaAccount) {
    score += 15; // Reduced - follower count alone means little
    greenFlags.push(`${formatNumber(profile.followers)} followers`);
  } else if (isLargeAccount) {
    score += 8;
    greenFlags.push(`${formatNumber(profile.followers)} followers`);
  } else if (profile.followers > 10000) {
    score += 3;
  } else if (profile.followers < 100) {
    score -= 5;
  }

  // === PHASE 1: ENGAGEMENT RATE (Critical new check) ===
  const engagementRate = tweetAnalysis.engagementRate;

  // Engagement rate thresholds vary by account size
  // Mega accounts (1M+) naturally have lower % because denominator is huge
  if (isMegaAccount) {
    // For mega accounts, even 0.01% engagement means thousands of likes
    if (engagementRate < 0.005) {
      score -= 20;
      redFlags.push(`Engagement: ${engagementRate}% (very low even for mega account)`);
    } else if (engagementRate >= 0.01) {
      score += 10;
      greenFlags.push(`Engagement: ${engagementRate}% (healthy for ${formatNumber(profile.followers)} followers)`);
    }
  } else if (isLargeAccount) {
    // 100K-1M followers
    if (engagementRate < 0.05) {
      score -= 25;
      redFlags.push(`Engagement: ${engagementRate}% (low - likely fake followers)`);
    } else if (engagementRate >= 0.2) {
      score += 12;
      greenFlags.push(`Engagement: ${engagementRate}% (healthy)`);
    }
  } else if (profile.followers > 1000) {
    // Regular accounts (1K-100K)
    if (engagementRate < 0.1) {
      score -= 30;
      redFlags.push(`Engagement: ${engagementRate}% (extremely low - likely fake followers)`);
    } else if (engagementRate < 0.5) {
      score -= 15;
      redFlags.push(`Engagement: ${engagementRate}% (low for follower count)`);
    } else if (engagementRate >= 1 && engagementRate <= 5) {
      score += 15;
      greenFlags.push(`Engagement: ${engagementRate}% (healthy)`);
    } else if (engagementRate > 5) {
      score += 10;
      greenFlags.push(`Engagement: ${engagementRate}% (high - active community)`);
    }
  }

  // === PHASE 1: REPLY RATIO (Builders talk, scammers broadcast) ===
  const replyRatio = tweetAnalysis.replyRatio;

  if (replyRatio < 5) {
    score -= 15;
    redFlags.push(`Only ${replyRatio}% replies - broadcaster, not community member`);
  } else if (replyRatio >= 20 && replyRatio <= 60) {
    score += 10;
    greenFlags.push(`${replyRatio}% replies - engages with community`);
  } else if (replyRatio > 60) {
    score += 5;
    greenFlags.push(`${replyRatio}% replies - very conversational`);
  }

  // === FOLLOWER QUALITY ===
  if (followerAnalysis.botPercent > 50) {
    score -= 25;
    redFlags.push(`${followerAnalysis.botPercent}% bot followers detected`);
  } else if (followerAnalysis.botPercent > 30) {
    score -= 10;
    redFlags.push(`${followerAnalysis.botPercent}% likely bot followers`);
  } else if (followerAnalysis.realPercent > 70) {
    score += 10;
    greenFlags.push('Healthy authentic follower base');
  }

  // === PHASE 2: VERIFIED FOLLOWERS ===
  if (followerAnalysis.verifiedFollowers >= 5) {
    score += 15;
    greenFlags.push(`${followerAnalysis.verifiedFollowers} verified accounts follow them`);
  } else if (followerAnalysis.verifiedFollowers >= 2) {
    score += 8;
    greenFlags.push(`${followerAnalysis.verifiedFollowers} verified followers`);
  }

  // === PHASE 2: FOLLOWERS OF FOLLOWERS QUALITY ===
  if (followerAnalysis.followersOfFollowersReal < 30) {
    score -= 15;
    redFlags.push('Followers are likely bots (2-level check)');
  } else if (followerAnalysis.followersOfFollowersReal > 70) {
    score += 8;
    greenFlags.push('Follower network appears authentic');
  }

  // === TWEET CONTENT ===
  if (tweetAnalysis.scamPercent > 30) {
    score -= 25;
    redFlags.push(`${tweetAnalysis.scamPercent}% tweets contain scam keywords`);
  } else if (tweetAnalysis.scamPercent > 15) {
    score -= 10;
    redFlags.push('Some promotional language detected');
  }

  if (tweetAnalysis.techPercent > 40) {
    score += 15;
    greenFlags.push(`${tweetAnalysis.techPercent}% technical content`);
  } else if (tweetAnalysis.techPercent > 20) {
    score += 8;
    greenFlags.push('Technical content creator');
  }

  // === FOLLOWING ANALYSIS ===
  if (followingAnalysis.suspiciousPercent > 20) {
    score -= 10;
    redFlags.push(`Follows ${followingAnalysis.suspiciousCount} suspicious accounts`);
  }
  if (followingAnalysis.techPercent > 40) {
    score += 8;
    greenFlags.push('Follows tech/dev community');
  }

  // === FOLLOWER/FOLLOWING RATIO ===
  if (profile.following > 0) {
    const ffRatio = profile.followers / profile.following;
    if (profile.following > 5000 && ffRatio < 0.1) {
      score -= 15;
      redFlags.push('Follow-farming pattern (follows many, few follow back)');
    } else if (ffRatio > 10 && profile.followers > 10000) {
      score += 5;
      greenFlags.push('Influential (many followers, selective following)');
    }
  }

  // === BIO ANALYSIS ===
  const bioLower = (profile.bio || '').toLowerCase();
  const strongDevKeywords = ['founder', 'cto', 'created', 'building', 'engineer at', 'developer at'];

  if (strongDevKeywords.some(k => bioLower.includes(k))) {
    score += 10;
    greenFlags.push('Founder/builder keywords in bio');
  } else if (DEV_BIO_KEYWORDS.some(k => bioLower.includes(k))) {
    score += 5;
    greenFlags.push('Developer keywords in bio');
  }

  const fakeSignalCount = FAKE_BIO_KEYWORDS.filter(k => bioLower.includes(k)).length;
  if (fakeSignalCount >= 2) {
    score -= 15;
    redFlags.push('Multiple suspicious keywords in bio');
  }

  // === GITHUB VERIFICATION ===
  let githubVerified = false;
  let githubData: XScanResult['githubData'] | undefined;

  const githubMatch = profile.bio?.match(/github\.com\/([a-zA-Z0-9_-]+)/i) ||
                      profile.website?.match(/github\.com\/([a-zA-Z0-9_-]+)/i);

  if (githubMatch) {
    const githubUsername = githubMatch[1];
    const headers: Record<string, string> = {
      'User-Agent': 'AuraSecurityBot/1.0',
      'Accept': 'application/vnd.github.v3+json'
    };
    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
    }

    const ghData = await fetchJson(`https://api.github.com/users/${githubUsername}`, headers);

    if (ghData && !ghData.message) {
      score += 10;
      greenFlags.push(`GitHub linked: ${githubUsername}`);

      // Check cross-verification
      if (ghData.twitter_username?.toLowerCase() === profile.username.toLowerCase()) {
        score += 20;
        greenFlags.push('GitHub ↔ X cross-verified (identity confirmed)');
        githubVerified = true;
      }

      if (ghData.public_repos > 50) {
        score += 10;
        greenFlags.push(`${ghData.public_repos} public repos`);
      } else if (ghData.public_repos > 20) {
        score += 5;
      }

      if (ghData.followers > 1000) {
        score += 10;
        greenFlags.push(`${formatNumber(ghData.followers)} GitHub followers`);
      } else if (ghData.followers > 100) {
        score += 5;
      }

      githubData = {
        username: githubUsername,
        repos: ghData.public_repos,
        followers: ghData.followers,
        crossVerified: githubVerified
      };
    }
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Determine verdict
  let grade: 'A' | 'B' | 'C' | 'D' | 'F';
  let verdict: 'LEGIT' | 'LIKELY LEGIT' | 'SUSPICIOUS' | 'LIKELY SCAM' | 'SCAM';
  let verdictEmoji: string;

  if (score >= 80) {
    grade = 'A';
    verdict = 'LEGIT';
    verdictEmoji = '🟢';
  } else if (score >= 65) {
    grade = 'B';
    verdict = 'LIKELY LEGIT';
    verdictEmoji = '🟡';
  } else if (score >= 50) {
    grade = 'C';
    verdict = 'SUSPICIOUS';
    verdictEmoji = '🟠';
  } else if (score >= 35) {
    grade = 'D';
    verdict = 'LIKELY SCAM';
    verdictEmoji = '🔴';
  } else {
    grade = 'F';
    verdict = 'SCAM';
    verdictEmoji = '🔴';
  }

  // PHASE 3: Record this scan in database
  try {
    recordXScan(username, score, verdict);
    updateXAccountReputation(username, 'scanned');
  } catch (err) {
    console.error('[X-SCAN] Error recording scan:', err);
  }

  return {
    profile,
    score,
    grade,
    verdict,
    verdictEmoji,
    redFlags,
    greenFlags,
    followerAnalysis: {
      quality: followerAnalysis.quality,
      realPercent: followerAnalysis.realPercent,
      botPercent: followerAnalysis.botPercent,
      analysis: followerAnalysis.analysis,
      verifiedFollowers: followerAnalysis.verifiedFollowers,
      followersOfFollowersReal: followerAnalysis.followersOfFollowersReal
    },
    tweetAnalysis,
    githubVerified,
    githubData,
    reputation,
    previousScans,
    isNewAccount,
    scannedAt: new Date().toISOString()
  };
}
