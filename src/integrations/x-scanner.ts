/**
 * X/Twitter Scanner - Profile Analysis for Crypto Projects
 *
 * Analyzes X/Twitter profiles for legitimacy signals:
 * - Account age and follower quality
 * - Bot follower detection
 * - Tweet content analysis (scam vs tech)
 * - GitHub cross-verification
 */

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
  };
  tweetAnalysis: {
    techPercent: number;
    scamPercent: number;
  };
  githubVerified: boolean;
  githubData?: {
    username: string;
    repos: number;
    followers: number;
    crossVerified: boolean;
  };
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
 * Get user's recent tweets
 */
async function getUserTweets(userId: string, bearerToken: string, count = 100): Promise<any[]> {
  const url = `https://api.twitter.com/2/users/${userId}/tweets?max_results=${Math.min(count, 100)}&tweet.fields=created_at,public_metrics,text`;

  const data = await fetchJson(url, {
    'Authorization': `Bearer ${bearerToken}`,
    'User-Agent': 'AuraSecurityBot/1.0'
  });

  return data?.data || [];
}

/**
 * Sample followers to check quality
 */
async function sampleFollowers(userId: string, bearerToken: string, count = 50): Promise<any[]> {
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
 * Analyze follower quality (bot detection)
 */
function analyzeFollowerQuality(followers: any[]): { quality: number; realPercent: number; botPercent: number; analysis: string } {
  if (!followers || followers.length === 0) {
    return { quality: 0, realPercent: 0, botPercent: 0, analysis: 'Could not sample followers' };
  }

  let realCount = 0;
  let botCount = 0;
  let suspiciousCount = 0;

  for (const f of followers) {
    const metrics = f.public_metrics || {};
    const followerCount = metrics.followers_count || 0;
    const followingCount = metrics.following_count || 0;
    const tweetCount = metrics.tweet_count || 0;
    const created = new Date(f.created_at);
    const ageMonths = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 30);
    const hasDefaultPic = f.profile_image_url?.includes('default_profile');
    const hasBio = f.description && f.description.length > 10;

    // Bot signals
    let botScore = 0;
    if (hasDefaultPic) botScore += 30;
    if (!hasBio) botScore += 20;
    if (tweetCount < 5) botScore += 25;
    if (ageMonths < 3) botScore += 15;
    if (followingCount > 1000 && followerCount < 50) botScore += 30; // Follow farming
    if (followerCount === 0 && tweetCount === 0) botScore += 40;

    // Real signals
    if (ageMonths > 24) botScore -= 20;
    if (hasBio) botScore -= 10;
    if (tweetCount > 100) botScore -= 15;
    if (followerCount > 100 && followingCount < followerCount) botScore -= 15;

    if (botScore >= 50) botCount++;
    else if (botScore >= 25) suspiciousCount++;
    else realCount++;
  }

  const total = followers.length;
  const realPercent = Math.round((realCount / total) * 100);
  const botPercent = Math.round((botCount / total) * 100);

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

  return { quality, realPercent, botPercent, analysis };
}

/**
 * Analyze tweet content
 */
function analyzeTweets(tweets: any[]): { techPercent: number; scamPercent: number } {
  if (!tweets || tweets.length === 0) {
    return { techPercent: 0, scamPercent: 0 };
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

  return {
    techPercent: Math.round((techCount / tweets.length) * 100),
    scamPercent: Math.round((scamCount / tweets.length) * 100)
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
 * Main X/Twitter scan function
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
    sampleFollowers(profile.id, bearerToken),
    getUserFollowing(profile.id, bearerToken)
  ]);

  // Run analysis
  const followerAnalysis = analyzeFollowerQuality(followers);
  const tweetAnalysis = analyzeTweets(tweets);
  const followingAnalysis = analyzeFollowing(following);

  // Calculate score
  let score = 50;
  const redFlags: string[] = [];
  const greenFlags: string[] = [];

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
    score += 20;
    greenFlags.push(`${formatNumber(profile.followers)} followers (major account)`);
  } else if (isLargeAccount) {
    score += 12;
    greenFlags.push(`${formatNumber(profile.followers)} followers`);
  } else if (profile.followers > 10000) {
    score += 5;
  } else if (profile.followers < 100) {
    score -= 5;
  }

  // === FOLLOWER QUALITY ===
  if (isMegaAccount) {
    if (followerAnalysis.botPercent > 60) {
      score -= 10;
      redFlags.push('High bot follower ratio for account size');
    } else {
      greenFlags.push('Follower quality normal for account size');
    }
  } else if (isLargeAccount) {
    if (followerAnalysis.botPercent > 50) {
      score -= 15;
      redFlags.push(`${followerAnalysis.botPercent}% bot followers detected`);
    }
  } else {
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

  return {
    profile,
    score,
    grade,
    verdict,
    verdictEmoji,
    redFlags,
    greenFlags,
    followerAnalysis,
    tweetAnalysis,
    githubVerified,
    githubData,
    scannedAt: new Date().toISOString()
  };
}
