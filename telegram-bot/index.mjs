// AuraSecurity Telegram Bot - Rug Check + X Profile Check
// Lambda function for t.me/aurasecuritychecker_bot
//
// RELIABILITY: This bot is mission-critical. It includes:
// - Retry logic with exponential backoff
// - Fallback API URLs
// - Graceful error handling
// - Request timeouts
// - DynamoDB-based deduplication (persists across Lambda instances)

import https from 'https';
import { DynamoDBClient, PutItemCommand, GetItemCommand } from '@aws-sdk/client-dynamodb';

const BOT_TOKEN = process.env.BOT_TOKEN;
const X_BEARER_TOKEN = process.env.X_BEARER_TOKEN;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY;

// Primary and fallback API URLs for reliability
const AURA_API_PRIMARY = process.env.AURA_API_URL || 'https://app.aurasecurity.io';
const AURA_API_FALLBACK = 'https://app.aurasecurity.io'; // Same for now, can add backup server later
const AURA_API_URL = AURA_API_PRIMARY;

const TELEGRAM_API = `https://api.telegram.org/bot${BOT_TOKEN}`;

// Retry configuration
const MAX_RETRIES = 3;
const RETRY_DELAY_MS = 1000;

// DynamoDB client for deduplication (persists across Lambda instances)
const dynamoClient = new DynamoDBClient({ region: 'us-east-1' });
const DEDUP_TABLE = 'aura-telegram-dedup';
const DEDUP_TTL_SECONDS = 300; // 5 minutes

// Check if update was already processed using DynamoDB
async function isDuplicate(updateId) {
  if (!updateId) return false;

  const updateIdStr = String(updateId);

  try {
    // Try to get existing record
    const getResult = await dynamoClient.send(new GetItemCommand({
      TableName: DEDUP_TABLE,
      Key: { update_id: { S: updateIdStr } }
    }));

    if (getResult.Item) {
      console.log(`[DEDUP] Skipping duplicate update_id: ${updateId}`);
      return true;
    }

    // Mark as processed with TTL
    const ttl = Math.floor(Date.now() / 1000) + DEDUP_TTL_SECONDS;
    await dynamoClient.send(new PutItemCommand({
      TableName: DEDUP_TABLE,
      Item: {
        update_id: { S: updateIdStr },
        ttl: { N: String(ttl) },
        timestamp: { S: new Date().toISOString() }
      },
      ConditionExpression: 'attribute_not_exists(update_id)'
    }));

    return false;
  } catch (error) {
    // ConditionalCheckFailedException means another Lambda already processed this
    if (error.name === 'ConditionalCheckFailedException') {
      console.log(`[DEDUP] Race condition caught - duplicate update_id: ${updateId}`);
      return true;
    }
    // Log error but don't block - fail open to avoid missing messages
    console.error('[DEDUP] DynamoDB error:', error.message);
    return false;
  }
}

// Retry wrapper with exponential backoff
async function withRetry(fn, maxRetries = MAX_RETRIES, delayMs = RETRY_DELAY_MS) {
  let lastError;
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      console.log(`Attempt ${attempt}/${maxRetries} failed:`, error.message);
      if (attempt < maxRetries) {
        const delay = delayMs * Math.pow(2, attempt - 1); // Exponential backoff
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
  }
  throw lastError;
}

// Safe message sender - never throws, always logs
async function safeSendMessage(chatId, text, parseMode = 'Markdown') {
  try {
    return await sendMessage(chatId, text, parseMode);
  } catch (error) {
    console.error('Failed to send message:', error.message);
    // Try plain text as fallback (in case Markdown parsing fails)
    try {
      return await sendMessage(chatId, text.replace(/[*_`\[\]]/g, ''), null);
    } catch (e) {
      console.error('Failed to send plain text fallback:', e.message);
    }
  }
}

// Scam/red flag keywords
const SCAM_KEYWORDS = ['airdrop', 'giveaway', 'dm me', 'limited spots', '100x', '1000x', 'guaranteed', 'free money', 'act now', 'last chance', 'whitelist', 'presale'];
const SHILL_KEYWORDS = ['bullish', 'moon', 'gem', 'alpha', 'nfa', 'dyor', 'lfg', 'wagmi', 'ngmi', 'probably nothing'];
const TECH_KEYWORDS = ['github', 'code', 'bug', 'fix', 'merge', 'pr', 'deploy', 'api', 'sdk', 'rust', 'typescript', 'python', 'solidity', 'smart contract', 'open source'];
const DEV_BIO_KEYWORDS = ['engineer', 'developer', 'dev', 'founder', 'cto', 'building', 'builder', 'hacker', 'open source', 'maintainer'];
const FAKE_BIO_KEYWORDS = ['dm for collab', 'promo', 'influencer', 'crypto enthusiast', 'investor', 'trader', 'calls'];

// Send message to Telegram (with optional inline keyboard)
async function sendMessage(chatId, text, parseMode = 'Markdown', replyMarkup = null) {
  return new Promise((resolve, reject) => {
    const payload = {
      chat_id: chatId,
      text: text,
      parse_mode: parseMode,
      disable_web_page_preview: true
    };
    if (replyMarkup) {
      payload.reply_markup = replyMarkup;
    }
    const data = JSON.stringify(payload);

    const url = new URL(`${TELEGRAM_API}/sendMessage`);
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(JSON.parse(body)));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Fetch HTML/JSON from URL
async function fetchUrl(url, headers = {}) {
  return new Promise((resolve, reject) => {
    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        'Accept-Language': 'en-US,en;q=0.5',
        ...headers
      }
    };

    https.get(options, (res) => {
      // Handle redirects
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        fetchUrl(res.headers.location, headers).then(resolve).catch(reject);
        return;
      }

      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ status: res.statusCode, data }));
    }).on('error', reject);
  });
}

// Fetch JSON from URL
async function fetchJson(url) {
  const response = await fetchUrl(url, { 'Accept': 'application/json' });
  try {
    return JSON.parse(response.data);
  } catch (e) {
    throw new Error('Invalid JSON response');
  }
}

// Call Aura Security Scanner API (internal - use callAuraScanWithRetry)
// Uses fast mode to skip slow scanners (semgrep takes 60+ seconds)
async function callAuraScanInternal(gitUrl, apiUrl = AURA_API_PRIMARY) {
  return new Promise((resolve, reject) => {
    const url = new URL(`${apiUrl}/tools`);
    const payload = JSON.stringify({
      tool: 'scan-local',
      arguments: {
        gitUrl: gitUrl,
        scanSecrets: true,
        scanPackages: true,
        fastMode: true  // Skip slow scanners (semgrep, checkov)
      }
    });

    const options = {
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(payload),
        'User-Agent': 'AuraSecurityBot/1.0'
      }
    };

    console.log('Calling Aura API:', apiUrl, 'for', gitUrl);

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        console.log('Aura API response status:', res.statusCode);
        try {
          const result = JSON.parse(data);
          if (result.error) {
            reject(new Error(result.error));
          } else {
            resolve(result);
          }
        } catch (e) {
          console.error('Parse error:', e.message, 'Data:', data.substring(0, 200));
          reject(new Error('Failed to parse scan response'));
        }
      });
    });

    req.on('error', (e) => {
      console.error('Aura API error:', e.message);
      reject(new Error('Failed to connect to AuraSecurity scanner'));
    });

    // Set timeout for scan (can take a while)
    req.setTimeout(180000, () => { // Increased to 3 minutes
      req.destroy();
      reject(new Error('Scan timed out (3 min limit)'));
    });

    req.write(payload);
    req.end();
  });
}

// Call Aura API with retry and fallback
async function callAuraScan(gitUrl) {
  try {
    // Try primary with retry
    return await withRetry(() => callAuraScanInternal(gitUrl, AURA_API_PRIMARY), 2, 2000);
  } catch (primaryError) {
    console.error('Primary API failed after retries:', primaryError.message);

    // Try fallback if different from primary
    if (AURA_API_FALLBACK !== AURA_API_PRIMARY) {
      console.log('Trying fallback API:', AURA_API_FALLBACK);
      try {
        return await withRetry(() => callAuraScanInternal(gitUrl, AURA_API_FALLBACK), 2, 2000);
      } catch (fallbackError) {
        console.error('Fallback API also failed:', fallbackError.message);
      }
    }

    // All attempts failed
    throw new Error('Scanner temporarily unavailable. Please try again in a few minutes.');
  }
}

// Call Claude API for AI analysis
async function askClaude(prompt, maxTokens = 1000) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify({
      model: 'claude-sonnet-4-20250514',
      max_tokens: maxTokens,
      messages: [{ role: 'user', content: prompt }]
    });

    const options = {
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01',
        'Content-Length': Buffer.byteLength(payload)
      }
    };

    const req = https.request(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          if (json.error) {
            reject(new Error(json.error.message || 'Claude API error'));
          } else {
            resolve(json.content[0].text);
          }
        } catch (e) {
          reject(new Error('Failed to parse Claude response'));
        }
      });
    });

    req.on('error', reject);
    req.setTimeout(30000, () => {
      req.destroy();
      reject(new Error('Claude API timeout'));
    });
    req.write(payload);
    req.end();
  });
}

// Get user's recent tweets from X API
async function getUserTweets(userId, count = 100) {
  return new Promise((resolve, reject) => {
    const url = `https://api.twitter.com/2/users/${userId}/tweets?max_results=${Math.min(count, 100)}&tweet.fields=created_at,public_metrics,text`;

    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${X_BEARER_TOKEN}`,
        'User-Agent': 'AuraSecurityBot/1.0'
      }
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.data || []);
        } catch (e) {
          resolve([]);
        }
      });
    }).on('error', () => resolve([]));
  });
}

// Get who the user follows
async function getUserFollowing(userId, count = 100) {
  return new Promise((resolve, reject) => {
    const url = `https://api.twitter.com/2/users/${userId}/following?max_results=${Math.min(count, 100)}&user.fields=public_metrics,verified,description,created_at`;

    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${X_BEARER_TOKEN}`,
        'User-Agent': 'AuraSecurityBot/1.0'
      }
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.data || []);
        } catch (e) {
          resolve([]);
        }
      });
    }).on('error', () => resolve([]));
  });
}

// Sample followers to check quality
async function sampleFollowers(userId, count = 50) {
  return new Promise((resolve, reject) => {
    const url = `https://api.twitter.com/2/users/${userId}/followers?max_results=${Math.min(count, 100)}&user.fields=public_metrics,verified,description,created_at,profile_image_url`;

    const urlObj = new URL(url);
    const options = {
      hostname: urlObj.hostname,
      path: urlObj.pathname + urlObj.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${X_BEARER_TOKEN}`,
        'User-Agent': 'AuraSecurityBot/1.0'
      }
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          resolve(json.data || []);
        } catch (e) {
          resolve([]);
        }
      });
    }).on('error', () => resolve([]));
  });
}

// Analyze follower quality
function analyzeFollowerQuality(followers) {
  if (!followers || followers.length === 0) {
    return { quality: 0, realPercent: 0, botPercent: 0, analysis: 'Could not sample followers' };
  }

  let realCount = 0;
  let botCount = 0;
  let suspiciousCount = 0;

  for (const f of followers) {
    const metrics = f.public_metrics || {};
    const followers = metrics.followers_count || 0;
    const following = metrics.following_count || 0;
    const tweets = metrics.tweet_count || 0;
    const created = new Date(f.created_at);
    const ageMonths = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 30);
    const hasDefaultPic = f.profile_image_url?.includes('default_profile');
    const hasBio = f.description && f.description.length > 10;

    // Bot signals
    let botScore = 0;
    if (hasDefaultPic) botScore += 30;
    if (!hasBio) botScore += 20;
    if (tweets < 5) botScore += 25;
    if (ageMonths < 3) botScore += 15;
    if (following > 1000 && followers < 50) botScore += 30; // Follow farming
    if (followers === 0 && tweets === 0) botScore += 40;

    // Real signals
    if (ageMonths > 24) botScore -= 20;
    if (hasBio) botScore -= 10;
    if (tweets > 100) botScore -= 15;
    if (followers > 100 && following < followers) botScore -= 15;

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
    analysis = '🚨 MAJORITY BOT FOLLOWERS';
  } else if (botPercent > 30) {
    analysis = '⚠️ High bot percentage';
  } else if (realPercent > 70) {
    analysis = '✅ Healthy follower base';
  } else {
    analysis = '⚠️ Mixed follower quality';
  }

  return { quality, realPercent, botPercent, suspiciousPercent: Math.round((suspiciousCount / total) * 100), analysis };
}

// Analyze tweets for patterns
function analyzeTweets(tweets) {
  if (!tweets || tweets.length === 0) {
    return { techPercent: 0, shillPercent: 0, scamPercent: 0, analysis: 'No tweets to analyze' };
  }

  let techCount = 0;
  let shillCount = 0;
  let scamCount = 0;
  let totalEngagement = 0;

  for (const tweet of tweets) {
    const text = tweet.text.toLowerCase();
    const metrics = tweet.public_metrics || {};
    totalEngagement += (metrics.like_count || 0) + (metrics.retweet_count || 0);

    // Check for keywords
    if (TECH_KEYWORDS.some(k => text.includes(k))) techCount++;
    if (SHILL_KEYWORDS.some(k => text.includes(k))) shillCount++;
    if (SCAM_KEYWORDS.some(k => text.includes(k))) scamCount++;
  }

  const total = tweets.length;
  const techPercent = Math.round((techCount / total) * 100);
  const shillPercent = Math.round((shillCount / total) * 100);
  const scamPercent = Math.round((scamCount / total) * 100);
  const avgEngagement = Math.round(totalEngagement / total);

  let analysis = '';
  if (scamPercent > 20) {
    analysis = '🚨 SCAM KEYWORDS DETECTED';
  } else if (shillPercent > 40) {
    analysis = '⚠️ High promotional content';
  } else if (techPercent > 30) {
    analysis = '✅ Technical content creator';
  } else {
    analysis = 'Mixed content';
  }

  return { techPercent, shillPercent, scamPercent, avgEngagement, analysis, totalTweets: total };
}

// Check following list for red flags
function analyzeFollowing(following) {
  if (!following || following.length === 0) {
    return { suspiciousCount: 0, analysis: 'Could not check following' };
  }

  let suspiciousCount = 0;
  let techCount = 0;
  const suspicious = [];

  for (const f of following) {
    const bio = (f.description || '').toLowerCase();
    const metrics = f.public_metrics || {};

    // Suspicious patterns
    if (SCAM_KEYWORDS.some(k => bio.includes(k))) {
      suspiciousCount++;
      suspicious.push(f.username);
    }

    // Tech patterns
    if (DEV_BIO_KEYWORDS.some(k => bio.includes(k))) {
      techCount++;
    }
  }

  const suspiciousPercent = Math.round((suspiciousCount / following.length) * 100);
  const techPercent = Math.round((techCount / following.length) * 100);

  let analysis = '';
  if (suspiciousPercent > 10) {
    analysis = `🚨 Follows ${suspiciousCount} suspicious accounts`;
  } else if (techPercent > 30) {
    analysis = '✅ Follows tech/dev accounts';
  } else {
    analysis = 'Normal following patterns';
  }

  return { suspiciousCount, suspiciousPercent, techPercent, analysis, suspicious: suspicious.slice(0, 5) };
}

// Quick security scan for scoring (with timeout)
async function quickSecurityScan(githubUrl) {
  return new Promise(async (resolve) => {
    const timeout = setTimeout(() => {
      resolve({ scanned: false, reason: 'timeout' });
    }, 45000); // 45 second timeout

    try {
      const result = await callAuraScan(githubUrl);
      clearTimeout(timeout);

      const scanDetails = result?.result?.scan_details || result?.scan_details || {};
      const secrets = scanDetails.secrets_found || 0;
      const vulns = scanDetails.package_vulns || 0;
      const rawFindings = scanDetails.raw_findings || {};

      // Count by severity
      let critical = 0, high = 0, medium = 0;
      if (rawFindings.secrets) {
        critical += rawFindings.secrets.filter(s => s.severity === 'critical').length;
        high += rawFindings.secrets.filter(s => s.severity === 'high').length;
      }
      if (rawFindings.packages) {
        critical += rawFindings.packages.filter(p => p.severity === 'critical').length;
        high += rawFindings.packages.filter(p => p.severity === 'high').length;
        medium += rawFindings.packages.filter(p => p.severity === 'medium').length;
      }

      resolve({
        scanned: true,
        secrets,
        vulns,
        critical,
        high,
        medium,
        total: secrets + vulns,
        grade: secrets > 0 ? 'F' : critical > 0 ? 'D' : high > 5 ? 'C' : high > 0 ? 'B' : 'A'
      });
    } catch (err) {
      clearTimeout(timeout);
      console.error('Quick security scan error:', err.message);
      resolve({ scanned: false, reason: err.message });
    }
  });
}

// Deep X profile analysis with AI
async function deepXAnalysis(profile, tweets, followers, following) {
  const followerAnalysis = analyzeFollowerQuality(followers);
  const tweetAnalysis = analyzeTweets(tweets);
  const followingAnalysis = analyzeFollowing(following);

  // Calculate base score - start at 50
  let score = 50;
  const redFlags = [];
  const greenFlags = [];

  // Determine account tier (large accounts evaluated differently)
  const isLargeAccount = profile.followers > 100000;
  const isMegaAccount = profile.followers > 1000000;

  // === ACCOUNT AGE (Big factor) ===
  const created = new Date(profile.createdAt);
  const ageYears = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);

  if (ageYears >= 10) {
    score += 20;
    greenFlags.push(`🏆 Account is ${Math.floor(ageYears)} years old (OG)`);
  } else if (ageYears >= 5) {
    score += 15;
    greenFlags.push(`Account is ${Math.floor(ageYears)} years old`);
  } else if (ageYears >= 2) {
    score += 8;
    greenFlags.push(`Account is ${Math.floor(ageYears)} years old`);
  } else if (ageYears < 0.5) {
    score -= 20;
    redFlags.push(`⚠️ Very new account (${Math.floor(ageYears * 12)} months)`);
  }

  // === FOLLOWER COUNT (Large following = legitimacy signal) ===
  if (isMegaAccount) {
    score += 20;
    greenFlags.push(`🌟 ${formatNumber(profile.followers)} followers (major account)`);
  } else if (isLargeAccount) {
    score += 12;
    greenFlags.push(`${formatNumber(profile.followers)} followers`);
  } else if (profile.followers > 10000) {
    score += 5;
  } else if (profile.followers < 100) {
    score -= 5;
  }

  // === FOLLOWER QUALITY (adjusted for account size) ===
  // Large accounts ALWAYS have some bots - don't penalize as heavily
  if (isMegaAccount) {
    // For mega accounts, only flag if >60% bots (very unusual)
    if (followerAnalysis.botPercent > 60) {
      score -= 10;
      redFlags.push(`High bot follower ratio for account size`);
    } else {
      greenFlags.push('Follower quality normal for account size');
    }
  } else if (isLargeAccount) {
    // For large accounts, only flag if >50% bots
    if (followerAnalysis.botPercent > 50) {
      score -= 15;
      redFlags.push(`${followerAnalysis.botPercent}% bot followers detected`);
    }
  } else {
    // For smaller accounts, be stricter
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

  // === TWEET CONTENT (only penalize clear scam patterns) ===
  // Only flag if HIGH percentage of scam keywords (not just a few mentions)
  if (tweetAnalysis.scamPercent > 30) {
    score -= 25;
    redFlags.push(`🚨 ${tweetAnalysis.scamPercent}% tweets contain scam keywords`);
  } else if (tweetAnalysis.scamPercent > 15) {
    score -= 10;
    redFlags.push(`Some promotional language detected`);
  }

  // Tech content is a positive signal
  if (tweetAnalysis.techPercent > 40) {
    score += 15;
    greenFlags.push(`💻 ${tweetAnalysis.techPercent}% technical content`);
  } else if (tweetAnalysis.techPercent > 20) {
    score += 8;
    greenFlags.push(`Technical content creator`);
  }

  // === FOLLOWING ANALYSIS (less weight, more noise here) ===
  // Only flag if following MANY suspicious accounts
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

  // Strong dev signals in bio
  const strongDevKeywords = ['founder', 'cto', 'created', 'building', 'engineer at', 'developer at'];
  if (strongDevKeywords.some(k => bioLower.includes(k))) {
    score += 10;
    greenFlags.push('Founder/builder keywords in bio');
  } else if (DEV_BIO_KEYWORDS.some(k => bioLower.includes(k))) {
    score += 5;
    greenFlags.push('Developer keywords in bio');
  }

  // Only penalize if multiple fake signals
  const fakeSignalCount = FAKE_BIO_KEYWORDS.filter(k => bioLower.includes(k)).length;
  if (fakeSignalCount >= 2) {
    score -= 15;
    redFlags.push('Multiple suspicious keywords in bio');
  }

  // === GITHUB VERIFICATION (HIGH WEIGHT) ===
  let githubMatch = profile.bio?.match(/github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/i);
  let githubVerified = false;
  let githubData = null;
  let githubUrl = null;
  let foundViaWebsite = false;

  // If no GitHub in bio, check website field from profile
  if (!githubMatch && profile.website) {
    // Check if website IS GitHub
    const directGithub = profile.website.match(/github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/i);
    if (directGithub) {
      githubMatch = directGithub;
      githubUrl = profile.website;
    } else {
      // Website is not GitHub - scrape it for GitHub links
      greenFlags.push(`🌐 Website: ${profile.website}`);
      const websiteGithub = await findGitHubOnWebsite(profile.website);
      if (websiteGithub) {
        githubUrl = websiteGithub;
        const urlMatch = websiteGithub.match(/github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/i);
        if (urlMatch) {
          githubMatch = urlMatch;
          foundViaWebsite = true;
        }
      }
    }
  }

  // Also check bio text for website if still no GitHub
  if (!githubMatch) {
    const bioWebsite = extractWebsiteFromBio(profile.bio);
    if (bioWebsite && bioWebsite !== profile.website) {
      const websiteGithub = await findGitHubOnWebsite(bioWebsite);
      if (websiteGithub) {
        githubUrl = websiteGithub;
        const urlMatch = websiteGithub.match(/github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/i);
        if (urlMatch) {
          githubMatch = urlMatch;
          foundViaWebsite = true;
        }
      }
    }
  }

  if (githubMatch) {
    try {
      // Extract owner (and optionally repo)
      const githubPath = githubMatch[1];
      const parts = githubPath.split('/');
      const owner = parts[0];
      const repo = parts[1];

      // Fetch user/org data
      githubData = await fetchJson(`https://api.github.com/users/${owner}`);
      if (githubData && !githubData.message) {
        if (foundViaWebsite) {
          score += 12;
          greenFlags.push(`💻 GitHub found via website: ${owner}`);
        } else {
          score += 10;
          greenFlags.push('GitHub link in bio');
        }

        // Check if GitHub links back (HUGE trust signal)
        if (githubData.twitter_username?.toLowerCase() === profile.username.toLowerCase()) {
          score += 20;
          greenFlags.push('✅ GitHub ↔ X cross-verified (identity confirmed)');
          githubVerified = true;
        }

        // GitHub quality signals
        if (githubData.public_repos > 50) {
          score += 10;
          greenFlags.push(`${githubData.public_repos} public repos`);
        } else if (githubData.public_repos > 20) {
          score += 5;
        }

        if (githubData.followers > 10000) {
          score += 15;
          greenFlags.push(`🌟 ${formatNumber(githubData.followers)} GitHub followers`);
        } else if (githubData.followers > 1000) {
          score += 10;
          greenFlags.push(`${formatNumber(githubData.followers)} GitHub followers`);
        } else if (githubData.followers > 100) {
          score += 5;
        }

        // If we have a specific repo, check its stats too
        if (repo) {
          try {
            const repoData = await fetchJson(`https://api.github.com/repos/${owner}/${repo}`);
            if (repoData && !repoData.message) {
              if (repoData.stargazers_count > 100) {
                score += 10;
                greenFlags.push(`⭐ ${formatNumber(repoData.stargazers_count)} stars on ${repo}`);
              } else if (repoData.stargazers_count > 10) {
                score += 5;
              }
            }
          } catch (e) {}
        }
      }
    } catch (e) {}
  }

  // === SECURITY SCAN (if GitHub found) ===
  let securityScan = null;
  if (githubMatch) {
    const repoUrl = `https://github.com/${githubMatch[1]}`;
    securityScan = await quickSecurityScan(repoUrl);

    if (securityScan.scanned) {
      if (securityScan.secrets > 0) {
        score -= 25;
        redFlags.push(`🔓 ${securityScan.secrets} SECRETS EXPOSED in code`);
      }
      if (securityScan.critical > 0) {
        score -= 15;
        redFlags.push(`🚨 ${securityScan.critical} critical vulnerabilities`);
      }
      if (securityScan.high > 5) {
        score -= 10;
        redFlags.push(`⚠️ ${securityScan.high} high severity vulnerabilities`);
      } else if (securityScan.high > 0) {
        score -= 5;
        redFlags.push(`${securityScan.high} high severity vulnerabilities`);
      }

      if (securityScan.total === 0) {
        score += 10;
        greenFlags.push('🔒 No security issues found in code');
      } else if (securityScan.secrets === 0 && securityScan.critical === 0) {
        greenFlags.push(`Security: ${securityScan.vulns} minor issues`);
      }
    }
  }

  // === VERIFIED STATUS ===
  if (profile.verified) {
    score += 5;
    greenFlags.push('Verified account');
  }

  // === ENGAGEMENT RATE (adjusted for size) ===
  if (profile.followers > 10000 && tweetAnalysis.avgEngagement) {
    const engagementRate = tweetAnalysis.avgEngagement / profile.followers;
    // Large accounts have lower engagement rates naturally
    const expectedRate = isMegaAccount ? 0.0005 : isLargeAccount ? 0.002 : 0.01;

    if (engagementRate < expectedRate * 0.1) {
      score -= 10;
      redFlags.push('Very low engagement for follower count');
    } else if (engagementRate > expectedRate) {
      score += 5;
      greenFlags.push('Healthy engagement rate');
    }
  }

  // === BONUS: Exceptional accounts ===
  // If multiple strong positive signals, boost score
  if (greenFlags.length >= 6 && redFlags.length <= 1) {
    score += 10;
  }

  // Clamp score
  score = Math.max(0, Math.min(100, score));

  // Cap score based on account age - new accounts can't get top scores
  if (ageYears < 0.5) {
    score = Math.min(score, 65);  // Max 65 for accounts < 6 months
    if (!redFlags.includes('⚠️ Very new account')) {
      redFlags.push('Score capped: Account too new for high trust');
    }
  } else if (ageYears < 1) {
    score = Math.min(score, 75);  // Max 75 for accounts < 1 year
  } else if (ageYears < 2) {
    score = Math.min(score, 85);  // Max 85 for accounts < 2 years
  }

  // GOAT GATES - Must pass ALL to be GOAT
  const goatGates = {
    accountAge: ageYears >= 3,  // Minimum 3 years
    majorFollowing: profile.followers >= 100000 || (githubData?.followers >= 5000),  // 100K X OR 5K GitHub
    crossVerified: githubVerified,  // Must have verified GitHub link
    highScore: score >= 85,  // High base score
    noMajorRedFlags: redFlags.length <= 1  // Max 1 red flag
  };

  const passedGoatGates = Object.values(goatGates).filter(Boolean).length;
  const isGoat = passedGoatGates === 5;  // Must pass ALL gates

  // Determine verdict
  let verdict, emoji, tier;
  if (isGoat && score >= 90) {
    verdict = "GOAT'ED DEV 🐐";
    emoji = '🐐';
    tier = 'goat';
  } else if (score >= 80) {
    verdict = 'VERIFIED LEGIT';
    emoji = '🟢';
    tier = 'legit';
  } else if (score >= 60) {
    verdict = 'PROBABLY OKAY';
    emoji = '🟡';
    tier = 'okay';
  } else if (score >= 40) {
    verdict = 'SUSPICIOUS';
    emoji = '🟠';
    tier = 'sus';
  } else {
    verdict = 'HIGH RISK';
    emoji = '🔴';
    tier = 'scam';
  }

  // If high score but failed GOAT gates, show why
  if (score >= 85 && !isGoat) {
    const failedGates = [];
    if (!goatGates.accountAge) failedGates.push('Account < 3 years old');
    if (!goatGates.majorFollowing) failedGates.push('Needs 100K+ X or 5K+ GitHub followers');
    if (!goatGates.crossVerified) failedGates.push('GitHub not cross-verified');
    if (!goatGates.noMajorRedFlags) failedGates.push('Has multiple red flags');

    if (failedGates.length > 0) {
      redFlags.push(`Not GOAT: ${failedGates.join(', ')}`);
    }
  }

  return {
    score,
    verdict,
    emoji,
    tier,
    redFlags,
    greenFlags,
    followerAnalysis,
    tweetAnalysis,
    followingAnalysis,
    githubVerified,
    githubData,
    githubUrl: githubMatch ? `https://github.com/${githubMatch[1]}` : null,
    foundViaWebsite,
    securityScan,
    profile
  };
}

// Format deep X analysis result
function formatDeepXResult(analysis) {
  const { score, verdict, emoji, tier, redFlags, greenFlags, followerAnalysis, tweetAnalysis, followingAnalysis, githubVerified, githubData, githubUrl, foundViaWebsite, securityScan, profile } = analysis;

  let msg = '';

  // Header
  if (tier === 'goat') {
    msg += `🐐 *DEVCHECK: @${profile.username}* 🐐\n`;
  } else {
    msg += `🔍 *DEVCHECK: @${profile.username}*\n`;
  }
  if (profile.name) msg += `_${profile.name}_\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

  // Score box
  msg += `┌────────────────────┐\n`;
  msg += `│ *TRUST SCORE: ${score}/100* ${emoji}\n`;
  msg += `│ ${verdict}\n`;
  msg += `└────────────────────┘\n\n`;

  // Quick stats line
  const created = new Date(profile.createdAt);
  const ageYears = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);
  const ageText = ageYears >= 1 ? `${Math.floor(ageYears)}y` : `${Math.floor(ageYears * 12)}mo`;
  msg += `👤 ${ageText} old • ${formatNumber(profile.followers)} followers • ${followerAnalysis.realPercent}% real\n\n`;

  // GitHub section
  if (githubData) {
    msg += `💻 *GITHUB*${foundViaWebsite ? ' _(via website)_' : ''}\n`;
    msg += `├─ [${githubData.login}](https://github.com/${githubData.login}) • ${githubData.public_repos} repos\n`;
    msg += `├─ ${formatNumber(githubData.followers)} followers\n`;
    msg += `└─ Cross-verified: ${githubVerified ? '✅ YES' : '❌ NO'}\n\n`;
  } else {
    msg += `💻 *GITHUB:* ❌ Not found\n\n`;
  }

  // Security section
  if (securityScan?.scanned) {
    const gradeEmoji = securityScan.grade === 'A' ? '✅' :
                       securityScan.grade === 'B' ? '🟢' :
                       securityScan.grade === 'C' ? '🟡' :
                       securityScan.grade === 'D' ? '🟠' : '🔴';
    msg += `🔒 *SECURITY:* Grade ${securityScan.grade} ${gradeEmoji}\n`;
    if (securityScan.secrets > 0) {
      msg += `├─ ⚠️ ${securityScan.secrets} secrets exposed!\n`;
    }
    if (securityScan.critical > 0 || securityScan.high > 0) {
      msg += `├─ ${securityScan.critical} critical, ${securityScan.high} high vulns\n`;
    }
    if (securityScan.total === 0) {
      msg += `└─ 🎉 Clean code!\n\n`;
    } else {
      msg += `└─ ${securityScan.vulns} total vulnerabilities\n\n`;
    }
  } else if (securityScan) {
    msg += `🔒 *SECURITY:* ⏱️ Scan timed out\n\n`;
  }

  // Red flags
  if (redFlags.length > 0) {
    msg += `🚨 *RED FLAGS*\n`;
    redFlags.forEach(f => {
      msg += `• ${f}\n`;
    });
    msg += `\n`;
  }

  // Green flags
  if (greenFlags.length > 0) {
    msg += `✅ *GREEN FLAGS*\n`;
    greenFlags.forEach(f => {
      msg += `• ${f}\n`;
    });
    msg += `\n`;
  }

  // Footer
  if (tier === 'goat') {
    msg += `🐐 _Elite verified developer_`;
  } else if (tier === 'legit') {
    msg += `✨ _Strong legitimacy signals_`;
  } else if (tier === 'okay') {
    msg += `⚠️ _Some concerns - DYOR_`;
  } else if (tier === 'sus') {
    msg += `🚨 _Multiple warnings - be careful_`;
  } else {
    msg += `🔴 _High risk - proceed with caution_`;
  }

  return {
    text: msg,
    username: profile.username,
    hasGithub: !!githubData,
    hasSecurity: securityScan?.scanned || false
  };
}

// Format detailed social stats (for button callback)
function formatSocialStats(analysis) {
  const { followerAnalysis, tweetAnalysis, followingAnalysis, profile } = analysis;

  let msg = `📊 *SOCIAL STATS: @${profile.username}*\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

  // Follower analysis
  msg += `👥 *FOLLOWER QUALITY*\n`;
  msg += `├─ Real accounts: ${followerAnalysis.realPercent}%\n`;
  msg += `├─ Suspicious: ${followerAnalysis.suspiciousPercent || 0}%\n`;
  msg += `├─ Bot-like: ${followerAnalysis.botPercent}%\n`;
  msg += `└─ ${followerAnalysis.analysis}\n\n`;

  // Tweet analysis
  msg += `📝 *TWEET ANALYSIS* (${tweetAnalysis.totalTweets || 0} tweets)\n`;
  msg += `├─ Technical content: ${tweetAnalysis.techPercent}%\n`;
  msg += `├─ Promotional/shill: ${tweetAnalysis.shillPercent}%\n`;
  msg += `├─ Scam keywords: ${tweetAnalysis.scamPercent}%\n`;
  msg += `└─ ${tweetAnalysis.analysis}\n\n`;

  // Following analysis
  msg += `🔗 *FOLLOWING QUALITY*\n`;
  msg += `├─ Tech/dev accounts: ${followingAnalysis.techPercent}%\n`;
  msg += `├─ Suspicious accounts: ${followingAnalysis.suspiciousCount}\n`;
  msg += `└─ ${followingAnalysis.analysis}`;

  return msg;
}

// Format detailed security info (for button callback)
function formatSecurityDetails(analysis) {
  const { securityScan, githubData, redFlags, greenFlags, profile } = analysis;

  let msg = `🔒 *SECURITY DETAILS: @${profile.username}*\n`;
  msg += `━━━━━━━━━━━━━━━━━━━━━━\n\n`;

  if (githubData) {
    msg += `💻 *GitHub:* [${githubData.login}](https://github.com/${githubData.login})\n`;
    msg += `├─ Repos: ${githubData.public_repos}\n`;
    msg += `├─ Followers: ${formatNumber(githubData.followers)}\n`;
    msg += `└─ Account: ${githubData.created_at ? new Date(githubData.created_at).getFullYear() : 'N/A'}\n\n`;
  }

  if (securityScan?.scanned) {
    const gradeEmoji = securityScan.grade === 'A' ? '✅' :
                       securityScan.grade === 'B' ? '🟢' :
                       securityScan.grade === 'C' ? '🟡' :
                       securityScan.grade === 'D' ? '🟠' : '🔴';
    msg += `🔒 *SECURITY SCAN*\n`;
    msg += `├─ Grade: ${securityScan.grade} ${gradeEmoji}\n`;
    msg += `├─ Secrets exposed: ${securityScan.secrets > 0 ? `${securityScan.secrets} 🚨` : '0 ✅'}\n`;
    msg += `├─ Vulnerabilities: ${securityScan.vulns}\n`;
    msg += `├─ Critical: ${securityScan.critical}\n`;
    msg += `├─ High: ${securityScan.high}\n`;
    msg += `├─ Medium: ${securityScan.medium}\n`;
    if (securityScan.total === 0) {
      msg += `└─ 🎉 Clean code!\n\n`;
    } else if (securityScan.secrets > 0) {
      msg += `└─ ⚠️ SECRETS EXPOSED!\n\n`;
    } else {
      msg += `└─ Review issues above\n\n`;
    }
  } else {
    msg += `🔒 Security scan not available\n\n`;
  }

  // Red flags
  if (redFlags.length > 0) {
    msg += `🚨 *RED FLAGS*\n`;
    redFlags.forEach(f => msg += `• ${f}\n`);
    msg += `\n`;
  }

  // Green flags
  if (greenFlags.length > 0) {
    msg += `✅ *GREEN FLAGS*\n`;
    greenFlags.forEach(f => msg += `• ${f}\n`);
  }

  return msg;
}

// Format help text (for button callback)
function formatHelpText() {
  return `ℹ️ *WHAT DO THESE MEAN?*
━━━━━━━━━━━━━━━━━━━━━━

📊 *Trust Score (0-100)*
How likely this dev is legitimate based on all signals combined.

👤 *Account Age*
Older accounts are more trustworthy. New accounts (<6mo) are capped at 65 score max.

👥 *Follower Quality*
We sample followers to detect bots and fake accounts. Real% = genuine followers.

💻 *GitHub Verification*
Cross-checks if their X links to GitHub AND GitHub links back to X (identity confirmed).

🔒 *Security Grade*
A-F grade based on code scan:
• A = Clean code, no issues
• B = Minor issues only
• C = Some high severity vulns
• D = Critical vulnerabilities
• F = Secrets exposed in code

🚨 *Red Flags*
Warning signs like new account, high bot followers, scam keywords, exposed secrets.

✅ *Green Flags*
Positive signals like verified account, GitHub cross-verified, clean code, organic followers.

*Score Tiers:*
🐐 GOAT (90+) = Elite verified dev
🟢 Legit (80+) = Strong signals
🟡 Okay (60-79) = Some concerns
🟠 Sus (40-59) = Multiple warnings
🔴 High Risk (<40) = Likely scam`;
}

// Answer callback query (acknowledge button press)
async function answerCallback(callbackId, text = '') {
  return new Promise((resolve, reject) => {
    const data = JSON.stringify({
      callback_query_id: callbackId,
      text: text
    });

    const url = new URL(`${TELEGRAM_API}/answerCallbackQuery`);
    const options = {
      hostname: url.hostname,
      path: url.pathname,
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(data)
      }
    };

    const req = https.request(options, (res) => {
      let body = '';
      res.on('data', chunk => body += chunk);
      res.on('end', () => resolve(JSON.parse(body)));
    });
    req.on('error', reject);
    req.write(data);
    req.end();
  });
}

// Analyze code for AI-generated patterns
async function analyzeAIPatterns(owner, repo) {
  const indicators = { ai: [], human: [] };
  let aiScore = 50; // Start neutral

  try {
    // Get commits
    const commits = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/commits?per_page=30`);

    if (Array.isArray(commits)) {
      // Check commit patterns
      if (commits.length <= 5) {
        aiScore += 15;
        indicators.ai.push('Very few commits (typical of AI-generated repos)');
      } else if (commits.length > 50) {
        aiScore -= 15;
        indicators.human.push(`${commits.length} commits showing development history`);
      }

      // Check for large initial commits
      if (commits.length > 0) {
        const firstCommit = commits[commits.length - 1];
        const commitDetail = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/commits/${firstCommit.sha}`);
        if (commitDetail.stats && commitDetail.stats.additions > 1000) {
          aiScore += 10;
          indicators.ai.push('Large initial commit (1000+ lines at once)');
        }
      }

      // Check commit messages
      const genericMessages = commits.filter(c => {
        const msg = c.commit?.message?.toLowerCase() || '';
        return msg.match(/^(initial commit|update|fix|add|create|first commit|init)$/i) ||
               msg.length < 10;
      });
      if (genericMessages.length > commits.length * 0.5) {
        aiScore += 10;
        indicators.ai.push('Generic commit messages');
      }

      // Check for personal commit messages
      const personalMessages = commits.filter(c => {
        const msg = c.commit?.message?.toLowerCase() || '';
        return msg.includes('todo') || msg.includes('wip') || msg.includes('hack') ||
               msg.includes('fix typo') || msg.includes('oops') || msg.includes('damn');
      });
      if (personalMessages.length > 0) {
        aiScore -= 15;
        indicators.human.push('Personal/casual commit messages found');
      }

      // Check unique contributors
      const uniqueAuthors = new Set(commits.map(c => c.author?.login).filter(Boolean));
      if (uniqueAuthors.size === 1) {
        aiScore += 5;
        indicators.ai.push('Single contributor');
      } else if (uniqueAuthors.size >= 3) {
        aiScore -= 10;
        indicators.human.push(`${uniqueAuthors.size} different contributors`);
      }
    }

    // Check README
    try {
      const readme = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/readme`);
      if (readme.content) {
        const content = Buffer.from(readme.content, 'base64').toString('utf-8');

        // Very polished README is AI indicator
        if (content.length > 3000 && content.includes('## ') && content.includes('```')) {
          aiScore += 10;
          indicators.ai.push('Very polished README with perfect structure');
        }

        // Check for AI disclaimers
        if (content.toLowerCase().includes('generated') || content.toLowerCase().includes('ai-assisted')) {
          aiScore += 20;
          indicators.ai.push('README mentions AI/generated content');
        }
      }
    } catch (e) {
      // No README
      indicators.human.push('No README file');
      aiScore -= 5;
    }

  } catch (e) {
    console.error('AI analysis error:', e.message);
  }

  aiScore = Math.max(0, Math.min(100, aiScore));

  return {
    aiLikelihood: aiScore,
    verdict: aiScore >= 70 ? 'Likely AI-Generated' : aiScore >= 50 ? 'Possibly AI-Assisted' : 'Likely Human-Written',
    indicators
  };
}

// Detect entry points and executability
async function analyzeExecutability(owner, repo) {
  const entryPoints = [];
  const buildSystems = [];
  const testIndicators = [];

  try {
    // Get file tree
    const tree = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`);
    const files = tree.tree?.filter(f => f.type === 'blob').map(f => f.path) || [];

    // Check for package.json (Node.js)
    if (files.includes('package.json')) {
      try {
        const pkgFile = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/contents/package.json`);
        const pkg = JSON.parse(Buffer.from(pkgFile.content, 'base64').toString('utf-8'));

        if (pkg.main) entryPoints.push({ type: 'Node.js', file: pkg.main });
        if (pkg.bin) entryPoints.push({ type: 'CLI', file: Object.values(pkg.bin)[0] });
        if (pkg.scripts?.start) entryPoints.push({ type: 'npm start', cmd: pkg.scripts.start });
        if (pkg.scripts?.build) buildSystems.push('npm build');
        if (pkg.scripts?.test) testIndicators.push('npm test script');
      } catch (e) {}
    }

    // Check for Python entry points
    if (files.some(f => f.endsWith('__main__.py'))) {
      entryPoints.push({ type: 'Python module', file: '__main__.py' });
    }
    if (files.includes('main.py') || files.includes('app.py')) {
      entryPoints.push({ type: 'Python', file: files.includes('main.py') ? 'main.py' : 'app.py' });
    }
    if (files.includes('setup.py') || files.includes('pyproject.toml')) {
      buildSystems.push('Python package');
    }

    // Check for Go
    const goFiles = files.filter(f => f.endsWith('.go'));
    if (goFiles.length > 0) {
      entryPoints.push({ type: 'Go', file: 'main.go or cmd/' });
    }
    if (files.includes('go.mod')) {
      buildSystems.push('Go modules');
    }

    // Check for Rust
    if (files.includes('Cargo.toml')) {
      entryPoints.push({ type: 'Rust', file: 'Cargo.toml' });
      buildSystems.push('Cargo');
    }

    // Check for Docker
    if (files.includes('Dockerfile') || files.includes('docker-compose.yml')) {
      buildSystems.push('Docker');
      entryPoints.push({ type: 'Docker', file: 'Dockerfile' });
    }

    // Check for CI/CD
    if (files.some(f => f.includes('.github/workflows'))) {
      buildSystems.push('GitHub Actions');
    }
    if (files.includes('Jenkinsfile')) {
      buildSystems.push('Jenkins');
    }

    // Check for tests
    if (files.some(f => f.includes('test') || f.includes('spec'))) {
      testIndicators.push('Test files found');
    }
    if (files.includes('jest.config.js') || files.includes('pytest.ini') || files.includes('.mocharc')) {
      testIndicators.push('Test framework configured');
    }

    // Check for Makefile
    if (files.includes('Makefile')) {
      buildSystems.push('Makefile');
    }

  } catch (e) {
    console.error('Executability analysis error:', e.message);
  }

  const isExecutable = entryPoints.length > 0;
  const hasTests = testIndicators.length > 0;
  const hasBuildSystem = buildSystems.length > 0;

  return {
    isExecutable,
    entryPoints,
    buildSystems,
    hasTests,
    testIndicators,
    verdict: isExecutable ?
      (hasTests ? 'Executable with tests' : 'Executable, no tests') :
      'No clear entry point'
  };
}

// Format detailed analysis for "More Details" button
function formatDetailedAnalysis(aiAnalysis, execAnalysis, repoUrl) {
  const statusMap = { good: '\u2705', warn: '\u26A0\uFE0F', bad: '\u274C' };

  let msg = `\u{1F9E0} *DETAILED ANALYSIS*\n\n`;
  msg += `\u{1F4E6} ${repoUrl}\n\n`;

  // AI Analysis
  msg += `\u{1F916} *AI-Generated Likelihood: ${aiAnalysis.aiLikelihood}%*\n`;
  msg += `Verdict: ${aiAnalysis.verdict}\n\n`;

  if (aiAnalysis.indicators.ai.length > 0) {
    msg += `\u{1F534} *AI Indicators:*\n`;
    aiAnalysis.indicators.ai.forEach(i => {
      msg += `\u2022 ${i}\n`;
    });
    msg += `\n`;
  }

  if (aiAnalysis.indicators.human.length > 0) {
    msg += `\u{1F7E2} *Human Indicators:*\n`;
    aiAnalysis.indicators.human.forEach(i => {
      msg += `\u2022 ${i}\n`;
    });
    msg += `\n`;
  }

  // Executability Analysis
  msg += `\u{1F527} *Code Executability*\n`;
  msg += `Verdict: ${execAnalysis.verdict}\n\n`;

  if (execAnalysis.entryPoints.length > 0) {
    msg += `${statusMap.good} *Entry Points:*\n`;
    execAnalysis.entryPoints.forEach(ep => {
      msg += `\u2022 ${ep.type}: \`${ep.file || ep.cmd}\`\n`;
    });
    msg += `\n`;
  } else {
    msg += `${statusMap.bad} No entry points detected\n\n`;
  }

  if (execAnalysis.buildSystems.length > 0) {
    msg += `\u{1F3D7} *Build Systems:* ${execAnalysis.buildSystems.join(', ')}\n`;
  }

  if (execAnalysis.hasTests) {
    msg += `${statusMap.good} *Tests:* ${execAnalysis.testIndicators.join(', ')}\n`;
  } else {
    msg += `${statusMap.warn} *Tests:* None detected\n`;
  }

  msg += `\n_Analysis powered by [AuraSecurity](https://aurasecurity.io)_`;

  return msg;
}

// Format security scan results for Telegram
function formatScanResult(apiResponse, gitUrl) {
  // API returns {result: {scan_details: ...}}
  const result = apiResponse.result || apiResponse;
  const scan = result.scan_details || {};
  const secrets = scan.secrets_found || 0;
  const vulns = scan.package_vulns || 0;
  const sastFindings = scan.sast_findings || 0;
  const totalFindings = secrets + vulns + sastFindings;

  // Determine severity
  let emoji, verdict;
  if (secrets > 0 || vulns > 10) {
    emoji = '\u{1F534}'; // Red
    verdict = 'CRITICAL ISSUES';
  } else if (vulns > 0 || sastFindings > 5) {
    emoji = '\u{1F7E0}'; // Orange
    verdict = 'SECURITY CONCERNS';
  } else if (sastFindings > 0) {
    emoji = '\u{1F7E1}'; // Yellow
    verdict = 'MINOR ISSUES';
  } else {
    emoji = '\u{1F7E2}'; // Green
    verdict = 'LOOKS CLEAN';
  }

  let msg = `${emoji} *SECURITY SCAN: ${verdict}*\n\n`;
  msg += `\u{1F4E6} Repository: ${gitUrl}\n\n`;

  // Summary stats
  msg += `*Findings Summary:*\n`;
  msg += secrets > 0 ? `\u{1F534} Secrets: ${secrets}\n` : `\u2705 Secrets: None\n`;
  msg += vulns > 0 ? `\u{1F7E0} Vulnerabilities: ${vulns}\n` : `\u2705 Vulnerabilities: None\n`;
  msg += sastFindings > 0 ? `\u{1F7E1} Code Issues: ${sastFindings}\n` : `\u2705 Code Issues: None\n`;

  // Tools used
  if (scan.tools_used && scan.tools_used.length > 0) {
    msg += `\n*Tools Used:* ${scan.tools_used.join(', ')}\n`;
  }

  // Top findings
  const rawFindings = scan.raw_findings || {};

  // Show top secrets (if any)
  if (rawFindings.secrets && rawFindings.secrets.length > 0) {
    msg += `\n\u{1F6A8} *Top Secrets Found:*\n`;
    rawFindings.secrets.slice(0, 5).forEach(s => {
      msg += `\u2022 ${s.type} in \`${s.file}:${s.line}\`\n`;
    });
    if (rawFindings.secrets.length > 5) {
      msg += `_...and ${rawFindings.secrets.length - 5} more_\n`;
    }
  }

  // Show top vulnerabilities (if any)
  if (rawFindings.packages && rawFindings.packages.length > 0) {
    msg += `\n\u26A0\uFE0F *Top Vulnerabilities:*\n`;
    rawFindings.packages.slice(0, 5).forEach(p => {
      const sev = p.severity === 'critical' ? '\u{1F534}' : p.severity === 'high' ? '\u{1F7E0}' : '\u{1F7E1}';
      msg += `${sev} ${p.name}@${p.version} (${p.severity})\n`;
    });
    if (rawFindings.packages.length > 5) {
      msg += `_...and ${rawFindings.packages.length - 5} more_\n`;
    }
  }

  // Verdict
  msg += `\n`;
  if (totalFindings === 0) {
    msg += `\u2728 _No security issues detected!_`;
  } else if (secrets > 0) {
    msg += `\u26A0\uFE0F _CAUTION: Exposed secrets detected. Review code before use._`;
  } else if (vulns > 5) {
    msg += `\u26A0\uFE0F _CAUTION: Multiple vulnerabilities found. Review before use._`;
  } else {
    msg += `\u{1F4DD} _Some issues found. Review before using in production._`;
  }

  msg += `\n\n_Full report: [AuraSecurity](https://aurasecurity.io)_`;

  // Extract owner/repo for callback
  const match = gitUrl.match(/github\.com\/([^\/]+)\/([^\/\s]+)/);
  const callbackData = match ? `details:${match[1]}/${match[2].replace(/\.git$/, '')}` : null;

  return { text: msg, callbackData };
}

// Extract GitHub link from a website
async function findGitHubOnWebsite(websiteUrl) {
  try {
    // Normalize URL
    if (!websiteUrl.startsWith('http')) {
      websiteUrl = 'https://' + websiteUrl;
    }

    console.log('Fetching website for GitHub link:', websiteUrl);

    const response = await fetchUrl(websiteUrl);
    if (response.status !== 200) {
      return null;
    }

    const html = response.data;

    // Look for GitHub links in the HTML
    const githubPatterns = [
      /href=["']?(https?:\/\/github\.com\/[a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)\/?["']?/gi,
      /github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/gi
    ];

    const found = new Set();

    for (const pattern of githubPatterns) {
      let match;
      while ((match = pattern.exec(html)) !== null) {
        const url = match[1] || match[0];
        if (url && !url.includes('github.com/orgs') && !url.includes('github.com/settings')) {
          // Clean up the URL
          let cleanUrl = url.replace(/["'>\s].*/g, '');
          if (!cleanUrl.startsWith('http')) {
            cleanUrl = 'https://github.com/' + cleanUrl.replace('github.com/', '');
          }
          found.add(cleanUrl);
        }
      }
    }

    // Return the first valid GitHub link (usually the main one)
    const links = Array.from(found);
    console.log('Found GitHub links:', links);

    // Prefer org/repo links over just org links
    const repoLink = links.find(l => l.split('/').length >= 5);
    if (repoLink) return repoLink;

    return links[0] || null;
  } catch (e) {
    console.error('Website fetch error:', e.message);
    return null;
  }
}

// Extract website URL from bio
function extractWebsiteFromBio(bio) {
  if (!bio) return null;

  // Common patterns for websites in bios
  const patterns = [
    // Direct URLs
    /(https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]*\.[a-zA-Z]{2,}(?:\/[^\s]*)?)/gi,
    // URLs without protocol
    /(?:^|\s)([a-zA-Z0-9][a-zA-Z0-9-]*\.(?:com|io|xyz|app|dev|co|org|net|gg)(?:\/[^\s]*)?)/gi
  ];

  for (const pattern of patterns) {
    const match = bio.match(pattern);
    if (match) {
      let url = match[0].trim();
      // Skip twitter/x links
      if (url.includes('twitter.com') || url.includes('x.com')) continue;
      // Skip github links (we check those separately)
      if (url.includes('github.com')) continue;
      // Skip discord/telegram
      if (url.includes('discord') || url.includes('t.me')) continue;

      return url;
    }
  }

  return null;
}

// Extract username from X URL or handle
function extractXUsername(input) {
  input = input.trim();

  // Handle full URLs like https://x.com/username?params or https://twitter.com/username
  const urlMatch = input.match(/(?:x\.com|twitter\.com)\/([a-zA-Z0-9_]+)/i);
  if (urlMatch) {
    return urlMatch[1];
  }

  // Handle multiple usernames (e.g., "@botname @realuser" in groups) - take the last non-bot one
  const usernames = input.match(/@?([a-zA-Z0-9_]+)/g);
  if (usernames && usernames.length > 1) {
    // Filter out bot usernames and take the last valid one
    const filtered = usernames
      .map(u => u.replace(/^@/, ''))
      .filter(u => !u.toLowerCase().includes('_bot') && !u.toLowerCase().endsWith('bot'));

    if (filtered.length > 0) {
      return filtered[filtered.length - 1].replace(/\?.*$/, '').trim();
    }
  }

  // Handle @username or plain username
  return input.replace(/^@/, '').replace(/\?.*$/, '').trim();
}

// Check X Profile using official X API v2
async function checkXProfile(username) {
  // Clean username - handle URLs and @ symbols
  username = extractXUsername(username);

  // Use official X API v2 - include url and entities for website
  const apiUrl = `https://api.twitter.com/2/users/by/username/${username}?user.fields=id,created_at,description,public_metrics,verified,verified_type,profile_image_url,url,entities`;

  return new Promise((resolve, reject) => {
    const url = new URL(apiUrl);
    const options = {
      hostname: url.hostname,
      path: url.pathname + url.search,
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${X_BEARER_TOKEN}`,
        'User-Agent': 'AuraSecurityBot/1.0'
      }
    };

    https.get(options, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        try {
          const json = JSON.parse(data);
          console.log('X API response:', JSON.stringify(json));

          if (json.errors) {
            const error = json.errors[0];
            if (error.title === 'Not Found Error') {
              reject(new Error(`@${username} not found. The account may not exist or is suspended.`));
            } else if (error.title === 'Authorization Error') {
              reject(new Error('X API authorization failed. Please check API credentials.'));
            } else {
              reject(new Error(error.detail || error.title || 'Unknown X API error'));
            }
            return;
          }

          if (!json.data) {
            reject(new Error(`Could not fetch profile for @${username}`));
            return;
          }

          const user = json.data;
          const metrics = user.public_metrics || {};

          // Extract expanded URL from entities if available
          let websiteUrl = null;
          if (user.entities?.url?.urls?.[0]?.expanded_url) {
            websiteUrl = user.entities.url.urls[0].expanded_url;
          } else if (user.url) {
            websiteUrl = user.url;
          }

          resolve({
            id: user.id,
            username: user.username,
            name: user.name,
            followers: metrics.followers_count || 0,
            following: metrics.following_count || 0,
            tweets: metrics.tweet_count || 0,
            bio: user.description || '',
            website: websiteUrl,
            verified: user.verified || false,
            verifiedType: user.verified_type || null,
            createdAt: user.created_at,
            profileImage: user.profile_image_url
          });
        } catch (e) {
          console.error('X API parse error:', e.message);
          reject(new Error('Failed to parse X API response'));
        }
      });
    }).on('error', (e) => {
      console.error('X API request error:', e.message);
      reject(new Error('Failed to connect to X API'));
    });
  });
}


// Calculate X trust score
function calculateXScore(profile) {
  let score = 50;
  const checks = [];

  // Account age
  if (profile.createdAt) {
    const created = new Date(profile.createdAt);
    const ageYears = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24 * 365);
    if (ageYears >= 3) {
      score += 15;
      checks.push({ name: 'Account Age', status: 'good', detail: `${Math.floor(ageYears)} years old` });
    } else if (ageYears >= 1) {
      score += 8;
      checks.push({ name: 'Account Age', status: 'warn', detail: `${Math.floor(ageYears * 12)} months old` });
    } else {
      score -= 10;
      const months = Math.floor(ageYears * 12);
      checks.push({ name: 'Account Age', status: 'bad', detail: months > 0 ? `${months} months old` : 'Very new account' });
    }
  }

  // Follower count
  if (profile.followers >= 10000) {
    score += 15;
    checks.push({ name: 'Followers', status: 'good', detail: formatNumber(profile.followers) });
  } else if (profile.followers >= 1000) {
    score += 8;
    checks.push({ name: 'Followers', status: 'warn', detail: formatNumber(profile.followers) });
  } else {
    score -= 5;
    checks.push({ name: 'Followers', status: 'bad', detail: `Only ${formatNumber(profile.followers)}` });
  }

  // Follower/Following ratio
  if (profile.following > 0) {
    const ratio = profile.followers / profile.following;
    if (ratio >= 10) {
      score += 10;
      checks.push({ name: 'F/F Ratio', status: 'good', detail: `${ratio.toFixed(1)}:1 (influencer)` });
    } else if (ratio >= 1) {
      score += 5;
      checks.push({ name: 'F/F Ratio', status: 'warn', detail: `${ratio.toFixed(1)}:1` });
    } else {
      score -= 5;
      checks.push({ name: 'F/F Ratio', status: 'bad', detail: `${ratio.toFixed(2)}:1 (follows more than followers)` });
    }
  }

  // Tweet count (activity)
  if (profile.tweets >= 1000) {
    score += 10;
    checks.push({ name: 'Activity', status: 'good', detail: `${formatNumber(profile.tweets)} tweets` });
  } else if (profile.tweets >= 100) {
    score += 5;
    checks.push({ name: 'Activity', status: 'warn', detail: `${profile.tweets} tweets` });
  } else {
    score -= 5;
    checks.push({ name: 'Activity', status: 'bad', detail: `Only ${profile.tweets} tweets` });
  }

  // Verified status
  if (profile.verified) {
    score += 5;
    checks.push({ name: 'Verified', status: 'good', detail: 'Yes' });
  } else {
    checks.push({ name: 'Verified', status: 'warn', detail: 'No' });
  }

  // Bio check - look for GitHub
  let githubUrl = null;
  if (profile.bio) {
    const githubMatch = profile.bio.match(/github\.com\/([a-zA-Z0-9_-]+(?:\/[a-zA-Z0-9_-]+)?)/i);
    if (githubMatch) {
      githubUrl = `https://github.com/${githubMatch[1]}`;
      checks.push({ name: 'GitHub', status: 'good', detail: 'Found in bio' });
    } else if (profile.bio.toLowerCase().includes('github')) {
      checks.push({ name: 'GitHub', status: 'warn', detail: 'Mentioned but no link' });
    }
  }

  score = Math.max(0, Math.min(100, score));

  return { score, checks, githubUrl };
}

// Perform GitHub trust scan
async function performTrustScan(gitUrl) {
  const match = gitUrl.match(/github\.com\/([^\/]+)(?:\/([^\/\s]+))?/);
  if (!match) {
    throw new Error('Invalid GitHub URL');
  }

  const owner = match[1];
  const repo = match[2]?.replace(/\.git$/, '');

  // If no repo specified, get user/org info
  if (!repo) {
    const userData = await fetchJson(`https://api.github.com/users/${owner}`);
    if (userData.message === 'Not Found') {
      throw new Error('GitHub user not found');
    }

    // Get their repos
    const repos = await fetchJson(`https://api.github.com/users/${owner}/repos?sort=stars&per_page=5`);

    return {
      type: 'user',
      owner,
      userData,
      topRepos: repos.slice(0, 3),
      url: `https://github.com/${owner}`
    };
  }

  // Full repo scan
  const repoData = await fetchJson(`https://api.github.com/repos/${owner}/${repo}`);

  if (repoData.message === 'Not Found') {
    throw new Error('Repository not found');
  }

  let contributors = [];
  try {
    contributors = await fetchJson(`https://api.github.com/repos/${owner}/${repo}/contributors?per_page=100`);
  } catch (e) {}

  const createdAt = new Date(repoData.created_at);
  const pushedAt = new Date(repoData.pushed_at);
  const now = new Date();
  const repoAgeDays = Math.floor((now - createdAt) / (1000 * 60 * 60 * 24));
  const daysSinceLastPush = Math.floor((now - pushedAt) / (1000 * 60 * 60 * 24));
  const contributorCount = Array.isArray(contributors) ? contributors.length : 0;

  let score = 50;
  const checks = [];

  // Project Age
  if (repoAgeDays > 365) {
    score += 10;
    checks.push({ name: 'Project Age', status: 'good', detail: `${Math.floor(repoAgeDays / 365)} years` });
  } else if (repoAgeDays > 90) {
    score += 5;
    checks.push({ name: 'Project Age', status: 'warn', detail: `${repoAgeDays} days` });
  } else {
    checks.push({ name: 'Project Age', status: 'bad', detail: `Only ${repoAgeDays} days` });
  }

  // Stars
  if (repoData.stargazers_count > 1000) {
    score += 10;
    checks.push({ name: 'Stars', status: 'good', detail: formatNumber(repoData.stargazers_count) });
  } else if (repoData.stargazers_count > 100) {
    score += 5;
    checks.push({ name: 'Stars', status: 'warn', detail: `${repoData.stargazers_count}` });
  } else {
    score -= 5;
    checks.push({ name: 'Stars', status: 'bad', detail: `Only ${repoData.stargazers_count}` });
  }

  // Contributors
  if (contributorCount > 10) {
    score += 10;
    checks.push({ name: 'Team', status: 'good', detail: `${contributorCount}+ contributors` });
  } else if (contributorCount > 3) {
    score += 5;
    checks.push({ name: 'Team', status: 'warn', detail: `${contributorCount} contributors` });
  } else {
    score -= 5;
    checks.push({ name: 'Team', status: 'bad', detail: `${contributorCount} contributor(s)` });
  }

  // Activity
  if (daysSinceLastPush < 30) {
    score += 10;
    checks.push({ name: 'Activity', status: 'good', detail: `${daysSinceLastPush}d ago` });
  } else if (daysSinceLastPush < 180) {
    score += 5;
    checks.push({ name: 'Activity', status: 'warn', detail: `${daysSinceLastPush}d ago` });
  } else {
    score -= 10;
    checks.push({ name: 'Activity', status: 'bad', detail: `${daysSinceLastPush}d inactive` });
  }

  // Fork
  if (repoData.fork) {
    score -= 10;
    checks.push({ name: 'Original', status: 'bad', detail: 'Fork' });
  } else {
    score += 5;
    checks.push({ name: 'Original', status: 'good', detail: 'Yes' });
  }

  // License
  if (repoData.license) {
    score += 5;
    checks.push({ name: 'License', status: 'good', detail: repoData.license.spdx_id || 'Yes' });
  }

  score = Math.max(0, Math.min(100, score));

  let grade, verdict, emoji;
  if (score >= 80) { grade = 'A'; verdict = 'SAFU'; emoji = 'green'; }
  else if (score >= 60) { grade = 'B'; verdict = 'DYOR'; emoji = 'yellow'; }
  else if (score >= 40) { grade = 'C'; verdict = 'RISKY'; emoji = 'orange'; }
  else { grade = 'F'; verdict = 'RUG ALERT'; emoji = 'red'; }

  return {
    type: 'repo',
    owner,
    repo,
    score,
    grade,
    verdict,
    emoji,
    checks,
    url: `https://github.com/${owner}/${repo}`
  };
}

function formatNumber(num) {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

// Format X result
function formatXResult(profile, xScore) {
  const emojiMap = { green: '\u{1F7E2}', yellow: '\u{1F7E1}', orange: '\u{1F7E0}', red: '\u{1F534}' };
  const statusMap = { good: '\u2705', warn: '\u26A0\uFE0F', bad: '\u274C' };

  let scoreEmoji = xScore.score >= 70 ? 'green' : xScore.score >= 50 ? 'yellow' : xScore.score >= 30 ? 'orange' : 'red';
  let verdict = xScore.score >= 70 ? 'LEGIT' : xScore.score >= 50 ? 'DYOR' : xScore.score >= 30 ? 'SUS' : 'SCAM LIKELY';

  let msg = `${emojiMap[scoreEmoji]} *X Profile: ${verdict}*\n`;
  msg += `Score: ${xScore.score}/100\n\n`;
  msg += `\u{1F464} [@${profile.username}](https://x.com/${profile.username})`;
  if (profile.name) msg += ` (${profile.name})`;
  msg += `\n\n`;

  for (const check of xScore.checks) {
    const icon = statusMap[check.status] || '\u2022';
    msg += `${icon} ${check.name}: ${check.detail}\n`;
  }

  if (xScore.githubUrl) {
    msg += `\n\u{1F4A1} _GitHub found! Use /devcheck @${profile.username} for full audit_`;
  }

  return msg;
}

// Format GitHub result
function formatGitResult(result) {
  const emojiMap = { green: '\u{1F7E2}', yellow: '\u{1F7E1}', orange: '\u{1F7E0}', red: '\u{1F534}' };
  const statusMap = { good: '\u2705', warn: '\u26A0\uFE0F', bad: '\u274C' };

  let msg = `${emojiMap[result.emoji]} *${result.verdict}* - Score: ${result.score}/100 (${result.grade})\n\n`;
  msg += `\u{1F4E6} [${result.owner}/${result.repo}](${result.url})\n\n`;

  for (const check of result.checks) {
    const icon = statusMap[check.status] || '\u2022';
    msg += `${icon} ${check.name}: ${check.detail}\n`;
  }

  const callbackData = result.repo ? `details:${result.owner}/${result.repo}` : null;

  return { text: msg, callbackData };
}

// Format combined result
function formatCombinedResult(profile, xScore, gitResult) {
  const emojiMap = { green: '\u{1F7E2}', yellow: '\u{1F7E1}', orange: '\u{1F7E0}', red: '\u{1F534}' };
  const statusMap = { good: '\u2705', warn: '\u26A0\uFE0F', bad: '\u274C' };

  // Combined score (weighted: 40% X, 60% GitHub)
  const combinedScore = Math.round(xScore.score * 0.4 + gitResult.score * 0.6);

  let verdict, emoji;
  if (combinedScore >= 75) { verdict = 'SAFU'; emoji = 'green'; }
  else if (combinedScore >= 55) { verdict = 'DYOR'; emoji = 'yellow'; }
  else if (combinedScore >= 35) { verdict = 'RISKY'; emoji = 'orange'; }
  else { verdict = 'RUG ALERT'; emoji = 'red'; }

  let msg = `${emojiMap[emoji]} *COMPREHENSIVE CHECK: ${verdict}*\n`;
  msg += `\u{1F3AF} Combined Score: ${combinedScore}/100\n\n`;

  msg += `\u{1F4F1} *X Profile* (${xScore.score}/100)\n`;
  msg += `[@${profile.username}](https://x.com/${profile.username})\n`;
  for (const check of xScore.checks.slice(0, 4)) {
    const icon = statusMap[check.status] || '\u2022';
    msg += `${icon} ${check.name}: ${check.detail}\n`;
  }

  msg += `\n\u{1F4BB} *GitHub* (${gitResult.score}/100)\n`;
  msg += `[${gitResult.owner}/${gitResult.repo}](${gitResult.url})\n`;
  for (const check of gitResult.checks.slice(0, 4)) {
    const icon = statusMap[check.status] || '\u2022';
    msg += `${icon} ${check.name}: ${check.detail}\n`;
  }

  if (combinedScore >= 75) {
    msg += `\n\u2728 _Both social presence and code look legitimate!_`;
  } else if (combinedScore >= 55) {
    msg += `\n\u26A0\uFE0F _Some concerns. Do your own research!_`;
  } else {
    msg += `\n\u{1F6A8} _Multiple red flags across social and code!_`;
  }

  const callbackData = gitResult.repo ? `details:${gitResult.owner}/${gitResult.repo}` : null;

  return { text: msg, callbackData };
}

// Main handler
export async function handler(event) {
  console.log('Event:', JSON.stringify(event));

  // Health check endpoint - for uptime monitoring
  if (event.path === '/health' || event.rawPath === '/health' || event.httpMethod === 'GET') {
    const healthCheck = {
      status: 'ok',
      timestamp: new Date().toISOString(),
      version: '1.1.0',
      services: {
        telegram: BOT_TOKEN ? 'configured' : 'missing',
        twitter: X_BEARER_TOKEN ? 'configured' : 'missing',
        claude: ANTHROPIC_API_KEY ? 'configured' : 'missing',
        aura_api: AURA_API_PRIMARY
      }
    };
    return {
      statusCode: 200,
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(healthCheck)
    };
  }

  try {
    const body = typeof event.body === 'string' ? JSON.parse(event.body) : event.body;

    // Deduplicate: Skip if we've already processed this update
    const updateId = body?.update_id;
    if (isDuplicate(updateId)) {
      return { statusCode: 200, body: 'OK - duplicate' };
    }

    // Handle callback queries (button presses)
    if (body.callback_query) {
      const callback = body.callback_query;
      const chatId = callback.message.chat.id;
      const callbackId = callback.id;
      const data = callback.data;

      console.log('Callback query:', data);

      // Acknowledge the button press
      await answerCallback(callbackId, 'Loading detailed analysis...');

      // Parse callback data: "details:owner/repo"
      if (data.startsWith('details:')) {
        const repoPath = data.replace('details:', '');
        const [owner, repo] = repoPath.split('/');

        await sendMessage(chatId, `\u{1F50D} Analyzing code patterns for ${owner}/${repo}...`);

        try {
          // Run AI and executability analysis in parallel
          const [aiAnalysis, execAnalysis] = await Promise.all([
            analyzeAIPatterns(owner, repo),
            analyzeExecutability(owner, repo)
          ]);

          const detailedMsg = formatDetailedAnalysis(
            aiAnalysis,
            execAnalysis,
            `https://github.com/${owner}/${repo}`
          );

          await sendMessage(chatId, detailedMsg);
        } catch (err) {
          console.error('Detailed analysis error:', err);
          await sendMessage(chatId, `\u274C Analysis failed: ${err.message}`);
        }
      }

      // Handle security scan for GitHub repos
      if (data.startsWith('scan:')) {
        const repoUrl = data.replace('scan:', '');

        await sendMessage(chatId, `🔒 *Running security scan...*\n_Checking for secrets, vulnerabilities, and code issues..._\n\n_This may take 1-2 minutes._`);

        try {
          const result = await callAuraScan(repoUrl);
          const formatted = formatScanResult(result, repoUrl);
          await sendMessage(chatId, formatted.text);
        } catch (err) {
          console.error('Security scan error:', err);
          await sendMessage(chatId, `❌ Security scan failed: ${err.message}`);
        }

        return { statusCode: 200, body: 'OK' };
      }

      // Handle AI deep dive for X profiles
      if (data.startsWith('ai_x:')) {
        const username = data.replace('ai_x:', '');

        await sendMessage(chatId, `🤖 *Running AI analysis on @${username}...*\n_Claude is analyzing this profile..._`);

        try {
          // Get profile and tweets for AI analysis
          const profile = await checkXProfile(username);
          const tweets = await getUserTweets(profile.id, 50);

          // Build prompt for Claude
          const tweetTexts = tweets.slice(0, 30).map(t => t.text).join('\n---\n');

          const prompt = `Analyze this X/Twitter profile for legitimacy and trustworthiness. Be direct and specific.

PROFILE:
- Username: @${profile.username}
- Name: ${profile.name}
- Bio: ${profile.bio || 'No bio'}
- Followers: ${profile.followers}
- Following: ${profile.following}
- Total tweets: ${profile.tweets}
- Account created: ${profile.createdAt}
- Verified: ${profile.verified}

RECENT TWEETS:
${tweetTexts}

Analyze and provide:
1. AUTHENTICITY SCORE (0-100): Is this a real person or bot/fake?
2. DEVELOPER CREDIBILITY (0-100): Evidence of actual technical work?
3. SCAM RISK (0-100): Likelihood this is a scam/fraud account?
4. KEY RED FLAGS: List any warning signs (be specific)
5. KEY GREEN FLAGS: List positive signals
6. VERDICT: One line summary

Be brutally honest. If it looks like a scam, say so clearly.`;

          const aiResponse = await askClaude(prompt, 800);

          let aiMsg = `🤖 *CLAUDE AI ANALYSIS*\n`;
          aiMsg += `━━━━━━━━━━━━━━━━━━━━━━━━\n\n`;
          aiMsg += `👤 [@${profile.username}](https://x.com/${profile.username})\n\n`;
          aiMsg += aiResponse;
          aiMsg += `\n\n_Analysis by Claude AI_`;

          await sendMessage(chatId, aiMsg);
        } catch (err) {
          console.error('AI analysis error:', err);
          await sendMessage(chatId, `\u274C AI analysis failed: ${err.message}`);
        }
      }

      // Handle Social Stats button
      if (data.startsWith('xsoc:')) {
        const username = data.replace('xsoc:', '');
        await answerCallback(callbackId, 'Loading social stats...');

        try {
          const profile = await checkXProfile(username);
          const userId = profile.id || await getUserId(username);

          const [tweets, followers, following] = await Promise.all([
            getUserTweets(userId, 100),
            sampleFollowers(userId, 50),
            getUserFollowing(userId, 100)
          ]);

          const followerAnalysis = analyzeFollowerQuality(followers);
          const tweetAnalysis = analyzeTweets(tweets);
          const followingAnalysis = analyzeFollowing(following);

          const msg = formatSocialStats({ followerAnalysis, tweetAnalysis, followingAnalysis, profile });
          await sendMessage(chatId, msg);
        } catch (err) {
          console.error('Social stats error:', err);
          await sendMessage(chatId, `\u274C Failed to load social stats: ${err.message}`);
        }
        return { statusCode: 200, body: 'OK' };
      }

      // Handle Security Details button
      if (data.startsWith('xsec:')) {
        const username = data.replace('xsec:', '');
        await answerCallback(callbackId, 'Loading security details...');

        try {
          const profile = await checkXProfile(username);
          const userId = profile.id || await getUserId(username);

          const [tweets, followers, following] = await Promise.all([
            getUserTweets(userId, 100),
            sampleFollowers(userId, 50),
            getUserFollowing(userId, 100)
          ]);

          const analysis = await deepXAnalysis(profile, tweets, followers, following);
          const msg = formatSecurityDetails(analysis);
          await sendMessage(chatId, msg);
        } catch (err) {
          console.error('Security details error:', err);
          await sendMessage(chatId, `\u274C Failed to load security details: ${err.message}`);
        }
        return { statusCode: 200, body: 'OK' };
      }

      // Handle Help button
      if (data === 'xhelp') {
        await answerCallback(callbackId, '');
        const msg = formatHelpText();
        await sendMessage(chatId, msg);
        return { statusCode: 200, body: 'OK' };
      }

      return { statusCode: 200, body: 'OK' };
    }

    const message = body?.message;

    if (!message?.text) {
      return { statusCode: 200, body: 'OK' };
    }

    const chatId = message.chat.id;
    const text = message.text.trim();
    const username = message.from?.first_name || 'anon';

    // /start command
    if (text === '/start') {
      await sendMessage(chatId,
        `\u{1F44B} Hey ${username}! I'm the *AuraSecurity Bot*.\n\n` +
        `I help you spot scams, rug pulls, and security issues.\n\n` +
        `*Commands:*\n` +
        `/rugcheck <github-url> - Trust score for repo\n` +
        `/scan <github-url> - Full security scan\n` +
        `/devcheck <@username> - Full dev audit (identity + security)\n` +
        `/xcheck <@username> - Same as devcheck\n\n` +
        `*Example:*\n` +
        `/scan https://github.com/ethereum/go-ethereum\n` +
        `/devcheck @VitalikButerin\n\n` +
        `_Powered by [AuraSecurity](https://aurasecurity.io)_`
      );
    }
    // /help command
    else if (text === '/help') {
      await sendMessage(chatId,
        `\u{1F50D} *AuraSecurity Bot Help*\n\n` +
        `*Commands:*\n` +
        `/rugcheck <url> - Trust score for repo\n` +
        `/scan <url> - Full security scan (secrets, vulns)\n` +
        `/devcheck <@user> - Full dev audit (identity + security)\n` +
        `/xcheck <@user> - Same as devcheck\n\n` +
        `*What I check:*\n\n` +
        `\u{1F6E1} *Security Scan (/scan):*\n` +
        `\u2022 Exposed secrets & API keys\n` +
        `\u2022 Vulnerable dependencies\n` +
        `\u2022 Code security issues (SAST)\n\n` +
        `\u{1F4F1} *Dev Check (/devcheck):*\n` +
        `\u2022 X profile & follower quality\n` +
        `\u2022 GitHub verification & security scan\n` +
        `\u2022 Combined trust score\n\n` +
        `\u{1F4BB} *Trust Score (/rugcheck):*\n` +
        `\u2022 Project age & stars\n` +
        `\u2022 Team size & activity\n` +
        `\u2022 Fork status & license\n\n` +
        `\u{1F9E0} *More Details Button:*\n` +
        `\u2022 AI-generated code detection\n` +
        `\u2022 Entry point analysis\n` +
        `\u2022 Build system detection\n` +
        `\u2022 Test coverage check\n\n` +
        `_Not financial advice. Always DYOR!_`
      );
    }
    // /rugcheck command
    else if (text.startsWith('/rugcheck')) {
      const url = text.replace(/^\/rugcheck(@[a-zA-Z0-9_]+)?/i, '').trim();

      if (!url) {
        await sendMessage(chatId, `\u274C Please provide a GitHub URL.\n\n*Example:*\n/rugcheck https://github.com/owner/repo`);
        return { statusCode: 200, body: 'OK' };
      }

      if (!url.includes('github.com')) {
        await sendMessage(chatId, `\u274C Only GitHub URLs supported.`);
        return { statusCode: 200, body: 'OK' };
      }

      await sendMessage(chatId, `\u{1F50D} Analyzing GitHub repo...`);

      try {
        const result = await performTrustScan(url);
        const formatted = formatGitResult(result);

        // Create inline keyboard with "More Details" button
        const replyMarkup = formatted.callbackData ? {
          inline_keyboard: [[
            { text: '\u{1F9E0} More Details (AI Check + Entry Points)', callback_data: formatted.callbackData }
          ]]
        } : null;

        await sendMessage(chatId, formatted.text, 'Markdown', replyMarkup);
      } catch (err) {
        await sendMessage(chatId, `\u274C Error: ${err.message}`);
      }
    }
    // /scan command - Full security scan
    else if (text.startsWith('/scan')) {
      const url = text.replace(/^\/scan(@[a-zA-Z0-9_]+)?/i, '').trim();

      if (!url) {
        await sendMessage(chatId, `\u274C Please provide a GitHub URL.\n\n*Example:*\n/scan https://github.com/owner/repo`);
        return { statusCode: 200, body: 'OK' };
      }

      if (!url.includes('github.com')) {
        await sendMessage(chatId, `\u274C Only GitHub URLs are supported for scanning.`);
        return { statusCode: 200, body: 'OK' };
      }

      await sendMessage(chatId, `\u{1F6E1} Starting security scan...\n_This may take 1-2 minutes._`);

      try {
        const result = await callAuraScan(url);
        const formatted = formatScanResult(result, url);

        // Create inline keyboard with "More Details" button
        const replyMarkup = formatted.callbackData ? {
          inline_keyboard: [[
            { text: '\u{1F9E0} More Details (AI Check + Entry Points)', callback_data: formatted.callbackData }
          ]]
        } : null;

        await sendMessage(chatId, formatted.text, 'Markdown', replyMarkup);
      } catch (err) {
        console.error('Scan error:', err);
        await sendMessage(chatId, `\u274C Scan failed: ${err.message}\n\n_Try /rugcheck for a quick trust check instead._`);
      }
    }
    // /xcheck or /devcheck command - DEEP ANALYSIS
    else if (text.startsWith('/xcheck') || text.startsWith('/devcheck')) {
      // Handle /command@botname format in groups
      let xInput = text.replace(/^\/(xcheck|devcheck)(@[a-zA-Z0-9_]+)?/i, '').trim();

      if (!xInput) {
        await sendMessage(chatId, `\u274C Please provide an X username.\n\n*Example:*\n${cmd} @username`);
        return { statusCode: 200, body: 'OK' };
      }

      // Extract username from URL or handle
      const xUsername = extractXUsername(xInput);
      await sendMessage(chatId, `🔍 *Running deep analysis on @${xUsername}...*\n\n_Checking: profile, followers, tweets, connections..._`);

      try {
        // Get basic profile first
        const profile = await checkXProfile(xUsername);

        // Get user ID for further API calls
        const userId = profile.id || await getUserId(xUsername);

        // Run deep analysis - fetch tweets, followers, following in parallel
        const [tweets, followers, following] = await Promise.all([
          getUserTweets(userId, 100),
          sampleFollowers(userId, 50),
          getUserFollowing(userId, 100)
        ]);

        // Run deep analysis
        const analysis = await deepXAnalysis(profile, tweets, followers, following);

        // Format compact result
        const result = formatDeepXResult(analysis);

        // Build inline keyboard buttons - compact view with expandable details
        const buttons = [
          [
            { text: '📊 Social Stats', callback_data: `xsoc:${xUsername}` },
            { text: '🔒 Security', callback_data: `xsec:${xUsername}` }
          ],
          [
            { text: 'ℹ️ Help', callback_data: 'xhelp' },
            { text: '🤖 AI Analysis', callback_data: `ai_x:${xUsername}` }
          ]
        ];

        const replyMarkup = { inline_keyboard: buttons };

        await sendMessage(chatId, result.text, 'Markdown', replyMarkup);
      } catch (err) {
        console.error('X check error:', err);
        await sendMessage(chatId, `\u274C Error: ${err.message}`);
      }
    }
    // /fullcheck command - redirect to devcheck (same deep analysis)
    else if (text.startsWith('/fullcheck')) {
      let xInput = text.replace(/^\/fullcheck(@[a-zA-Z0-9_]+)?/i, '').trim();

      if (!xInput) {
        await sendMessage(chatId, `\u274C Please provide an X username.\n\n*Example:*\n/fullcheck @username\n\n_Tip: /fullcheck and /devcheck do the same thing!_`);
        return { statusCode: 200, body: 'OK' };
      }

      // Check if user passed a GitHub URL instead of X username
      if (xInput.includes('github.com')) {
        await sendMessage(chatId, `\u{1F4A1} That's a GitHub URL. Use /rugcheck for GitHub:\n\n/rugcheck ${xInput}\n\n_/fullcheck is for X usernames_`);
        return { statusCode: 200, body: 'OK' };
      }

      // Extract username and run deep analysis (same as /devcheck)
      const xUsername = extractXUsername(xInput);
      await sendMessage(chatId, `🔍 *Running full dev audit on @${xUsername}...*\n\n_Checking: profile, followers, tweets, GitHub, security..._`);

      try {
        const profile = await checkXProfile(xUsername);
        const userId = profile.id || await getUserId(xUsername);

        const [tweets, followers, following] = await Promise.all([
          getUserTweets(userId, 100),
          sampleFollowers(userId, 50),
          getUserFollowing(userId, 100)
        ]);

        const analysis = await deepXAnalysis(profile, tweets, followers, following);
        const result = formatDeepXResult(analysis);

        // Same buttons as /devcheck
        const buttons = [
          [
            { text: '📊 Social Stats', callback_data: `xsoc:${xUsername}` },
            { text: '🔒 Security', callback_data: `xsec:${xUsername}` }
          ],
          [
            { text: 'ℹ️ Help', callback_data: 'xhelp' },
            { text: '🤖 AI Analysis', callback_data: `ai_x:${xUsername}` }
          ]
        ];

        await sendMessage(chatId, result.text, 'Markdown', { inline_keyboard: buttons });
      } catch (err) {
        await sendMessage(chatId, `\u274C Error: ${err.message}`);
      }
    }
    // Auto-detect URLs/usernames
    else if (text.includes('github.com')) {
      await sendMessage(chatId, `\u{1F4A1} Tip: Use /rugcheck with that URL:\n\n/rugcheck ${text}`);
    }
    else if (text.startsWith('@') || text.match(/^[a-zA-Z_][a-zA-Z0-9_]{0,14}$/)) {
      const handle = text.replace('@', '');
      await sendMessage(chatId, `\u{1F4A1} Want to check this account?\n\n/devcheck @${handle}`);
    }

    return { statusCode: 200, body: 'OK' };

  } catch (error) {
    console.error('Error:', error);
    return { statusCode: 200, body: 'OK' };
  }
}
