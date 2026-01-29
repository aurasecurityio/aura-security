/**
 * AuraSecurity Discord Bot - Lambda Handler
 *
 * Security Features:
 * - Ed25519 signature verification (required by Discord)
 * - AWS Secrets Manager for token storage
 * - Input validation and sanitization
 * - Rate limiting via Discord's built-in system
 */

import { SecretsManagerClient, GetSecretValueCommand } from '@aws-sdk/client-secrets-manager';
import { LambdaClient, InvokeCommand } from '@aws-sdk/client-lambda';
import crypto from 'crypto';

// Cache secrets to avoid repeated API calls
let cachedSecrets = null;

// Scanner API endpoint
const SCANNER_API = process.env.SCANNER_API_URL || 'https://app.aurasecurity.io';

/**
 * Get Discord credentials from Secrets Manager
 */
async function getSecrets() {
  if (cachedSecrets) return cachedSecrets;

  const client = new SecretsManagerClient({ region: 'us-east-1' });
  const response = await client.send(new GetSecretValueCommand({
    SecretId: 'aura/discord-bot'
  }));

  cachedSecrets = JSON.parse(response.SecretString);
  return cachedSecrets;
}

/**
 * Verify Discord signature using Ed25519
 * This is REQUIRED by Discord for all interactions
 */
function verifyDiscordSignature(publicKey, signature, timestamp, body) {
  try {
    // Discord uses Ed25519 signatures
    const message = Buffer.from(timestamp + body);
    const sig = Buffer.from(signature, 'hex');
    const key = Buffer.from(publicKey, 'hex');

    // Use Node.js crypto for Ed25519 verification
    return crypto.verify(null, message, { key, format: 'der', type: 'spki' }, sig);
  } catch (error) {
    // Fallback: manual verification using tweetnacl-compatible approach
    return verifyEd25519Manual(publicKey, signature, timestamp, body);
  }
}

/**
 * Manual Ed25519 verification (tweetnacl-compatible)
 */
function verifyEd25519Manual(publicKeyHex, signatureHex, timestamp, body) {
  try {
    const message = timestamp + body;

    // Convert hex strings to Uint8Arrays
    const publicKey = hexToUint8Array(publicKeyHex);
    const signature = hexToUint8Array(signatureHex);
    const messageBytes = new TextEncoder().encode(message);

    // Use SubtleCrypto for Ed25519 verification
    // Note: This requires Node.js 18+ with experimental flag or use nacl library
    // For Lambda, we'll use a simplified check and rely on Discord's retry mechanism

    // Basic length checks
    if (publicKey.length !== 32) return false;
    if (signature.length !== 64) return false;

    // For production, we need tweetnacl or noble-ed25519
    // Since we can't add deps in Lambda easily, use crypto.verify with proper key format
    const keyObject = crypto.createPublicKey({
      key: Buffer.concat([
        // Ed25519 public key DER header
        Buffer.from('302a300506032b6570032100', 'hex'),
        Buffer.from(publicKey)
      ]),
      format: 'der',
      type: 'spki'
    });

    return crypto.verify(null, Buffer.from(messageBytes), keyObject, Buffer.from(signature));
  } catch (error) {
    console.error('Ed25519 verification error:', error.message);
    return false;
  }
}

function hexToUint8Array(hex) {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
  }
  return bytes;
}

/**
 * Validate GitHub URL to prevent injection
 */
function isValidGitUrl(url) {
  if (!url || typeof url !== 'string') return false;

  // Check for dangerous characters
  if (/[;&|`$(){}[\]<>\s]/.test(url)) return false;

  // Must be a valid GitHub URL
  const githubPattern = /^https:\/\/github\.com\/[\w\-\.]+\/[\w\-\.]+(?:\.git)?$/i;
  return githubPattern.test(url);
}

/**
 * Extract owner/repo from GitHub URL
 */
function parseGitHubUrl(url) {
  const match = url.match(/github\.com\/([\w\-\.]+)\/([\w\-\.]+)/i);
  if (!match) return null;
  return { owner: match[1], repo: match[2].replace(/\.git$/, '') };
}

/**
 * Call the scanner API
 */
async function callScannerApi(tool, args) {
  try {
    console.log(`Calling API: ${tool} with args:`, JSON.stringify(args));
    const response = await fetch(`${SCANNER_API}/tools`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ tool, arguments: args })
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Scanner API error: ${response.status} - ${text}`);
    }

    const data = await response.json();
    console.log('API response received');
    return data.result || data;
  } catch (error) {
    console.error('Scanner API error:', error);
    throw error;
  }
}

/**
 * Format trust/rugcheck results for Discord
 */
function formatTrustResults(result, repoUrl) {
  const repoName = result.repoName ? `${result.owner}/${result.repoName}` : repoUrl;

  // Use verdict from API
  let riskColor = 0x00ff00; // Green default
  if (result.verdict === 'SCAM' || result.trustScore < 30) {
    riskColor = 0xff0000; // Red
  } else if (result.verdict === 'SUSPICIOUS' || result.trustScore < 50) {
    riskColor = 0xff8c00; // Orange
  } else if (result.verdict === 'CAUTION' || result.trustScore < 70) {
    riskColor = 0xffff00; // Yellow
  }

  // Build checks summary (top 5)
  const checksText = (result.checks || [])
    .slice(0, 5)
    .map(c => `${c.status === 'good' ? '✅' : c.status === 'warning' ? '⚠️' : c.status === 'danger' ? '❌' : 'ℹ️'} ${c.name}`)
    .join('\n') || 'No checks available';

  return {
    embeds: [{
      title: `${result.verdictEmoji || '🔍'} ${result.verdict || 'SCAN'}: ${repoName}`,
      description: result.summary || 'Trust analysis complete.',
      color: riskColor,
      fields: [
        {
          name: 'Trust Score',
          value: `**${result.trustScore || 0}/100** (${result.grade || 'N/A'})`,
          inline: true
        },
        {
          name: 'Verdict',
          value: result.verdict || 'Unknown',
          inline: true
        },
        {
          name: 'Checks',
          value: checksText,
          inline: false
        }
      ],
      footer: {
        text: 'AuraSecurity | Rug Check'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format vulnerability scan results for Discord
 */
function formatVulnScanResults(result, repoUrl) {
  const scanDetails = result.scan_details || {};
  const parsed = parseGitHubUrl(repoUrl);
  const repoName = parsed ? `${parsed.owner}/${parsed.repo}` : repoUrl;

  // Check if the scan itself failed (e.g., clone error, invalid URL)
  if (result.scan_failed || result.error || scanDetails.error) {
    const errorMsg = result.error || scanDetails.error || 'Scan failed';
    return {
      embeds: [{
        title: `❌ Scan Failed — ${repoName}`,
        description: errorMsg,
        color: 0xff0000,
        footer: { text: 'AuraSecurity | Vulnerability Scan' },
        timestamp: new Date().toISOString()
      }]
    };
  }

  // Count vulnerabilities from events
  let criticalCount = 0;
  let highCount = 0;
  let secretsCount = scanDetails.secrets_found || 0;
  let pkgVulns = scanDetails.package_vulns || 0;

  // Parse events for severity counts
  (result.events || []).forEach(e => {
    if (e.event_type === 'finding_raised') {
      const claim = e.payload?.claim || '';
      const match = claim.match(/(\d+) critical and (\d+) high/i);
      if (match) {
        criticalCount = parseInt(match[1]) || 0;
        highCount = parseInt(match[2]) || 0;
      }
    }
  });

  // Determine risk level
  let riskLevel = 'LOW';
  let riskEmoji = '🟢';
  let riskColor = 0x00ff00;

  if (criticalCount > 0 || secretsCount > 0) {
    riskLevel = 'CRITICAL';
    riskEmoji = '🔴';
    riskColor = 0xff0000;
  } else if (highCount > 0 || pkgVulns > 50) {
    riskLevel = 'HIGH';
    riskEmoji = '🟠';
    riskColor = 0xff8c00;
  } else if (pkgVulns > 10) {
    riskLevel = 'MEDIUM';
    riskEmoji = '🟡';
    riskColor = 0xffff00;
  }

  // Build findings summary
  const findings = [];
  if (secretsCount > 0) findings.push(`🔑 **${secretsCount}** secrets exposed`);
  if (criticalCount > 0) findings.push(`🔴 **${criticalCount}** critical vulnerabilities`);
  if (highCount > 0) findings.push(`🟠 **${highCount}** high vulnerabilities`);
  if (pkgVulns > 0) findings.push(`📦 **${pkgVulns}** vulnerable packages`);
  if (scanDetails.dockerfile_findings > 0) findings.push(`🐳 **${scanDetails.dockerfile_findings}** Dockerfile issues`);

  const findingsText = findings.length > 0 ? findings.join('\n') : '✅ No major issues found';

  return {
    embeds: [{
      title: `${riskEmoji} Security Scan: ${repoName}`,
      description: `Full vulnerability analysis complete.`,
      color: riskColor,
      fields: [
        {
          name: 'Risk Level',
          value: `**${riskLevel}**`,
          inline: true
        },
        {
          name: 'Packages Scanned',
          value: `${scanDetails.packages_scanned || 0}`,
          inline: true
        },
        {
          name: 'Findings',
          value: findingsText,
          inline: false
        }
      ],
      footer: {
        text: 'AuraSecurity | Vulnerability Scan'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format dev check results
 */
function formatDevCheckResults(result, repoUrl) {
  const repoName = result.repoName ? `${result.owner}/${result.repoName}` : repoUrl;

  let trustColor = 0x00ff00;
  if (result.trustScore < 50) {
    trustColor = 0xff0000;
  } else if (result.trustScore < 70) {
    trustColor = 0xffff00;
  }

  // Extract developer-related checks
  const devChecks = (result.checks || [])
    .filter(c => ['repo_age', 'commits', 'contributors', 'stars'].includes(c.id))
    .map(c => `${c.status === 'good' ? '✅' : c.status === 'warning' ? '⚠️' : '❌'} **${c.name}**: ${c.explanation}`)
    .join('\n') || 'No developer info available';

  return {
    embeds: [{
      title: `${result.verdictEmoji || '👤'} Developer Check: ${result.owner || 'Unknown'}`,
      description: result.summary || 'Developer analysis complete.',
      color: trustColor,
      fields: [
        {
          name: 'Trust Score',
          value: `**${result.trustScore || 0}/100** (${result.grade || 'N/A'})`,
          inline: true
        },
        {
          name: 'Verdict',
          value: result.verdict || 'Unknown',
          inline: true
        },
        {
          name: 'Repository',
          value: repoName,
          inline: true
        },
        {
          name: 'Developer Analysis',
          value: devChecks,
          inline: false
        }
      ],
      footer: {
        text: 'AuraSecurity | Developer Trust Analysis'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format X/Twitter scan results for Discord
 */
function formatXCheckResults(result) {
  const profile = result.profile || {};

  let trustColor = 0x00ff00;
  if (result.score < 40) {
    trustColor = 0xff0000;
  } else if (result.score < 65) {
    trustColor = 0xffff00;
  }

  // Format flags
  const greenFlags = (result.greenFlags || []).slice(0, 4).map(f => `✅ ${f}`).join('\n') || 'None';
  const redFlags = (result.redFlags || []).slice(0, 4).map(f => `❌ ${f}`).join('\n') || 'None';

  return {
    embeds: [{
      title: `${result.verdictEmoji || '🔍'} ${result.verdict || 'ANALYSIS'}: @${profile.username || 'Unknown'}`,
      description: profile.bio ? `*"${profile.bio.slice(0, 200)}${profile.bio.length > 200 ? '...' : ''}"*` : 'No bio',
      color: trustColor,
      thumbnail: profile.profileImage ? { url: profile.profileImage } : undefined,
      fields: [
        {
          name: 'Trust Score',
          value: `**${result.score || 0}/100** (${result.grade || 'N/A'})`,
          inline: true
        },
        {
          name: 'Followers',
          value: `${profile.followers?.toLocaleString() || 0}`,
          inline: true
        },
        {
          name: 'Account Age',
          value: profile.createdAt ? `${Math.floor((Date.now() - new Date(profile.createdAt).getTime()) / (1000*60*60*24*365))} years` : 'Unknown',
          inline: true
        },
        {
          name: 'Follower Quality',
          value: result.followerAnalysis?.analysis
            ? `${result.followerAnalysis.realPercent}% real, ${result.followerAnalysis.botPercent}% bots`
            : (result.profile?.followers > 1000000 ? 'Sample too small for mega account' : 'Could not analyze'),
          inline: true
        },
        {
          name: 'GitHub Verified',
          value: result.githubVerified ? '✅ Yes' : '❌ No',
          inline: true
        },
        {
          name: 'Green Flags',
          value: greenFlags,
          inline: false
        },
        {
          name: 'Red Flags',
          value: redFlags,
          inline: false
        }
      ],
      footer: {
        text: 'AuraSecurity | X Profile Analysis'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format AI verification results for Discord
 */
function formatAICheckResults(result) {
  // Handle NOT APPLICABLE case - simplified output
  if (result.verdict === 'NOT APPLICABLE') {
    return {
      embeds: [{
        title: `➖ ${result.repoName || 'Unknown'}`,
        description: result.summary || 'This is a software project, not an AI/ML project.',
        color: 0x808080,  // Gray - neutral
        fields: [
          {
            name: 'AI Check',
            value: 'Not applicable - this project is not an AI/ML project',
            inline: false
          },
          {
            name: 'Tip',
            value: 'Use `/aicheck` on projects that claim to be AI-powered to verify if they have real AI code.',
            inline: false
          }
        ],
        footer: {
          text: 'AuraSecurity | AI Project Verifier'
        },
        timestamp: new Date().toISOString()
      }]
    };
  }

  // For AI projects (real, hype, wrapper, or uncertain)
  let color = 0x00ff00;  // Green for REAL AI
  if (result.verdict === 'HYPE ONLY') {
    color = 0xff6600;  // Orange for HYPE
  } else if (result.verdict === 'WRAPPER') {
    color = 0x9966ff;  // Purple for WRAPPER
  } else if (result.verdict === 'UNCERTAIN') {
    color = 0xffff00;  // Yellow for UNCERTAIN
  } else if (result.verdict === 'LIKELY REAL') {
    color = 0x00cc00;  // Light green
  }

  const evidence = result.evidence || {};
  const wrapperAnalysis = result.wrapperAnalysis || {};
  const libs = (evidence.aiLibraries || []).slice(0, 5).join(', ') || 'None found';
  const greenFlags = (result.greenFlags || []).slice(0, 4).map(f => `✅ ${f}`).join('\n') || 'None';
  const redFlags = (result.redFlags || []).slice(0, 4).map(f => `❌ ${f}`).join('\n') || 'None';

  // Build wrapper analysis display
  let wrapperDisplay = '';
  if (wrapperAnalysis.analysis) {
    wrapperDisplay = wrapperAnalysis.analysis;
    if (wrapperAnalysis.realImplementationPatterns > 0) {
      wrapperDisplay += `\n🧠 ${wrapperAnalysis.realImplementationPatterns} real ML patterns`;
    }
    if (wrapperAnalysis.apiWrapperPatterns > 0) {
      wrapperDisplay += `\n📦 ${wrapperAnalysis.apiWrapperPatterns} API wrapper patterns`;
    }
    if (wrapperAnalysis.valueAddPatterns > 0) {
      wrapperDisplay += `\n✨ ${wrapperAnalysis.valueAddPatterns} value-add patterns`;
    }
  }

  const fields = [
    {
      name: 'AI Score',
      value: `**${result.aiScore}/100**`,
      inline: true
    },
    {
      name: 'Real AI Project?',
      value: result.isRealAI ? '✅ Yes' : (result.verdict === 'WRAPPER' ? '📦 Wrapper' : '❌ No'),
      inline: true
    },
    {
      name: 'AI Libraries Found',
      value: libs,
      inline: false
    }
  ];

  // Add wrapper analysis if available
  if (wrapperDisplay) {
    fields.push({
      name: 'Wrapper Analysis',
      value: wrapperDisplay,
      inline: false
    });
  }

  fields.push({
    name: 'Evidence',
    value: [
      evidence.modelFiles?.length > 0 ? `📦 ${evidence.modelFiles.length} model files` : null,
      evidence.aiCodeFiles?.length > 0 ? `💻 ${evidence.aiCodeFiles.length} AI code files` : null,
      evidence.trainingScripts ? '🏋️ Training scripts' : null,
      evidence.inferenceCode ? '🎯 Inference code' : null,
      evidence.hasNotebook ? '📓 Jupyter notebooks' : null
    ].filter(Boolean).join('\n') || 'No AI evidence found',
    inline: false
  });

  fields.push({
    name: 'Green Flags',
    value: greenFlags,
    inline: true
  });

  fields.push({
    name: 'Red Flags',
    value: redFlags,
    inline: true
  });

  return {
    embeds: [{
      title: `${result.verdictEmoji || '🤖'} ${result.verdict || 'ANALYSIS'}: ${result.repoName || 'Unknown'}`,
      description: result.summary || 'AI verification complete.',
      color: color,
      fields: fields,
      footer: {
        text: 'AuraSecurity | AI Project Verifier'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format scam check results for Discord
 */
function formatScamCheckResults(result) {
  // Handle rate limit / unavailable state
  if (result.trustUnavailable && result.score === null) {
    const repoDisplay = result.owner ? `${result.owner}/${result.repoName}` : (result.repoName || 'Unknown');
    return {
      embeds: [{
        title: `⏳ Rate Limited — ${repoDisplay}`,
        description: result.analysis || 'GitHub API rate limit reached. Try again in a few minutes.',
        color: 0x808080,
        footer: { text: 'AuraSecurity | Project Check' },
        timestamp: new Date().toISOString()
      }]
    };
  }

  // Use unified fields if available, fallback to legacy
  const hasUnified = result.score !== undefined && result.verdict;

  if (hasUnified) {
    // === UNIFIED CARD ===
    const colors = {
      'SAFU': 0x00ff00,
      'DYOR': 0xffff00,
      'RISKY': 0xff8c00,
      'RUG ALERT': 0xff0000
    };

    const tagsText = (result.tags || []).map(t => `\`${t}\``).join(' ');
    const repoDisplay = result.owner ? `${result.owner}/${result.repoName}` : (result.repoName || 'Unknown');

    // Code safety line
    const codeStatus = result.codeSafety?.status || 'UNKNOWN';
    const codeEmoji = codeStatus === 'CLEAN' ? '✅' : codeStatus === 'WARNING' ? '🟡' : '🚨';
    const codeLine = `${codeEmoji} ${result.codeSafety?.summary || 'N/A'}`;

    // Trust line
    const trustStatus = result.projectTrust?.status || 'UNKNOWN';
    const trustEmoji = trustStatus === 'SAFU' ? '✅' : trustStatus === 'DYOR' ? '🟡' : '🟠';
    const trustLine = `${trustEmoji} ${trustStatus} (${result.projectTrust?.trustScore || 0}/100)`;

    // Secrets line
    const secretsEmoji = result.secretsScan?.status === 'CLEAN' ? '✅' : '🚨';
    const secretsLine = result.secretsScan?.status === 'CLEAN' ? `${secretsEmoji} None found` : `${secretsEmoji} ${result.secretsScan?.count || 0} leaked`;

    const fields = [
      { name: 'Code Safety', value: codeLine, inline: false },
      { name: 'Project Trust', value: trustLine, inline: true },
      { name: 'Secrets', value: secretsLine, inline: true }
    ];

    // Red flags
    const redFlags = (result.redFlags || []).slice(0, 5);
    if (redFlags.length > 0) {
      fields.push({
        name: '⚠ Red Flags',
        value: redFlags.map(f => `• ${f}`).join('\n'),
        inline: false
      });
    }

    // Green flags
    const greenFlags = (result.greenFlags || []).slice(0, 5);
    if (greenFlags.length > 0) {
      fields.push({
        name: '✅ Green Flags',
        value: greenFlags.map(f => `• ${f}`).join('\n'),
        inline: false
      });
    }

    // Analysis
    if (result.analysis) {
      fields.push({
        name: '💬 Analysis',
        value: result.analysis.slice(0, 1024),
        inline: false
      });
    }

    return {
      embeds: [{
        title: `${result.verdictEmoji || '🔍'} ${result.verdict} — ${repoDisplay}`,
        description: `**Score: ${result.score}/100**\n${tagsText}`,
        color: colors[result.verdict] || 0x808080,
        fields: fields,
        footer: { text: 'AuraSecurity | Project Check' },
        timestamp: new Date().toISOString()
      }]
    };
  }

  // === LEGACY FALLBACK (if unified fields missing) ===
  let color = 0x00ff00;
  let emoji = '✅';

  if (result.riskLevel === 'critical' || result.isLikelyScam) {
    color = 0xff0000; emoji = '🚨';
  } else if (result.riskLevel === 'high') {
    color = 0xff6600; emoji = '⚠️';
  } else if (result.riskLevel === 'medium') {
    color = 0xffff00; emoji = '🟡';
  }

  const redFlags = (result.redFlags || []).slice(0, 5).map(f => `❌ ${f}`).join('\n') || 'None detected';
  let matchesText = 'None detected';
  if (result.matches && result.matches.length > 0) {
    matchesText = result.matches.slice(0, 3).map(m =>
      `**${m.signatureName}** (${m.severity})\n${m.description}`
    ).join('\n\n');
  }

  const fields = [
    { name: 'Scam Score', value: `**${result.scamScore}/100**`, inline: true },
    { name: 'Risk Level', value: `**${(result.riskLevel || 'unknown').toUpperCase()}**`, inline: true },
    { name: 'Likely Scam?', value: result.isLikelyScam ? '🚨 YES' : '✅ NO', inline: true },
    { name: 'Red Flags', value: redFlags, inline: false }
  ];

  if (result.matches && result.matches.length > 0) {
    fields.push({ name: 'Known Scam Patterns Matched', value: matchesText, inline: false });
  }

  return {
    embeds: [{
      title: `${emoji} Scam Check: ${result.repoName || 'Unknown'}`,
      description: result.summary || 'Scam pattern analysis complete.',
      color: color,
      fields: fields,
      footer: { text: 'AuraSecurity | Scam Pattern Detection' },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Format compare results for Discord
 */
function formatCompareResults(result) {
  const r1 = result.repo1 || {};
  const r2 = result.repo2 || {};

  let winnerText = '🤝 **TIE** - Both projects scored the same';
  if (result.winner === 1) {
    winnerText = `🏆 **${r1.name}** is the safer choice`;
  } else if (result.winner === 2) {
    winnerText = `🏆 **${r2.name}** is the safer choice`;
  }

  return {
    embeds: [{
      title: '⚔️ Project Comparison',
      description: winnerText,
      color: 0x5865F2,
      fields: [
        {
          name: `${r1.verdictEmoji || '📊'} ${r1.name || 'Repo 1'}`,
          value: `Score: **${r1.score || 0}/100** (${r1.grade || 'N/A'})\nVerdict: ${r1.verdict || 'Unknown'}`,
          inline: true
        },
        {
          name: `${r2.verdictEmoji || '📊'} ${r2.name || 'Repo 2'}`,
          value: `Score: **${r2.score || 0}/100** (${r2.grade || 'N/A'})\nVerdict: ${r2.verdict || 'Unknown'}`,
          inline: true
        },
        {
          name: 'Summary - Repo 1',
          value: r1.summary?.slice(0, 200) || 'No summary',
          inline: false
        },
        {
          name: 'Summary - Repo 2',
          value: r2.summary?.slice(0, 200) || 'No summary',
          inline: false
        }
      ],
      footer: {
        text: 'AuraSecurity | Project Comparison'
      },
      timestamp: new Date().toISOString()
    }]
  };
}

/**
 * Handle slash commands
 */
async function handleSlashCommand(interaction) {
  const { name, options } = interaction.data;

  switch (name) {
    case 'rugcheck':
    case 'scan': {
      const repoUrl = options?.find(o => o.name === 'repo')?.value;

      if (!repoUrl) {
        return {
          type: 4, // CHANNEL_MESSAGE_WITH_SOURCE
          data: {
            content: ':x: Please provide a GitHub repository URL.',
            flags: 64 // Ephemeral
          }
        };
      }

      if (!isValidGitUrl(repoUrl)) {
        return {
          type: 4,
          data: {
            content: ':x: Invalid GitHub URL. Please provide a valid repository URL (e.g., https://github.com/owner/repo)',
            flags: 64
          }
        };
      }

      // Acknowledge the command (deferred response)
      // We'll send the actual response via webhook followup
      return {
        type: 5, // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
        data: {
          content: ':hourglass: Scanning repository...'
        }
      };
    }

    case 'devcheck': {
      const repoUrl = options?.find(o => o.name === 'repo')?.value;

      if (!repoUrl) {
        return {
          type: 4,
          data: {
            content: ':x: Please provide a GitHub repository URL.',
            flags: 64
          }
        };
      }

      if (!isValidGitUrl(repoUrl)) {
        return {
          type: 4,
          data: {
            content: ':x: Invalid GitHub URL.',
            flags: 64
          }
        };
      }

      return {
        type: 5,
        data: {
          content: ':hourglass: Checking developer...'
        }
      };
    }

    case 'help': {
      return {
        type: 4,
        data: {
          embeds: [{
            title: ':shield: AuraSecurity Bot Commands',
            color: 0x5865F2, // Discord blurple
            fields: [
              {
                name: '/rugcheck <repo>',
                value: 'Quick security scan - checks for common red flags, secrets, and vulnerabilities.',
                inline: false
              },
              {
                name: '/scan <repo>',
                value: 'Full security audit - deep analysis of code, dependencies, and security issues.',
                inline: false
              },
              {
                name: '/devcheck <repo>',
                value: 'Developer trust analysis - checks account age, activity, and reputation.',
                inline: false
              },
              {
                name: '/xcheck <username>',
                value: 'X/Twitter profile analysis - bot detection, follower quality, GitHub verification.',
                inline: false
              },
              {
                name: '/aicheck <repo>',
                value: 'AI project verifier - checks if repo has real AI code or is just hype.',
                inline: false
              },
              {
                name: '/scamcheck <repo>',
                value: 'Scam detector - checks for known rug pull patterns, honeypots, and wallet drainers.',
                inline: false
              },
              {
                name: '/compare <repo1> <repo2>',
                value: 'Compare two projects side-by-side - which one to ape?',
                inline: false
              },
              {
                name: '/help',
                value: 'Show this help message.',
                inline: false
              }
            ],
            footer: {
              text: 'AuraSecurity | Protecting the crypto community'
            }
          }]
        }
      };
    }

    default:
      return {
        type: 4,
        data: {
          content: ':x: Unknown command.',
          flags: 64
        }
      };
  }
}

/**
 * Process deferred responses (for scan operations)
 */
async function processDeferredResponse(interaction, secrets) {
  const { name, options } = interaction.data;
  const repoUrl = options?.find(o => o.name === 'repo')?.value;
  const applicationId = interaction.application_id;
  const interactionToken = interaction.token;

  // Webhook URL for followup messages
  const webhookUrl = `https://discord.com/api/v10/webhooks/${applicationId}/${interactionToken}`;

  try {
    let result;
    let formattedResponse;

    if (name === 'rugcheck' || name === 'scan') {
      // Call scanner API
      result = await callScannerApi('/scan', {
        gitUrl: repoUrl,
        fastMode: name === 'rugcheck'
      });
      formattedResponse = formatVulnScanResults(result, repoUrl);
    } else if (name === 'devcheck') {
      result = await callScannerApi('/trust', { gitUrl: repoUrl });
      formattedResponse = formatDevCheckResults(result, repoUrl);
    }

    // Send followup message
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(formattedResponse)
    });
  } catch (error) {
    console.error('Deferred response error:', error);

    // Send error message
    await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        content: `:x: Scan failed: ${error.message}`
      })
    });
  }
}

/**
 * Lambda Handler
 */
export const handler = async (event) => {
  console.log('Lambda invoked:', event.type || 'discord_interaction');

  // Handle deferred command (async invocation from self)
  if (event.type === 'deferred_command') {
    console.log(`Processing deferred ${event.command} for:`, event.repoUrl);
    const webhookUrl = `https://discord.com/api/v10/webhooks/${event.applicationId}/${event.interactionToken}`;

    try {
      let result;
      let formattedResponse;

      if (event.command === 'scan') {
        // Full vulnerability scan
        result = await callScannerApi('scan-local', {
          gitUrl: event.repoUrl,
          scanSecrets: true,
          scanPackages: true,
          fastMode: true
        });
        formattedResponse = formatVulnScanResults(result, event.repoUrl);
      } else if (event.command === 'devcheck') {
        // Developer trust check
        result = await callScannerApi('trust-scan', { gitUrl: event.repoUrl });
        formattedResponse = formatDevCheckResults(result, event.repoUrl);
      } else if (event.command === 'xcheck') {
        // X/Twitter profile check
        result = await callScannerApi('x-scan', { username: event.username });
        formattedResponse = formatXCheckResults(result);
      } else if (event.command === 'aicheck') {
        // AI project verification
        result = await callScannerApi('ai-check', { gitUrl: event.repoUrl });
        formattedResponse = formatAICheckResults(result);
      } else if (event.command === 'scamcheck') {
        // Scam pattern detection
        result = await callScannerApi('scam-scan', { gitUrl: event.repoUrl });
        formattedResponse = formatScamCheckResults(result);
      } else if (event.command === 'compare') {
        // Compare two repos
        result = await callScannerApi('compare', { repo1: event.repo1, repo2: event.repo2 });
        formattedResponse = formatCompareResults(result);
      } else {
        // rugcheck - quick trust scan
        result = await callScannerApi('trust-scan', { gitUrl: event.repoUrl });
        formattedResponse = formatTrustResults(result, event.repoUrl);
      }

      // Send followup message to Discord
      const discordResponse = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formattedResponse)
      });

      console.log('Followup sent, status:', discordResponse.status);
      return { statusCode: 200, body: 'OK' };

    } catch (error) {
      console.error('Deferred command error:', error);

      // Send error message
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: `:x: ${event.command} failed: ${error.message}` })
      });

      return { statusCode: 200, body: 'Error handled' };
    }
  }

  // Handle Discord interaction
  try {
    // Get secrets
    const secrets = await getSecrets();

    // Parse request body
    const body = event.body;
    const signature = event.headers['x-signature-ed25519'];
    const timestamp = event.headers['x-signature-timestamp'];

    // Verify Discord signature (REQUIRED)
    if (!signature || !timestamp) {
      console.error('Missing signature headers');
      return {
        statusCode: 401,
        body: JSON.stringify({ error: 'Missing signature' })
      };
    }

    const isValid = verifyEd25519Manual(secrets.public_key, signature, timestamp, body);

    if (!isValid) {
      console.error('Invalid signature');
      return {
        statusCode: 401,
        body: JSON.stringify({ error: 'Invalid signature' })
      };
    }

    // Parse interaction
    const interaction = JSON.parse(body);

    // Handle PING (Discord verification)
    if (interaction.type === 1) {
      console.log('Responding to Discord PING');
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: 1 }) // PONG
      };
    }

    // Handle APPLICATION_COMMAND (slash commands)
    if (interaction.type === 2) {
      const { name, options } = interaction.data;

      // Handle repo-based scan commands
      if (name === 'rugcheck' || name === 'scan' || name === 'devcheck' || name === 'aicheck' || name === 'scamcheck') {
        const repoUrl = options?.find(o => o.name === 'repo')?.value;

        if (!repoUrl) {
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: ':x: Please provide a GitHub repository URL.', flags: 64 }
            })
          };
        }

        if (!isValidGitUrl(repoUrl)) {
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: ':x: Invalid GitHub URL. Use format: https://github.com/owner/repo', flags: 64 }
            })
          };
        }

        // Use deferred response for ALL scan commands to avoid 3-second timeout
        console.log(`Deferring ${name} for ${repoUrl}`);

        // Invoke self asynchronously to do the actual work
        const lambdaClient = new LambdaClient({ region: 'us-east-1' });
        await lambdaClient.send(new InvokeCommand({
          FunctionName: 'AuraSecurityDiscordBot',
          InvocationType: 'Event', // Async invocation
          Payload: JSON.stringify({
            type: 'deferred_command',
            command: name,
            repoUrl: repoUrl,
            applicationId: interaction.application_id,
            interactionToken: interaction.token
          })
        }));

        // Return deferred response immediately (within 3 seconds)
        return {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 5 }) // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
        };
      }

      // Handle X/Twitter check command
      if (name === 'xcheck') {
        const username = options?.find(o => o.name === 'username')?.value;

        if (!username) {
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: ':x: Please provide an X/Twitter username.', flags: 64 }
            })
          };
        }

        console.log(`Deferring xcheck for ${username}`);

        const lambdaClient = new LambdaClient({ region: 'us-east-1' });
        await lambdaClient.send(new InvokeCommand({
          FunctionName: 'AuraSecurityDiscordBot',
          InvocationType: 'Event',
          Payload: JSON.stringify({
            type: 'deferred_command',
            command: 'xcheck',
            username: username,
            applicationId: interaction.application_id,
            interactionToken: interaction.token
          })
        }));

        return {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 5 })
        };
      }

      // Handle compare command
      if (name === 'compare') {
        const repo1 = options?.find(o => o.name === 'repo1')?.value;
        const repo2 = options?.find(o => o.name === 'repo2')?.value;

        if (!repo1 || !repo2) {
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: ':x: Please provide two GitHub repository URLs.', flags: 64 }
            })
          };
        }

        if (!isValidGitUrl(repo1) || !isValidGitUrl(repo2)) {
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: ':x: Invalid GitHub URL(s). Use format: https://github.com/owner/repo', flags: 64 }
            })
          };
        }

        console.log(`Deferring compare: ${repo1} vs ${repo2}`);

        const lambdaClient = new LambdaClient({ region: 'us-east-1' });
        await lambdaClient.send(new InvokeCommand({
          FunctionName: 'AuraSecurityDiscordBot',
          InvocationType: 'Event',
          Payload: JSON.stringify({
            type: 'deferred_command',
            command: 'compare',
            repo1: repo1,
            repo2: repo2,
            applicationId: interaction.application_id,
            interactionToken: interaction.token
          })
        }));

        return {
          statusCode: 200,
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ type: 5 })
        };
      }

      // For other commands (like /help), handle normally
      const response = await handleSlashCommand(interaction);
      return {
        statusCode: 200,
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(response)
      };
    }

    // Unknown interaction type
    return {
      statusCode: 400,
      body: JSON.stringify({ error: 'Unknown interaction type' })
    };

  } catch (error) {
    console.error('Handler error:', error);
    return {
      statusCode: 500,
      body: JSON.stringify({ error: 'Internal server error' })
    };
  }
};
