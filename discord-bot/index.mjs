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
      formattedResponse = formatScanResults(result, repoUrl);
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

  // Handle deferred scan (async invocation from self)
  if (event.type === 'deferred_scan') {
    console.log('Processing deferred scan for:', event.repoUrl);
    const webhookUrl = `https://discord.com/api/v10/webhooks/${event.applicationId}/${event.interactionToken}`;

    try {
      // Do the full vulnerability scan
      const result = await callScannerApi('scan-local', {
        gitUrl: event.repoUrl,
        scanSecrets: true,
        scanPackages: true,
        fastMode: true
      });

      const formattedResponse = formatVulnScanResults(result, event.repoUrl);

      // Send followup message to Discord
      const discordResponse = await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formattedResponse)
      });

      console.log('Followup sent, status:', discordResponse.status);
      return { statusCode: 200, body: 'OK' };

    } catch (error) {
      console.error('Deferred scan error:', error);

      // Send error message
      await fetch(webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ content: `:x: Scan failed: ${error.message}` })
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

      // Handle scan commands
      if (name === 'rugcheck' || name === 'scan' || name === 'devcheck') {
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

        // For /scan (slow), use deferred response pattern
        if (name === 'scan') {
          console.log(`Deferring scan for ${repoUrl}`);

          // Invoke self asynchronously to do the actual work
          const lambdaClient = new LambdaClient({ region: 'us-east-1' });
          await lambdaClient.send(new InvokeCommand({
            FunctionName: 'AuraSecurityDiscordBot',
            InvocationType: 'Event', // Async invocation
            Payload: JSON.stringify({
              type: 'deferred_scan',
              command: name,
              repoUrl: repoUrl,
              applicationId: interaction.application_id,
              interactionToken: interaction.token
            })
          }));

          // Return deferred response immediately
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 5 }) // DEFERRED_CHANNEL_MESSAGE_WITH_SOURCE
          };
        }

        // For quick commands (rugcheck, devcheck), process synchronously
        try {
          console.log(`Processing ${name} for ${repoUrl}`);
          let result;
          let formattedResponse;

          if (name === 'devcheck') {
            result = await callScannerApi('trust-scan', { gitUrl: repoUrl });
            formattedResponse = formatDevCheckResults(result, repoUrl);
          } else {
            result = await callScannerApi('trust-scan', { gitUrl: repoUrl });
            formattedResponse = formatTrustResults(result, repoUrl);
          }

          console.log('Scan complete, returning result');
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ type: 4, data: formattedResponse })
          };
        } catch (error) {
          console.error('Scan error:', error);
          return {
            statusCode: 200,
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
              type: 4,
              data: { content: `:x: Scan failed: ${error.message}` }
            })
          };
        }
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
