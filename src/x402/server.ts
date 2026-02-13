/**
 * x402 API Server
 *
 * HTTP server for x402-enabled endpoints:
 * - POST /v1/rugcheck
 * - POST /v1/scamcheck
 * - POST /v1/fullprobe
 * - POST /v1/attest
 * - GET /v1/pricing
 * - GET /v1/payment/:id
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { processPayment, type X402Request } from './middleware.js';
import { getPayment, getPaymentStats } from './payments.js';
import { PRICING } from './pricing.js';
import { performTrustScan } from '../integrations/trust-scanner.js';
import { quickScamScan } from '../integrations/scam-detector.js';
import { probeWebsite } from '../integrations/website-probe.js';
import { scanAndAttest, scanAndAttestDryRun } from '../erc7710/attestation.js';

const PORT = parseInt(process.env.X402_PORT || '3002', 10);

/**
 * Parse JSON body from request
 */
async function parseBody(req: IncomingMessage): Promise<any> {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => body += chunk);
    req.on('end', () => {
      try {
        resolve(body ? JSON.parse(body) : {});
      } catch {
        resolve({});
      }
    });
    req.on('error', reject);
  });
}

/**
 * Send JSON response
 */
function sendJson(res: ServerResponse, status: number, data: any, headers?: Record<string, string>): void {
  res.writeHead(status, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, X-Payment-Id, X-Payment-Signature',
    ...headers
  });
  res.end(JSON.stringify(data, null, 2));
}

/**
 * Convert IncomingMessage to X402Request
 */
function toX402Request(req: IncomingMessage, body: any): X402Request {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);

  return {
    method: req.method || 'GET',
    url: req.url || '/',
    path: url.pathname,
    headers: {
      'x-payment-id': req.headers['x-payment-id'] as string | undefined,
      'x-payment-signature': req.headers['x-payment-signature'] as string | undefined,
      'content-type': req.headers['content-type'] as string | undefined
    },
    body,
    ip: req.socket.remoteAddress
  };
}

/**
 * Handle /v1/rugcheck
 */
async function handleRugcheck(body: any): Promise<any> {
  const { repo } = body;

  if (!repo) {
    throw new Error('Missing required field: repo');
  }

  console.log(`[X402] Rugcheck: ${repo}`);
  const result = await performTrustScan(repo);

  return {
    repo,
    score: result.trustScore,
    grade: result.grade,
    verdict: result.verdict,
    verdictEmoji: result.verdictEmoji,
    summary: result.summary,
    checks: result.checks,
    metrics: result.metrics,
    scannedAt: result.scannedAt
  };
}

/**
 * Handle /v1/scamcheck
 */
async function handleScamcheck(body: any): Promise<any> {
  const { repo } = body;

  if (!repo) {
    throw new Error('Missing required field: repo');
  }

  console.log(`[X402] Scamcheck: ${repo}`);

  // Parse GitHub URL
  const githubMatch = repo.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  if (!githubMatch) {
    throw new Error('Invalid GitHub URL');
  }

  const owner = githubMatch[1];
  const repoName = githubMatch[2].replace(/\.git$/, '');

  const headers: Record<string, string> = {
    'User-Agent': 'AuraSecurityBot/1.0',
    'Accept': 'application/vnd.github.v3+json'
  };
  if (process.env.GITHUB_TOKEN) {
    headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
  }

  // Fetch repo tree
  const treeRes = await fetch(
    `https://api.github.com/repos/${owner}/${repoName}/git/trees/HEAD?recursive=1`,
    { headers }
  );

  if (!treeRes.ok) {
    throw new Error(`Failed to fetch repository: ${treeRes.status}`);
  }

  const treeData = await treeRes.json();
  const files = treeData.tree?.filter((f: any) => f.type === 'blob').map((f: any) => f.path) || [];

  // Fetch README
  let readme = '';
  const readmeFile = files.find((f: string) => f.toLowerCase().includes('readme'));
  if (readmeFile) {
    try {
      const readmeRes = await fetch(
        `https://api.github.com/repos/${owner}/${repoName}/contents/${readmeFile}`,
        { headers }
      );
      if (readmeRes.ok) {
        const readmeData = await readmeRes.json();
        if (readmeData.content) {
          readme = Buffer.from(readmeData.content, 'base64').toString('utf-8');
        }
      }
    } catch { /* skip */ }
  }

  // Run scam scan
  const result = await quickScamScan(files, readme, undefined, repoName);

  return {
    repo,
    hasRedFlags: result.hasRedFlags,
    riskLevel: result.riskLevel,
    redFlags: result.redFlags,
    filesScanned: files.length,
    scannedAt: new Date().toISOString()
  };
}

/**
 * Handle /v1/fullprobe
 */
async function handleFullprobe(body: any): Promise<any> {
  const { url } = body;

  if (!url) {
    throw new Error('Missing required field: url');
  }

  console.log(`[X402] Full probe: ${url}`);

  // Probe the website
  const probeResult = await probeWebsite(url);

  // Try to find and scan linked GitHub repo
  let repoScan = null;
  const allUrls = [...probeResult.apiCalls.map((a: any) => a.url), url];
  let repoUrl: string | null = null;

  for (const u of allUrls) {
    const githubMatch = u.match(/github\.com\/([^\/]+\/[^\/\s]+)/i);
    if (githubMatch) {
      repoUrl = `https://github.com/${githubMatch[1]}`;
      break;
    }
  }

  if (repoUrl) {
    try {
      repoScan = await performTrustScan(repoUrl);
    } catch { /* skip if repo scan fails */ }
  }

  return {
    url,
    probe: {
      verdict: probeResult.verdict,
      verdictReason: probeResult.verdictReason,
      riskLevel: probeResult.riskLevel,
      hasApiActivity: probeResult.hasApiActivity,
      apiCalls: probeResult.apiCalls.length,
      externalApis: probeResult.externalApis,
      frameworks: probeResult.frameworks,
      hosting: probeResult.hosting,
      loadTime: probeResult.loadTime
    },
    repo: repoScan ? {
      url: repoUrl,
      trustScore: repoScan.trustScore,
      grade: repoScan.grade,
      verdict: repoScan.verdict
    } : null,
    scannedAt: new Date().toISOString()
  };
}

/**
 * Handle /v1/attest — scan + publish EAS attestation on Base
 */
async function handleAttest(body: any): Promise<any> {
  const { target, scanType } = body;

  if (!target) {
    throw new Error('Missing required field: target');
  }

  const validTypes = ['rugcheck', 'scamcheck', 'fullprobe'];
  if (!scanType || !validTypes.includes(scanType)) {
    throw new Error(`Invalid scanType. Must be one of: ${validTypes.join(', ')}`);
  }

  console.log(`[X402] Attest: ${scanType} on ${target}`);
  const result = await scanAndAttest({ target, scanType });

  return {
    attestationUID: result.attestationUID,
    chain: result.chain,
    codeHash: result.attestationData.codeHash,
    reportHash: result.attestationData.reportHash,
    findings: {
      critical: Number(result.attestationData.criticalCount),
      high: Number(result.attestationData.highCount),
      medium: Number(result.attestationData.mediumCount)
    },
    easExplorerUrl: result.easExplorerUrl,
    scanSummary: result.scanSummary,
    scannedAt: new Date().toISOString()
  };
}

/**
 * Handle requests
 */
async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
  const path = url.pathname;
  const method = req.method || 'GET';

  // CORS preflight
  if (method === 'OPTIONS') {
    sendJson(res, 200, { ok: true });
    return;
  }

  // Parse body for POST requests
  const body = method === 'POST' ? await parseBody(req) : {};

  // Public endpoints (no payment required)

  // GET /v1/pricing - Show pricing info
  if (path === '/v1/pricing' && method === 'GET') {
    sendJson(res, 200, {
      endpoints: PRICING,
      payment_methods: ['solana'],
      currency: 'USD'
    });
    return;
  }

  // GET /v1/payment/:id - Check payment status
  if (path.startsWith('/v1/payment/') && method === 'GET') {
    const paymentId = path.split('/').pop();
    const payment = getPayment(paymentId || '');

    if (!payment) {
      sendJson(res, 404, { error: 'Payment not found' });
      return;
    }

    sendJson(res, 200, {
      payment_id: payment.id,
      status: payment.status,
      endpoint: payment.endpoint,
      amount_usd: payment.amount_usd,
      amount_lamports: payment.amount_lamports,
      solana_address: payment.solana_address,
      memo: payment.memo,
      created_at: payment.created_at,
      expires_at: payment.expires_at,
      paid_at: payment.paid_at,
      used_at: payment.used_at
    });
    return;
  }

  // GET /v1/stats - Payment statistics (for admin)
  if (path === '/v1/stats' && method === 'GET') {
    sendJson(res, 200, getPaymentStats());
    return;
  }

  // GET /v1/health - Health check
  if (path === '/v1/health' && method === 'GET') {
    sendJson(res, 200, { status: 'ok', timestamp: new Date().toISOString() });
    return;
  }

  // POST /v1/attest/test - Free dry-run attestation (no payment, no on-chain publish)
  if (path === '/v1/attest/test' && method === 'POST') {
    try {
      const { target, scanType } = body;
      if (!target) {
        sendJson(res, 400, { error: 'Missing required field: target' });
        return;
      }
      const validTypes = ['rugcheck', 'scamcheck', 'fullprobe'];
      if (!scanType || !validTypes.includes(scanType)) {
        sendJson(res, 400, { error: `Invalid scanType. Must be one of: ${validTypes.join(', ')}` });
        return;
      }
      console.log(`[X402] Attest dry-run: ${scanType} on ${target}`);
      const result = await scanAndAttestDryRun({ target, scanType });
      sendJson(res, 200, result);
    } catch (err) {
      console.error(`[X402] Attest dry-run error:`, err);
      sendJson(res, 500, { error: 'Scan failed', message: err instanceof Error ? err.message : 'Unknown error' });
    }
    return;
  }

  // Paid endpoints
  const x402Paths = ['/v1/rugcheck', '/v1/scamcheck', '/v1/fullprobe', '/v1/attest'];

  if (x402Paths.includes(path) && method === 'POST') {
    const x402Req = toX402Request(req, body);

    // Process payment
    const paymentResponse = await processPayment(x402Req);

    if (paymentResponse) {
      sendJson(res, paymentResponse.status, paymentResponse.body, paymentResponse.headers);
      return;
    }

    // Payment valid - execute scan
    try {
      let result;

      switch (path) {
        case '/v1/rugcheck':
          result = await handleRugcheck(body);
          break;
        case '/v1/scamcheck':
          result = await handleScamcheck(body);
          break;
        case '/v1/fullprobe':
          result = await handleFullprobe(body);
          break;
        case '/v1/attest':
          result = await handleAttest(body);
          break;
        default:
          throw new Error('Unknown endpoint');
      }

      sendJson(res, 200, result);
    } catch (err) {
      console.error(`[X402] Handler error:`, err);
      sendJson(res, 500, {
        error: 'Scan failed',
        message: err instanceof Error ? err.message : 'Unknown error'
      });
    }

    return;
  }

  // 404 for unknown routes
  sendJson(res, 404, {
    error: 'Not found',
    message: `Unknown endpoint: ${method} ${path}`,
    available_endpoints: [
      'GET  /v1/pricing',
      'GET  /v1/health',
      'GET  /v1/payment/:id',
      'GET  /v1/stats',
      'POST /v1/rugcheck',
      'POST /v1/scamcheck',
      'POST /v1/fullprobe',
      'POST /v1/attest'
    ]
  });
}

/**
 * Start the x402 API server
 */
export function startX402Server(): void {
  const server = createServer(async (req, res) => {
    try {
      await handleRequest(req, res);
    } catch (err) {
      console.error('[X402] Server error:', err);
      sendJson(res, 500, { error: 'Internal server error' });
    }
  });

  server.listen(PORT, () => {
    console.log(`[X402] API server running on http://127.0.0.1:${PORT}`);
    console.log(`[X402] Endpoints:`);
    console.log(`[X402]   GET  /v1/pricing     - View pricing`);
    console.log(`[X402]   GET  /v1/health      - Health check`);
    console.log(`[X402]   POST /v1/rugcheck    - Trust scan ($0.005)`);
    console.log(`[X402]   POST /v1/scamcheck   - Scam detection ($0.01)`);
    console.log(`[X402]   POST /v1/fullprobe    - Website + repo probe ($0.01)`);
    console.log(`[X402]   POST /v1/attest       - Scan + EAS attestation on Base ($0.02)`);
  });
}

// Allow running standalone - ONLY when invoked directly via `node dist/x402/server.js`
// Do NOT auto-start when imported as a module (import.meta.url check was incorrect)
const isDirectlyInvoked = process.argv[1]?.endsWith('x402/server.js') ||
                          process.argv[1]?.endsWith('x402\\server.js');
if (isDirectlyInvoked) {
  startX402Server();
}
