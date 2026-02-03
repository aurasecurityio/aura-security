/**
 * x402 API Server
 *
 * HTTP server for x402-enabled endpoints:
 * - POST /v1/rugcheck
 * - POST /v1/scamcheck
 * - POST /v1/xcheck
 * - GET /v1/pricing
 * - GET /v1/payment/:id
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { processPayment, type X402Request } from './middleware.js';
import { getPayment, getPaymentStats } from './payments.js';
import { PRICING } from './pricing.js';
import { performTrustScan } from '../integrations/trust-scanner.js';
import { detectScamPatterns, quickScamScan } from '../integrations/scam-detector.js';
import { performXScan } from '../integrations/x-scanner.js';

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
  const result = await quickScamScan(files, readme);

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
 * Handle /v1/xcheck
 */
async function handleXcheck(body: any): Promise<any> {
  const { username } = body;

  if (!username) {
    throw new Error('Missing required field: username');
  }

  console.log(`[X402] Xcheck: ${username}`);
  const result = await performXScan(username);

  return {
    username,
    score: result.score,
    grade: result.grade,
    verdict: result.verdict,
    verdictEmoji: result.verdictEmoji,
    profile: result.profile,
    followerAnalysis: result.followerAnalysis,
    tweetAnalysis: result.tweetAnalysis,
    redFlags: result.redFlags,
    greenFlags: result.greenFlags,
    scannedAt: result.scannedAt
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

  // Paid endpoints
  const x402Paths = ['/v1/rugcheck', '/v1/scamcheck', '/v1/xcheck'];

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
        case '/v1/xcheck':
          result = await handleXcheck(body);
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
      'POST /v1/xcheck'
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
    console.log(`[X402]   POST /v1/xcheck      - X/Twitter analysis ($0.01)`);
  });
}

// Allow running standalone - check for x402 in path or when run as main module
const isMainModule = process.argv[1]?.includes('x402') ||
                     import.meta.url.includes('x402/server');
if (isMainModule) {
  startX402Server();
}
