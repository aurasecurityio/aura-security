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

const ATTEST_DEMO_HTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Aura Security — ERC-7710 Attestation Demo</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace; background: #0a0a0f; color: #e0e0e0; min-height: 100vh; }
  .container { max-width: 860px; margin: 0 auto; padding: 40px 24px; }
  h1 { font-size: 20px; color: #00ffaa; margin-bottom: 4px; letter-spacing: 1px; }
  .subtitle { color: #666; font-size: 13px; margin-bottom: 32px; }
  .subtitle a { color: #4a9eff; text-decoration: none; }
  .input-row { display: flex; gap: 10px; margin-bottom: 16px; }
  input[type="text"] { flex: 1; background: #111118; border: 1px solid #2a2a3a; color: #e0e0e0; padding: 12px 16px; border-radius: 6px; font-family: inherit; font-size: 14px; outline: none; }
  input[type="text"]:focus { border-color: #00ffaa; }
  input[type="text"]::placeholder { color: #444; }
  select { background: #111118; border: 1px solid #2a2a3a; color: #e0e0e0; padding: 12px 16px; border-radius: 6px; font-family: inherit; font-size: 14px; outline: none; cursor: pointer; min-width: 150px; }
  select:focus { border-color: #00ffaa; }
  button { background: #00ffaa; color: #0a0a0f; border: none; padding: 12px 28px; border-radius: 6px; font-family: inherit; font-size: 14px; font-weight: 700; cursor: pointer; letter-spacing: 0.5px; transition: all 0.2s; }
  button:hover { background: #00dd88; }
  button:disabled { background: #333; color: #666; cursor: not-allowed; }
  .status { margin: 20px 0; padding: 16px; border-radius: 6px; font-size: 13px; display: none; }
  .status.loading { display: block; background: #111128; border: 1px solid #2a2a4a; color: #8888ff; }
  .status.error { display: block; background: #1a1118; border: 1px solid #4a2a2a; color: #ff6666; }
  .result { display: none; margin-top: 24px; }
  .result.show { display: block; }
  .card { background: #111118; border: 1px solid #2a2a3a; border-radius: 8px; padding: 20px; margin-bottom: 16px; }
  .card-title { font-size: 12px; color: #666; text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 12px; }
  .verdict-row { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
  .score { font-size: 48px; font-weight: 700; line-height: 1; }
  .score.safe { color: #00ffaa; }
  .score.warn { color: #ffaa00; }
  .score.danger { color: #ff4444; }
  .verdict-text { font-size: 16px; font-weight: 600; }
  .verdict-text.safe { color: #00ffaa; }
  .verdict-text.warn { color: #ffaa00; }
  .verdict-text.danger { color: #ff4444; }
  .grade-badge { display: inline-block; padding: 4px 12px; border-radius: 4px; font-weight: 700; font-size: 14px; }
  .grade-A { background: #003322; color: #00ffaa; }
  .grade-B { background: #1a2800; color: #aaff00; }
  .grade-C { background: #2a1a00; color: #ffaa00; }
  .grade-F { background: #2a0a0a; color: #ff4444; }
  .findings-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px; margin-top: 12px; }
  .finding-box { text-align: center; padding: 16px; border-radius: 6px; }
  .finding-box.critical { background: #1a0a0a; border: 1px solid #4a1a1a; }
  .finding-box.high { background: #1a1000; border: 1px solid #4a3000; }
  .finding-box.medium { background: #0a1a1a; border: 1px solid #1a3a3a; }
  .finding-count { font-size: 28px; font-weight: 700; }
  .finding-box.critical .finding-count { color: #ff4444; }
  .finding-box.high .finding-count { color: #ffaa00; }
  .finding-box.medium .finding-count { color: #44aaff; }
  .finding-label { font-size: 11px; color: #666; text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
  .hash-row { display: flex; justify-content: space-between; align-items: center; padding: 8px 0; border-bottom: 1px solid #1a1a2a; font-size: 13px; }
  .hash-row:last-child { border-bottom: none; }
  .hash-label { color: #666; min-width: 100px; }
  .hash-value { color: #4a9eff; word-break: break-all; font-size: 12px; cursor: pointer; }
  .hash-value:hover { color: #6ab4ff; }
  .encoded-data { margin-top: 12px; padding: 12px; background: #0a0a14; border-radius: 4px; font-size: 11px; color: #4a9eff; word-break: break-all; max-height: 80px; overflow-y: auto; }
  .checks-list { margin-top: 8px; }
  .check-item { display: flex; align-items: center; gap: 8px; padding: 6px 0; font-size: 13px; border-bottom: 1px solid #1a1a2a; }
  .check-item:last-child { border-bottom: none; }
  .check-icon { width: 18px; text-align: center; }
  .check-icon.good { color: #00ffaa; }
  .check-icon.warn { color: #ffaa00; }
  .check-icon.bad { color: #ff4444; }
  .check-icon.info { color: #4a9eff; }
  .check-name { color: #aaa; min-width: 140px; }
  .check-detail { color: #666; font-size: 12px; }
  .flow-diagram { padding: 20px; text-align: center; }
  .flow-step { display: inline-block; padding: 8px 16px; border-radius: 4px; font-size: 12px; margin: 0 4px; }
  .flow-arrow { color: #333; margin: 0 2px; }
  .flow-step.active { background: #00ffaa15; border: 1px solid #00ffaa40; color: #00ffaa; }
  .flow-step.pending { background: #ffffff08; border: 1px solid #ffffff15; color: #444; }
  .tag { display: inline-block; padding: 2px 8px; border-radius: 3px; font-size: 11px; margin-left: 8px; }
  .tag.dry { background: #2a2a00; color: #aaaa00; }
  .tag.base { background: #001a2a; color: #4a9eff; }
  .summary-text { color: #888; font-size: 13px; line-height: 1.6; margin-top: 8px; }
  .copy-toast { position: fixed; bottom: 24px; right: 24px; background: #00ffaa; color: #0a0a0f; padding: 8px 16px; border-radius: 4px; font-size: 12px; font-weight: 600; display: none; }
  .copy-toast.show { display: block; }
  @media (max-width: 600px) {
    .input-row { flex-direction: column; }
    .findings-grid { grid-template-columns: 1fr; }
    .verdict-row { flex-direction: column; text-align: center; }
  }
</style>
</head>
<body>
<div class="container">
  <h1>AURA SECURITY</h1>
  <div class="subtitle">ERC-7710 Security-Gated Delegation — <a href="https://eips.ethereum.org/EIPS/eip-7710" target="_blank">EIP-7710</a> x <a href="https://attest.org" target="_blank">EAS</a> on Base</div>

  <div class="card">
    <div class="flow-diagram">
      <span class="flow-step active" id="f1">Scan Target</span>
      <span class="flow-arrow">&rarr;</span>
      <span class="flow-step pending" id="f2">Hash Findings</span>
      <span class="flow-arrow">&rarr;</span>
      <span class="flow-step pending" id="f3">ABI Encode</span>
      <span class="flow-arrow">&rarr;</span>
      <span class="flow-step pending" id="f4">Publish to EAS</span>
      <span class="flow-arrow">&rarr;</span>
      <span class="flow-step pending" id="f5">Enforcer Reads</span>
    </div>
  </div>

  <div class="input-row">
    <input type="text" id="target" placeholder="https://github.com/owner/repo" value="https://github.com/aurasecurityio/aura-security">
    <select id="scanType">
      <option value="rugcheck">Rugcheck</option>
      <option value="scamcheck">Scamcheck</option>
    </select>
    <button id="btn" onclick="runAttest()">Scan & Attest</button>
  </div>

  <div class="status" id="status"></div>

  <div class="result" id="result">
    <div class="card">
      <div class="card-title">Scan Verdict</div>
      <div class="verdict-row">
        <div class="score" id="r-score"></div>
        <div>
          <div class="verdict-text" id="r-verdict"></div>
          <span class="grade-badge" id="r-grade"></span>
          <span class="tag dry">DRY RUN</span>
          <span class="tag base">BASE</span>
        </div>
      </div>
      <div class="summary-text" id="r-summary"></div>
    </div>

    <div class="card">
      <div class="card-title">On-Chain Attestation Data</div>
      <div class="findings-grid">
        <div class="finding-box critical">
          <div class="finding-count" id="r-critical">0</div>
          <div class="finding-label">Critical</div>
        </div>
        <div class="finding-box high">
          <div class="finding-count" id="r-high">0</div>
          <div class="finding-label">High</div>
        </div>
        <div class="finding-box medium">
          <div class="finding-count" id="r-medium">0</div>
          <div class="finding-label">Medium</div>
        </div>
      </div>
      <div style="margin-top: 16px;">
        <div class="hash-row">
          <span class="hash-label">codeHash</span>
          <span class="hash-value" id="r-codehash" onclick="copyHash(this)"></span>
        </div>
        <div class="hash-row">
          <span class="hash-label">reportHash</span>
          <span class="hash-value" id="r-reporthash" onclick="copyHash(this)"></span>
        </div>
      </div>
      <div class="card-title" style="margin-top: 16px;">ABI-Encoded (bytes)</div>
      <div class="encoded-data" id="r-encoded" onclick="copyHash(this)"></div>
    </div>

    <div class="card">
      <div class="card-title">Security Checks</div>
      <div class="checks-list" id="r-checks"></div>
    </div>
  </div>
</div>

<div class="copy-toast" id="toast">Copied to clipboard</div>

<script>
const icons = { good: '&#10003;', warn: '&#9888;', bad: '&#10007;', info: '&#8505;' };

async function runAttest() {
  const target = document.getElementById('target').value.trim();
  const scanType = document.getElementById('scanType').value;
  const btn = document.getElementById('btn');
  const status = document.getElementById('status');
  const result = document.getElementById('result');

  if (!target) return;

  btn.disabled = true;
  btn.textContent = 'Scanning...';
  result.classList.remove('show');
  status.className = 'status loading';
  status.style.display = 'block';
  status.textContent = 'Running ' + scanType + ' scan on ' + target + ' ...';

  setFlow(1);

  try {
    const apiBase = window.location.origin;
    const res = await fetch(apiBase + '/v1/attest/test', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ target, scanType })
    });

    setFlow(2);
    const data = await res.json();

    if (!res.ok) throw new Error(data.error || data.message || 'Scan failed');

    setFlow(3);

    status.style.display = 'none';
    render(data);
    result.classList.add('show');

    setTimeout(() => setFlow(4), 400);
  } catch (err) {
    status.className = 'status error';
    status.textContent = 'Error: ' + err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan & Attest';
  }
}

function render(d) {
  const s = d.scanSummary || {};

  const score = s.trustScore ?? (d.findings.critical === 0 && d.findings.high === 0 ? 80 : 30);
  const cls = score >= 70 ? 'safe' : score >= 40 ? 'warn' : 'danger';

  document.getElementById('r-score').textContent = score;
  document.getElementById('r-score').className = 'score ' + cls;

  const verdict = s.verdict || (d.findings.critical > 0 ? 'RISKY' : 'CLEAN');
  document.getElementById('r-verdict').textContent = verdict;
  document.getElementById('r-verdict').className = 'verdict-text ' + cls;

  const grade = s.grade || '?';
  const gradeEl = document.getElementById('r-grade');
  gradeEl.textContent = 'Grade: ' + grade;
  gradeEl.className = 'grade-badge grade-' + grade;

  document.getElementById('r-summary').textContent = s.summary || '';

  document.getElementById('r-critical').textContent = d.findings.critical;
  document.getElementById('r-high').textContent = d.findings.high;
  document.getElementById('r-medium').textContent = d.findings.medium;

  document.getElementById('r-codehash').textContent = d.codeHash;
  document.getElementById('r-reporthash').textContent = d.reportHash;
  document.getElementById('r-encoded').textContent = d.encodedData;

  const checks = s.checks || [];
  const checksEl = document.getElementById('r-checks');
  checksEl.innerHTML = checks.map(c =>
    '<div class="check-item">' +
    '<span class="check-icon ' + c.status + '">' + (icons[c.status] || '') + '</span>' +
    '<span class="check-name">' + c.name + '</span>' +
    '<span class="check-detail">' + c.explanation + '</span>' +
    '</div>'
  ).join('');
}

function setFlow(step) {
  for (let i = 1; i <= 5; i++) {
    document.getElementById('f' + i).className = 'flow-step ' + (i <= step ? 'active' : 'pending');
  }
}

function copyHash(el) {
  navigator.clipboard.writeText(el.textContent);
  const toast = document.getElementById('toast');
  toast.classList.add('show');
  setTimeout(() => toast.classList.remove('show'), 1500);
}
</script>
</body>
</html>`;


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

  // GET /v1/attest/demo - Interactive demo page
  if (path === '/v1/attest/demo' && method === 'GET') {
    res.writeHead(200, {
      'Content-Type': 'text/html',
      'Access-Control-Allow-Origin': '*'
    });
    res.end(ATTEST_DEMO_HTML);
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
