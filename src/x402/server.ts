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
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
  :root {
    --bg: #030712;
    --bg-elevated: #0f172a;
    --bg-card: rgba(15, 23, 42, 0.6);
    --bg-input: rgba(15, 23, 42, 0.8);
    --border: rgba(148, 163, 184, 0.1);
    --border-hover: rgba(148, 163, 184, 0.2);
    --border-active: rgba(6, 182, 212, 0.5);
    --text: #f8fafc;
    --text-secondary: #94a3b8;
    --text-muted: #64748b;
    --primary: #06b6d4;
    --primary-dim: rgba(6, 182, 212, 0.15);
    --primary-glow: rgba(6, 182, 212, 0.4);
    --danger: #ef4444;
    --danger-dim: rgba(239, 68, 68, 0.15);
    --warning: #f59e0b;
    --warning-dim: rgba(245, 158, 11, 0.15);
    --success: #10b981;
    --success-dim: rgba(16, 185, 129, 0.15);
    --orange: #f97316;
    --orange-dim: rgba(249, 115, 22, 0.15);
    --radius: 12px;
    --radius-lg: 16px;
    --radius-sm: 8px;
  }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg); color: var(--text); min-height: 100vh; }
  body::before { content: ''; position: fixed; top: 0; left: 0; right: 0; height: 600px; background: radial-gradient(ellipse 60% 40% at 50% 0%, rgba(6, 182, 212, 0.08) 0%, transparent 70%); pointer-events: none; z-index: 0; }

  /* Nav */
  .nav { position: sticky; top: 12px; z-index: 100; max-width: 900px; margin: 12px auto; padding: 0.6rem 1.25rem; display: flex; align-items: center; justify-content: space-between; background: rgba(3, 7, 18, 0.85); backdrop-filter: blur(20px); border: 1px solid var(--border); border-radius: var(--radius-lg); }
  .nav-brand { font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 15px; color: var(--text); display: flex; align-items: center; gap: 8px; text-decoration: none; }
  .nav-brand svg { width: 22px; height: 22px; }
  .nav-links { display: flex; gap: 20px; align-items: center; }
  .nav-links a { color: var(--text-secondary); font-size: 13px; text-decoration: none; font-weight: 500; transition: color 0.2s; }
  .nav-links a:hover { color: var(--text); }

  .container { position: relative; z-index: 1; max-width: 900px; margin: 0 auto; padding: 32px 24px; }

  /* Header */
  .page-label { font-family: 'Space Grotesk', sans-serif; font-size: 12px; font-weight: 600; color: var(--primary); text-transform: uppercase; letter-spacing: 0.12em; margin-bottom: 8px; }
  h1 { font-family: 'Space Grotesk', sans-serif; font-size: 28px; font-weight: 700; color: var(--text); margin-bottom: 6px; }
  .subtitle { color: var(--text-muted); font-size: 14px; margin-bottom: 28px; }
  .subtitle a { color: var(--primary); text-decoration: none; }
  .subtitle a:hover { text-decoration: underline; }

  /* Cards */
  .card { background: var(--bg-elevated); border: 1px solid var(--border); border-radius: var(--radius); padding: 1.15rem; margin-bottom: 12px; }
  .card-title { font-family: 'Space Grotesk', sans-serif; font-size: 11px; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.1em; margin-bottom: 12px; }

  /* Flow */
  .flow-diagram { padding: 16px 0; display: flex; align-items: center; justify-content: center; flex-wrap: wrap; gap: 6px; }
  .flow-step { padding: 7px 14px; border-radius: var(--radius-sm); font-family: 'Space Grotesk', sans-serif; font-size: 12px; font-weight: 500; transition: all 0.3s; }
  .flow-arrow { color: var(--text-muted); font-size: 12px; }
  .flow-step.active { background: var(--primary-dim); border: 1px solid var(--border-active); color: var(--primary); }
  .flow-step.pending { background: var(--bg-card); border: 1px solid var(--border); color: var(--text-muted); }

  /* Input row */
  .input-row { display: flex; gap: 10px; margin-bottom: 16px; }
  input[type="text"] { flex: 1; background: var(--bg-input); border: 1px solid var(--border); color: var(--text); padding: 12px 16px; border-radius: var(--radius-lg); font-family: 'Inter', sans-serif; font-size: 14px; outline: none; transition: all 0.2s; }
  input[type="text"]:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-dim); }
  input[type="text"]::placeholder { color: var(--text-muted); }
  select { background: var(--bg-input); border: 1px solid var(--border); color: var(--text); padding: 12px 16px; border-radius: var(--radius); font-family: 'Inter', sans-serif; font-size: 14px; outline: none; cursor: pointer; min-width: 140px; transition: all 0.2s; }
  select:focus { border-color: var(--primary); box-shadow: 0 0 0 3px var(--primary-dim); }
  button { background: linear-gradient(135deg, var(--primary), #0891b2); color: #fff; border: none; padding: 12px 24px; border-radius: var(--radius); font-family: 'Space Grotesk', sans-serif; font-size: 14px; font-weight: 600; cursor: pointer; transition: all 0.2s; }
  button:hover { filter: brightness(1.1); transform: translateY(-1px); }
  button:disabled { background: var(--bg-elevated); color: var(--text-muted); cursor: not-allowed; transform: none; filter: none; }

  /* Status */
  .status { margin: 16px 0; padding: 14px 16px; border-radius: var(--radius-sm); font-size: 13px; display: none; }
  .status.loading { display: block; background: var(--primary-dim); border: 1px solid var(--border-active); color: var(--primary); }
  .status.error { display: block; background: var(--danger-dim); border: 1px solid rgba(239, 68, 68, 0.3); color: var(--danger); }

  /* Result */
  .result { display: none; margin-top: 20px; }
  .result.show { display: block; animation: fadeIn 0.3s ease; }
  @keyframes fadeIn { from { opacity: 0; transform: translateY(8px); } to { opacity: 1; transform: translateY(0); } }

  /* Verdict */
  .verdict-row { display: flex; align-items: center; gap: 20px; }
  .score-ring { position: relative; width: 80px; height: 80px; flex-shrink: 0; }
  .score-ring svg { width: 80px; height: 80px; transform: rotate(-90deg); }
  .score-ring .bg { fill: none; stroke: rgba(148, 163, 184, 0.1); stroke-width: 8; }
  .score-ring .fill { fill: none; stroke-width: 8; stroke-linecap: round; transition: stroke-dashoffset 0.6s ease; }
  .score-num { position: absolute; top: 50%; left: 50%; transform: translate(-50%, -50%); font-family: 'Space Grotesk', sans-serif; font-size: 22px; font-weight: 700; color: var(--text); }
  .verdict-info { flex: 1; }
  .verdict-banner { display: inline-block; padding: 5px 14px; border-radius: var(--radius-sm); font-family: 'Space Grotesk', sans-serif; font-weight: 700; font-size: 13px; text-transform: uppercase; letter-spacing: 0.05em; }
  .verdict-banner.safe { background: var(--success-dim); color: var(--success); border: 1px solid rgba(16, 185, 129, 0.3); }
  .verdict-banner.warn { background: var(--warning-dim); color: var(--warning); border: 1px solid rgba(245, 158, 11, 0.3); }
  .verdict-banner.danger { background: var(--danger-dim); color: var(--danger); border: 1px solid rgba(239, 68, 68, 0.3); }
  .tag { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 10px; font-weight: 600; font-family: 'Space Grotesk', sans-serif; letter-spacing: 0.05em; margin-left: 6px; text-transform: uppercase; }
  .tag.dry { background: var(--warning-dim); color: var(--warning); }
  .tag.base { background: var(--primary-dim); color: var(--primary); }
  .summary-text { color: var(--text-secondary); font-size: 13px; line-height: 1.6; margin-top: 10px; }

  /* Findings grid */
  .findings-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 10px; margin-top: 10px; }
  .finding-box { text-align: center; padding: 16px 12px; border-radius: var(--radius-sm); }
  .finding-box.critical { background: var(--danger-dim); border: 1px solid rgba(239, 68, 68, 0.2); }
  .finding-box.high { background: var(--orange-dim); border: 1px solid rgba(249, 115, 22, 0.2); }
  .finding-box.medium { background: var(--warning-dim); border: 1px solid rgba(245, 158, 11, 0.2); }
  .finding-count { font-family: 'Space Grotesk', sans-serif; font-size: 28px; font-weight: 700; }
  .finding-box.critical .finding-count { color: var(--danger); }
  .finding-box.high .finding-count { color: var(--orange); }
  .finding-box.medium .finding-count { color: var(--warning); }
  .finding-label { font-size: 10px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; margin-top: 4px; }

  /* Hashes */
  .hash-row { display: flex; align-items: baseline; gap: 12px; padding: 8px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
  .hash-row:last-child { border-bottom: none; }
  .hash-label { color: var(--text-muted); min-width: 95px; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
  .hash-value { color: var(--primary); font-family: 'JetBrains Mono', monospace; word-break: break-all; font-size: 11px; cursor: pointer; transition: color 0.2s; }
  .hash-value:hover { color: #22d3ee; }
  .encoded-data { margin-top: 10px; padding: 12px; background: rgba(3, 7, 18, 0.6); border: 1px solid var(--border); border-radius: var(--radius-sm); font-family: 'JetBrains Mono', monospace; font-size: 10px; color: var(--primary); word-break: break-all; max-height: 72px; overflow-y: auto; cursor: pointer; }

  /* Checks */
  .checks-list { margin-top: 4px; }
  .check-item { display: flex; align-items: center; gap: 10px; padding: 7px 0; font-size: 13px; border-bottom: 1px solid var(--border); }
  .check-item:last-child { border-bottom: none; }
  .check-icon { width: 18px; text-align: center; font-size: 13px; }
  .check-icon.good { color: var(--success); }
  .check-icon.warn { color: var(--warning); }
  .check-icon.bad { color: var(--danger); }
  .check-icon.info { color: var(--primary); }
  .check-name { color: var(--text-secondary); min-width: 130px; font-weight: 500; font-size: 12px; }
  .check-detail { color: var(--text-muted); font-size: 12px; }

  /* Toast */
  .copy-toast { position: fixed; bottom: 24px; right: 24px; background: var(--primary); color: #fff; padding: 8px 16px; border-radius: var(--radius-sm); font-size: 12px; font-weight: 600; font-family: 'Space Grotesk', sans-serif; display: none; z-index: 200; }
  .copy-toast.show { display: block; animation: fadeIn 0.2s ease; }

  @media (max-width: 640px) {
    .input-row { flex-direction: column; }
    .findings-grid { grid-template-columns: 1fr; }
    .verdict-row { flex-direction: column; text-align: center; }
    .flow-diagram { gap: 4px; }
    .flow-step { font-size: 11px; padding: 5px 10px; }
  }
</style>
</head>
<body>
<nav class="nav">
  <a class="nav-brand" href="https://app.aurasecurity.io/app">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10" stroke="var(--primary)" /><circle cx="12" cy="12" r="4" fill="var(--primary)" opacity="0.3"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4" stroke="var(--primary)" stroke-width="1.5"/></svg>
    aurasecurity
  </a>
  <div class="nav-links">
    <a href="https://app.aurasecurity.io/app">Dashboard</a>
    <a href="https://github.com/aurasecurityio/aura-security" target="_blank">GitHub</a>
    <a href="https://t.me/aurasecuritychecker_bot" target="_blank">Telegram</a>
  </div>
</nav>

<div class="container">
  <div class="page-label">ERC-7710 Security-Gated Delegation</div>
  <h1>Scan. Attest. Enforce.</h1>
  <div class="subtitle">Run a security scan and publish the result as an <a href="https://attest.org" target="_blank">EAS</a> attestation on <a href="https://base.org" target="_blank">Base</a>. Caveat enforcers read it before allowing delegations.</div>

  <div class="card" style="margin-bottom: 20px;">
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
    <input type="text" id="target" placeholder="github.com/owner/repo or any URL..." value="https://github.com/aurasecurityio/aura-security">
    <select id="scanType">
      <option value="rugcheck">Rugcheck</option>
      <option value="scamcheck">Scamcheck</option>
    </select>
    <button id="btn" onclick="runAttest()">Scan & Attest</button>
  </div>

  <div class="status" id="status"></div>

  <div class="result" id="result">
    <div class="card">
      <div class="card-title">Verdict</div>
      <div class="verdict-row">
        <div class="score-ring">
          <svg viewBox="0 0 80 80"><circle class="bg" cx="40" cy="40" r="34"/><circle class="fill" id="r-ring" cx="40" cy="40" r="34" stroke-dasharray="213.6" stroke-dashoffset="213.6"/></svg>
          <div class="score-num" id="r-score">0</div>
        </div>
        <div class="verdict-info">
          <span class="verdict-banner" id="r-verdict">SCANNING</span>
          <span class="tag dry">DRY RUN</span>
          <span class="tag base">BASE</span>
          <div class="summary-text" id="r-summary"></div>
        </div>
      </div>
    </div>

    <div class="card">
      <div class="card-title">Attestation Data</div>
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
      <div style="margin-top: 14px;">
        <div class="hash-row">
          <span class="hash-label">codeHash</span>
          <span class="hash-value" id="r-codehash" onclick="copyHash(this)"></span>
        </div>
        <div class="hash-row">
          <span class="hash-label">reportHash</span>
          <span class="hash-value" id="r-reporthash" onclick="copyHash(this)"></span>
        </div>
      </div>
      <div class="card-title" style="margin-top: 14px;">ABI-Encoded Bytes</div>
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
const circ = 2 * Math.PI * 34;

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
    const res = await fetch(window.location.origin + '/v1/attest/test', {
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
    setTimeout(function() { setFlow(4); }, 400);
  } catch (err) {
    status.className = 'status error';
    status.textContent = err.message;
  } finally {
    btn.disabled = false;
    btn.textContent = 'Scan & Attest';
  }
}

function render(d) {
  var s = d.scanSummary || {};
  var score = s.trustScore != null ? s.trustScore : (d.findings.critical === 0 && d.findings.high === 0 ? 80 : 30);
  var cls = score >= 70 ? 'safe' : score >= 40 ? 'warn' : 'danger';
  var color = cls === 'safe' ? '#10b981' : cls === 'warn' ? '#f59e0b' : '#ef4444';

  document.getElementById('r-score').textContent = score;
  var ring = document.getElementById('r-ring');
  ring.style.stroke = color;
  ring.style.strokeDashoffset = circ - (circ * score / 100);

  var verdict = s.verdict || (d.findings.critical > 0 ? 'RISKY' : 'CLEAN');
  var vEl = document.getElementById('r-verdict');
  vEl.textContent = verdict;
  vEl.className = 'verdict-banner ' + cls;

  document.getElementById('r-summary').textContent = s.summary || '';
  document.getElementById('r-critical').textContent = d.findings.critical;
  document.getElementById('r-high').textContent = d.findings.high;
  document.getElementById('r-medium').textContent = d.findings.medium;
  document.getElementById('r-codehash').textContent = d.codeHash;
  document.getElementById('r-reporthash').textContent = d.reportHash;
  document.getElementById('r-encoded').textContent = d.encodedData;

  var checks = s.checks || [];
  document.getElementById('r-checks').innerHTML = checks.map(function(c) {
    return '<div class="check-item"><span class="check-icon ' + c.status + '">' + (icons[c.status]||'') + '</span><span class="check-name">' + c.name + '</span><span class="check-detail">' + c.explanation + '</span></div>';
  }).join('');
}

function setFlow(step) {
  for (var i = 1; i <= 5; i++) {
    document.getElementById('f' + i).className = 'flow-step ' + (i <= step ? 'active' : 'pending');
  }
}

function copyHash(el) {
  navigator.clipboard.writeText(el.textContent);
  var t = document.getElementById('toast');
  t.classList.add('show');
  setTimeout(function() { t.classList.remove('show'); }, 1500);
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
