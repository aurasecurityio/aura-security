/**
 * Report Generation for AuraSecurity
 *
 * Generates HTML security reports from scan results.
 * Reports include: trust score, scam analysis, findings breakdown,
 * and actionable recommendations.
 */

export interface ReportData {
  repoUrl: string;
  generatedAt: string;
  trustScan?: {
    trustScore: number;
    grade: string;
    verdict: string;
    checks?: Array<{ name: string; passed: boolean; details: string; weight: number }>;
    metrics?: Record<string, unknown>;
  };
  scamScan?: {
    scamScore: number;
    riskLevel: string;
    isLikelyScam: boolean;
    flags?: string[];
    summary?: string;
  };
  localScan?: {
    secrets_found: number;
    package_vulns: number;
    sast_findings: number;
    tools_used: string[];
    findings?: Array<{ type: string; severity: string; file?: string; line?: number; message: string }>;
  };
  xScan?: {
    score: number;
    grade: string;
    verdict: string;
    username: string;
  };
  aiCheck?: {
    isRealAI: boolean;
    confidence: number;
    summary: string;
  };
}

export type ReportFormat = 'html' | 'json';

function gradeColor(grade: string): string {
  const map: Record<string, string> = {
    'A+': '#00c853', A: '#00c853',
    'B+': '#64dd17', B: '#64dd17',
    'C+': '#ffd600', C: '#ffd600',
    D: '#ff6d00',
    F: '#d50000',
  };
  return map[grade] || '#757575';
}

function severityColor(severity: string): string {
  const map: Record<string, string> = {
    critical: '#d50000',
    high: '#ff6d00',
    medium: '#ffd600',
    low: '#64dd17',
    info: '#2196f3',
  };
  return map[severity.toLowerCase()] || '#757575';
}

function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function renderTrustSection(data: ReportData['trustScan']): string {
  if (!data) return '';
  const color = gradeColor(data.grade);
  const checks = data.checks || [];

  return `
    <div class="section">
      <h2>Trust Score</h2>
      <div class="score-card">
        <div class="score-value" style="color: ${color}">${data.trustScore}/100</div>
        <div class="score-grade" style="background: ${color}">${data.grade}</div>
        <div class="score-verdict">${escapeHtml(data.verdict)}</div>
      </div>
      ${checks.length > 0 ? `
        <table class="checks-table">
          <thead><tr><th>Check</th><th>Result</th><th>Details</th></tr></thead>
          <tbody>
            ${checks.map(c => `
              <tr>
                <td>${escapeHtml(c.name)}</td>
                <td class="${c.passed ? 'pass' : 'fail'}">${c.passed ? 'PASS' : 'FAIL'}</td>
                <td>${escapeHtml(c.details)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      ` : ''}
    </div>
  `;
}

function renderScamSection(data: ReportData['scamScan']): string {
  if (!data) return '';
  const color = data.isLikelyScam ? '#d50000' : data.riskLevel === 'medium' ? '#ff6d00' : '#00c853';
  const flags = data.flags || [];

  return `
    <div class="section">
      <h2>Scam Analysis</h2>
      <div class="score-card">
        <div class="score-value" style="color: ${color}">Risk: ${data.scamScore}/100</div>
        <div class="score-grade" style="background: ${color}">${data.riskLevel.toUpperCase()}</div>
        ${data.isLikelyScam ? '<div class="alert-badge">LIKELY SCAM</div>' : ''}
      </div>
      ${data.summary ? `<p class="summary">${escapeHtml(data.summary)}</p>` : ''}
      ${flags.length > 0 ? `
        <div class="flags">
          <h3>Red Flags</h3>
          <ul>${flags.map(f => `<li class="flag">${escapeHtml(f)}</li>`).join('')}</ul>
        </div>
      ` : ''}
    </div>
  `;
}

function renderLocalScanSection(data: ReportData['localScan']): string {
  if (!data) return '';
  const findings = data.findings || [];

  return `
    <div class="section">
      <h2>Code Scan</h2>
      <div class="stats-row">
        <div class="stat">
          <div class="stat-value" style="color: ${data.secrets_found > 0 ? '#d50000' : '#00c853'}">${data.secrets_found}</div>
          <div class="stat-label">Secrets</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: ${data.package_vulns > 0 ? '#ff6d00' : '#00c853'}">${data.package_vulns}</div>
          <div class="stat-label">Vulnerabilities</div>
        </div>
        <div class="stat">
          <div class="stat-value" style="color: ${data.sast_findings > 0 ? '#ffd600' : '#00c853'}">${data.sast_findings}</div>
          <div class="stat-label">SAST Findings</div>
        </div>
      </div>
      <p class="tools-used">Tools: ${data.tools_used.join(', ') || 'none'}</p>
      ${findings.length > 0 ? `
        <table class="findings-table">
          <thead><tr><th>Severity</th><th>Type</th><th>File</th><th>Message</th></tr></thead>
          <tbody>
            ${findings.slice(0, 50).map(f => `
              <tr>
                <td><span class="severity-badge" style="background: ${severityColor(f.severity)}">${escapeHtml(f.severity.toUpperCase())}</span></td>
                <td>${escapeHtml(f.type)}</td>
                <td>${f.file ? escapeHtml(f.file) + (f.line ? `:${f.line}` : '') : '-'}</td>
                <td>${escapeHtml(f.message)}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
        ${findings.length > 50 ? `<p class="truncated">Showing 50 of ${findings.length} findings</p>` : ''}
      ` : '<p class="clean">No findings detected.</p>'}
    </div>
  `;
}

function renderXScanSection(data: ReportData['xScan']): string {
  if (!data) return '';
  const color = gradeColor(data.grade);

  return `
    <div class="section">
      <h2>X/Twitter: @${escapeHtml(data.username)}</h2>
      <div class="score-card">
        <div class="score-value" style="color: ${color}">${data.score}/100</div>
        <div class="score-grade" style="background: ${color}">${data.grade}</div>
        <div class="score-verdict">${escapeHtml(data.verdict)}</div>
      </div>
    </div>
  `;
}

function renderAICheckSection(data: ReportData['aiCheck']): string {
  if (!data) return '';
  const color = data.isRealAI ? '#00c853' : '#d50000';

  return `
    <div class="section">
      <h2>AI Verification</h2>
      <div class="score-card">
        <div class="score-value" style="color: ${color}">${data.isRealAI ? 'REAL AI' : 'NOT REAL AI'}</div>
        <div class="score-verdict">Confidence: ${data.confidence}%</div>
      </div>
      <p class="summary">${escapeHtml(data.summary)}</p>
    </div>
  `;
}

export function generateHtmlReport(data: ReportData): string {
  const repoName = data.repoUrl.replace(/^https?:\/\/github\.com\//, '');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AuraSecurity Report: ${escapeHtml(repoName)}</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }
  .container { max-width: 900px; margin: 0 auto; padding: 20px; }
  header { text-align: center; padding: 40px 0 20px; border-bottom: 1px solid #333; margin-bottom: 30px; }
  header h1 { font-size: 28px; color: #00e5ff; margin-bottom: 8px; }
  header .repo { font-size: 18px; color: #90caf9; }
  header .timestamp { font-size: 13px; color: #666; margin-top: 8px; }
  .section { background: #1a1a1a; border: 1px solid #333; border-radius: 8px; padding: 24px; margin-bottom: 20px; }
  .section h2 { font-size: 20px; color: #00e5ff; margin-bottom: 16px; padding-bottom: 8px; border-bottom: 1px solid #333; }
  .score-card { display: flex; align-items: center; gap: 16px; margin-bottom: 16px; }
  .score-value { font-size: 32px; font-weight: bold; }
  .score-grade { color: #fff; font-weight: bold; padding: 4px 12px; border-radius: 4px; font-size: 18px; }
  .score-verdict { font-size: 16px; color: #bbb; }
  .alert-badge { background: #d50000; color: #fff; padding: 4px 12px; border-radius: 4px; font-weight: bold; animation: pulse 2s infinite; }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.7; } }
  .stats-row { display: flex; gap: 24px; margin-bottom: 16px; }
  .stat { text-align: center; flex: 1; padding: 16px; background: #222; border-radius: 8px; }
  .stat-value { font-size: 28px; font-weight: bold; }
  .stat-label { font-size: 13px; color: #888; margin-top: 4px; }
  table { width: 100%; border-collapse: collapse; margin-top: 12px; }
  th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #333; font-size: 14px; }
  th { color: #00e5ff; font-weight: 600; }
  .pass { color: #00c853; font-weight: bold; }
  .fail { color: #d50000; font-weight: bold; }
  .severity-badge { color: #fff; padding: 2px 8px; border-radius: 3px; font-size: 12px; font-weight: bold; }
  .flags ul { list-style: none; padding: 0; }
  .flag { padding: 6px 0; color: #ff6d00; }
  .flag::before { content: "\\26A0 "; }
  .summary { color: #bbb; margin: 8px 0; }
  .tools-used { color: #666; font-size: 13px; }
  .clean { color: #00c853; font-weight: bold; }
  .truncated { color: #666; font-size: 13px; font-style: italic; margin-top: 8px; }
  footer { text-align: center; padding: 30px 0; color: #444; font-size: 13px; }
  footer a { color: #00e5ff; text-decoration: none; }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1>AuraSecurity Report</h1>
    <div class="repo">${escapeHtml(repoName)}</div>
    <div class="timestamp">Generated: ${escapeHtml(data.generatedAt)}</div>
  </header>
  ${renderTrustSection(data.trustScan)}
  ${renderScamSection(data.scamScan)}
  ${renderLocalScanSection(data.localScan)}
  ${renderXScanSection(data.xScan)}
  ${renderAICheckSection(data.aiCheck)}
  <footer>
    Powered by <a href="https://aurasecurity.io">AuraSecurity</a> &mdash; Autonomous Security for AI Agents
  </footer>
</div>
</body>
</html>`;
}

export function generateJsonReport(data: ReportData): string {
  return JSON.stringify({
    meta: {
      generator: 'AuraSecurity',
      version: '0.6.0',
      generatedAt: data.generatedAt,
      repoUrl: data.repoUrl,
    },
    trustScan: data.trustScan || null,
    scamScan: data.scamScan || null,
    localScan: data.localScan || null,
    xScan: data.xScan || null,
    aiCheck: data.aiCheck || null,
  }, null, 2);
}

export function generateReport(data: ReportData, format: ReportFormat = 'html'): string {
  if (format === 'json') return generateJsonReport(data);
  return generateHtmlReport(data);
}
