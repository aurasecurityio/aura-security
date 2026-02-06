/**
 * Website Probe - Detect if a site has real backend activity
 *
 * Uses Browserless.io to load pages and intercept network requests.
 * Detects: API calls, WebSocket connections, data flow patterns.
 *
 * Signs of a REAL app:
 * - Multiple API endpoints returning JSON
 * - WebSocket connections for real-time data
 * - Authentication endpoints
 * - External API integrations (CoinGecko, Alchemy, etc.)
 *
 * Signs of a RUG/FAKE:
 * - Static HTML only, no API calls
 * - Forms that POST to nowhere
 * - No data flowing in/out
 * - All content hardcoded in HTML
 */

const BROWSERLESS_API_URL = 'https://chrome.browserless.io/function';
const PROBE_TIMEOUT = 30000; // 30 seconds

export interface NetworkRequest {
  url: string;
  method: string;
  resourceType: string;
  status?: number;
  contentType?: string;
  isApi?: boolean;
  isWebSocket?: boolean;
}

export interface ProbeResult {
  url: string;
  success: boolean;
  error?: string;

  // Network analysis
  totalRequests: number;
  apiCalls: NetworkRequest[];
  webSocketConnections: string[];
  externalApis: string[];

  // Verdicts
  hasApiActivity: boolean;
  hasWebSocket: boolean;
  hasExternalIntegrations: boolean;

  // Tech detection
  frameworks: string[];
  hosting: string;

  // Final verdict
  verdict: 'ACTIVE' | 'STATIC' | 'SUSPICIOUS' | 'ERROR';
  verdictReason: string;
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH';

  // Timing
  loadTime: number;
  probeTime: number;
}

// Known external APIs that indicate real integrations
const KNOWN_APIS = [
  { pattern: /coingecko\.com/i, name: 'CoinGecko' },
  { pattern: /coinmarketcap\.com/i, name: 'CoinMarketCap' },
  { pattern: /alchemy\.com|alchemyapi/i, name: 'Alchemy' },
  { pattern: /infura\.io/i, name: 'Infura' },
  { pattern: /etherscan\.io/i, name: 'Etherscan' },
  { pattern: /moralis\.io/i, name: 'Moralis' },
  { pattern: /thegraph\.com/i, name: 'The Graph' },
  { pattern: /chainlink/i, name: 'Chainlink' },
  { pattern: /binance\.com\/api/i, name: 'Binance' },
  { pattern: /api\.opensea/i, name: 'OpenSea' },
  { pattern: /uniswap/i, name: 'Uniswap' },
  { pattern: /aave\.com/i, name: 'Aave' },
  { pattern: /compound\.finance/i, name: 'Compound' },
  { pattern: /1inch/i, name: '1inch' },
  { pattern: /dexscreener/i, name: 'DexScreener' },
  { pattern: /defined\.fi/i, name: 'Defined.fi' },
  { pattern: /birdeye\.so/i, name: 'Birdeye' },
  { pattern: /solscan\.io/i, name: 'Solscan' },
  { pattern: /helius/i, name: 'Helius' },
  { pattern: /quicknode/i, name: 'QuickNode' },
];

// Framework detection patterns
const FRAMEWORK_PATTERNS = [
  { pattern: /_next|__next/i, name: 'Next.js' },
  { pattern: /react|__react/i, name: 'React' },
  { pattern: /vue|__vue/i, name: 'Vue.js' },
  { pattern: /angular/i, name: 'Angular' },
  { pattern: /svelte/i, name: 'Svelte' },
  { pattern: /webpack/i, name: 'Webpack' },
  { pattern: /vite/i, name: 'Vite' },
];

// Hosting detection
const HOSTING_PATTERNS = [
  { pattern: /vercel|\.vercel\.app/i, name: 'Vercel' },
  { pattern: /netlify/i, name: 'Netlify' },
  { pattern: /cloudflare/i, name: 'Cloudflare' },
  { pattern: /amazonaws\.com|cloudfront/i, name: 'AWS' },
  { pattern: /github\.io/i, name: 'GitHub Pages' },
  { pattern: /firebase/i, name: 'Firebase' },
  { pattern: /heroku/i, name: 'Heroku' },
];

/**
 * Probe a website for network activity
 */
export async function probeWebsite(targetUrl: string): Promise<ProbeResult> {
  const startTime = Date.now();
  const apiKey = process.env.BROWSERLESS_API_KEY;

  if (!apiKey) {
    return {
      url: targetUrl,
      success: false,
      error: 'BROWSERLESS_API_KEY not configured',
      totalRequests: 0,
      apiCalls: [],
      webSocketConnections: [],
      externalApis: [],
      hasApiActivity: false,
      hasWebSocket: false,
      hasExternalIntegrations: false,
      frameworks: [],
      hosting: 'Unknown',
      verdict: 'ERROR',
      verdictReason: 'API key not configured',
      riskLevel: 'HIGH',
      loadTime: 0,
      probeTime: 0,
    };
  }

  // Normalize URL
  if (!targetUrl.startsWith('http')) {
    targetUrl = 'https://' + targetUrl;
  }

  // The function code to run in Browserless
  const functionCode = `
    module.exports = async ({ page }) => {
      const networkRequests = [];
      const wsConnections = [];
      let loadTime = 0;

      // Intercept all network requests
      page.on('request', req => {
        const url = req.url();
        networkRequests.push({
          url: url,
          method: req.method(),
          resourceType: req.resourceType(),
        });

        // Detect WebSocket upgrade requests
        if (url.startsWith('wss://') || url.startsWith('ws://')) {
          wsConnections.push(url);
        }
      });

      // Capture response info
      page.on('response', res => {
        const url = res.url();
        const existing = networkRequests.find(r => r.url === url);
        if (existing) {
          existing.status = res.status();
          existing.contentType = res.headers()['content-type'] || '';
        }
      });

      const startNav = Date.now();

      try {
        // Navigate with timeout
        await page.goto('${targetUrl}', {
          waitUntil: 'networkidle2',
          timeout: 25000
        });

        loadTime = Date.now() - startNav;

        // Wait a bit more for lazy-loaded content
        await new Promise(r => setTimeout(r, 3000));

      } catch (err) {
        // Page might have partial load, continue with what we have
        loadTime = Date.now() - startNav;
      }

      return {
        networkRequests,
        wsConnections,
        loadTime,
        pageTitle: await page.title().catch(() => ''),
      };
    }
  `;

  try {
    const response = await fetch(`${BROWSERLESS_API_URL}?token=${apiKey}`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code: functionCode }),
      signal: AbortSignal.timeout(PROBE_TIMEOUT),
    });

    if (!response.ok) {
      const text = await response.text();
      throw new Error(`Browserless API error: ${response.status} - ${text.slice(0, 200)}`);
    }

    const data = await response.json();
    const { networkRequests, wsConnections, loadTime } = data;

    // Analyze the network requests
    const result = analyzeNetworkActivity(
      targetUrl,
      networkRequests || [],
      wsConnections || [],
      loadTime || 0,
      Date.now() - startTime
    );

    return result;

  } catch (err: any) {
    return {
      url: targetUrl,
      success: false,
      error: err.message || 'Unknown error',
      totalRequests: 0,
      apiCalls: [],
      webSocketConnections: [],
      externalApis: [],
      hasApiActivity: false,
      hasWebSocket: false,
      hasExternalIntegrations: false,
      frameworks: [],
      hosting: 'Unknown',
      verdict: 'ERROR',
      verdictReason: err.message || 'Failed to probe website',
      riskLevel: 'HIGH',
      loadTime: 0,
      probeTime: Date.now() - startTime,
    };
  }
}

/**
 * Analyze network requests to determine site activity
 */
function analyzeNetworkActivity(
  url: string,
  requests: NetworkRequest[],
  wsConnections: string[],
  loadTime: number,
  probeTime: number
): ProbeResult {

  // Filter and categorize requests
  const apiCalls: NetworkRequest[] = [];
  const externalApisFound: Set<string> = new Set();
  const frameworksFound: Set<string> = new Set();
  let hostingProvider = 'Unknown';

  for (const req of requests) {
    // Skip static assets
    if (['image', 'stylesheet', 'font', 'media'].includes(req.resourceType)) {
      continue;
    }

    // Detect API calls (XHR/fetch returning JSON)
    const isApi = (
      req.resourceType === 'fetch' ||
      req.resourceType === 'xhr' ||
      req.url.includes('/api/') ||
      req.url.includes('/v1/') ||
      req.url.includes('/v2/') ||
      req.url.includes('/graphql') ||
      (req.contentType && req.contentType.includes('application/json'))
    );

    if (isApi) {
      req.isApi = true;
      apiCalls.push(req);
    }

    // Detect known external APIs
    for (const api of KNOWN_APIS) {
      if (api.pattern.test(req.url)) {
        externalApisFound.add(api.name);
      }
    }

    // Detect frameworks
    for (const fw of FRAMEWORK_PATTERNS) {
      if (fw.pattern.test(req.url)) {
        frameworksFound.add(fw.name);
      }
    }

    // Detect hosting
    for (const host of HOSTING_PATTERNS) {
      if (host.pattern.test(req.url)) {
        hostingProvider = host.name;
      }
    }
  }

  // Calculate verdicts
  const hasApiActivity = apiCalls.length > 0;
  const hasWebSocket = wsConnections.length > 0;
  const hasExternalIntegrations = externalApisFound.size > 0;

  // Determine final verdict
  let verdict: ProbeResult['verdict'];
  let verdictReason: string;
  let riskLevel: ProbeResult['riskLevel'];

  if (apiCalls.length >= 3 || (apiCalls.length >= 1 && hasWebSocket)) {
    verdict = 'ACTIVE';
    verdictReason = `Found ${apiCalls.length} API calls${hasWebSocket ? ' + WebSocket' : ''}${hasExternalIntegrations ? ` + ${externalApisFound.size} external APIs` : ''}`;
    riskLevel = 'LOW';
  } else if (apiCalls.length >= 1 || hasExternalIntegrations) {
    verdict = 'ACTIVE';
    verdictReason = `Minimal API activity (${apiCalls.length} calls)`;
    riskLevel = 'MEDIUM';
  } else if (requests.length > 50) {
    // Lots of requests but no API calls - might be static site with lots of assets
    verdict = 'SUSPICIOUS';
    verdictReason = `${requests.length} requests but no API calls detected - possibly static site`;
    riskLevel = 'MEDIUM';
  } else {
    verdict = 'STATIC';
    verdictReason = 'No API activity or backend calls detected - static landing page';
    riskLevel = 'HIGH';
  }

  return {
    url,
    success: true,
    totalRequests: requests.length,
    apiCalls,
    webSocketConnections: wsConnections,
    externalApis: Array.from(externalApisFound),
    hasApiActivity,
    hasWebSocket,
    hasExternalIntegrations,
    frameworks: Array.from(frameworksFound),
    hosting: hostingProvider,
    verdict,
    verdictReason,
    riskLevel,
    loadTime,
    probeTime,
  };
}

/**
 * Format probe result for display
 */
export function formatProbeResult(result: ProbeResult): string {
  if (!result.success) {
    return `PROBE FAILED: ${result.url}\nError: ${result.error}`;
  }

  const lines: string[] = [];

  // Header with verdict
  const verdictEmoji = result.verdict === 'ACTIVE' ? '✅' :
                       result.verdict === 'STATIC' ? '⚠️' :
                       result.verdict === 'SUSPICIOUS' ? '🟡' : '❌';

  lines.push(`${verdictEmoji} PROBE: ${result.url}`);
  lines.push('');

  // Network Analysis
  lines.push('Network Analysis:');
  lines.push(`├── Total Requests: ${result.totalRequests}`);
  lines.push(`├── API Calls: ${result.apiCalls.length} ${result.hasApiActivity ? '✓' : '✗'}`);

  // Show top API endpoints (max 5)
  if (result.apiCalls.length > 0) {
    const topApis = result.apiCalls.slice(0, 5);
    for (const api of topApis) {
      const status = api.status ? `(${api.status})` : '';
      const shortUrl = api.url.length > 50 ? api.url.slice(0, 47) + '...' : api.url;
      lines.push(`│   └── ${api.method} ${shortUrl} ${status}`);
    }
    if (result.apiCalls.length > 5) {
      lines.push(`│   └── ...and ${result.apiCalls.length - 5} more`);
    }
  }

  lines.push(`├── WebSocket: ${result.webSocketConnections.length > 0 ? result.webSocketConnections.length + ' ✓' : 'None ✗'}`);

  if (result.externalApis.length > 0) {
    lines.push(`└── External APIs: ${result.externalApis.join(', ')} ✓`);
  } else {
    lines.push(`└── External APIs: None detected`);
  }

  lines.push('');

  // Tech Stack
  if (result.frameworks.length > 0 || result.hosting !== 'Unknown') {
    lines.push('Tech Stack:');
    if (result.frameworks.length > 0) {
      lines.push(`├── Frameworks: ${result.frameworks.join(', ')}`);
    }
    lines.push(`└── Hosting: ${result.hosting}`);
    lines.push('');
  }

  // Timing
  lines.push(`Load Time: ${(result.loadTime / 1000).toFixed(1)}s | Probe Time: ${(result.probeTime / 1000).toFixed(1)}s`);
  lines.push('');

  // Verdict
  const riskEmoji = result.riskLevel === 'LOW' ? '🟢' :
                    result.riskLevel === 'MEDIUM' ? '🟡' : '🔴';

  lines.push(`${riskEmoji} VERDICT: ${result.verdict}`);
  lines.push(result.verdictReason);

  if (result.verdict === 'STATIC') {
    lines.push('');
    lines.push('⚠️ Warning: No backend activity detected.');
    lines.push('This may be a static landing page with no real product.');
  }

  return lines.join('\n');
}
