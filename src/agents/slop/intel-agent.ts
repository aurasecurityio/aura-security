/**
 * Intel Agent - SLOP Native
 *
 * Threat intelligence gathering and alerting.
 * Monitors CVE feeds, security advisories, and emerging threats.
 *
 * Tools:
 * - check-cve: Get details about a specific CVE
 * - search-cves: Search for CVEs by keyword, package, or date
 * - get-advisories: Get security advisories for packages
 * - check-package: Check if a package has known vulnerabilities
 * - get-trending: Get trending/recent vulnerabilities
 * - subscribe: Subscribe to alerts for packages/keywords
 * - get-threat-feed: Get latest threat intelligence feed
 */

import { SLOPAgent } from './base.js';
import {
  SLOPAgentConfig,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
} from './types.js';

// Intel Types
export interface CVEDetails {
  id: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvssScore: number;
  cvssVector?: string;
  publishedDate: string;
  modifiedDate: string;
  references: string[];
  affectedProducts: AffectedProduct[];
  exploitAvailable: boolean;
  patchAvailable: boolean;
  cwe?: string[];
}

export interface AffectedProduct {
  vendor: string;
  product: string;
  versions: string[];
  versionRange?: string;
}

export interface SecurityAdvisory {
  id: string;
  source: 'github' | 'npm' | 'snyk' | 'nvd' | 'osv';
  package: string;
  ecosystem: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  vulnerableVersions: string;
  patchedVersions?: string;
  cve?: string;
  url: string;
  publishedAt: string;
}

export interface ThreatFeedEntry {
  id: string;
  type: 'cve' | 'malware' | 'campaign' | 'ioc' | 'advisory';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  source: string;
  timestamp: string;
  tags: string[];
  indicators?: string[];
  relatedCVEs?: string[];
  url?: string;
}

export interface Subscription {
  id: string;
  type: 'package' | 'keyword' | 'cve-pattern' | 'ecosystem';
  value: string;
  alertLevel: 'all' | 'high' | 'critical';
  webhookUrl?: string;
  createdAt: string;
}

export interface PackageVulnCheck {
  package: string;
  version?: string;
  ecosystem: string;
  vulnerable: boolean;
  vulnerabilities: SecurityAdvisory[];
  recommendedVersion?: string;
  lastChecked: string;
}

// Known high-profile CVEs database (for demo/offline)
const KNOWN_CVES: Record<string, Partial<CVEDetails>> = {
  'CVE-2021-44228': {
    id: 'CVE-2021-44228',
    description: 'Apache Log4j2 Remote Code Execution (Log4Shell)',
    severity: 'critical',
    cvssScore: 10.0,
    exploitAvailable: true,
    patchAvailable: true,
  },
  'CVE-2021-45046': {
    id: 'CVE-2021-45046',
    description: 'Apache Log4j2 Thread Context DoS',
    severity: 'critical',
    cvssScore: 9.0,
    exploitAvailable: true,
    patchAvailable: true,
  },
  'CVE-2022-22965': {
    id: 'CVE-2022-22965',
    description: 'Spring Framework RCE (Spring4Shell)',
    severity: 'critical',
    cvssScore: 9.8,
    exploitAvailable: true,
    patchAvailable: true,
  },
  'CVE-2023-44487': {
    id: 'CVE-2023-44487',
    description: 'HTTP/2 Rapid Reset Attack',
    severity: 'high',
    cvssScore: 7.5,
    exploitAvailable: true,
    patchAvailable: true,
  },
  'CVE-2024-3094': {
    id: 'CVE-2024-3094',
    description: 'XZ Utils Backdoor',
    severity: 'critical',
    cvssScore: 10.0,
    exploitAvailable: true,
    patchAvailable: true,
  },
};

const INTEL_TOOLS: SLOPTool[] = [
  {
    name: 'check-cve',
    description: 'Get detailed information about a specific CVE',
    parameters: {
      cveId: {
        type: 'string',
        description: 'CVE ID (e.g., CVE-2021-44228)',
        required: true,
      },
    },
  },
  {
    name: 'search-cves',
    description: 'Search for CVEs by keyword, package, or criteria',
    parameters: {
      keyword: {
        type: 'string',
        description: 'Search keyword',
        required: false,
      },
      package: {
        type: 'string',
        description: 'Package name to search',
        required: false,
      },
      severity: {
        type: 'string',
        description: 'Filter by severity (critical, high, medium, low)',
        required: false,
      },
      daysBack: {
        type: 'number',
        description: 'Search CVEs from last N days (default: 30)',
        required: false,
      },
      limit: {
        type: 'number',
        description: 'Max results (default: 20)',
        required: false,
      },
    },
  },
  {
    name: 'get-advisories',
    description: 'Get security advisories for a package',
    parameters: {
      package: {
        type: 'string',
        description: 'Package name',
        required: true,
      },
      ecosystem: {
        type: 'string',
        description: 'Ecosystem (npm, pypi, maven, go, etc.)',
        required: false,
      },
    },
  },
  {
    name: 'check-package',
    description: 'Check if a package version has known vulnerabilities',
    parameters: {
      package: {
        type: 'string',
        description: 'Package name',
        required: true,
      },
      version: {
        type: 'string',
        description: 'Package version',
        required: false,
      },
      ecosystem: {
        type: 'string',
        description: 'Ecosystem (npm, pypi, maven, go)',
        required: false,
      },
    },
  },
  {
    name: 'get-trending',
    description: 'Get trending/recent high-profile vulnerabilities',
    parameters: {
      limit: {
        type: 'number',
        description: 'Number of results (default: 10)',
        required: false,
      },
    },
  },
  {
    name: 'subscribe',
    description: 'Subscribe to vulnerability alerts',
    parameters: {
      type: {
        type: 'string',
        description: 'Subscription type (package, keyword, ecosystem)',
        required: true,
      },
      value: {
        type: 'string',
        description: 'Value to monitor (package name, keyword, etc.)',
        required: true,
      },
      alertLevel: {
        type: 'string',
        description: 'Alert level (all, high, critical)',
        required: false,
      },
      webhookUrl: {
        type: 'string',
        description: 'Webhook URL for alerts',
        required: false,
      },
    },
  },
  {
    name: 'get-threat-feed',
    description: 'Get latest threat intelligence feed',
    parameters: {
      types: {
        type: 'array',
        description: 'Filter by types (cve, malware, campaign)',
        required: false,
      },
      limit: {
        type: 'number',
        description: 'Number of entries (default: 20)',
        required: false,
      },
    },
  },
  {
    name: 'check-ioc',
    description: 'Check if an indicator is malicious (IP, domain, hash)',
    parameters: {
      indicator: {
        type: 'string',
        description: 'Indicator to check (IP, domain, or file hash)',
        required: true,
      },
      type: {
        type: 'string',
        description: 'Indicator type (ip, domain, hash)',
        required: false,
      },
    },
  },
];

export class IntelAgent extends SLOPAgent {
  private subscriptions: Map<string, Subscription> = new Map();
  private cveCache: Map<string, CVEDetails> = new Map();
  private advisoryCache: Map<string, SecurityAdvisory[]> = new Map();

  constructor(config: SLOPAgentConfig) {
    super(config, INTEL_TOOLS);
  }

  async handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult> {
    const { tool, arguments: args } = call;

    try {
      switch (tool) {
        case 'check-cve':
          return { result: await this.checkCVE(args.cveId as string) };

        case 'search-cves':
          return { result: await this.searchCVEs({
            keyword: args.keyword as string | undefined,
            package: args.package as string | undefined,
            severity: args.severity as string | undefined,
            daysBack: args.daysBack as number | undefined,
            limit: args.limit as number | undefined,
          })};

        case 'get-advisories':
          return { result: await this.getAdvisories(
            args.package as string,
            args.ecosystem as string | undefined
          )};

        case 'check-package':
          return { result: await this.checkPackage(
            args.package as string,
            args.version as string | undefined,
            args.ecosystem as string | undefined
          )};

        case 'get-trending':
          return { result: await this.getTrending(args.limit as number | undefined) };

        case 'subscribe':
          return { result: await this.subscribe({
            type: args.type as 'package' | 'keyword' | 'ecosystem',
            value: args.value as string,
            alertLevel: args.alertLevel as 'all' | 'high' | 'critical' | undefined,
            webhookUrl: args.webhookUrl as string | undefined,
          })};

        case 'get-threat-feed':
          return { result: await this.getThreatFeed(
            args.types as string[] | undefined,
            args.limit as number | undefined
          )};

        case 'check-ioc':
          return { result: await this.checkIOC(
            args.indicator as string,
            args.type as string | undefined
          )};

        default:
          return { error: `Unknown tool: ${tool}` };
      }
    } catch (error) {
      return { error: String(error) };
    }
  }

  /**
   * Get CVE details
   */
  private async checkCVE(cveId: string): Promise<CVEDetails | null> {
    // Normalize CVE ID
    const normalizedId = cveId.toUpperCase();

    // Check cache
    if (this.cveCache.has(normalizedId)) {
      return this.cveCache.get(normalizedId)!;
    }

    // Check known CVEs
    if (KNOWN_CVES[normalizedId]) {
      const known = KNOWN_CVES[normalizedId];
      const cve: CVEDetails = {
        id: normalizedId,
        description: known.description || 'No description available',
        severity: known.severity || 'medium',
        cvssScore: known.cvssScore || 5.0,
        publishedDate: '2024-01-01',
        modifiedDate: new Date().toISOString().split('T')[0],
        references: [],
        affectedProducts: [],
        exploitAvailable: known.exploitAvailable || false,
        patchAvailable: known.patchAvailable || false,
      };

      this.cveCache.set(normalizedId, cve);
      return cve;
    }

    // Try NVD API
    try {
      const response = await fetch(
        `https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=${normalizedId}`,
        {
          headers: { 'Accept': 'application/json' },
        }
      );

      if (response.ok) {
        const data = await response.json() as {
          vulnerabilities?: Array<{
            cve: {
              id: string;
              descriptions: Array<{ value: string }>;
              metrics?: {
                cvssMetricV31?: Array<{ cvssData: { baseScore: number; baseSeverity: string; vectorString: string } }>;
              };
              published: string;
              lastModified: string;
              references: Array<{ url: string }>;
            };
          }>;
        };

        const vuln = data.vulnerabilities?.[0]?.cve;
        if (vuln) {
          const cvssData = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
          const cve: CVEDetails = {
            id: vuln.id,
            description: vuln.descriptions?.[0]?.value || 'No description',
            severity: this.cvssToSeverity(cvssData?.baseScore || 0),
            cvssScore: cvssData?.baseScore || 0,
            cvssVector: cvssData?.vectorString,
            publishedDate: vuln.published,
            modifiedDate: vuln.lastModified,
            references: vuln.references?.map(r => r.url) || [],
            affectedProducts: [],
            exploitAvailable: false,
            patchAvailable: false,
          };

          this.cveCache.set(normalizedId, cve);
          return cve;
        }
      }
    } catch {
      // NVD API failed
    }

    return null;
  }

  /**
   * Search CVEs
   */
  private async searchCVEs(params: {
    keyword?: string;
    package?: string;
    severity?: string;
    daysBack?: number;
    limit?: number;
  }): Promise<{ cves: CVEDetails[]; total: number }> {
    const { keyword, severity, daysBack = 30, limit = 20 } = params;

    // For demo, return known CVEs filtered
    let results = Object.values(KNOWN_CVES).map(k => ({
      id: k.id!,
      description: k.description!,
      severity: k.severity!,
      cvssScore: k.cvssScore!,
      publishedDate: '2024-01-01',
      modifiedDate: new Date().toISOString().split('T')[0],
      references: [],
      affectedProducts: [],
      exploitAvailable: k.exploitAvailable!,
      patchAvailable: k.patchAvailable!,
    })) as CVEDetails[];

    if (keyword) {
      const kw = keyword.toLowerCase();
      results = results.filter(c =>
        c.description.toLowerCase().includes(kw) ||
        c.id.toLowerCase().includes(kw)
      );
    }

    if (severity) {
      results = results.filter(c => c.severity === severity);
    }

    return {
      cves: results.slice(0, limit),
      total: results.length,
    };
  }

  /**
   * Get advisories for a package
   */
  private async getAdvisories(packageName: string, ecosystem?: string): Promise<{
    package: string;
    advisories: SecurityAdvisory[];
    total: number;
  }> {
    const cacheKey = `${ecosystem || 'all'}:${packageName}`;

    if (this.advisoryCache.has(cacheKey)) {
      const cached = this.advisoryCache.get(cacheKey)!;
      return { package: packageName, advisories: cached, total: cached.length };
    }

    const advisories: SecurityAdvisory[] = [];

    // Try GitHub Advisory Database
    try {
      const query = `
        query {
          securityVulnerabilities(first: 20, ecosystem: ${ecosystem?.toUpperCase() || 'NPM'}, package: "${packageName}") {
            nodes {
              advisory {
                ghsaId
                summary
                description
                severity
                publishedAt
                references { url }
              }
              vulnerableVersionRange
              firstPatchedVersion { identifier }
            }
          }
        }
      `;

      const response = await fetch('https://api.github.com/graphql', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `bearer ${process.env.GITHUB_TOKEN || ''}`,
        },
        body: JSON.stringify({ query }),
      });

      if (response.ok) {
        const data = await response.json() as {
          data?: {
            securityVulnerabilities?: {
              nodes: Array<{
                advisory: {
                  ghsaId: string;
                  summary: string;
                  description: string;
                  severity: string;
                  publishedAt: string;
                  references: Array<{ url: string }>;
                };
                vulnerableVersionRange: string;
                firstPatchedVersion?: { identifier: string };
              }>;
            };
          };
        };

        const nodes = data.data?.securityVulnerabilities?.nodes || [];
        for (const node of nodes) {
          advisories.push({
            id: node.advisory.ghsaId,
            source: 'github',
            package: packageName,
            ecosystem: ecosystem || 'npm',
            severity: node.advisory.severity.toLowerCase() as SecurityAdvisory['severity'],
            title: node.advisory.summary,
            description: node.advisory.description,
            vulnerableVersions: node.vulnerableVersionRange,
            patchedVersions: node.firstPatchedVersion?.identifier,
            url: node.advisory.references?.[0]?.url || '',
            publishedAt: node.advisory.publishedAt,
          });
        }
      }
    } catch {
      // GitHub API failed, continue with other sources
    }

    // Try OSV
    try {
      const response = await fetch('https://api.osv.dev/v1/query', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          package: { name: packageName, ecosystem: ecosystem || 'npm' },
        }),
      });

      if (response.ok) {
        const data = await response.json() as {
          vulns?: Array<{
            id: string;
            summary: string;
            details: string;
            severity?: Array<{ type: string; score: string }>;
            published: string;
            affected: Array<{
              ranges: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
            }>;
            references: Array<{ url: string }>;
          }>;
        };

        for (const vuln of data.vulns || []) {
          if (!advisories.find(a => a.id === vuln.id)) {
            advisories.push({
              id: vuln.id,
              source: 'osv',
              package: packageName,
              ecosystem: ecosystem || 'npm',
              severity: this.osvSeverityToLevel(vuln.severity),
              title: vuln.summary,
              description: vuln.details,
              vulnerableVersions: this.extractVersionRange(vuln.affected),
              url: vuln.references?.[0]?.url || '',
              publishedAt: vuln.published,
            });
          }
        }
      }
    } catch {
      // OSV API failed
    }

    this.advisoryCache.set(cacheKey, advisories);

    return { package: packageName, advisories, total: advisories.length };
  }

  /**
   * Check package for vulnerabilities
   */
  private async checkPackage(
    packageName: string,
    version?: string,
    ecosystem?: string
  ): Promise<PackageVulnCheck> {
    const { advisories } = await this.getAdvisories(packageName, ecosystem);

    let vulnerable = false;
    let matchingAdvisories = advisories;

    if (version) {
      matchingAdvisories = advisories.filter(a =>
        this.versionMatches(version, a.vulnerableVersions)
      );
      vulnerable = matchingAdvisories.length > 0;
    } else {
      vulnerable = advisories.length > 0;
    }

    // Find recommended version
    let recommendedVersion: string | undefined;
    for (const advisory of advisories) {
      if (advisory.patchedVersions) {
        recommendedVersion = advisory.patchedVersions;
        break;
      }
    }

    return {
      package: packageName,
      version,
      ecosystem: ecosystem || 'npm',
      vulnerable,
      vulnerabilities: matchingAdvisories,
      recommendedVersion,
      lastChecked: new Date().toISOString(),
    };
  }

  /**
   * Get trending vulnerabilities
   */
  private async getTrending(limit = 10): Promise<{
    trending: CVEDetails[];
    lastUpdated: string;
  }> {
    // Return known high-profile CVEs
    const trending = Object.values(KNOWN_CVES)
      .map(k => ({
        id: k.id!,
        description: k.description!,
        severity: k.severity!,
        cvssScore: k.cvssScore!,
        publishedDate: '2024-01-01',
        modifiedDate: new Date().toISOString().split('T')[0],
        references: [],
        affectedProducts: [],
        exploitAvailable: k.exploitAvailable!,
        patchAvailable: k.patchAvailable!,
      }))
      .sort((a, b) => b.cvssScore - a.cvssScore)
      .slice(0, limit);

    return {
      trending,
      lastUpdated: new Date().toISOString(),
    };
  }

  /**
   * Subscribe to alerts
   */
  private async subscribe(params: {
    type: 'package' | 'keyword' | 'ecosystem';
    value: string;
    alertLevel?: 'all' | 'high' | 'critical';
    webhookUrl?: string;
  }): Promise<{ success: boolean; subscription: Subscription }> {
    const subscription: Subscription = {
      id: `sub-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`,
      type: params.type,
      value: params.value,
      alertLevel: params.alertLevel || 'high',
      webhookUrl: params.webhookUrl,
      createdAt: new Date().toISOString(),
    };

    this.subscriptions.set(subscription.id, subscription);

    await this.writeMemory(`intel:subscription:${subscription.id}`, subscription);

    return { success: true, subscription };
  }

  /**
   * Get threat intelligence feed
   */
  private async getThreatFeed(
    types?: string[],
    limit = 20
  ): Promise<{ entries: ThreatFeedEntry[]; lastUpdated: string }> {
    const entries: ThreatFeedEntry[] = [];

    // Generate feed from known CVEs
    for (const cve of Object.values(KNOWN_CVES)) {
      entries.push({
        id: cve.id!,
        type: 'cve',
        severity: cve.severity!,
        title: cve.description!,
        description: `${cve.description}. CVSS Score: ${cve.cvssScore}`,
        source: 'nvd',
        timestamp: new Date().toISOString(),
        tags: ['vulnerability', cve.severity!],
        relatedCVEs: [cve.id!],
      });
    }

    // Add some threat intelligence entries
    entries.push({
      id: 'threat-supply-chain-2024',
      type: 'campaign',
      severity: 'high',
      title: 'Increased Supply Chain Attacks on NPM Packages',
      description: 'Security researchers have observed an increase in supply chain attacks targeting popular NPM packages.',
      source: 'intel-feed',
      timestamp: new Date().toISOString(),
      tags: ['supply-chain', 'npm', 'malware'],
    });

    let filtered = entries;
    if (types && types.length > 0) {
      filtered = entries.filter(e => types.includes(e.type));
    }

    return {
      entries: filtered.slice(0, limit),
      lastUpdated: new Date().toISOString(),
    };
  }

  /**
   * Check if indicator is malicious
   */
  private async checkIOC(indicator: string, type?: string): Promise<{
    indicator: string;
    type: string;
    malicious: boolean;
    confidence: number;
    sources: string[];
    details: string;
  }> {
    // Detect type if not provided
    const detectedType = type || this.detectIOCType(indicator);

    // For demo, return a simulated result
    // In production, would query threat intel APIs
    return {
      indicator,
      type: detectedType,
      malicious: false,
      confidence: 0,
      sources: [],
      details: 'No threat intelligence available for this indicator',
    };
  }

  // ===== Helper Methods =====

  private cvssToSeverity(score: number): CVEDetails['severity'] {
    if (score >= 9.0) return 'critical';
    if (score >= 7.0) return 'high';
    if (score >= 4.0) return 'medium';
    return 'low';
  }

  private osvSeverityToLevel(severity?: Array<{ type: string; score: string }>): SecurityAdvisory['severity'] {
    if (!severity || severity.length === 0) return 'medium';
    const cvss = severity.find(s => s.type === 'CVSS_V3');
    if (cvss) {
      const score = parseFloat(cvss.score);
      return this.cvssToSeverity(score);
    }
    return 'medium';
  }

  private extractVersionRange(affected: Array<{
    ranges: Array<{ events: Array<{ introduced?: string; fixed?: string }> }>;
  }>): string {
    const ranges: string[] = [];
    for (const a of affected) {
      for (const range of a.ranges || []) {
        const introduced = range.events?.find(e => e.introduced)?.introduced;
        const fixed = range.events?.find(e => e.fixed)?.fixed;
        if (introduced && fixed) {
          ranges.push(`>=${introduced} <${fixed}`);
        } else if (introduced) {
          ranges.push(`>=${introduced}`);
        }
      }
    }
    return ranges.join(' || ') || '*';
  }

  private versionMatches(version: string, range: string): boolean {
    // Simplified version matching
    // In production, use semver library
    if (range === '*') return true;
    if (range.includes(version)) return true;
    return false;
  }

  private detectIOCType(indicator: string): string {
    // IP address
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) {
      return 'ip';
    }
    // Domain
    if (/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(indicator)) {
      return 'domain';
    }
    // SHA256
    if (/^[a-fA-F0-9]{64}$/.test(indicator)) {
      return 'hash-sha256';
    }
    // MD5
    if (/^[a-fA-F0-9]{32}$/.test(indicator)) {
      return 'hash-md5';
    }
    return 'unknown';
  }
}

// Export factory function
export function createIntelAgent(port = 4008, coordinatorUrl?: string): IntelAgent {
  return new IntelAgent({
    id: 'intel',
    name: 'Intel Agent',
    port,
    description: 'Threat intelligence - CVE monitoring, advisories, and threat feeds',
    coordinatorUrl,
  });
}
