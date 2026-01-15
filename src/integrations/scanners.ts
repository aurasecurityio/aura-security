// Scanner Parsers - Parse output from security scanning tools
// Supports: Snyk, Trivy, Semgrep, npm audit, and custom formats

import type { EvidenceBundle } from '../types/events.js';

export interface VulnerabilityFinding {
  id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description?: string;
  package?: string;
  version?: string;
  fixedIn?: string;
  cve?: string;
  cwes?: string[];
  file?: string;
  line?: number;
}

export interface ScanResult {
  scanner: string;
  timestamp: string;
  findings: VulnerabilityFinding[];
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  raw?: string;
}

export abstract class ScannerParser {
  abstract name: string;
  abstract parse(input: string | object): ScanResult;

  toEvidenceBundle(result: ScanResult): Partial<EvidenceBundle> {
    const vulnScan = `critical: ${result.summary.critical}\nhigh: ${result.summary.high}\nmedium: ${result.summary.medium}\nlow: ${result.summary.low}`;
    return { vuln_scan: vulnScan };
  }

  protected normalizeSeverity(sev: string): VulnerabilityFinding['severity'] {
    const s = sev.toLowerCase();
    if (s === 'critical' || s === 'crit') return 'critical';
    if (s === 'high' || s === 'h') return 'high';
    if (s === 'medium' || s === 'med' || s === 'moderate') return 'medium';
    return 'low';
  }
}

// Snyk JSON output parser
export class SnykParser extends ScannerParser {
  name = 'snyk';

  parse(input: string | object): ScanResult {
    const data = typeof input === 'string' ? JSON.parse(input) : input;
    const findings: VulnerabilityFinding[] = [];

    const vulnerabilities = data.vulnerabilities || [];
    for (const vuln of vulnerabilities) {
      findings.push({
        id: vuln.id,
        severity: this.normalizeSeverity(vuln.severity),
        title: vuln.title,
        description: vuln.description,
        package: vuln.packageName || vuln.moduleName,
        version: vuln.version,
        fixedIn: vuln.fixedIn?.[0],
        cve: vuln.identifiers?.CVE?.[0],
        cwes: vuln.identifiers?.CWE
      });
    }

    return {
      scanner: this.name,
      timestamp: new Date().toISOString(),
      findings,
      summary: this.summarize(findings),
      raw: typeof input === 'string' ? input : JSON.stringify(input)
    };
  }

  private summarize(findings: VulnerabilityFinding[]): ScanResult['summary'] {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    };
  }
}

// Trivy JSON output parser
export class TrivyParser extends ScannerParser {
  name = 'trivy';

  parse(input: string | object): ScanResult {
    const data = typeof input === 'string' ? JSON.parse(input) : input;
    const findings: VulnerabilityFinding[] = [];

    const results = data.Results || [];
    for (const result of results) {
      const vulns = result.Vulnerabilities || [];
      for (const vuln of vulns) {
        findings.push({
          id: vuln.VulnerabilityID,
          severity: this.normalizeSeverity(vuln.Severity),
          title: vuln.Title || vuln.VulnerabilityID,
          description: vuln.Description,
          package: vuln.PkgName,
          version: vuln.InstalledVersion,
          fixedIn: vuln.FixedVersion,
          cve: vuln.VulnerabilityID.startsWith('CVE') ? vuln.VulnerabilityID : undefined,
          cwes: vuln.CweIDs
        });
      }
    }

    return {
      scanner: this.name,
      timestamp: new Date().toISOString(),
      findings,
      summary: this.summarize(findings),
      raw: typeof input === 'string' ? input : JSON.stringify(input)
    };
  }

  private summarize(findings: VulnerabilityFinding[]): ScanResult['summary'] {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    };
  }
}

// Semgrep JSON output parser (SAST)
export class SemgrepParser extends ScannerParser {
  name = 'semgrep';

  parse(input: string | object): ScanResult {
    const data = typeof input === 'string' ? JSON.parse(input) : input;
    const findings: VulnerabilityFinding[] = [];

    const results = data.results || [];
    for (const result of results) {
      findings.push({
        id: result.check_id,
        severity: this.normalizeSeverity(result.extra?.severity || 'medium'),
        title: result.extra?.message || result.check_id,
        description: result.extra?.metadata?.description,
        file: result.path,
        line: result.start?.line,
        cwes: result.extra?.metadata?.cwe ? [result.extra.metadata.cwe] : undefined
      });
    }

    return {
      scanner: this.name,
      timestamp: new Date().toISOString(),
      findings,
      summary: this.summarize(findings),
      raw: typeof input === 'string' ? input : JSON.stringify(input)
    };
  }

  private summarize(findings: VulnerabilityFinding[]): ScanResult['summary'] {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    };
  }
}

// npm audit JSON output parser
export class NpmAuditParser extends ScannerParser {
  name = 'npm-audit';

  parse(input: string | object): ScanResult {
    const data = typeof input === 'string' ? JSON.parse(input) : input;
    const findings: VulnerabilityFinding[] = [];

    // npm audit v2 format
    const vulnerabilities = data.vulnerabilities || {};
    for (const [pkgName, vuln] of Object.entries(vulnerabilities)) {
      const v = vuln as Record<string, unknown>;
      findings.push({
        id: `npm-${pkgName}`,
        severity: this.normalizeSeverity(v.severity as string || 'medium'),
        title: v.title as string || `Vulnerability in ${pkgName}`,
        description: v.url as string,
        package: pkgName,
        version: v.range as string,
        fixedIn: v.fixAvailable ? 'Update available' : undefined
      });
    }

    return {
      scanner: this.name,
      timestamp: new Date().toISOString(),
      findings,
      summary: this.summarize(findings),
      raw: typeof input === 'string' ? input : JSON.stringify(input)
    };
  }

  private summarize(findings: VulnerabilityFinding[]): ScanResult['summary'] {
    return {
      critical: findings.filter(f => f.severity === 'critical').length,
      high: findings.filter(f => f.severity === 'high').length,
      medium: findings.filter(f => f.severity === 'medium').length,
      low: findings.filter(f => f.severity === 'low').length
    };
  }
}

// Generic parser for simple formats
export class GenericParser extends ScannerParser {
  name = 'generic';

  parse(input: string | object): ScanResult {
    // Parse simple format like "critical: 5\nhigh: 10"
    if (typeof input === 'string') {
      const summary = { critical: 0, high: 0, medium: 0, low: 0 };

      const lines = input.split('\n');
      for (const line of lines) {
        const match = line.match(/(critical|high|medium|low)[:\s]+(\d+)/i);
        if (match) {
          const sev = match[1].toLowerCase() as keyof typeof summary;
          summary[sev] = parseInt(match[2], 10);
        }
      }

      return {
        scanner: this.name,
        timestamp: new Date().toISOString(),
        findings: [],
        summary,
        raw: input
      };
    }

    // Object format
    const data = input as Record<string, unknown>;
    return {
      scanner: this.name,
      timestamp: new Date().toISOString(),
      findings: [],
      summary: {
        critical: (data.critical as number) || 0,
        high: (data.high as number) || 0,
        medium: (data.medium as number) || 0,
        low: (data.low as number) || 0
      },
      raw: JSON.stringify(input)
    };
  }
}

// Factory function to get appropriate parser
export function getParser(scannerName: string): ScannerParser {
  switch (scannerName.toLowerCase()) {
    case 'snyk': return new SnykParser();
    case 'trivy': return new TrivyParser();
    case 'semgrep': return new SemgrepParser();
    case 'npm':
    case 'npm-audit': return new NpmAuditParser();
    default: return new GenericParser();
  }
}
