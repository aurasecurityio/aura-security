// Output Format Generators
// Supports: SARIF 2.1.0, JUnit XML, JSON Summary, GitLab Security Report

import type { LocalScanResult, PackageFinding, SecretFinding, IaCFinding, DockerfileFinding } from '../integrations/local-scanner.js';

// ============ SARIF 2.1.0 Format ============
// Static Analysis Results Interchange Format
// Used by GitHub Code Scanning, VS Code, etc.

export interface SARIFRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription?: {
    text: string;
  };
  helpUri?: string;
  defaultConfiguration?: {
    level: 'none' | 'note' | 'warning' | 'error';
  };
  properties?: {
    tags?: string[];
    precision?: string;
    'security-severity'?: string;
  };
}

export interface SARIFResult {
  ruleId: string;
  level: 'none' | 'note' | 'warning' | 'error';
  message: {
    text: string;
  };
  locations?: Array<{
    physicalLocation: {
      artifactLocation: {
        uri: string;
        uriBaseId?: string;
      };
      region?: {
        startLine: number;
        startColumn?: number;
        endLine?: number;
        endColumn?: number;
      };
    };
  }>;
  fixes?: Array<{
    description: {
      text: string;
    };
  }>;
  properties?: Record<string, unknown>;
}

export interface SARIFRun {
  tool: {
    driver: {
      name: string;
      informationUri: string;
      version: string;
      rules: SARIFRule[];
    };
  };
  results: SARIFResult[];
  invocations?: Array<{
    executionSuccessful: boolean;
    endTimeUtc?: string;
  }>;
}

export interface SARIFReport {
  $schema: string;
  version: '2.1.0';
  runs: SARIFRun[];
}

// Severity to SARIF level mapping
function severityToLevel(severity: string): 'none' | 'note' | 'warning' | 'error' {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    case 'low':
      return 'note';
    default:
      return 'none';
  }
}

// Severity to security-severity score (for GitHub)
function severityToScore(severity: string): string {
  switch (severity.toLowerCase()) {
    case 'critical': return '9.0';
    case 'high': return '7.0';
    case 'medium': return '5.0';
    case 'low': return '3.0';
    default: return '1.0';
  }
}

// Generate SARIF report from scan results
export function toSARIF(result: LocalScanResult, targetPath?: string): SARIFReport {
  const rules: SARIFRule[] = [];
  const results: SARIFResult[] = [];
  const ruleIds = new Set<string>();

  // Helper to add rule if not exists
  const addRule = (id: string, name: string, description: string, severity: string, tags: string[]) => {
    if (!ruleIds.has(id)) {
      ruleIds.add(id);
      rules.push({
        id,
        name,
        shortDescription: { text: description },
        defaultConfiguration: { level: severityToLevel(severity) },
        properties: {
          tags,
          'security-severity': severityToScore(severity)
        }
      });
    }
  };

  // Process secrets
  for (const secret of result.secrets) {
    const ruleId = `secret/${secret.type.toLowerCase().replace(/\s+/g, '-')}`;
    addRule(
      ruleId,
      `Secret: ${secret.type}`,
      `Potential secret or credential found: ${secret.type}`,
      secret.severity,
      ['security', 'secret-detection']
    );

    results.push({
      ruleId,
      level: severityToLevel(secret.severity),
      message: { text: `Found ${secret.type} in source code` },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: secret.file.replace(targetPath ? targetPath + '/' : '', ''),
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: secret.line
          }
        }
      }]
    });
  }

  // Process package vulnerabilities
  for (const pkg of result.packages) {
    const ruleId = pkg.vulnId ? `vuln/${pkg.vulnId}` : `vuln/${pkg.name}`;
    addRule(
      ruleId,
      pkg.vulnId || `Vulnerability in ${pkg.name}`,
      pkg.title || `Security vulnerability in ${pkg.name}@${pkg.version}`,
      pkg.severity,
      ['security', 'dependency', 'vulnerability']
    );

    results.push({
      ruleId,
      level: severityToLevel(pkg.severity),
      message: {
        text: `${pkg.name}@${pkg.version}: ${pkg.title || pkg.vulnId || 'vulnerability found'}${pkg.fixedVersion ? ` (fix: ${pkg.fixedVersion})` : ''}`
      },
      fixes: pkg.fixedVersion ? [{
        description: { text: `Upgrade to version ${pkg.fixedVersion}` }
      }] : undefined
    });
  }

  // Process SAST findings
  for (const sast of result.sastFindings) {
    const ruleId = `sast/${sast.rule.replace(/[^a-zA-Z0-9-]/g, '-')}`;
    addRule(
      ruleId,
      sast.rule,
      sast.message,
      sast.severity,
      ['security', 'sast']
    );

    results.push({
      ruleId,
      level: severityToLevel(sast.severity),
      message: { text: sast.message },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: sast.file.replace(targetPath ? targetPath + '/' : '', ''),
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: sast.line
          }
        }
      }]
    });
  }

  // Process IaC findings
  for (const iac of result.iacFindings) {
    const ruleId = `iac/${iac.checkId}`;
    addRule(
      ruleId,
      iac.checkId,
      iac.title,
      iac.severity,
      ['security', 'iac', iac.checkType]
    );

    results.push({
      ruleId,
      level: severityToLevel(iac.severity),
      message: { text: `${iac.title} - Resource: ${iac.resource}` },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: iac.file.replace(targetPath ? targetPath + '/' : '', ''),
            uriBaseId: '%SRCROOT%'
          }
        }
      }],
      fixes: iac.guideline ? [{
        description: { text: iac.guideline }
      }] : undefined
    });
  }

  // Process Dockerfile findings
  for (const docker of result.dockerfileFindings) {
    const ruleId = `dockerfile/${docker.code}`;
    addRule(
      ruleId,
      docker.code,
      docker.message,
      docker.severity,
      ['security', 'dockerfile', 'container']
    );

    results.push({
      ruleId,
      level: severityToLevel(docker.severity),
      message: { text: docker.message },
      locations: [{
        physicalLocation: {
          artifactLocation: {
            uri: docker.file.replace(targetPath ? targetPath + '/' : '', ''),
            uriBaseId: '%SRCROOT%'
          },
          region: {
            startLine: docker.line
          }
        }
      }]
    });
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [{
      tool: {
        driver: {
          name: 'SlopAuditor',
          informationUri: 'https://github.com/slopsecurityadmin/slop-security-auditor',
          version: '0.2.0',
          rules
        }
      },
      results,
      invocations: [{
        executionSuccessful: true,
        endTimeUtc: new Date().toISOString()
      }]
    }]
  };
}

// ============ JUnit XML Format ============

export function toJUnit(result: LocalScanResult): string {
  const totalTests = result.secrets.length + result.packages.length +
                     result.sastFindings.length + result.iacFindings.length +
                     result.dockerfileFindings.length;

  const failures = result.secrets.filter(s => s.severity === 'critical' || s.severity === 'high').length +
                   result.packages.filter(p => p.severity === 'critical' || p.severity === 'high').length +
                   result.iacFindings.filter(i => i.severity === 'critical' || i.severity === 'high').length +
                   result.dockerfileFindings.filter(d => d.severity === 'critical' || d.severity === 'high').length;

  let xml = `<?xml version="1.0" encoding="UTF-8"?>
<testsuites name="SlopAuditor Security Scan" tests="${totalTests}" failures="${failures}" time="0">
  <testsuite name="Secrets" tests="${result.secrets.length}" failures="${result.secrets.filter(s => s.severity === 'critical' || s.severity === 'high').length}">
`;

  for (const secret of result.secrets) {
    const isFailure = secret.severity === 'critical' || secret.severity === 'high';
    xml += `    <testcase name="${escapeXml(secret.type)}" classname="${escapeXml(secret.file)}">\n`;
    if (isFailure) {
      xml += `      <failure message="${escapeXml(secret.type)} found at line ${secret.line}" type="${secret.severity}">${escapeXml(secret.snippet)}</failure>\n`;
    }
    xml += `    </testcase>\n`;
  }

  xml += `  </testsuite>
  <testsuite name="Vulnerabilities" tests="${result.packages.length}" failures="${result.packages.filter(p => p.severity === 'critical' || p.severity === 'high').length}">
`;

  for (const pkg of result.packages) {
    const isFailure = pkg.severity === 'critical' || pkg.severity === 'high';
    xml += `    <testcase name="${escapeXml(pkg.name)}@${escapeXml(pkg.version)}" classname="dependencies">\n`;
    if (isFailure) {
      xml += `      <failure message="${escapeXml(pkg.vulnId || 'vulnerability')}" type="${pkg.severity}">${escapeXml(pkg.title || '')}</failure>\n`;
    }
    xml += `    </testcase>\n`;
  }

  xml += `  </testsuite>
  <testsuite name="IaC" tests="${result.iacFindings.length}" failures="${result.iacFindings.filter(i => i.severity === 'critical' || i.severity === 'high').length}">
`;

  for (const iac of result.iacFindings) {
    const isFailure = iac.severity === 'critical' || iac.severity === 'high';
    xml += `    <testcase name="${escapeXml(iac.checkId)}" classname="${escapeXml(iac.file)}">\n`;
    if (isFailure) {
      xml += `      <failure message="${escapeXml(iac.title)}" type="${iac.severity}">${escapeXml(iac.guideline || '')}</failure>\n`;
    }
    xml += `    </testcase>\n`;
  }

  xml += `  </testsuite>
</testsuites>`;

  return xml;
}

function escapeXml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&apos;');
}

// ============ GitLab Security Report Format ============

export interface GitLabVulnerability {
  id: string;
  category: string;
  name: string;
  message: string;
  description: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info' | 'Unknown';
  confidence?: 'High' | 'Medium' | 'Low' | 'Unknown';
  scanner: {
    id: string;
    name: string;
  };
  location: {
    file?: string;
    start_line?: number;
    end_line?: number;
    dependency?: {
      package: { name: string };
      version: string;
    };
  };
  identifiers: Array<{
    type: string;
    name: string;
    value: string;
    url?: string;
  }>;
  solution?: string;
}

export interface GitLabSecurityReport {
  version: string;
  vulnerabilities: GitLabVulnerability[];
  scan: {
    analyzer: {
      id: string;
      name: string;
      version: string;
      vendor: { name: string };
    };
    scanner: {
      id: string;
      name: string;
      version: string;
      vendor: { name: string };
    };
    type: string;
    start_time: string;
    end_time: string;
    status: 'success' | 'failure';
  };
}

function toGitLabSeverity(severity: string): GitLabVulnerability['severity'] {
  switch (severity.toLowerCase()) {
    case 'critical': return 'Critical';
    case 'high': return 'High';
    case 'medium': return 'Medium';
    case 'low': return 'Low';
    default: return 'Unknown';
  }
}

export function toGitLabReport(result: LocalScanResult, reportType: 'sast' | 'dependency_scanning' | 'secret_detection'): GitLabSecurityReport {
  const vulnerabilities: GitLabVulnerability[] = [];
  const startTime = new Date().toISOString();

  if (reportType === 'secret_detection') {
    for (const secret of result.secrets) {
      vulnerabilities.push({
        id: `secret-${Buffer.from(secret.file + secret.line).toString('base64').substring(0, 16)}`,
        category: 'secret_detection',
        name: secret.type,
        message: `${secret.type} detected`,
        description: `Potential secret found in ${secret.file}`,
        severity: toGitLabSeverity(secret.severity),
        confidence: 'High',
        scanner: {
          id: 'slop-auditor-secrets',
          name: 'SlopAuditor Secret Detection'
        },
        location: {
          file: secret.file,
          start_line: secret.line,
          end_line: secret.line
        },
        identifiers: [{
          type: 'slop_auditor_secret',
          name: secret.type,
          value: secret.type
        }]
      });
    }
  }

  if (reportType === 'dependency_scanning') {
    for (const pkg of result.packages) {
      vulnerabilities.push({
        id: pkg.vulnId || `dep-${Buffer.from(pkg.name + pkg.version).toString('base64').substring(0, 16)}`,
        category: 'dependency_scanning',
        name: pkg.vulnId || `Vulnerability in ${pkg.name}`,
        message: pkg.title || `Security vulnerability in ${pkg.name}`,
        description: `${pkg.name}@${pkg.version} has a known vulnerability`,
        severity: toGitLabSeverity(pkg.severity),
        scanner: {
          id: 'slop-auditor-deps',
          name: 'SlopAuditor Dependency Scanning'
        },
        location: {
          dependency: {
            package: { name: pkg.name },
            version: pkg.version
          }
        },
        identifiers: pkg.vulnId ? [{
          type: pkg.vulnId.startsWith('CVE') ? 'cve' : 'ghsa',
          name: pkg.vulnId,
          value: pkg.vulnId,
          url: pkg.vulnId.startsWith('CVE')
            ? `https://nvd.nist.gov/vuln/detail/${pkg.vulnId}`
            : `https://github.com/advisories/${pkg.vulnId}`
        }] : [],
        solution: pkg.fixedVersion ? `Upgrade to version ${pkg.fixedVersion}` : undefined
      });
    }
  }

  if (reportType === 'sast') {
    for (const sast of result.sastFindings) {
      vulnerabilities.push({
        id: `sast-${Buffer.from(sast.file + sast.line + sast.rule).toString('base64').substring(0, 16)}`,
        category: 'sast',
        name: sast.rule,
        message: sast.message,
        description: sast.message,
        severity: toGitLabSeverity(sast.severity),
        scanner: {
          id: 'slop-auditor-sast',
          name: 'SlopAuditor SAST'
        },
        location: {
          file: sast.file,
          start_line: sast.line
        },
        identifiers: [{
          type: 'semgrep_rule',
          name: sast.rule,
          value: sast.rule
        }]
      });
    }

    // Include IaC in SAST report
    for (const iac of result.iacFindings) {
      vulnerabilities.push({
        id: `iac-${Buffer.from(iac.file + iac.checkId).toString('base64').substring(0, 16)}`,
        category: 'sast',
        name: iac.checkId,
        message: iac.title,
        description: iac.guideline || iac.title,
        severity: toGitLabSeverity(iac.severity),
        scanner: {
          id: 'slop-auditor-iac',
          name: 'SlopAuditor IaC'
        },
        location: {
          file: iac.file
        },
        identifiers: [{
          type: 'checkov_check',
          name: iac.checkId,
          value: iac.checkId
        }],
        solution: iac.guideline
      });
    }
  }

  return {
    version: '15.0.0',
    vulnerabilities,
    scan: {
      analyzer: {
        id: 'slop-auditor',
        name: 'SlopAuditor',
        version: '0.2.0',
        vendor: { name: 'SlopAuditor' }
      },
      scanner: {
        id: 'slop-auditor',
        name: 'SlopAuditor',
        version: '0.2.0',
        vendor: { name: 'SlopAuditor' }
      },
      type: reportType,
      start_time: startTime,
      end_time: new Date().toISOString(),
      status: 'success'
    }
  };
}

// ============ JSON Summary Format ============

export interface JSONSummary {
  scan: {
    path: string;
    timestamp: string;
    duration?: number;
    tools: string[];
    languages: string[];
  };
  summary: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  findings: {
    secrets: number;
    vulnerabilities: number;
    sast: number;
    iac: number;
    dockerfile: number;
  };
  exitCode: number;
}

export function toJSONSummary(result: LocalScanResult): JSONSummary {
  const critical = result.secrets.filter(s => s.severity === 'critical').length +
                   result.packages.filter(p => p.severity === 'critical').length +
                   result.iacFindings.filter(i => i.severity === 'critical').length +
                   result.dockerfileFindings.filter(d => d.severity === 'critical').length;

  const high = result.secrets.filter(s => s.severity === 'high').length +
               result.packages.filter(p => p.severity === 'high').length +
               result.iacFindings.filter(i => i.severity === 'high').length +
               result.dockerfileFindings.filter(d => d.severity === 'high').length;

  const medium = result.secrets.filter(s => s.severity === 'medium').length +
                 result.packages.filter(p => p.severity === 'medium').length +
                 result.iacFindings.filter(i => i.severity === 'medium').length +
                 result.dockerfileFindings.filter(d => d.severity === 'medium').length;

  const low = result.secrets.filter(s => s.severity === 'low').length +
              result.packages.filter(p => p.severity === 'low').length +
              result.iacFindings.filter(i => i.severity === 'low').length +
              result.dockerfileFindings.filter(d => d.severity === 'low').length;

  const total = critical + high + medium + low;

  return {
    scan: {
      path: result.path,
      timestamp: result.timestamp,
      tools: result.toolsUsed,
      languages: result.languagesDetected
    },
    summary: { total, critical, high, medium, low },
    findings: {
      secrets: result.secrets.length,
      vulnerabilities: result.packages.length,
      sast: result.sastFindings.length,
      iac: result.iacFindings.length,
      dockerfile: result.dockerfileFindings.length
    },
    exitCode: critical > 0 ? 2 : high > 0 ? 1 : 0
  };
}
