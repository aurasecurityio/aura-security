/**
 * Aura Protocol Scanner
 *
 * Wrapper that uses the Aura Protocol multi-agent architecture
 * while maintaining backward compatibility with the existing scanner interface.
 */

import * as os from 'os';
import { orchestrator, ParallelOrchestrator, OrchestratorResult } from '../orchestrator/index.js';
import { ZoneFinding } from '../zones/types.js';
import type { LocalScanResult, SecretFinding, PackageFinding, SastFinding, IaCFinding } from './local-scanner.js';

export interface AuraScanConfig {
  targetPath: string;
  // Run full scan with policy evaluation (slower, fewer false positives)
  fullScan?: boolean;
  // Enable specific zones
  enableScannerZone?: boolean;
  enablePolicyZone?: boolean;
}

export interface AuraScanResult {
  // Original format for backward compatibility
  legacy: LocalScanResult;
  // New Aura format with zone info
  aura: {
    zones: Array<{
      id: string;
      name: string;
      type: string;
      color: string;
      status: string;
      findingCount: number;
      duration: number;
    }>;
    agents: Array<{
      id: string;
      name: string;
      role: string;
      status: string;
      findingCount: number;
      duration: number;
    }>;
    findings: ZoneFinding[];
    summary: OrchestratorResult['summary'];
  };
}

/**
 * Run a security scan using the Aura Protocol architecture
 */
export async function auraScan(config: AuraScanConfig): Promise<AuraScanResult> {
  console.log('[Aura] Starting Aura Protocol scan...');
  console.log(`[Aura] Target: ${config.targetPath}`);

  // Run orchestrator
  const result = config.fullScan !== false
    ? await orchestrator.fullScan(config.targetPath)
    : await orchestrator.quickScan(config.targetPath);

  console.log(`[Aura] Scan complete in ${result.duration}ms`);
  console.log(`[Aura] Agents used: ${result.summary.agentsUsed.join(', ')}`);
  console.log(`[Aura] Total findings: ${result.summary.totalFindings}`);

  // Convert to legacy format
  const legacy = convertToLegacyFormat(result);

  // Build Aura format with zone info
  const zones = Array.from(result.zoneResults.entries()).map(([zoneId, zoneResult]) => ({
    id: zoneId,
    name: zoneResult.zoneName,
    type: zoneResult.zoneType,
    color: getZoneColor(zoneResult.zoneType),
    status: zoneResult.status,
    findingCount: zoneResult.findings.length,
    duration: zoneResult.duration,
  }));

  const agents = Array.from(result.zoneResults.values()).flatMap((zoneResult) =>
    zoneResult.agentResults.map((agentResult) => ({
      id: agentResult.agentId,
      name: agentResult.agentName,
      role: getAgentRole(agentResult.agentId),
      status: agentResult.status,
      findingCount: agentResult.findings.length,
      duration: agentResult.duration,
    }))
  );

  return {
    legacy,
    aura: {
      zones,
      agents,
      findings: result.findings,
      summary: result.summary,
    },
  };
}

/**
 * Convert orchestrator result to legacy LocalScanResult format
 */
function convertToLegacyFormat(result: OrchestratorResult): LocalScanResult {
  const secrets: SecretFinding[] = [];
  const packages: PackageFinding[] = [];
  const sastFindings: SastFinding[] = [];
  const iacFindings: IaCFinding[] = [];

  for (const finding of result.findings) {
    if (finding.type === 'secret') {
      secrets.push({
        file: finding.file || '',
        line: finding.line || 0,
        type: finding.title,
        snippet: (finding.metadata?.match as string) || '***',
        severity: finding.severity as SecretFinding['severity'],
      });
    } else if (finding.type === 'vulnerability') {
      packages.push({
        name: (finding.metadata?.package as string) || finding.title,
        version: (finding.metadata?.installedVersion as string) || (finding.metadata?.version as string) || 'unknown',
        vulnerabilities: 1,
        severity: finding.severity as PackageFinding['severity'],
        vulnId: (finding.metadata?.vulnerabilityId as string) || undefined,
        title: finding.title,
        fixedVersion: (finding.metadata?.fixedVersion as string) || (finding.metadata?.fixVersions as string[])?.[0],
      });
    } else if (finding.type === 'policy_violation') {
      // Map policy violations to SAST findings
      sastFindings.push({
        file: finding.file || '',
        line: finding.line || 0,
        rule: finding.title,
        message: finding.description,
        severity: finding.severity,
      });
    }
  }

  return {
    path: result.targetPath,
    timestamp: new Date().toISOString(),
    secrets,
    packages,
    sastFindings,
    iacFindings,
    dockerfileFindings: [],
    gitInfo: null,
    envFiles: [],
    systemInfo: {
      platform: process.platform,
      hostname: os.hostname(),
      user: os.userInfo().username,
      nodeVersion: process.version,
      cwd: process.cwd(),
    },
    discoveredServices: [],
    discoveredModules: [],
    toolsUsed: result.summary.agentsUsed,
    languagesDetected: [],
  };
}

function getZoneColor(zoneType: string): string {
  switch (zoneType) {
    case 'scanner':
      return '#22c55e'; // Green
    case 'policy':
      return '#ef4444'; // Red
    case 'reporting':
      return '#3b82f6'; // Blue
    default:
      return '#888888';
  }
}

function getAgentRole(agentId: string): string {
  const scannerAgents = ['gitleaks', 'trivy', 'semgrep', 'grype', 'npm-audit'];
  const policyAgents = ['policy-evaluator', 'validator'];
  const reporterAgents = ['sarif-reporter'];
  const notifierAgents = ['slack-notifier', 'discord-notifier'];

  if (scannerAgents.includes(agentId)) return 'scanner';
  if (policyAgents.includes(agentId)) return 'policy';
  if (reporterAgents.includes(agentId)) return 'reporter';
  if (notifierAgents.includes(agentId)) return 'notifier';
  return 'unknown';
}

/**
 * Get orchestrator state for visualization
 */
export function getAuraState() {
  return orchestrator.getState();
}

/**
 * Get available agents
 */
export async function getAvailableAgents() {
  return orchestrator.getAvailableAgents();
}

// Export orchestrator for direct access
export { orchestrator };
