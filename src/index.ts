// aurasecurity - Main entry point
// No Aura bus = No run (fail-closed)

// Load .env file for environment variables
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env from project root
const envPath = join(__dirname, '..', '.env');
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, 'utf-8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1).trim();
        // Remove surrounding quotes if present
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (!process.env[key]) {
          process.env[key] = value;
        }
      }
    }
  }
  console.log('[ENV] Loaded environment from .env file');
}

import { AuraServer } from './aura/server.js';
import { AuraClient } from './aura/client.js';
import { AuditorPipeline } from './auditor/pipeline.js';
import { SchemaValidator, ValidationError } from './auditor/validator.js';
import { LocalScanner, scanRemoteGit } from './integrations/local-scanner.js';
import type { LocalScanResult, SecretFinding, PackageFinding } from './integrations/local-scanner.js';
import { auraScan, getAuraState, getAvailableAgents } from './integrations/aura-scanner.js';
import { getWebSocketServer, type AuditorWebSocket } from './websocket/index.js';
import { performTrustScan } from './integrations/trust-scanner.js';
import { performXScan } from './integrations/x-scanner.js';
import { performAIVerification } from './integrations/ai-verifier.js';
import { detectScamPatterns, quickScamScan } from './integrations/scam-detector.js';
import {
  reportRug,
  getDevReputation,
  isDevFlagged,
  flagDeveloper,
  submitFeedback,
  getDbStats as getRugDbStats,
  getRecentRugs,
  getFlaggedDevs,
  getAccuracyStats,
  getXDbStats,
  flagXAccount,
  getXAccountReputation
} from './integrations/rug-database.js';
import { performEnhancedTrustScan } from './integrations/enhanced-scanner.js';
import { probeWebsite, formatProbeResult } from './integrations/website-probe.js';
import { MoltbookAgent as MoltbookAgentRunner } from './integrations/moltbook/agent.js';
import { ClawstrAgent } from './integrations/clawstr/agent.js';
import { generateReport, type ReportData, type ReportFormat } from './reporting/index.js';

const PORT = parseInt(process.env.AURA_PORT ?? '3000', 10);
const WS_PORT = parseInt(process.env.WS_PORT ?? '3001', 10);
const AURA_BUS_URL = process.env.AURA_BUS_URL;
const AUTH_ENABLED = process.env.AUTH_ENABLED === 'true';
const AUTH_MASTER_KEY = process.env.AUTH_MASTER_KEY || '';

// Secret patterns for remote scanning - stricter patterns to avoid false positives
const REMOTE_SECRET_PATTERNS = [
  { name: 'AWS Access Key', regex: /AKIA[0-9A-Z]{16}/g, severity: 'critical' as const },
  // AWS Secret Key - must have mixed chars (not just ===), and be in quotes or after =
  { name: 'AWS Secret Key', regex: /(?:secret|aws)[_-]?(?:key|access)?\s*[=:]\s*['"]([A-Za-z0-9\/+]{40})['"]/gi, severity: 'critical' as const },
  { name: 'Private Key', regex: /-----BEGIN\s+(RSA|EC|OPENSSH|PGP|ENCRYPTED)?\s*PRIVATE\s+KEY-----/g, severity: 'critical' as const },
  { name: 'GitHub Token', regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: 'critical' as const },
  { name: 'GitLab Token', regex: /glpat-[A-Za-z0-9_-]{20,}/g, severity: 'critical' as const },
  { name: 'Stripe Key', regex: /sk_live_[A-Za-z0-9]{24,}/g, severity: 'critical' as const },
  { name: 'Stripe Test Key', regex: /sk_test_[A-Za-z0-9]{24,}/g, severity: 'medium' as const },
  { name: 'Slack Token', regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g, severity: 'high' as const },
  { name: 'Database URL', regex: /(mongodb|postgres|mysql|redis):\/\/[^:]+:[^@]+@[^\s"']+/gi, severity: 'critical' as const },
  { name: 'JWT Token', regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{20,}/g, severity: 'medium' as const },
  { name: 'OpenAI Key', regex: /sk-[A-Za-z0-9]{32,}/g, severity: 'high' as const },
  { name: 'API Key Assignment', regex: /api[_-]?key\s*[=:]\s*['"]([A-Za-z0-9_\-]{20,})['"]/gi, severity: 'high' as const },
  { name: 'Password Assignment', regex: /password\s*[=:]\s*['"]([^'"]{8,})['"]/gi, severity: 'critical' as const },
  // Generic secret/key assignment with actual values (not placeholders)
  { name: 'Secret Assignment', regex: /(?:secret|private)[_-]?key\s*[=:]\s*['"]([A-Fa-f0-9]{32,})['"]/gi, severity: 'critical' as const },
  { name: 'Hex Private Key', regex: /(?:private[_-]?key|priv[_-]?key)\s*[=:]\s*['"]?([A-Fa-f0-9]{64})['"]?/gi, severity: 'critical' as const },
];

// Scan a remote Git repo via API without cloning
async function scanRemoteGitRepo(gitUrl: string): Promise<unknown> {
  // Parse GitHub URL: https://github.com/owner/repo
  const githubMatch = gitUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
  const gitlabMatch = gitUrl.match(/gitlab\.com\/([^\/]+)\/([^\/]+)/);

  if (!githubMatch && !gitlabMatch) {
    throw new Error('Only GitHub and GitLab URLs are supported for remote scanning');
  }

  const isGitHub = !!githubMatch;
  const owner = (githubMatch || gitlabMatch)![1];
  const repo = (githubMatch || gitlabMatch)![2].replace(/\.git$/, '');

  console.log(`[AURA] Fetching ${isGitHub ? 'GitHub' : 'GitLab'} repo: ${owner}/${repo}`);

  const secrets: Array<{ file: string; line: number; type: string; severity: string }> = [];
  const discoveredServices: Array<{ id: string; name: string; type: string; source: string; severity: string }> = [];
  const discoveredModules: Array<{ id: string; name: string; type: string; fileCount: number; path: string; files: string[] }> = [];
  const scannedFiles: string[] = [];

  try {
    // Fetch repo tree
    let treeUrl: string;
    let headers: Record<string, string> = { 'User-Agent': 'Aura-Security' };

    if (isGitHub) {
      treeUrl = `https://api.github.com/repos/${owner}/${repo}/git/trees/HEAD?recursive=1`;
      if (process.env.GITHUB_TOKEN) {
        headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
      }
    } else {
      treeUrl = `https://gitlab.com/api/v4/projects/${encodeURIComponent(`${owner}/${repo}`)}/repository/tree?recursive=true&per_page=100`;
      if (process.env.GITLAB_TOKEN) {
        headers['PRIVATE-TOKEN'] = process.env.GITLAB_TOKEN;
      }
    }

    const treeRes = await fetch(treeUrl, { headers });
    if (!treeRes.ok) {
      throw new Error(`Failed to fetch repo tree: ${treeRes.status} ${treeRes.statusText}`);
    }

    const treeData = await treeRes.json() as { tree?: Array<{ path: string; type: string; size?: number }>; truncated?: boolean } | Array<{ path: string; type: string }>;

    // Get file list
    let files: Array<{ path: string; type: string }>;
    if (isGitHub) {
      const ghData = treeData as { tree: Array<{ path: string; type: string }> };
      files = ghData.tree?.filter(f => f.type === 'blob') || [];
    } else {
      files = (treeData as Array<{ path: string; type: string }>).filter(f => f.type === 'blob');
    }

    console.log(`[AURA] Found ${files.length} files in repo`);

    // Filter to scannable files
    const scanExtensions = ['.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.env', '.py', '.go', '.rb', '.php', '.java', '.cs', '.config', '.conf', '.sh', '.bash'];
    const scanFiles = files.filter(f => {
      const ext = f.path.substring(f.path.lastIndexOf('.')).toLowerCase();
      const name = f.path.split('/').pop() || '';
      return scanExtensions.includes(ext) || name.startsWith('.env') || name === 'package.json' || name === 'Dockerfile';
    }).slice(0, 100); // Limit to 100 files for API rate limits

    console.log(`[AURA] Scanning ${scanFiles.length} relevant files`);

    // Scan each file
    for (const file of scanFiles) {
      try {
        let contentUrl: string;
        if (isGitHub) {
          contentUrl = `https://api.github.com/repos/${owner}/${repo}/contents/${encodeURIComponent(file.path)}`;
        } else {
          contentUrl = `https://gitlab.com/api/v4/projects/${encodeURIComponent(`${owner}/${repo}`)}/repository/files/${encodeURIComponent(file.path)}/raw?ref=HEAD`;
        }

        const contentRes = await fetch(contentUrl, { headers });
        if (!contentRes.ok) continue;

        let content: string;
        if (isGitHub) {
          const contentData = await contentRes.json() as { content?: string; encoding?: string };
          if (contentData.content && contentData.encoding === 'base64') {
            content = Buffer.from(contentData.content, 'base64').toString('utf-8');
          } else {
            continue;
          }
        } else {
          content = await contentRes.text();
        }

        scannedFiles.push(file.path);

        // Scan for secrets
        const lines = content.split('\n');
        for (let i = 0; i < lines.length; i++) {
          const line = lines[i];
          for (const pattern of REMOTE_SECRET_PATTERNS) {
            pattern.regex.lastIndex = 0;
            if (pattern.regex.test(line)) {
              secrets.push({
                file: file.path,
                line: i + 1,
                type: pattern.name,
                severity: pattern.severity
              });
            }
          }
        }

        // Check for service usage
        if (content.includes('mongodb') || content.includes('mongoose')) {
          if (!discoveredServices.find(s => s.id === 'mongodb')) {
            discoveredServices.push({ id: 'mongodb', name: 'MongoDB', type: 'database', source: file.path, severity: 'high' });
          }
        }
        if (content.includes('postgres') || content.includes('pg.')) {
          if (!discoveredServices.find(s => s.id === 'postgres')) {
            discoveredServices.push({ id: 'postgres', name: 'PostgreSQL', type: 'database', source: file.path, severity: 'high' });
          }
        }
        if (content.includes('redis')) {
          if (!discoveredServices.find(s => s.id === 'redis')) {
            discoveredServices.push({ id: 'redis', name: 'Redis', type: 'cache', source: file.path, severity: 'medium' });
          }
        }
        if (content.includes('stripe')) {
          if (!discoveredServices.find(s => s.id === 'stripe')) {
            discoveredServices.push({ id: 'stripe', name: 'Stripe', type: 'api', source: file.path, severity: 'critical' });
          }
        }
        if (content.includes('aws-sdk') || content.includes('AWS')) {
          if (!discoveredServices.find(s => s.id === 'aws')) {
            discoveredServices.push({ id: 'aws', name: 'AWS', type: 'cloud', source: file.path, severity: 'critical' });
          }
        }
        if (content.includes('firebase')) {
          if (!discoveredServices.find(s => s.id === 'firebase')) {
            discoveredServices.push({ id: 'firebase', name: 'Firebase', type: 'cloud', source: file.path, severity: 'high' });
          }
        }
        if (content.includes('openai')) {
          if (!discoveredServices.find(s => s.id === 'openai')) {
            discoveredServices.push({ id: 'openai', name: 'OpenAI', type: 'api', source: file.path, severity: 'high' });
          }
        }

      } catch {
        // Skip files that can't be fetched
      }
    }

    // Detect modules from directory structure
    const dirs = new Set<string>();
    files.forEach(f => {
      const parts = f.path.split('/');
      if (parts.length > 1) {
        dirs.add(parts[0]);
      }
    });

    const modulePatterns: Record<string, { type: string; name: string }> = {
      'src': { type: 'source', name: 'Source' },
      'lib': { type: 'lib', name: 'Library' },
      'components': { type: 'component', name: 'Components' },
      'pages': { type: 'component', name: 'Pages' },
      'api': { type: 'api', name: 'API' },
      'services': { type: 'service', name: 'Services' },
      'utils': { type: 'lib', name: 'Utils' },
      'config': { type: 'config', name: 'Config' },
      'tests': { type: 'test', name: 'Tests' },
      'test': { type: 'test', name: 'Tests' },
      '__tests__': { type: 'test', name: 'Tests' },
    };

    dirs.forEach(dir => {
      const match = modulePatterns[dir.toLowerCase()];
      if (match) {
        const dirFiles = files.filter(f => f.path.startsWith(dir + '/')).map(f => f.path);
        discoveredModules.push({
          id: dir.toLowerCase(),
          name: match.name,
          type: match.type,
          fileCount: dirFiles.length,
          path: dir,
          files: dirFiles.slice(0, 10)
        });
      }
    });

    // Build result
    const hasCritical = secrets.some(s => s.severity === 'critical');
    const hasHigh = secrets.some(s => s.severity === 'high');

    const events = secrets.map(s => ({
      event_type: s.severity === 'critical' ? 'escalation_triggered' : 'finding_raised',
      target: 'self',
      payload: {
        severity: s.severity,
        claim: `${s.type} found in ${s.file}:${s.line}`,
        attack_path: ['Secret detected in source code', 'Exposed in public repository', 'Attacker extracts credentials'],
        affected_assets: ['secrets'],
        evidence_refs: [{ type: 'diff', pointer: `${s.file}:${s.line}` }],
        assurance_break: ['integrity', 'access_control'],
        confidence: 0.9
      },
      timestamp: new Date().toISOString()
    }));

    console.log(`[AURA] Remote scan complete. Found ${secrets.length} secrets, ${discoveredServices.length} services, ${discoveredModules.length} modules`);

    return {
      agent_id: 'exploit-reviewer',
      agent_state: hasCritical ? 'escalated' : hasHigh ? 'conflict' : 'idle',
      events,
      meta: { assumptions: [], uncertainties: [] },
      scan_details: {
        path: `${isGitHub ? 'github' : 'gitlab'}:${owner}/${repo}`,
        secrets_found: secrets.length,
        packages_scanned: 0,
        env_files: 0,
        services_discovered: discoveredServices.length,
        modules_discovered: discoveredModules.length,
        git_info: { branch: 'HEAD', remoteUrl: gitUrl },
        system_info: { platform: 'remote', hostname: isGitHub ? 'github.com' : 'gitlab.com' },
        raw_findings: { secrets, packages: [], envFiles: [] },
        discovered_services: discoveredServices,
        discovered_modules: discoveredModules,
        files_scanned: scannedFiles.length
      }
    };

  } catch (err) {
    console.error('[AURA] Remote scan error:', err);
    throw err;
  }
}

async function main(): Promise<void> {
  console.log('[AURA] Starting auditor pipeline...');

  // Create Aura server
  const server = new AuraServer({
    port: PORT,
    authEnabled: AUTH_ENABLED,
    masterKey: AUTH_MASTER_KEY,
  });

  // Create Aura client for publishing to bus (if configured)
  let busClient: AuraClient | null = null;

  if (AURA_BUS_URL) {
    busClient = new AuraClient({ baseUrl: AURA_BUS_URL });

    try {
      await busClient.connect();
      console.log(`[AURA] Connected to bus at ${AURA_BUS_URL}`);
    } catch (err) {
      console.error('[AURA] FATAL: Cannot connect to Aura bus - fail-closed');
      process.exit(1);
    }
  } else {
    // Self-contained mode: client publishes to own server
    busClient = new AuraClient({ baseUrl: `http://127.0.0.1:${PORT}` });
  }

  // Create pipeline
  const pipeline = new AuditorPipeline({ auraClient: busClient });
  const validator = new SchemaValidator();

  // Register auditor tool
  server.registerTool({
    name: 'audit',
    description: 'Analyze change event for security findings',
    parameters: {
      type: 'object',
      required: ['change_event', 'evidence_bundle', 'policy_context']
    },
    handler: async (args) => {
      try {
        return await pipeline.analyze(args);
      } catch (err) {
        if (err instanceof ValidationError) {
          return {
            agent_id: 'exploit-reviewer',
            agent_state: 'blocked',
            events: [{
              event_type: 'escalation_triggered',
              target: 'self',
              payload: {
                severity: 'critical',
                claim: 'Input validation failed - blocking execution',
                attack_path: ['Malformed input received', 'Validation rejected payload'],
                affected_assets: [],
                evidence_refs: [],
                assurance_break: ['integrity'],
                confidence: 1.0
              },
              timestamp: new Date().toISOString()
            }],
            meta: {
              assumptions: [],
              uncertainties: [],
              validation_errors: err.errors
            }
          };
        }
        throw err;
      }
    }
  });

  // Register local scan tool
  server.registerTool({
    name: 'scan-local',
    description: 'Scan local filesystem or Git repo for security issues (secrets, vulnerabilities, env files)',
    parameters: {
      type: 'object',
      properties: {
        targetPath: { type: 'string', description: 'Path to scan (defaults to current directory)' },
        gitUrl: { type: 'string', description: 'Git URL to clone and scan' },
        scanSecrets: { type: 'boolean', default: true },
        scanPackages: { type: 'boolean', default: true },
        scanEnvFiles: { type: 'boolean', default: true },
        fastMode: { type: 'boolean', default: false, description: 'Skip slow scanners (semgrep, checkov) for faster results' }
      }
    },
    handler: async (args) => {
      try {
        let targetPath = (args.targetPath as string) || process.cwd();

        // Handle Git URL - clone and scan with full tool suite
        if (args.gitUrl) {
          const gitUrl = args.gitUrl as string;
          console.log(`[AURA] Cloning and scanning remote repo: ${gitUrl}`);

          try {
            // Use the clone-based scanner for full capabilities
            const remoteResult = await scanRemoteGit({
              gitUrl,
              scanSecrets: args.scanSecrets !== false,
              scanPackages: args.scanPackages !== false,
              fastMode: args.fastMode === true  // Skip slow scanners when true
            });

            console.log(`[AURA] Remote scan complete in ${remoteResult.cloneDuration + remoteResult.scanDuration}ms`);
            console.log(`[AURA] Found: ${remoteResult.secrets.length} secrets, ${remoteResult.packages.length} vulns`);

            // Save to database and calculate score
            try {
              const db = server.getDatabase();
              const auditId = db.saveAudit('code', gitUrl, remoteResult as LocalScanResult);
              console.log(`[AURA] Remote scan saved to database: ${auditId}`);

              // Calculate and save security score
              const scoreCounts = {
                critical: (remoteResult.secrets?.filter((s: SecretFinding) => s.severity === 'critical').length || 0) +
                          (remoteResult.packages?.filter((p: PackageFinding) => p.severity === 'critical').length || 0),
                high: (remoteResult.secrets?.filter((s: SecretFinding) => s.severity === 'high').length || 0) +
                      (remoteResult.packages?.filter((p: PackageFinding) => p.severity === 'high').length || 0),
                medium: (remoteResult.secrets?.filter((s: SecretFinding) => s.severity === 'medium').length || 0) +
                        (remoteResult.packages?.filter((p: PackageFinding) => p.severity === 'medium').length || 0) +
                        (remoteResult.sastFindings?.length || 0),
                low: (remoteResult.secrets?.filter((s: SecretFinding) => s.severity === 'low').length || 0) +
                     (remoteResult.packages?.filter((p: PackageFinding) => p.severity === 'low').length || 0) +
                     (remoteResult.envFiles?.length || 0)
              };
              const score = db.saveScore(gitUrl, auditId, scoreCounts);
              console.log(`[AURA] Security score: ${score.score} (${score.grade})`);
            } catch (dbErr) {
              console.error('[AURA] Failed to save remote scan to database:', dbErr);
            }

            // Convert to audit input and run through pipeline
            const scanner = new LocalScanner({ targetPath: remoteResult.path });
            const auditInput = scanner.toAuditorInput(remoteResult);

            let auditResult;
            try {
              auditResult = await pipeline.analyze(auditInput);
            } catch {
              auditResult = {
                agent_id: 'exploit-reviewer',
                agent_state: remoteResult.secrets.length > 0 ? 'conflict' : 'aligned',
                events: [],
                meta: { assumptions: [], uncertainties: [] }
              };
            }

            // Build full response with scan details
            return {
              ...auditResult,
              scan_details: {
                path: remoteResult.gitUrl,
                secrets_found: remoteResult.secrets.length,
                packages_scanned: remoteResult.packages.length,
                package_vulns: remoteResult.packages.length,
                sast_findings: remoteResult.sastFindings.length,
                iac_findings: remoteResult.iacFindings.length,
                dockerfile_findings: remoteResult.dockerfileFindings.length,
                env_files: remoteResult.envFiles.length,
                services_discovered: remoteResult.discoveredServices.length,
                modules_discovered: remoteResult.discoveredModules.length,
                git_info: remoteResult.gitInfo,
                system_info: { platform: 'remote', hostname: 'git-clone' },
                tools_used: remoteResult.toolsUsed,
                languages_detected: remoteResult.languagesDetected,
                clone_duration_ms: remoteResult.cloneDuration,
                scan_duration_ms: remoteResult.scanDuration,
                raw_findings: {
                  secrets: remoteResult.secrets,
                  packages: remoteResult.packages,
                  sastFindings: remoteResult.sastFindings,
                  iacFindings: remoteResult.iacFindings,
                  dockerfileFindings: remoteResult.dockerfileFindings
                }
              }
            };
          } catch (gitErr) {
            console.error(`[AURA] Remote Git scan failed:`, gitErr);
            const errorMsg = gitErr instanceof Error ? gitErr.message : 'Unknown error';
            return {
              agent_id: 'exploit-reviewer',
              agent_state: 'blocked',
              events: [],
              meta: { assumptions: [], uncertainties: [] },
              error: `Remote scan failed: ${errorMsg}`,
              scan_failed: true,
              scan_details: {
                path: gitUrl,
                secrets_found: 0,
                packages_scanned: 0,
                package_vulns: 0,
                sast_findings: 0,
                iac_findings: 0,
                dockerfile_findings: 0,
                env_files: 0,
                services_discovered: 0,
                modules_discovered: 0,
                error: errorMsg
              }
            };
          }
        }
        const scanner = new LocalScanner({
          targetPath,
          scanSecrets: args.scanSecrets !== false,
          scanPackages: args.scanPackages !== false,
          scanEnvFiles: args.scanEnvFiles !== false
        });

        console.log(`[AURA] Starting local scan of: ${targetPath}`);

        // Notify WebSocket clients that scan is starting
        const wsScanId = `scan-${Date.now()}`;
        const ws = getWebSocketServer(WS_PORT);
        ws.notifyAuditStarted({
          auditId: wsScanId,
          type: 'code',
          target: targetPath
        });

        const scanResult = await scanner.scan();
        console.log(`[AURA] Scan complete. Found ${scanResult.secrets.length} secrets, ${scanResult.packages.length} package issues, ${scanResult.sastFindings.length} SAST findings`);

        // Convert to audit input and run through pipeline
        const auditInput = scanner.toAuditorInput(scanResult);

        let auditResult;
        try {
          auditResult = await pipeline.analyze(auditInput);
        } catch (pipelineErr) {
          // If pipeline fails, create a basic result from scan data
          console.log(`[AURA] Pipeline analysis skipped: ${pipelineErr}`);
          const events = scanResult.secrets.map(s => ({
            event_type: s.severity === 'critical' ? 'escalation_triggered' : 'finding_raised',
            target: 'self',
            payload: {
              severity: s.severity,
              claim: `${s.type} found in ${s.file}:${s.line}`,
              attack_path: ['Secret detected in source code', 'Exposed in repository', 'Attacker extracts credentials'],
              affected_assets: [s.type.toLowerCase().includes('aws') ? 'infra' : s.type.toLowerCase().includes('password') ? 'auth' : 'secrets'],
              evidence_refs: [{ type: 'diff', pointer: `${s.file}:${s.line}` }],
              assurance_break: ['integrity', 'access_control'],
              confidence: 0.9
            },
            timestamp: new Date().toISOString()
          }));

          auditResult = {
            agent_id: 'exploit-reviewer',
            agent_state: scanResult.secrets.some(s => s.severity === 'critical') ? 'escalated' :
                         scanResult.secrets.length > 0 ? 'conflict' : 'idle',
            events,
            meta: { assumptions: [], uncertainties: [] }
          };
        }

        // Include raw scan results in response
        const scanId = `local-scan-${Date.now()}`;
        const fullResult = {
          ...auditResult,
          scan_details: {
            path: scanResult.path,
            secrets_found: scanResult.secrets.length,
            packages_scanned: scanResult.packages.length,
            package_vulns: scanResult.packages.filter(p => p.vulnerabilities > 0).length,
            sast_findings: scanResult.sastFindings.length,
            env_files: scanResult.envFiles.length,
            services_discovered: scanResult.discoveredServices.length,
            modules_discovered: scanResult.discoveredModules.length,
            git_info: scanResult.gitInfo,
            system_info: scanResult.systemInfo,
            tools_used: scanResult.toolsUsed,
            raw_findings: {
              secrets: scanResult.secrets,
              packages: scanResult.packages,
              envFiles: scanResult.envFiles,
              sastFindings: scanResult.sastFindings
            },
            // Discovered services for dynamic map building
            discovered_services: scanResult.discoveredServices,
            // Discovered code modules/directories for codebase mapping
            discovered_modules: scanResult.discoveredModules
          }
        };

        // Store scan result to memory for history browsing
        try {
          await busClient.publishToMemory({
            key: `audit:${scanId}:${Date.now()}`,
            value: fullResult,
            metadata: {
              type: 'local-scan',
              path: scanResult.path,
              timestamp: new Date().toISOString()
            }
          });
          console.log(`[AURA] Scan result stored to memory: ${scanId}`);
        } catch (storeErr) {
          console.error('[AURA] Failed to store scan result to memory:', storeErr);
        }

        // Store to SQLite database for persistent history
        let auditId: string | undefined;
        try {
          const db = server.getDatabase();
          auditId = db.saveAudit('code', scanResult.path, scanResult as LocalScanResult);
          console.log(`[AURA] Scan result saved to database: ${auditId}`);

          // Calculate and save security score
          const scoreCounts = {
            critical: (scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'critical').length || 0) +
                      (scanResult.packages?.filter((p: PackageFinding) => p.severity === 'critical').length || 0),
            high: (scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'high').length || 0) +
                  (scanResult.packages?.filter((p: PackageFinding) => p.severity === 'high').length || 0),
            medium: (scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'medium').length || 0) +
                    (scanResult.packages?.filter((p: PackageFinding) => p.severity === 'medium').length || 0) +
                    (scanResult.sastFindings?.length || 0),
            low: (scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'low').length || 0) +
                 (scanResult.packages?.filter((p: PackageFinding) => p.severity === 'low').length || 0) +
                 (scanResult.envFiles?.length || 0)
          };
          const score = db.saveScore(scanResult.path, auditId, scoreCounts);
          console.log(`[AURA] Security score: ${score.score} (${score.grade})`);
        } catch (dbErr) {
          console.error('[AURA] Failed to save to database:', dbErr);
        }

        // Send notifications if enabled
        if (auditId) {
          try {
            const notifyService = server.getNotificationService();
            const summary = {
              critical: scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'critical').length || 0,
              high: scanResult.secrets?.filter((s: SecretFinding) => s.severity === 'high').length || 0,
              medium: (scanResult.packages?.length || 0) + (scanResult.sastFindings?.length || 0),
              low: scanResult.envFiles?.length || 0
            };
            const result = await notifyService.notify({
              title: `Security Scan Complete`,
              message: `Scanned \`${scanResult.path}\``,
              severity: summary.critical > 0 ? 'critical' : summary.high > 0 ? 'high' : 'low',
              auditId,
              target: scanResult.path,
              findings: summary
            });
            if (result.sent.length > 0) {
              console.log(`[AURA] Notifications sent: ${result.sent.join(', ')}`);
            }

            // Notify WebSocket clients that scan is complete
            ws.notifyAuditCompleted({
              auditId,
              type: 'code',
              target: scanResult.path,
              summary
            });
          } catch (notifyErr) {
            console.error('[AURA] Notification error:', notifyErr);
          }
        }

        return fullResult;
      } catch (err) {
        console.error('[AURA] Local scan error:', err);
        return {
          agent_id: 'exploit-reviewer',
          agent_state: 'blocked',
          events: [{
            event_type: 'escalation_triggered',
            target: 'self',
            payload: {
              severity: 'medium',
              claim: `Local scan failed: ${err instanceof Error ? err.message : 'Unknown error'}`,
              attack_path: ['Scan execution failed'],
              affected_assets: [],
              evidence_refs: [],
              assurance_break: [],
              confidence: 1.0
            },
            timestamp: new Date().toISOString()
          }],
          meta: { assumptions: [], uncertainties: [`Scan error: ${err}`] }
        };
      }
    }
  });

  // Register Aura Protocol scan tool (multi-agent architecture)
  server.registerTool({
    name: 'scan-aura',
    description: 'Aura Protocol scan - Multi-agent parallel security scanning with isolated zones',
    parameters: {
      type: 'object',
      properties: {
        targetPath: { type: 'string', description: 'Path to scan (defaults to current directory)' },
        fullScan: { type: 'boolean', default: true, description: 'Run policy evaluation (slower, fewer false positives)' }
      }
    },
    handler: async (args) => {
      try {
        const targetPath = (args.targetPath as string) || process.cwd();
        const fullScan = args.fullScan !== false;

        console.log(`[AURA] Starting Aura Protocol scan of: ${targetPath}`);
        console.log(`[AURA] Mode: ${fullScan ? 'Full (with policy evaluation)' : 'Quick (scanner only)'}`);

        // Notify WebSocket clients that scan is starting
        const wsScanId = `aura-scan-${Date.now()}`;
        const ws = getWebSocketServer(WS_PORT);
        ws.notifyAuditStarted({
          auditId: wsScanId,
          type: 'aura-protocol',
          target: targetPath
        });

        // Run Aura Protocol scan
        const result = await auraScan({
          targetPath,
          fullScan
        });

        console.log(`[AURA] Aura Protocol scan complete`);
        console.log(`[AURA] Zones executed: ${result.aura.zones.map(z => z.name).join(', ')}`);
        console.log(`[AURA] Agents used: ${result.aura.agents.filter(a => a.status === 'success').map(a => a.name).join(', ')}`);
        console.log(`[AURA] Findings: ${result.aura.summary.totalFindings}`);

        // Store in database
        let auditId: string | undefined;
        try {
          const db = server.getDatabase();
          auditId = db.saveAudit('code', targetPath, {
            path: targetPath,
            timestamp: new Date().toISOString(),
            secrets: result.legacy.secrets,
            packages: result.legacy.packages,
            sastFindings: result.legacy.sastFindings,
            iacFindings: [],
            dockerfileFindings: [],
            gitInfo: null,
            envFiles: [],
            systemInfo: result.legacy.systemInfo,
            discoveredServices: [],
            discoveredModules: [],
            toolsUsed: result.aura.summary.agentsUsed,
            languagesDetected: [],
            zones: result.aura.zones,
            agents: result.aura.agents
          } as any);
          console.log(`[AURA] Aura scan saved to database: ${auditId}`);

          // Save security score
          const scoreCounts = {
            critical: result.aura.summary.bySeverity['critical'] || 0,
            high: result.aura.summary.bySeverity['high'] || 0,
            medium: result.aura.summary.bySeverity['medium'] || 0,
            low: result.aura.summary.bySeverity['low'] || 0
          };
          const score = db.saveScore(targetPath, auditId, scoreCounts);
          console.log(`[AURA] Security score: ${score.score} (${score.grade})`);
        } catch (dbErr) {
          console.error('[AURA] Database save error:', dbErr);
          auditId = `aura-${Date.now()}`;
        }

        // Notify WebSocket clients
        ws.notifyAuditCompleted({
          auditId: auditId || `aura-${Date.now()}`,
          type: 'aura-protocol',
          target: targetPath,
          summary: {
            critical: result.aura.summary.bySeverity['critical'] || 0,
            high: result.aura.summary.bySeverity['high'] || 0,
            medium: result.aura.summary.bySeverity['medium'] || 0,
            low: result.aura.summary.bySeverity['low'] || 0
          }
        });

        return {
          agent_id: 'aura-orchestrator',
          agent_state: result.aura.summary.totalFindings > 0 ? 'conflict' : 'aligned',
          events: result.aura.findings.map(f => ({
            event_type: f.severity === 'critical' ? 'escalation_triggered' : 'finding_raised',
            target: 'self',
            payload: {
              severity: f.severity,
              claim: f.title,
              description: f.description,
              file: f.file,
              line: f.line,
              type: f.type,
              agent: f.agentId
            },
            timestamp: new Date(f.timestamp).toISOString()
          })),
          meta: {
            zones: result.aura.zones,
            agents: result.aura.agents,
            summary: result.aura.summary
          },
          scan_details: {
            path: targetPath,
            mode: fullScan ? 'full' : 'quick',
            secrets_found: result.aura.summary.byType['secret'] || 0,
            vulnerabilities_found: result.aura.summary.byType['vulnerability'] || 0,
            total_findings: result.aura.summary.totalFindings,
            tools_used: result.aura.summary.agentsUsed,
            zones_executed: result.aura.zones.length,
            agents_executed: result.aura.agents.length,
            raw_findings: {
              secrets: result.legacy.secrets,
              packages: result.legacy.packages,
              sastFindings: result.legacy.sastFindings
            }
          }
        };
      } catch (err) {
        console.error('[AURA] Aura Protocol scan error:', err);
        return {
          agent_id: 'aura-orchestrator',
          agent_state: 'blocked',
          events: [],
          meta: { error: err instanceof Error ? err.message : 'Unknown error' }
        };
      }
    }
  });

  // Register Aura state endpoint (for visualization)
  server.registerTool({
    name: 'aura-state',
    description: 'Get current Aura Protocol state (zones, agents) for visualization',
    parameters: { type: 'object', properties: {} },
    handler: async () => {
      const state = getAuraState();
      const availableAgents = await getAvailableAgents();
      return {
        ...state,
        availableAgents: availableAgents.map(a => ({
          id: a.config.id,
          name: a.config.name,
          role: a.config.role,
          description: a.config.description
        }))
      };
    }
  });

  // Register Trust Scan tool (Rug Check for crypto investors)
  server.registerTool({
    name: 'trust-scan',
    description: 'Rug Check - Verify if a GitHub repository is legitimate (for crypto investors)',
    parameters: {
      type: 'object',
      required: ['gitUrl'],
      properties: {
        gitUrl: { type: 'string', description: 'GitHub repository URL to check' }
      }
    },
    handler: async (args) => {
      try {
        const gitUrl = args.gitUrl as string;
        console.log(`[AURA] Starting Rug Check for: ${gitUrl}`);

        const result = await performTrustScan(gitUrl);

        console.log(`[AURA] Rug Check complete: ${result.trustScore}/100 (${result.verdict})`);

        return result;
      } catch (err) {
        console.error('[AURA] Rug Check error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          trustScore: 0,
          grade: 'F',
          verdict: 'ERROR',
          summary: 'Failed to scan repository. Please check the URL and try again.'
        };
      }
    }
  });

  // Register X/Twitter Scan tool
  server.registerTool({
    name: 'x-scan',
    description: 'Analyze X/Twitter profile for legitimacy (follower quality, bot detection, content analysis)',
    parameters: {
      type: 'object',
      required: ['username'],
      properties: {
        username: { type: 'string', description: 'X/Twitter username or URL (e.g., @elonmusk or https://x.com/elonmusk)' }
      }
    },
    handler: async (args) => {
      try {
        const username = args.username as string;
        console.log(`[AURA] Starting X scan for: ${username}`);

        const result = await performXScan(username);

        console.log(`[AURA] X scan complete: ${result.score}/100 (${result.verdict})`);

        return result;
      } catch (err) {
        console.error('[AURA] X scan error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          score: 0,
          grade: 'F',
          verdict: 'ERROR',
          summary: 'Failed to scan X profile. Check the username and try again.'
        };
      }
    }
  });

  // Register AI Project Verifier tool
  server.registerTool({
    name: 'ai-check',
    description: 'Verify if a GitHub repo is a real AI project or just hype',
    parameters: {
      type: 'object',
      required: ['gitUrl'],
      properties: {
        gitUrl: { type: 'string', description: 'GitHub repository URL to verify' }
      }
    },
    handler: async (args) => {
      try {
        const gitUrl = args.gitUrl as string;
        console.log(`[AURA] Starting AI verification for: ${gitUrl}`);

        const result = await performAIVerification(gitUrl);

        console.log(`[AURA] AI check complete: ${result.aiScore}/100 (${result.verdict})`);

        return result;
      } catch (err) {
        console.error('[AURA] AI check error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          aiScore: 0,
          verdict: 'ERROR',
          isRealAI: false,
          summary: 'Failed to verify AI project. Check the URL and try again.'
        };
      }
    }
  });

  // Register Scam Detection tool
  server.registerTool({
    name: 'scam-scan',
    description: 'Detect known scam patterns, rug pull templates, and code similarity to known scams',
    parameters: {
      type: 'object',
      required: ['gitUrl'],
      properties: {
        gitUrl: { type: 'string', description: 'GitHub repository URL to scan for scam patterns' }
      }
    },
    handler: async (args) => {
      try {
        const gitUrl = args.gitUrl as string;
        console.log(`[AURA] Starting scam detection for: ${gitUrl}`);

        // Parse GitHub URL
        const githubMatch = gitUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
        if (!githubMatch) {
          throw new Error('Invalid GitHub URL');
        }

        const owner = githubMatch[1];
        const repo = githubMatch[2].replace(/\.git$/, '');

        const headers: Record<string, string> = {
          'User-Agent': 'AuraSecurityBot/1.0',
          'Accept': 'application/vnd.github.v3+json'
        };
        if (process.env.GITHUB_TOKEN) {
          headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
        }

        // Fetch repo tree
        const repoRes = await fetch(`https://api.github.com/repos/${owner}/${repo}`, { headers });
        if (!repoRes.ok) {
          // Check if rate limited (403 or 429) — return unified "unavailable" instead of error
          if (repoRes.status === 403 || repoRes.status === 429) {
            const remaining = repoRes.headers.get('x-ratelimit-remaining');
            const isRateLimit = remaining === '0' || repoRes.status === 429;
            if (isRateLimit) {
              console.error(`[AURA] GitHub API rate limited (${repoRes.status}) — cannot scan ${owner}/${repo}`);
              return {
                url: gitUrl,
                repoName: repo,
                owner,
                score: null,
                grade: null,
                verdict: null,
                verdictEmoji: null,
                trustUnavailable: true,
                codeSafety: { status: 'UNAVAILABLE', scamScore: 0, matches: [], summary: 'GitHub API rate limit reached — scan unavailable' },
                projectTrust: { status: 'UNAVAILABLE', trustScore: null, checks: [], summary: 'GitHub API rate limit reached' },
                secretsScan: { status: 'UNAVAILABLE', count: 0 },
                tags: [],
                redFlags: [],
                greenFlags: [],
                analysis: 'GitHub API rate limit reached. Cannot scan this repository right now. Try again in a few minutes.',
                scamScore: 0,
                riskLevel: 'unknown',
                isLikelyScam: false,
                summary: 'Rate limited — try again shortly',
                matches: [],
                scannedAt: new Date().toISOString()
              };
            }
          }
          throw new Error(`Failed to fetch repository: ${repoRes.status}`);
        }
        const repoData = await repoRes.json();

        // Fetch file tree
        const treeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/git/trees/${repoData.default_branch}?recursive=1`, { headers });
        let files: Array<{ path: string; type: string }> = [];
        if (treeRes.ok) {
          const treeData = await treeRes.json();
          files = treeData.tree?.filter((f: { type: string }) => f.type === 'blob') || [];
        }

        // Check for code files - if none, repo is suspicious
        const codeExtensions = ['.js', '.ts', '.jsx', '.tsx', '.py', '.go', '.rs', '.sol', '.java', '.c', '.cpp', '.rb', '.php'];
        const codeFileCount = files.filter(f => codeExtensions.some(ext => f.path.endsWith(ext))).length;
        const hasNoCode = codeFileCount === 0;
        console.log(`[AURA] scam-scan: files=${files.length}, codeFiles=${codeFileCount}, hasNoCode=${hasNoCode}`);

        // Fetch README
        let readmeContent = '';
        const readmeFile = files.find(f => f.path.toLowerCase().includes('readme'));
        if (readmeFile) {
          try {
            const readmeRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${readmeFile.path}`, { headers });
            if (readmeRes.ok) {
              const readmeData = await readmeRes.json();
              if (readmeData.content) {
                readmeContent = Buffer.from(readmeData.content, 'base64').toString('utf-8');
              }
            }
          } catch { /* skip */ }
        }

        // Quick scam scan on file names and README
        const quickResult = await quickScamScan(
          files.map(f => f.path),
          readmeContent,
          repoData.description
        );

        // If quick scan finds red flags, do deep scan
        let deepResult = null;
        if (quickResult.hasRedFlags || quickResult.riskLevel !== 'low') {
          // Fetch code files for deep scan
          const codeFiles = files
            .filter(f => f.path.endsWith('.sol') || f.path.endsWith('.rs') || f.path.endsWith('.ts') || f.path.endsWith('.js'))
            .slice(0, 10);

          const fileContents: Array<{ path: string; content?: string }> = [];
          for (const file of codeFiles) {
            try {
              const fileRes = await fetch(`https://api.github.com/repos/${owner}/${repo}/contents/${file.path}`, { headers });
              if (fileRes.ok) {
                const fileData = await fileRes.json();
                if (fileData.content) {
                  fileContents.push({
                    path: file.path,
                    content: Buffer.from(fileData.content, 'base64').toString('utf-8')
                  });
                }
              }
            } catch { /* skip */ }
          }

          deepResult = await detectScamPatterns({
            files: fileContents,
            readme: readmeContent,
            description: repoData.description,
            name: repo
          });
        }

        // Build response using "worst finding wins" logic
        // Both quick scan and deep scan contribute - we take the worst signal
        const noCodeRedFlags = hasNoCode ? ['No code files found - nothing to scan (SUSPICIOUS)'] : [];

        // Risk level from deep scan (if it ran)
        const deepRiskLevel = deepResult ? (deepResult.scamScore >= 70 ? 'critical' : deepResult.scamScore >= 50 ? 'high' : deepResult.scamScore >= 25 ? 'medium' : 'low') : 'low';

        // Take the WORST risk level from both scans
        const riskOrder = { low: 0, medium: 1, high: 2, critical: 3 } as Record<string, number>;
        const quickRisk = riskOrder[quickResult.riskLevel] || 0;
        const deepRisk = riskOrder[deepRiskLevel] || 0;
        const noCodeRisk = hasNoCode ? 1 : 0; // medium
        const worstRisk = Math.max(quickRisk, deepRisk, noCodeRisk);
        const finalRiskLevel = Object.entries(riskOrder).find(([_, v]) => v === worstRisk)?.[0] || 'low';

        // Score: take the higher of deep scan score or quick scan implied score
        const quickImpliedScore = quickResult.riskLevel === 'critical' ? 80 : quickResult.riskLevel === 'high' ? 60 : quickResult.riskLevel === 'medium' ? 30 : 0;
        const deepScore = deepResult?.scamScore || 0;
        const noCodeScore = hasNoCode ? 35 : 0;
        const finalScamScore = Math.max(deepScore, quickImpliedScore, noCodeScore);

        const hasScamMatches = (deepResult?.matches?.length || 0) > 0;

        // Summary: pick the most relevant one, never contradict
        let finalSummary: string;
        if (hasNoCode) {
          finalSummary = 'SUSPICIOUS: No code files to analyze - cannot verify safety';
        } else if (deepResult?.summary) {
          // Deep scan summary already handles "never say CLEAN with matches"
          finalSummary = deepResult.summary;
        } else if (quickResult.hasRedFlags) {
          finalSummary = `Found ${quickResult.redFlags.length} red flags in initial scan`;
        } else {
          finalSummary = 'No known scam patterns detected';
        }

        // Run trust scan in parallel for unified results
        let trustResult: any = null;
        let trustFailed = false;
        try {
          trustResult = await performTrustScan(gitUrl);
        } catch (trustErr: any) {
          console.error('[AURA] Trust scan failed during scam-scan:', trustErr?.message || trustErr);
          trustFailed = true;
        }

        // === UNIFIED SCORING ===
        // Start with trust score, apply scam-scan overrides downward
        // If trust scan failed (e.g., rate limit), don't use a fake default
        const trustScore = trustFailed ? null : (trustResult?.trustScore ?? 50);
        let unifiedScore = trustScore ?? 50;
        let scamCap = 100;

        // Check match quality: high-confidence critical matches are real threats,
        // low-confidence or generic pattern matches on high-trust repos are likely false positives
        const highConfidenceCritical = deepResult?.matches?.some(
          (m: any) => m.severity === 'critical' && (m.confidence ?? 50) >= 60
        );
        const anyCritical = deepResult?.matches?.some((m: any) => m.severity === 'critical');
        const anyHigh = deepResult?.matches?.some((m: any) => m.severity === 'high');
        const hasMatches = (deepResult?.matches?.length ?? 0) > 0;

        // When trust is very high (90+), only high-confidence critical matches
        // should force a low cap. Generic/low-confidence matches get tempered.
        const highTrust = (trustScore ?? 0) >= 90;

        if (highConfidenceCritical) {
          // Real threat — hard cap regardless of trust
          scamCap = 20;
        } else if (anyCritical && !highTrust) {
          // Low-confidence critical on low-trust repo — still cap hard
          scamCap = 20;
        } else if (anyCritical && highTrust) {
          // Low-confidence critical on high-trust repo — temper it
          scamCap = 60;
        } else if (anyHigh && !highTrust) {
          scamCap = 35;
        } else if (anyHigh && highTrust) {
          // Generic high-severity matches on established repo — temper
          scamCap = 70;
        } else if (hasMatches) {
          scamCap = 50;
        }
        if (hasNoCode) {
          scamCap = Math.min(scamCap, 40);
        }
        unifiedScore = Math.min(unifiedScore, scamCap);

        // isLikelyScam: true if real threat signals present
        // High-trust repos with only low-confidence matches are NOT likely scams
        const hasHighConfidenceMatches = deepResult?.matches?.some(
          (m: any) => (m.confidence ?? 50) >= 60
        );
        const isLikelyScam = highTrust
          ? (hasHighConfidenceMatches || quickResult.riskLevel === 'critical')
          : (deepResult?.isLikelyScam || quickResult.riskLevel === 'critical' || hasNoCode || hasScamMatches);

        // Unified grade and verdict
        let unifiedGrade: string, unifiedVerdict: string, unifiedEmoji: string;
        if (unifiedScore >= 80) {
          unifiedGrade = 'A'; unifiedVerdict = 'SAFU'; unifiedEmoji = '🟢';
        } else if (unifiedScore >= 60) {
          unifiedGrade = 'B'; unifiedVerdict = 'DYOR'; unifiedEmoji = '🟡';
        } else if (unifiedScore >= 35) {
          unifiedGrade = 'C'; unifiedVerdict = 'RISKY'; unifiedEmoji = '🟠';
        } else {
          unifiedGrade = 'F'; unifiedVerdict = 'RUG ALERT'; unifiedEmoji = '🔴';
        }

        // === CODE SAFETY ===
        const codeSafetyStatus = isLikelyScam ? 'DANGER' : (finalScamScore > 0 ? 'WARNING' : 'CLEAN');
        const codeSafetySummary = hasNoCode
          ? 'No code files found — nothing to analyze'
          : isLikelyScam
            ? `${(deepResult?.matches?.length || 0)} scam pattern(s) detected`
            : finalScamScore > 0
              ? `Minor concerns found (score: ${finalScamScore})`
              : 'No scam patterns detected';

        // === PROJECT TRUST ===
        const projectTrustStatus = trustResult?.verdict || 'UNKNOWN';
        const projectTrustSummary = trustResult?.summary || 'Trust scan unavailable';

        // === SECRETS ===
        const secretsCount = trustResult?.metrics?.secretsFound ?? 0;

        // === TAGS ===
        const tags: string[] = [];
        const metrics = trustResult?.metrics;
        if (metrics) {
          // Age
          if (metrics.repoAgeDays < 7) tags.push('#NewProject');
          else if (metrics.repoAgeDays < 30) tags.push('#UnderOneMonth');
          else if (metrics.repoAgeDays > 365) tags.push('#Established');
          // Dev
          if (metrics.ownerAccountAgeDays !== undefined && metrics.ownerAccountAgeDays < 30) tags.push('#NewDev');
          if (metrics.contributorCount === 1) tags.push('#SoloDev');
          else if (metrics.contributorCount > 10) tags.push('#ActiveTeam');
          // Code
          if (metrics.commitCount <= 1) tags.push('#SingleCommit');
          else if (metrics.commitCount > 100) tags.push('#ActiveDev');
          if (metrics.codeFileCount === 0) tags.push('#NoCode');
          if (metrics.hasTests) tags.push('#HasTests');
          // Safety
          if (finalScamScore === 0 && !hasNoCode) tags.push('#CleanCode');
          if (secretsCount === 0) tags.push('#NoSecrets');
          else tags.push('#LeakedSecrets');
          if (isLikelyScam) tags.push('#ScamDetected');
          if (metrics.isArchived) tags.push('#Archived');
          if (metrics.isFork) tags.push('#Fork');
        }

        // === RED FLAGS & GREEN FLAGS ===
        const allRedFlags: string[] = [...noCodeRedFlags, ...(quickResult.redFlags || []), ...(deepResult?.warnings || [])];
        const greenFlags: string[] = [];

        if (trustResult?.checks) {
          for (const check of trustResult.checks) {
            if (check.status === 'bad') {
              allRedFlags.push(check.explanation);
            } else if (check.status === 'warn' && check.id !== 'secrets') {
              allRedFlags.push(check.explanation);
            }
          }
          // Green flags from trust checks
          if (metrics) {
            if (metrics.codeFileCount > 0) greenFlags.push(`${metrics.codeFileCount} real code files${metrics.language ? ` (${metrics.language})` : ''}`);
            if (metrics.hasTests) greenFlags.push('Has test suite');
            if (!isLikelyScam && !hasNoCode && finalScamScore === 0) greenFlags.push('No wallet drainers or rug patterns');
            if (secretsCount === 0) greenFlags.push('No leaked secrets');
            if (metrics.commitCount > 100) greenFlags.push(`${metrics.commitCount} commits — active development`);
            if (metrics.contributorCount > 5) greenFlags.push(`${metrics.contributorCount}+ contributors`);
            if (metrics.repoAgeDays > 365) greenFlags.push(`${Math.floor(metrics.repoAgeDays / 365)} year(s) of history`);
            if (metrics.hasLicense) greenFlags.push('Open-source license');
          }
        }

        // === DETERMINISTIC COMMENTARY ===
        let analysis = '';
        const codeClean = !isLikelyScam && finalScamScore === 0 && !hasNoCode;
        const highTrustVerdict = unifiedScore >= 80;
        const lowTrust = unifiedScore < 60;

        if (hasNoCode) {
          analysis = `No code files to analyze. Repository contains ${files.length} files but none are source code. Cannot verify safety. This pattern is common in placeholder repos created before a rug pull.`;
        } else if (isLikelyScam) {
          const matchNames = (deepResult?.matches || []).map((m: any) => m.signatureName).join(', ');
          analysis = `DANGER. ${(deepResult?.matches?.length || 0)} known scam pattern(s) detected: ${matchNames}. This code contains signatures associated with known rug pull techniques.`;
        } else if (codeClean && highTrust) {
          const years = metrics ? Math.floor(metrics.repoAgeDays / 365) : 0;
          const commitText = metrics?.commitCount ? `${metrics.commitCount} commits` : 'active development';
          const contribText = metrics?.contributorCount ? `${metrics.contributorCount} contributors` : 'multiple contributors';
          analysis = `Established, actively maintained project. ${commitText}, ${contribText}${years > 0 ? ` over ${years} year(s)` : ''}. No scam patterns, no leaked secrets. Strong builder signals.`;
        } else if (codeClean && lowTrust) {
          const ownerAge = metrics?.ownerAccountAgeDays ?? 0;
          const commits = metrics?.commitCount ?? 0;
          analysis = `Code is clean — no scam patterns, drainers, or obfuscation detected. Zero track record.${ownerAge > 0 ? ` Developer account is ${ownerAge} days old.` : ''} Only ${commits} commit(s). No community engagement. These are the exact signals present in 90% of rug pulls on Solana.`;
        } else if (codeClean) {
          // Mid-range trust
          const warnings = allRedFlags.length;
          analysis = `Code is clean with no scam patterns detected.${warnings > 0 ? ` ${warnings} concern(s) noted in project metadata.` : ''} Review the red flags above before investing.`;
        } else {
          analysis = finalSummary;
        }

        // Handle archived projects
        if (metrics?.isArchived && codeClean) {
          const monthsAgo = metrics.daysSinceLastPush ? Math.floor(metrics.daysSinceLastPush / 30) : 0;
          analysis = `Project is archived and no longer maintained.${monthsAgo > 0 ? ` Last updated ${monthsAgo} month(s) ago.` : ''} Code was clean when active but no longer receives security updates.`;
        }

        // Handle forks
        if (metrics?.isFork && metrics?.forkChangedLines !== undefined && metrics.forkChangedLines < 50) {
          analysis = `This is a fork with minimal changes (${metrics.forkChangedLines} lines). Minimal-effort projects that clone established codebases are a common rug pull tactic.`;
        }

        // If trust scan failed, override analysis to be honest about it
        if (trustFailed && !isLikelyScam && !hasNoCode) {
          analysis = `Code scan completed — no scam patterns or drainers detected. Trust analysis unavailable (GitHub API limit reached). Run again shortly for full project scoring.`;
        }

        const result = {
          url: gitUrl,
          repoName: repo,
          owner,
          // === Unified fields ===
          score: trustFailed ? null : unifiedScore,
          grade: trustFailed ? null : unifiedGrade,
          verdict: trustFailed ? null : unifiedVerdict,
          verdictEmoji: trustFailed ? null : unifiedEmoji,
          trustUnavailable: trustFailed || undefined,
          codeSafety: {
            status: codeSafetyStatus,
            scamScore: finalScamScore,
            matches: deepResult?.matches || [],
            summary: codeSafetySummary
          },
          projectTrust: {
            status: projectTrustStatus,
            trustScore,
            checks: trustResult?.checks || [],
            summary: projectTrustSummary
          },
          secretsScan: {
            status: secretsCount === 0 ? 'CLEAN' : 'FOUND',
            count: secretsCount
          },
          tags,
          redFlags: allRedFlags,
          greenFlags,
          analysis,
          // === Legacy fields (backward compat) ===
          quickScan: quickResult,
          deepScan: deepResult,
          isLikelyScam,
          scamScore: finalScamScore,
          riskLevel: finalRiskLevel,
          summary: finalSummary,
          matches: deepResult?.matches || [],
          scannedAt: new Date().toISOString()
        };

        console.log(`[AURA] Scam detection complete: unified=${result.score}/100 (${result.verdict}), scam=${result.scamScore}/100 (${result.riskLevel})`);

        return result;
      } catch (err) {
        console.error('[AURA] Scam detection error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          scamScore: 0,
          riskLevel: 'unknown',
          isLikelyScam: false,
          summary: 'Failed to scan for scam patterns. Check the URL and try again.'
        };
      }
    }
  });

  // Register Compare tool (compare two repos)
  server.registerTool({
    name: 'compare',
    description: 'Compare two GitHub repositories side-by-side for trust scores',
    parameters: {
      type: 'object',
      required: ['repo1', 'repo2'],
      properties: {
        repo1: { type: 'string', description: 'First GitHub repository URL' },
        repo2: { type: 'string', description: 'Second GitHub repository URL' }
      }
    },
    handler: async (args) => {
      try {
        const repo1 = args.repo1 as string;
        const repo2 = args.repo2 as string;
        console.log(`[AURA] Comparing: ${repo1} vs ${repo2}`);

        // Run both scans in parallel
        const [scan1, scan2] = await Promise.all([
          performTrustScan(repo1),
          performTrustScan(repo2)
        ]);

        // Determine winner
        const winner = scan1.trustScore > scan2.trustScore ? 1 :
                       scan2.trustScore > scan1.trustScore ? 2 : 0;

        return {
          repo1: {
            url: repo1,
            name: scan1.repoName,
            score: scan1.trustScore,
            grade: scan1.grade,
            verdict: scan1.verdict,
            verdictEmoji: scan1.verdictEmoji,
            summary: scan1.summary
          },
          repo2: {
            url: repo2,
            name: scan2.repoName,
            score: scan2.trustScore,
            grade: scan2.grade,
            verdict: scan2.verdict,
            verdictEmoji: scan2.verdictEmoji,
            summary: scan2.summary
          },
          winner,
          recommendation: winner === 1 ? `${scan1.repoName} looks safer` :
                          winner === 2 ? `${scan2.repoName} looks safer` :
                          'Both projects have similar trust scores',
          scannedAt: new Date().toISOString()
        };
      } catch (err) {
        console.error('[AURA] Compare error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          summary: 'Failed to compare repositories. Check the URLs and try again.'
        };
      }
    }
  });

  // === Moltbook Integration Tools ===

  // Initialize Moltbook agent (lazy — only starts if MOLTBOOK_API_KEY is set)
  let moltbookAgent: MoltbookAgentRunner | null = null;

  const getMoltbookAgent = (): MoltbookAgentRunner => {
    if (!moltbookAgent) {
      moltbookAgent = new MoltbookAgentRunner();
    }
    return moltbookAgent;
  };

  // Agent Trust Score tool
  server.registerTool({
    name: 'agent-trust',
    description: 'Score a Moltbook agent\'s trust level (identity, behavior, network, content signals)',
    parameters: {
      type: 'object',
      required: ['agentName'],
      properties: {
        agentName: { type: 'string', description: 'Moltbook agent name to score' }
      }
    },
    handler: async (args) => {
      try {
        const agentName = args.agentName as string;
        console.log(`[AURA] Scoring Moltbook agent: ${agentName}`);
        const agent = getMoltbookAgent();
        const score = await agent.scoreAgent(agentName);
        if (!score) {
          return { error: `Agent "${agentName}" not found on Moltbook` };
        }
        return score;
      } catch (err) {
        console.error('[AURA] Agent trust error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Bot Farm Detection tool
  server.registerTool({
    name: 'bot-detect',
    description: 'Run bot farm detection on tracked Moltbook agents',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getMoltbookAgent();
        const detector = agent.getBotDetector();
        const clusters = detector.detect();
        return {
          clustersFound: clusters.length,
          clusters: clusters.map(c => ({
            id: c.id,
            agents: c.agents,
            confidence: c.confidence,
            signals: c.signals
          })),
          stats: detector.getStats()
        };
      } catch (err) {
        console.error('[AURA] Bot detect error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Moltbook Agent Status tool
  server.registerTool({
    name: 'moltbook-status',
    description: 'Get Moltbook agent status (scanner, monitor, jail stats)',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getMoltbookAgent();
        return agent.getStatus();
      } catch (err) {
        console.error('[AURA] Moltbook status error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Manually trigger daily summary post
  server.registerTool({
    name: 'moltbook-daily-summary',
    description: 'Manually trigger a daily summary post to /s/builds with current scan stats',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getMoltbookAgent();
        await agent.postDailySummary();
        return { success: true, message: 'Daily summary posted' };
      } catch (err) {
        console.error('[AURA] Daily summary error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Agent Reputation query tool
  server.registerTool({
    name: 'agent-reputation',
    description: 'Query a Moltbook agent\'s reputation score based on the repos they\'ve shared',
    parameters: {
      type: 'object',
      required: ['agentName'],
      properties: {
        agentName: { type: 'string', description: 'Moltbook agent name to query' }
      }
    },
    handler: async (args) => {
      try {
        const agentName = args.agentName as string;
        const agent = getMoltbookAgent();
        const rep = agent.getAgentReputation(agentName);
        if (!rep) {
          return { error: `No reputation data for "${agentName}" — they haven't shared any repos we've scanned yet` };
        }
        return {
          agentName: rep.agentName,
          reputationScore: rep.reputationScore,
          safeRepos: rep.safeRepos,
          riskyRepos: rep.riskyRepos,
          scamRepos: rep.scamRepos,
          totalScans: rep.totalScans,
          lastUpdated: new Date(rep.lastUpdated).toISOString(),
          recentScans: rep.repoScans.slice(-5).map(r => ({
            repo: r.repoUrl,
            verdict: r.verdict,
            score: r.score,
          })),
        };
      } catch (err) {
        console.error('[AURA] Agent reputation error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Manually trigger weekly leaderboard post
  server.registerTool({
    name: 'moltbook-leaderboard',
    description: 'Manually trigger a weekly trust leaderboard post to /s/builds',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getMoltbookAgent();
        await agent.postLeaderboard();
        return { success: true, message: 'Leaderboard posted' };
      } catch (err) {
        console.error('[AURA] Leaderboard error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // === Clawstr Integration Tools ===

  // Initialize Clawstr agent (lazy — only starts if CLAWSTR_PRIVATE_KEY is set)
  let clawstrAgent: ClawstrAgent | null = null;

  const getClawstrAgent = (): ClawstrAgent => {
    if (!clawstrAgent) {
      clawstrAgent = new ClawstrAgent({
        enabled: process.env.CLAWSTR_ENABLED === 'true',
        privateKey: process.env.CLAWSTR_PRIVATE_KEY || '',
        relays: process.env.CLAWSTR_RELAYS?.split(',') || [
          'wss://relay.ditto.pub',
          'wss://nos.lol',
          'wss://relay.primal.net',
        ],
        subclaws: process.env.CLAWSTR_SUBCLAWS?.split(',') || [
          '/c/ai-freedom',
          '/c/builds',
          '/c/agent-economy',
        ],
      });
    }
    return clawstrAgent;
  };

  // Clawstr Status tool
  server.registerTool({
    name: 'clawstr-status',
    description: 'Get Clawstr agent status (connection, monitor stats)',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getClawstrAgent();
        return agent.getStatus();
      } catch (err) {
        console.error('[AURA] Clawstr status error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Clawstr Scan and Post tool
  server.registerTool({
    name: 'clawstr-scan',
    description: 'Scan a GitHub repo and post results to a Clawstr subclaw',
    parameters: {
      type: 'object',
      required: ['repoUrl'],
      properties: {
        repoUrl: { type: 'string', description: 'GitHub repository URL to scan' },
        subclaw: { type: 'string', description: 'Subclaw to post to (default: /c/builds)' }
      }
    },
    handler: async (args) => {
      try {
        const repoUrl = args.repoUrl as string;
        const subclaw = (args.subclaw as string) || '/c/builds';
        const agent = getClawstrAgent();
        const eventId = await agent.scanAndPost(repoUrl, subclaw);
        return { success: true, eventId, subclaw };
      } catch (err) {
        console.error('[AURA] Clawstr scan error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Clawstr Post tool
  server.registerTool({
    name: 'clawstr-post',
    description: 'Post a message to a Clawstr subclaw',
    parameters: {
      type: 'object',
      required: ['content'],
      properties: {
        content: { type: 'string', description: 'Message content' },
        subclaw: { type: 'string', description: 'Subclaw to post to (default: /c/builds)' }
      }
    },
    handler: async (args) => {
      try {
        const content = args.content as string;
        const subclaw = (args.subclaw as string) || '/c/builds';
        const agent = getClawstrAgent();
        const eventId = await agent.postToSubclaw(subclaw, content);
        return { success: true, eventId, subclaw };
      } catch (err) {
        console.error('[AURA] Clawstr post error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Register Clawstr Note tool (kind 1 - visible on all Nostr clients)
  server.registerTool({
    name: 'clawstr-note',
    description: 'Post a regular Nostr note (kind 1) - visible on primal.net, njump.me, and all Nostr clients',
    parameters: {
      type: 'object',
      required: ['content'],
      properties: {
        content: { type: 'string', description: 'Note content' },
        hashtags: { type: 'array', items: { type: 'string' }, description: 'Hashtags to add (e.g. ["security", "github"])' }
      }
    },
    handler: async (args) => {
      try {
        const content = args.content as string;
        const hashtags = args.hashtags as string[] | undefined;
        const agent = getClawstrAgent();
        const client = agent.getClient();
        const eventId = await client.postNote(content, hashtags);
        return { success: true, eventId, kind: 1, visibleOn: ['primal.net', 'njump.me', 'iris.to', 'snort.social'] };
      } catch (err) {
        console.error('[AURA] Clawstr note error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Clawstr Leaderboard tool
  server.registerTool({
    name: 'clawstr-leaderboard',
    description: 'Post the weekly agent reputation leaderboard to Clawstr',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const agent = getClawstrAgent();
        const eventId = await agent.postLeaderboard();
        if (eventId) {
          return { success: true, eventId, message: 'Leaderboard posted to /c/builds' };
        }
        return { success: false, message: 'Failed to post leaderboard' };
      } catch (err) {
        console.error('[AURA] Clawstr leaderboard error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Clawstr Agent Reputation tool
  server.registerTool({
    name: 'clawstr-reputation',
    description: 'Get reputation score for a Clawstr agent by pubkey',
    parameters: {
      type: 'object',
      properties: {
        pubkey: { type: 'string', description: 'Nostr pubkey (hex format)' }
      }
    },
    handler: async (args) => {
      try {
        const agent = getClawstrAgent();
        const pubkey = args.pubkey as string | undefined;

        if (pubkey) {
          const rep = agent.getAgentReputation(pubkey);
          if (rep) {
            return {
              pubkey: rep.pubkey,
              displayName: rep.displayName,
              reputationScore: rep.reputationScore,
              safeRepos: rep.safeRepos,
              riskyRepos: rep.riskyRepos,
              scamRepos: rep.scamRepos,
              totalScans: rep.totalScans,
              lastUpdated: new Date(rep.lastUpdated).toISOString()
            };
          }
          return { error: 'Agent not found' };
        }

        // Return all reputations if no pubkey specified
        const all = agent.getAllReputations();
        return {
          totalAgents: all.length,
          agents: all.map(r => ({
            pubkey: r.pubkey.slice(0, 16) + '...',
            displayName: r.displayName,
            score: r.reputationScore,
            safe: r.safeRepos,
            risky: r.riskyRepos,
            scam: r.scamRepos
          }))
        };
      } catch (err) {
        console.error('[AURA] Clawstr reputation error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Register Report Generation tool
  server.registerTool({
    name: 'generate-report',
    description: 'Generate an HTML or JSON security report for a GitHub repository. Runs trust-scan and scam-scan, then produces a formatted report.',
    parameters: {
      type: 'object',
      required: ['repoUrl'],
      properties: {
        repoUrl: { type: 'string', description: 'GitHub repository URL' },
        format: { type: 'string', enum: ['html', 'json'], description: 'Report format (default: html)' },
        includeLocalScan: { type: 'boolean', description: 'Include local code scan (default: false)' },
      }
    },
    handler: async (args) => {
      const repoUrl = args.repoUrl as string;
      const format = (args.format as ReportFormat) || 'html';

      console.log(`[AURA] Generating ${format} report for: ${repoUrl}`);

      const reportData: ReportData = {
        repoUrl,
        generatedAt: new Date().toISOString(),
      };

      // Run trust scan
      try {
        const trustResult = await performTrustScan(repoUrl);
        reportData.trustScan = {
          trustScore: trustResult.trustScore,
          grade: trustResult.grade,
          verdict: trustResult.verdict,
          checks: trustResult.checks?.map(c => ({
            name: c.name,
            passed: c.status === 'good',
            details: c.explanation,
            weight: c.points,
          })),
          metrics: trustResult.metrics as unknown as Record<string, unknown>,
        };
      } catch (err) {
        console.error('[AURA] Report trust-scan failed:', err);
      }

      // Run scam scan (use the registered tool handler to get the full result)
      try {
        const scamTool = server.getTool('scam-scan');
        if (scamTool) {
          const scamResult = await scamTool.handler({ gitUrl: repoUrl }) as any;
          reportData.scamScan = {
            scamScore: scamResult.scamScore ?? scamResult.codeSafety?.scamScore ?? 0,
            riskLevel: scamResult.riskLevel ?? (scamResult.isLikelyScam ? 'high' : 'low'),
            isLikelyScam: scamResult.isLikelyScam ?? false,
            flags: scamResult.redFlags ?? scamResult.warnings ?? [],
            summary: scamResult.summary ?? scamResult.analysis ?? '',
          };
        }
      } catch (err) {
        console.error('[AURA] Report scam-scan failed:', err);
      }

      // Optionally run local scan (clones repo)
      if (args.includeLocalScan) {
        try {
          const localResult = await scanRemoteGit({ gitUrl: repoUrl, scanSecrets: true, scanPackages: true, fastMode: true });
          reportData.localScan = {
            secrets_found: localResult.secrets.length,
            package_vulns: localResult.packages.filter((p: PackageFinding) => p.severity === 'critical' || p.severity === 'high').length,
            sast_findings: localResult.sastFindings?.length ?? 0,
            tools_used: localResult.toolsUsed,
            findings: [
              ...localResult.secrets.map((s: SecretFinding) => ({
                type: 'secret', severity: 'high' as string, file: s.file, line: s.line, message: `${s.type}: ${s.snippet || 'Secret detected'}`
              })),
              ...localResult.packages.map((p: PackageFinding) => ({
                type: 'vulnerability', severity: p.severity || 'medium', file: p.name, message: `${p.name}@${p.version}: ${p.title || 'vulnerable'}`
              })),
            ],
          };
        } catch (err) {
          console.error('[AURA] Report local-scan failed:', err);
        }
      }

      const report = generateReport(reportData, format);
      console.log(`[AURA] Report generated: ${report.length} chars (${format})`);

      return {
        format,
        repoUrl,
        reportLength: report.length,
        report,
        generatedAt: reportData.generatedAt,
      };
    }
  });

  // === Rug Database Tools ===

  // Report a confirmed rug
  server.registerTool({
    name: 'report-rug',
    description: 'Report a confirmed rug pull to the database (helps improve future scans)',
    parameters: {
      type: 'object',
      required: ['repoUrl'],
      properties: {
        repoUrl: { type: 'string', description: 'GitHub repository URL that rugged' },
        rugType: { type: 'string', description: 'Type of rug (e.g., "liquidity pull", "mint exploit", "honeypot")' },
        evidence: { type: 'string', description: 'Evidence or notes about the rug' },
        reportedBy: { type: 'string', description: 'Who is reporting (optional)' }
      }
    },
    handler: async (args) => {
      try {
        const repoUrl = args.repoUrl as string;
        const githubMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/);
        if (!githubMatch) {
          return { error: 'Invalid GitHub URL' };
        }

        const success = reportRug({
          repoUrl,
          owner: githubMatch[1],
          repoName: githubMatch[2].replace(/\.git$/, ''),
          rugType: args.rugType as string,
          evidence: args.evidence as string,
          reportedBy: args.reportedBy as string
        });

        if (success) {
          console.log(`[AURA] Rug reported: ${repoUrl}`);
          return {
            success: true,
            message: `Rug reported: ${repoUrl}`,
            note: 'This repo and its owner are now flagged. Future scans will show warnings.'
          };
        } else {
          return { error: 'Failed to report rug' };
        }
      } catch (err) {
        console.error('[AURA] Report rug error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Get rug database stats
  server.registerTool({
    name: 'rug-db-stats',
    description: 'Get statistics from the rug database (confirmed rugs, flagged devs, accuracy)',
    parameters: {
      type: 'object',
      properties: {}
    },
    handler: async () => {
      try {
        const dbStats = getRugDbStats();
        const accuracy = getAccuracyStats();
        const recentRugs = getRecentRugs(5);
        const flaggedDevs = getFlaggedDevs();
        const xStats = getXDbStats();

        return {
          database: dbStats,
          xAccounts: xStats,
          accuracy: {
            ...accuracy,
            note: accuracy.totalWithFeedback > 0
              ? `${accuracy.accuracy}% accurate on ${accuracy.totalWithFeedback} scans with feedback`
              : 'No feedback data yet - submit feedback to help us learn!'
          },
          recentRugs,
          flaggedDevs: flaggedDevs.slice(0, 10)
        };
      } catch (err) {
        console.error('[AURA] Rug DB stats error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Submit feedback on a scan
  server.registerTool({
    name: 'submit-feedback',
    description: 'Submit feedback on a scan result (helps improve accuracy)',
    parameters: {
      type: 'object',
      required: ['repoUrl', 'outcome'],
      properties: {
        repoUrl: { type: 'string', description: 'GitHub repository URL' },
        outcome: { type: 'string', enum: ['rugged', 'safe', 'unknown'], description: 'What actually happened' },
        source: { type: 'string', description: 'Who is providing feedback (optional)' }
      }
    },
    handler: async (args) => {
      try {
        const repoUrl = args.repoUrl as string;
        const outcome = args.outcome as 'rugged' | 'safe' | 'unknown';
        const source = args.source as string;

        const success = submitFeedback(repoUrl, outcome, source);

        if (success) {
          const message = outcome === 'rugged'
            ? 'Feedback recorded. Repo added to rug database and owner flagged.'
            : 'Feedback recorded. This helps improve our accuracy!';
          return { success: true, message };
        } else {
          return { error: 'Failed to submit feedback' };
        }
      } catch (err) {
        console.error('[AURA] Submit feedback error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Get developer reputation
  server.registerTool({
    name: 'dev-reputation',
    description: 'Get a GitHub developer\'s reputation from the rug database',
    parameters: {
      type: 'object',
      required: ['username'],
      properties: {
        username: { type: 'string', description: 'GitHub username' }
      }
    },
    handler: async (args) => {
      try {
        const username = args.username as string;
        const reputation = getDevReputation(username);
        const flagged = isDevFlagged(username);

        if (!reputation && !flagged.flagged) {
          return {
            username,
            status: 'unknown',
            message: 'No data on this developer yet. They haven\'t been scanned or reported.'
          };
        }

        return {
          username,
          reputation: reputation || { reputationScore: 50, totalRepos: 0, ruggedRepos: 0, safeRepos: 0 },
          flagged: flagged.flagged,
          flagReason: flagged.reason,
          rugCount: flagged.rugCount,
          warning: flagged.flagged ? `⚠️ This developer has ${flagged.rugCount} confirmed rug(s)!` : null
        };
      } catch (err) {
        console.error('[AURA] Dev reputation error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Flag a developer
  server.registerTool({
    name: 'flag-dev',
    description: 'Manually flag a developer as a known bad actor',
    parameters: {
      type: 'object',
      required: ['username', 'reason'],
      properties: {
        username: { type: 'string', description: 'GitHub username to flag' },
        reason: { type: 'string', description: 'Reason for flagging' }
      }
    },
    handler: async (args) => {
      try {
        const username = args.username as string;
        const reason = args.reason as string;

        const success = flagDeveloper(username, reason);

        if (success) {
          return {
            success: true,
            message: `Developer ${username} flagged: ${reason}`,
            note: 'All future scans of repos by this developer will show warnings.'
          };
        } else {
          return { error: 'Failed to flag developer' };
        }
      } catch (err) {
        console.error('[AURA] Flag dev error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // X Account Reputation Check
  server.registerTool({
    name: 'x-reputation',
    description: 'Check X/Twitter account reputation from our database',
    parameters: {
      type: 'object',
      required: ['username'],
      properties: {
        username: { type: 'string', description: 'X/Twitter username (without @)' }
      }
    },
    handler: async (args) => {
      try {
        const username = (args.username as string).replace(/^@/, '');
        const reputation = getXAccountReputation(username);

        if (!reputation) {
          return {
            username,
            status: 'unknown',
            message: 'No data on this X account yet. Run an x-scan first.'
          };
        }

        return {
          username,
          reputation,
          warning: reputation.flagged ? `⚠️ This account is flagged: ${reputation.flagReason}` : null,
          summary: reputation.scamCount > 0
            ? `⚠️ Linked to ${reputation.scamCount} scam project(s)`
            : reputation.legitCount > 0
              ? `✅ ${reputation.legitCount} verified legit project(s)`
              : 'No project history yet'
        };
      } catch (err) {
        console.error('[AURA] X reputation error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Flag X Account
  server.registerTool({
    name: 'flag-x-account',
    description: 'Manually flag an X/Twitter account as suspicious or scammer',
    parameters: {
      type: 'object',
      required: ['username', 'reason'],
      properties: {
        username: { type: 'string', description: 'X/Twitter username to flag' },
        reason: { type: 'string', description: 'Reason for flagging' }
      }
    },
    handler: async (args) => {
      try {
        const username = (args.username as string).replace(/^@/, '');
        const reason = args.reason as string;

        const success = flagXAccount(username, reason);

        if (success) {
          return {
            success: true,
            message: `X account @${username} flagged: ${reason}`,
            note: 'All future x-scans of this account will show warnings.'
          };
        } else {
          return { error: 'Failed to flag X account' };
        }
      } catch (err) {
        console.error('[AURA] Flag X account error:', err);
        return { error: err instanceof Error ? err.message : 'Unknown error' };
      }
    }
  });

  // Enhanced trust scan (with rug database intelligence)
  server.registerTool({
    name: 'enhanced-trust-scan',
    description: 'Trust scan with rug database intelligence (checks known rugs, dev reputation, fork origins)',
    parameters: {
      type: 'object',
      required: ['gitUrl'],
      properties: {
        gitUrl: { type: 'string', description: 'GitHub repository URL to check' }
      }
    },
    handler: async (args) => {
      try {
        const gitUrl = args.gitUrl as string;
        console.log(`[AURA] Enhanced trust scan for: ${gitUrl}`);

        const result = await performEnhancedTrustScan(gitUrl);

        console.log(`[AURA] Enhanced scan complete: ${result.adjustedScore}/100 (${result.adjustedVerdict})`);
        if (result.knownRug) {
          console.log(`[AURA] ⚠️ KNOWN RUG detected!`);
        }
        if (result.ownerHistory.hasRuggedBefore) {
          console.log(`[AURA] ⚠️ Owner has ${result.ownerHistory.rugCount} previous rug(s)`);
        }

        return result;
      } catch (err) {
        console.error('[AURA] Enhanced trust scan error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          trustScore: 0,
          grade: 'F',
          verdict: 'ERROR',
          summary: 'Failed to scan repository. Please check the URL and try again.'
        };
      }
    }
  });

  // Website Probe - Detect static vs active sites (rug detection)
  server.registerTool({
    name: 'probe',
    description: 'Probe a website to detect if it has real backend activity or is just a static landing page (rug detection)',
    parameters: {
      type: 'object',
      required: ['url'],
      properties: {
        url: { type: 'string', description: 'Website URL to probe (e.g., https://example.com)' }
      }
    },
    handler: async (args) => {
      try {
        const url = args.url as string;
        console.log(`[AURA] Probing website: ${url}`);

        const result = await probeWebsite(url);

        console.log(`[AURA] Probe complete: ${result.verdict} (${result.apiCalls.length} API calls, ${result.webSocketConnections.length} WebSocket)`);

        return {
          ...result,
          formatted: formatProbeResult(result)
        };
      } catch (err) {
        console.error('[AURA] Probe error:', err);
        return {
          error: err instanceof Error ? err.message : 'Unknown error',
          verdict: 'ERROR',
          riskLevel: 'HIGH'
        };
      }
    }
  });

  // Start HTTP server
  await server.start();
  console.log(`[AURA] Auditor listening on http://127.0.0.1:${PORT}`);
  console.log('[AURA] Endpoints: /info, /tools, /memory, /settings, /audits, /stats, /notifications');

  // Start Moltbook agent if API key is available
  if (process.env.MOLTBOOK_API_KEY) {
    try {
      const agent = getMoltbookAgent();
      await agent.start();
      console.log('[AURA] Moltbook agent started');
    } catch (err) {
      console.error('[AURA] Moltbook agent failed to start:', err);
    }
  } else {
    console.log('[AURA] Moltbook agent not started (set MOLTBOOK_API_KEY to enable)');
  }

  // Start Clawstr agent if private key is available
  if (process.env.CLAWSTR_PRIVATE_KEY && process.env.CLAWSTR_ENABLED === 'true') {
    try {
      const agent = getClawstrAgent();
      await agent.start();
      console.log('[AURA] Clawstr agent started');
    } catch (err) {
      console.error('[AURA] Clawstr agent failed to start:', err);
    }
  } else {
    console.log('[AURA] Clawstr agent not started (set CLAWSTR_ENABLED=true and CLAWSTR_PRIVATE_KEY to enable)');
  }

  // Start WebSocket server for real-time updates
  const wsServer = getWebSocketServer(WS_PORT);
  await wsServer.start();
  console.log(`[AURA] WebSocket server on ws://127.0.0.1:${WS_PORT}`);

  // Connect client to self for memory storage
  if (!AURA_BUS_URL) {
    await busClient.connect();
    console.log('[AURA] Self-contained mode: client connected to local server');
  }

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n[AURA] Shutting down...');
    await server.stop();
    await busClient?.disconnect();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\n[AURA] Shutting down...');
    await server.stop();
    await busClient?.disconnect();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error('[AURA] FATAL:', err);
  process.exit(1);
});

// Export for programmatic use
export { AuraServer } from './aura/server.js';
export { AuraClient } from './aura/client.js';
export { AuditorPipeline } from './auditor/pipeline.js';
export { SchemaValidator, ValidationError } from './auditor/validator.js';
export * from './types/events.js';

// Client SDK exports
export {
  AuditClient,
  createPullRequestEvent,
  createDeployEvent,
  createInfraChangeEvent
} from './client/index.js';
export type { AuditClientConfig, AuditRequest, AuditResult, ServerInfo } from './client/index.js';

// Pipeline framework exports
export {
  SecurityPipeline,
  SecretsDetectionStage,
  VulnerabilityScanStage,
  CriticalAssetStage,
  InfrastructureChangeStage,
  ProductionDeployStage
} from './pipeline/index.js';
export type { PipelineContext, AnalysisStage, RuleDefinition, RuleResult } from './pipeline/index.js';

// Integration exports
export { WebhookServer, defaultHandlers } from './integrations/webhook.js';
export { GitHubIntegration } from './integrations/github.js';
export { GitLabIntegration } from './integrations/gitlab.js';
export { SnykParser, TrivyParser, SemgrepParser, NpmAuditParser, getParser } from './integrations/scanners.js';
export { ConfigLoader, configLoader } from './integrations/config.js';
export type { AuditorConfig, ModuleConfig, IntegrationConfig } from './integrations/config.js';
export { LocalScanner, quickLocalScan, scanRemoteGit, isGitUrl } from './integrations/local-scanner.js';
export type { LocalScanConfig, LocalScanResult, SecretFinding, PackageFinding, SastFinding, DiscoveredService, DiscoveredModule, RemoteScanConfig, RemoteScanResult } from './integrations/local-scanner.js';

// AWS Scanner exports
export { AWSScanner, scanAWS } from './integrations/aws-scanner.js';
export type { AWSScanConfig, AWSScanResult, AWSFinding } from './integrations/aws-scanner.js';

// Database exports
export { AuditorDatabase, getDatabase, closeDatabase } from './database/index.js';
export type { AuditRecord, SettingsRecord, NotificationRecord, ApiKeyRecord } from './database/index.js';

// Notification exports
export { NotificationService, createNotificationFromAudit } from './integrations/notifications.js';
export type { NotificationConfig, NotificationPayload } from './integrations/notifications.js';

// WebSocket exports
export { AuditorWebSocket, getWebSocketServer, closeWebSocketServer } from './websocket/index.js';
export type { WSMessage, AuditStartedPayload, AuditCompletedPayload, FindingPayload } from './websocket/index.js';

// Trust Scanner exports (Rug Check)
export { performTrustScan } from './integrations/trust-scanner.js';
export type { TrustScanResult, TrustCheck, TrustMetrics } from './integrations/trust-scanner.js';

// AI Verifier exports
export { performAIVerification } from './integrations/ai-verifier.js';
export type { AIVerifyResult } from './integrations/ai-verifier.js';

// Scam Detector exports
export { detectScamPatterns, quickScamScan, getScamSignatures, addScamSignature } from './integrations/scam-detector.js';
export type { ScamSignature, ScamDetectionResult, SimilarityMatch } from './integrations/scam-detector.js';

// Report Generation exports
export { generateReport, generateHtmlReport, generateJsonReport } from './reporting/index.js';
export type { ReportData, ReportFormat } from './reporting/index.js';

// Moltbook Integration exports
export { MoltbookClient, MoltbookScanner, MoltbookAgent, FeedMonitor, makePostDecision, formatScanResult, formatScanError, formatPostTitle, AgentScorer, BotFarmDetector, JailEnforcer } from './integrations/moltbook/index.js';
export type { MoltbookAgentConfig, PostDecision, AgentTrustScore, JailLevel, BotCluster, AgentReputation, RepoScanRecord } from './integrations/moltbook/index.js';

// Clawstr Integration exports (Nostr-based AI agent network)
export { ClawstrAgent, ClawstrClient, ClawstrMonitor, startClawstrAgent, generateClawstrKeys } from './integrations/clawstr/index.js';
export type { ClawstrAgentStatus, ClawstrAgentConfig, NostrEvent, NostrKeyPair, ScanRequest as ClawstrScanRequest, MentionRequest as ClawstrMentionRequest } from './integrations/clawstr/index.js';

// x402 Payment API exports
export { startX402Server, PRICING, getPrice, createPayment, getPayment, getPaymentStats, verifySolanaPayment } from './x402/index.js';
export type { Payment, PaymentRequest, PaymentMethod, X402Config } from './x402/index.js';

// Rug Database exports (track confirmed rugs, dev reputation, feedback loop)
export {
  reportRug,
  isKnownRug,
  hasOwnerRuggedBefore,
  getDevReputation,
  updateDevReputation,
  isDevFlagged,
  flagDeveloper,
  recordScan,
  submitFeedback,
  getAccuracyStats,
  addScamSignatureToDb,
  isForkedFromScam,
  ownerHasScamSignatures,
  getDbStats,
  getRecentRugs,
  getFlaggedDevs
} from './integrations/index.js';
export type { RugReport, DevReputation } from './integrations/index.js';

// Enhanced Scanner exports (trust scan + rug database intelligence)
export { performEnhancedTrustScan, quickRugDbCheck } from './integrations/index.js';
export type { EnhancedTrustResult } from './integrations/index.js';

// Website Probe exports (detect static vs active sites)
export { probeWebsite, formatProbeResult } from './integrations/index.js';
export type { ProbeResult, NetworkRequest } from './integrations/index.js';
