// SLOP Auditor - Main entry point
// No SLOP bus = No run (fail-closed)

import { SlopServer } from './slop/server.js';
import { SlopClient } from './slop/client.js';
import { AuditorPipeline } from './auditor/pipeline.js';
import { SchemaValidator, ValidationError } from './auditor/validator.js';
import { LocalScanner, scanRemoteGit } from './integrations/local-scanner.js';
import type { LocalScanResult, SecretFinding } from './integrations/local-scanner.js';
import { getWebSocketServer, type AuditorWebSocket } from './websocket/index.js';

const PORT = parseInt(process.env.SLOP_PORT ?? '3000', 10);
const WS_PORT = parseInt(process.env.WS_PORT ?? '3001', 10);
const SLOP_BUS_URL = process.env.SLOP_BUS_URL;

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

  console.log(`[SLOP] Fetching ${isGitHub ? 'GitHub' : 'GitLab'} repo: ${owner}/${repo}`);

  const secrets: Array<{ file: string; line: number; type: string; severity: string }> = [];
  const discoveredServices: Array<{ id: string; name: string; type: string; source: string; severity: string }> = [];
  const discoveredModules: Array<{ id: string; name: string; type: string; fileCount: number; path: string; files: string[] }> = [];
  const scannedFiles: string[] = [];

  try {
    // Fetch repo tree
    let treeUrl: string;
    let headers: Record<string, string> = { 'User-Agent': 'SLOP-Auditor' };

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

    console.log(`[SLOP] Found ${files.length} files in repo`);

    // Filter to scannable files
    const scanExtensions = ['.js', '.ts', '.jsx', '.tsx', '.json', '.yaml', '.yml', '.env', '.py', '.go', '.rb', '.php', '.java', '.cs', '.config', '.conf', '.sh', '.bash'];
    const scanFiles = files.filter(f => {
      const ext = f.path.substring(f.path.lastIndexOf('.')).toLowerCase();
      const name = f.path.split('/').pop() || '';
      return scanExtensions.includes(ext) || name.startsWith('.env') || name === 'package.json' || name === 'Dockerfile';
    }).slice(0, 100); // Limit to 100 files for API rate limits

    console.log(`[SLOP] Scanning ${scanFiles.length} relevant files`);

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

    console.log(`[SLOP] Remote scan complete. Found ${secrets.length} secrets, ${discoveredServices.length} services, ${discoveredModules.length} modules`);

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
    console.error('[SLOP] Remote scan error:', err);
    throw err;
  }
}

async function main(): Promise<void> {
  console.log('[SLOP] Starting auditor pipeline...');

  // Create SLOP server
  const server = new SlopServer({ port: PORT });

  // Create SLOP client for publishing to bus (if configured)
  let busClient: SlopClient | null = null;

  if (SLOP_BUS_URL) {
    busClient = new SlopClient({ baseUrl: SLOP_BUS_URL });

    try {
      await busClient.connect();
      console.log(`[SLOP] Connected to bus at ${SLOP_BUS_URL}`);
    } catch (err) {
      console.error('[SLOP] FATAL: Cannot connect to SLOP bus - fail-closed');
      process.exit(1);
    }
  } else {
    // Self-contained mode: client publishes to own server
    busClient = new SlopClient({ baseUrl: `http://127.0.0.1:${PORT}` });
  }

  // Create pipeline
  const pipeline = new AuditorPipeline({ slopClient: busClient });
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
        scanEnvFiles: { type: 'boolean', default: true }
      }
    },
    handler: async (args) => {
      try {
        let targetPath = (args.targetPath as string) || process.cwd();

        // Handle Git URL - clone and scan with full tool suite
        if (args.gitUrl) {
          const gitUrl = args.gitUrl as string;
          console.log(`[SLOP] Cloning and scanning remote repo: ${gitUrl}`);

          try {
            // Use the clone-based scanner for full capabilities
            const remoteResult = await scanRemoteGit({
              gitUrl,
              scanSecrets: args.scanSecrets !== false,
              scanPackages: args.scanPackages !== false
            });

            console.log(`[SLOP] Remote scan complete in ${remoteResult.cloneDuration + remoteResult.scanDuration}ms`);
            console.log(`[SLOP] Found: ${remoteResult.secrets.length} secrets, ${remoteResult.packages.length} vulns`);

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
            console.error(`[SLOP] Remote Git scan failed:`, gitErr);
            return {
              agent_id: 'exploit-reviewer',
              agent_state: 'blocked',
              events: [],
              meta: { assumptions: [], uncertainties: [] },
              error: `Remote scan failed: ${gitErr instanceof Error ? gitErr.message : 'Unknown error'}`
            };
          }
        }
        const scanner = new LocalScanner({
          targetPath,
          scanSecrets: args.scanSecrets !== false,
          scanPackages: args.scanPackages !== false,
          scanEnvFiles: args.scanEnvFiles !== false
        });

        console.log(`[SLOP] Starting local scan of: ${targetPath}`);

        // Notify WebSocket clients that scan is starting
        const wsScanId = `scan-${Date.now()}`;
        const ws = getWebSocketServer(WS_PORT);
        ws.notifyAuditStarted({
          auditId: wsScanId,
          type: 'code',
          target: targetPath
        });

        const scanResult = await scanner.scan();
        console.log(`[SLOP] Scan complete. Found ${scanResult.secrets.length} secrets, ${scanResult.packages.length} package issues, ${scanResult.sastFindings.length} SAST findings`);

        // Convert to audit input and run through pipeline
        const auditInput = scanner.toAuditorInput(scanResult);

        let auditResult;
        try {
          auditResult = await pipeline.analyze(auditInput);
        } catch (pipelineErr) {
          // If pipeline fails, create a basic result from scan data
          console.log(`[SLOP] Pipeline analysis skipped: ${pipelineErr}`);
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
          console.log(`[SLOP] Scan result stored to memory: ${scanId}`);
        } catch (storeErr) {
          console.error('[SLOP] Failed to store scan result to memory:', storeErr);
        }

        // Store to SQLite database for persistent history
        let auditId: string | undefined;
        try {
          const db = server.getDatabase();
          auditId = db.saveAudit('code', scanResult.path, scanResult as LocalScanResult);
          console.log(`[SLOP] Scan result saved to database: ${auditId}`);
        } catch (dbErr) {
          console.error('[SLOP] Failed to save to database:', dbErr);
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
              console.log(`[SLOP] Notifications sent: ${result.sent.join(', ')}`);
            }

            // Notify WebSocket clients that scan is complete
            ws.notifyAuditCompleted({
              auditId,
              type: 'code',
              target: scanResult.path,
              summary
            });
          } catch (notifyErr) {
            console.error('[SLOP] Notification error:', notifyErr);
          }
        }

        return fullResult;
      } catch (err) {
        console.error('[SLOP] Local scan error:', err);
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

  // Start HTTP server
  await server.start();
  console.log(`[SLOP] Auditor listening on http://127.0.0.1:${PORT}`);
  console.log('[SLOP] Endpoints: /info, /tools, /memory, /settings, /audits, /stats, /notifications');

  // Start WebSocket server for real-time updates
  const wsServer = getWebSocketServer(WS_PORT);
  await wsServer.start();
  console.log(`[SLOP] WebSocket server on ws://127.0.0.1:${WS_PORT}`);

  // Connect client to self for memory storage
  if (!SLOP_BUS_URL) {
    await busClient.connect();
    console.log('[SLOP] Self-contained mode: client connected to local server');
  }

  // Graceful shutdown
  process.on('SIGINT', async () => {
    console.log('\n[SLOP] Shutting down...');
    await server.stop();
    await busClient?.disconnect();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    console.log('\n[SLOP] Shutting down...');
    await server.stop();
    await busClient?.disconnect();
    process.exit(0);
  });
}

main().catch((err) => {
  console.error('[SLOP] FATAL:', err);
  process.exit(1);
});

// Export for programmatic use
export { SlopServer } from './slop/server.js';
export { SlopClient } from './slop/client.js';
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
export type { AuditRecord, SettingsRecord, NotificationRecord } from './database/index.js';

// Notification exports
export { NotificationService, createNotificationFromAudit } from './integrations/notifications.js';
export type { NotificationConfig, NotificationPayload } from './integrations/notifications.js';

// WebSocket exports
export { AuditorWebSocket, getWebSocketServer, closeWebSocketServer } from './websocket/index.js';
export type { WSMessage, AuditStartedPayload, AuditCompletedPayload, FindingPayload } from './websocket/index.js';
