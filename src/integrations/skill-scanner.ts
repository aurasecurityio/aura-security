/**
 * AURA Skill Scanner
 *
 * Scans AI agent skills (OpenClaw, Claude MCP, LangChain) for security issues.
 * Detects malware patterns, credential theft, prompt injection, and privilege escalation.
 *
 * Part of AURA: Agent Universal Reputation & Assurance
 */

import { detectScamPatterns } from './scam-detector.js';
import { performTrustScan } from './trust-scanner.js';

// ============================================================================
// Types
// ============================================================================

export type SkillFormat = 'openclaw' | 'mcp' | 'langchain' | 'auto';
export type SkillVerdict = 'SAFE' | 'WARNING' | 'DANGEROUS' | 'BLOCKED';
export type FindingSeverity = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export interface MalwareMatch {
  pattern: string;
  match: string;
  file: string;
  line?: number;
  severity: FindingSeverity;
  category: 'credential_theft' | 'file_exfil' | 'network' | 'exec' | 'crypto_miner' | 'backdoor';
  description: string;
}

export interface PermissionIssue {
  permission: string;
  severity: FindingSeverity;
  reason: string;
  recommendation: string;
}

export interface PromptInjectionRisk {
  pattern: string;
  match: string;
  file: string;
  severity: FindingSeverity;
  description: string;
}

export interface NetworkRisk {
  url: string;
  file: string;
  severity: FindingSeverity;
  reason: string;
}

export interface SkillMetadata {
  name: string;
  description?: string;
  author?: string;
  version?: string;
  requires?: {
    bins?: string[];
    env?: string[];
    config?: string[];
  };
  permissions?: {
    filesystem?: string[];
    network?: string[];
    exec?: string[];
  };
}

export interface SkillScanResult {
  // Identification
  skillId: string;
  name: string;
  source: SkillFormat;
  sourceUrl?: string;

  // Verdicts
  verdict: SkillVerdict;
  riskScore: number; // 0-100 (0 = safe, 100 = dangerous)

  // Findings
  malwarePatterns: MalwareMatch[];
  permissionIssues: PermissionIssue[];
  promptInjectionRisks: PromptInjectionRisk[];
  networkRisks: NetworkRisk[];

  // Metadata
  metadata?: SkillMetadata;
  repoTrustScore?: number;
  authorReputation?: number;

  // Badge eligibility
  verifiedBadge: boolean;
  badgeReason: string;

  // Summary
  summary: string;
  recommendations: string[];

  // Timing
  scanTime: number;
}

// ============================================================================
// Malware Patterns
// ============================================================================

const MALWARE_PATTERNS: Array<{
  pattern: RegExp;
  severity: FindingSeverity;
  category: MalwareMatch['category'];
  description: string;
}> = [
  // === Credential Theft ===
  {
    pattern: /process\.env\.(API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY|SEED|MNEMONIC)/gi,
    severity: 'HIGH',
    category: 'credential_theft',
    description: 'Accesses sensitive environment variables'
  },
  {
    pattern: /keychain|credential[s]?\.get|wallet.*seed|mnemonic/gi,
    severity: 'CRITICAL',
    category: 'credential_theft',
    description: 'Attempts to access system keychain or wallet credentials'
  },
  {
    pattern: /\.ssh\/|id_rsa|id_ed25519|authorized_keys/gi,
    severity: 'CRITICAL',
    category: 'credential_theft',
    description: 'Accesses SSH keys'
  },
  {
    pattern: /\.aws\/credentials|\.boto|aws_access_key/gi,
    severity: 'CRITICAL',
    category: 'credential_theft',
    description: 'Accesses AWS credentials'
  },
  {
    pattern: /\.env\s*['"]\s*\)|dotenv|loadEnv/gi,
    severity: 'MEDIUM',
    category: 'credential_theft',
    description: 'Loads environment files (may contain secrets)'
  },

  // === File Exfiltration ===
  {
    pattern: /fs\.(readFile|readdir).*\/(etc|home|Users|root)/gi,
    severity: 'HIGH',
    category: 'file_exfil',
    description: 'Reads sensitive system directories'
  },
  {
    pattern: /glob\.(sync|glob).*(\*\*\/\*|\*\.\*)/gi,
    severity: 'MEDIUM',
    category: 'file_exfil',
    description: 'Recursive file scanning'
  },
  {
    pattern: /\/etc\/passwd|\/etc\/shadow|\.bashrc|\.zshrc|\.profile/gi,
    severity: 'HIGH',
    category: 'file_exfil',
    description: 'Accesses system configuration files'
  },

  // === Dangerous Execution ===
  {
    pattern: /child_process.*curl.*\|.*bash/gi,
    severity: 'CRITICAL',
    category: 'exec',
    description: 'Downloads and executes remote code'
  },
  {
    pattern: /eval\s*\(\s*(atob|Buffer\.from|decodeURI)/gi,
    severity: 'CRITICAL',
    category: 'exec',
    description: 'Executes obfuscated/encoded code'
  },
  {
    pattern: /new\s+Function\s*\(/gi,
    severity: 'HIGH',
    category: 'exec',
    description: 'Dynamic function creation (potential code injection)'
  },
  {
    pattern: /exec(Sync)?\s*\(\s*['"`].*\$\{/gi,
    severity: 'HIGH',
    category: 'exec',
    description: 'Command injection via template literals'
  },
  {
    pattern: /rm\s+-rf\s+[\/~]|del\s+\/[sq]/gi,
    severity: 'CRITICAL',
    category: 'exec',
    description: 'Destructive file deletion command'
  },
  {
    pattern: /sudo\s+|doas\s+|pkexec\s+/gi,
    severity: 'HIGH',
    category: 'exec',
    description: 'Privilege escalation attempt'
  },

  // === Suspicious Network Activity ===
  {
    pattern: /webhook\.site|requestbin\.com|ngrok\.io|burpcollaborator/gi,
    severity: 'HIGH',
    category: 'network',
    description: 'Data exfiltration endpoint detected'
  },
  {
    pattern: /fetch\s*\(\s*['"`]?\s*\+|\$\{.*\}.*fetch/gi,
    severity: 'MEDIUM',
    category: 'network',
    description: 'Dynamic URL construction (potential exfiltration)'
  },
  {
    pattern: /pastebin\.com|hastebin|ghostbin|rentry\.co/gi,
    severity: 'MEDIUM',
    category: 'network',
    description: 'Paste service URL (potential C2 or exfil)'
  },
  {
    pattern: /discord\.com\/api\/webhooks|slack\.com\/api|telegram\.org\/bot/gi,
    severity: 'MEDIUM',
    category: 'network',
    description: 'Messaging webhook (potential data exfiltration)'
  },

  // === Crypto Mining ===
  {
    pattern: /coinhive|cryptonight|monero.*miner|xmrig|stratum\+tcp/gi,
    severity: 'CRITICAL',
    category: 'crypto_miner',
    description: 'Cryptocurrency mining code detected'
  },

  // === Backdoors ===
  {
    pattern: /reverse.shell|bind.shell|nc\s+-[lp]|netcat.*-e/gi,
    severity: 'CRITICAL',
    category: 'backdoor',
    description: 'Reverse/bind shell detected'
  },
  {
    pattern: /socket\.connect.*\d+\.\d+\.\d+\.\d+/gi,
    severity: 'HIGH',
    category: 'backdoor',
    description: 'Direct IP connection (potential C2)'
  },
];

// ============================================================================
// Prompt Injection Patterns
// ============================================================================

const PROMPT_INJECTION_PATTERNS: Array<{
  pattern: RegExp;
  severity: FindingSeverity;
  description: string;
}> = [
  {
    pattern: /ignore\s+(previous|all|prior)\s+(instructions?|prompts?|rules?)/gi,
    severity: 'HIGH',
    description: 'Attempts to override system instructions'
  },
  {
    pattern: /disregard\s+(your|the|all)\s+(instructions?|guidelines?|rules?)/gi,
    severity: 'HIGH',
    description: 'Attempts to bypass guidelines'
  },
  {
    pattern: /\[\s*SYSTEM\s*\]|\[\s*ADMIN\s*\]|\[\s*DEVELOPER\s*\]/gi,
    severity: 'MEDIUM',
    description: 'Fake system/admin tags'
  },
  {
    pattern: /you\s+are\s+(now|no\s+longer)\s+(a|an|the)/gi,
    severity: 'MEDIUM',
    description: 'Identity manipulation attempt'
  },
  {
    pattern: /pretend\s+(you|to\s+be)|roleplay\s+as|act\s+as\s+if/gi,
    severity: 'LOW',
    description: 'Role manipulation (context dependent)'
  },
  {
    pattern: /new\s+instruction[s]?:|updated\s+rules?:|override:/gi,
    severity: 'HIGH',
    description: 'Attempts to inject new instructions'
  },
  {
    pattern: /<!--.*-->|\/\*.*\*\/|#.*hidden/gi,
    severity: 'MEDIUM',
    description: 'Hidden instructions in comments'
  },
  {
    pattern: /\u200b|\u200c|\u200d|\ufeff/g, // Zero-width characters
    severity: 'MEDIUM',
    description: 'Zero-width characters (potential hidden content)'
  },
];

// ============================================================================
// Dangerous Permissions
// ============================================================================

const DANGEROUS_PERMISSIONS: Array<{
  pattern: RegExp;
  permission: string;
  severity: FindingSeverity;
  reason: string;
  recommendation: string;
}> = [
  {
    pattern: /filesystem.*[*\/]|fs\..*\*|read.*home|write.*root/gi,
    permission: 'Unrestricted filesystem access',
    severity: 'HIGH',
    reason: 'Can read/write anywhere on the system',
    recommendation: 'Limit to specific directories'
  },
  {
    pattern: /network.*\*|fetch.*any|http.*unrestricted/gi,
    permission: 'Unrestricted network access',
    severity: 'MEDIUM',
    reason: 'Can connect to any external server',
    recommendation: 'Allowlist specific domains'
  },
  {
    pattern: /exec.*\*|shell.*true|command.*unrestricted/gi,
    permission: 'Unrestricted command execution',
    severity: 'CRITICAL',
    reason: 'Can run any system command',
    recommendation: 'Allowlist specific commands only'
  },
  {
    pattern: /sudo|root|admin|elevated/gi,
    permission: 'Elevated privileges',
    severity: 'CRITICAL',
    reason: 'Requests admin/root access',
    recommendation: 'Run with minimal privileges'
  },
];

// ============================================================================
// Suspicious URLs / Domains
// ============================================================================

const SUSPICIOUS_DOMAINS = [
  // Known exfil services
  'webhook.site', 'requestbin.com', 'hookbin.com', 'pipedream.net',
  // Paste services (can be C2)
  'pastebin.com', 'hastebin.com', 'ghostbin.co', 'paste.ee',
  // URL shorteners (hide real destination)
  'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd',
  // Known malicious
  'evil.com', 'hack.me',
];

// ============================================================================
// Whitelisted Security Research Domains (reduce false positives)
// ============================================================================

const SECURITY_RESEARCH_DOMAINS = [
  // Security research & news
  'opensourcemalware.com', 'thehackernews.com', 'krebsonsecurity.com',
  'bleepingcomputer.com', 'securityweek.com', 'darkreading.com',
  // Vendor security blogs
  'crowdstrike.com', 'snyk.io', 'jfrog.com', 'aikido.dev', 'koi.ai',
  'virustotal.com', 'vectra.ai', 'cisco.com', 'defectdojo.com',
  'prompt.security', 'toxsec.com',
  // CVE & vuln databases
  'cve.org', 'nvd.nist.gov', 'cvedetails.com',
  // OWASP
  'owasp.org', 'genai.owasp.org',
  // Documentation
  'docs.openclaw.ai', 'github.com/openclaw',
];

// ============================================================================
// Context Detection Helpers
// ============================================================================

interface ContentContext {
  inCodeBlock: boolean;
  inDocumentation: boolean;
  lineContext: string;
}

/**
 * Determine if a match at a given position is in a code block or documentation
 */
function getContentContext(content: string, matchIndex: number): ContentContext {
  const beforeMatch = content.slice(0, matchIndex);
  const currentLineStart = beforeMatch.lastIndexOf('\n') + 1;
  const lineEnd = content.indexOf('\n', matchIndex);
  const currentLine = content.slice(currentLineStart, lineEnd === -1 ? undefined : lineEnd);

  // Count code block markers before this position
  const codeBlockStarts = (beforeMatch.match(/```/g) || []).length;
  const inCodeBlock = codeBlockStarts % 2 === 1;

  // Check if in markdown list describing threats (documentation context)
  const docPatterns = [
    /^\s*[-*]\s+/,              // Markdown list item
    /^\s*\d+\.\s+/,             // Numbered list (e.g., "1. Known C2 IPs...")
    /^#+\s+/,                   // Heading
  ];

  // Content patterns that indicate this is documentation about threats, not actual threats
  const threatDocPatterns = [
    /known.*malicious/i,       // "Known malicious..."
    /detects?/i,               // "Detects..."
    /scans?\s*(for)?/i,        // "Scans for..."
    /checks?\s*(for)?/i,       // "Checks for..."
    /monitors?\s*(for)?/i,     // "Monitors for..."
    /threats?/i,               // "Threats..."
    /indicators?\s+of/i,       // "Indicators of..."
    /ioc|c2|command.and.control/i, // IOC documentation
    /security.*scan/i,         // "Security scan..."
    /backdoors?/i,             // "Backdoors..." (documenting, not implementing)
    /exfiltration/i,           // "Exfiltration..." (documenting)
    /credential.*theft/i,      // "Credential theft..." (documenting)
    /targeting/i,              // "targeting..." (documenting what to look for)
    /stealer/i,                // "stealer" (documenting malware types)
    /markers?/i,               // "markers" (documenting detection)
    /endpoints?.*\(/i,         // "endpoints (..." (listing examples)
  ];

  const isListItem = docPatterns.some(p => p.test(currentLine));
  const isThreatDoc = threatDocPatterns.some(p => p.test(currentLine));

  // Consider it documentation if it's a list item OR contains threat documentation language
  const inDocumentation = isListItem || isThreatDoc;

  return {
    inCodeBlock,
    inDocumentation,
    lineContext: currentLine.trim().slice(0, 100),
  };
}

/**
 * Check if a URL is from a whitelisted security research domain
 */
function isSecurityResearchUrl(url: string): boolean {
  const lowerUrl = url.toLowerCase();
  return SECURITY_RESEARCH_DOMAINS.some(domain => lowerUrl.includes(domain));
}

// ============================================================================
// Main Scanner Function
// ============================================================================

export async function scanSkill(
  skillSource: string,  // URL or raw content
  options: {
    format?: SkillFormat;
    includeRepoTrust?: boolean;
    timeout?: number;
  } = {}
): Promise<SkillScanResult> {
  const startTime = Date.now();
  const format = options.format || 'auto';

  // Initialize result
  const result: SkillScanResult = {
    skillId: generateSkillId(skillSource),
    name: 'Unknown',
    source: format,
    sourceUrl: skillSource.startsWith('http') ? skillSource : undefined,
    verdict: 'SAFE',
    riskScore: 0,
    malwarePatterns: [],
    permissionIssues: [],
    promptInjectionRisks: [],
    networkRisks: [],
    verifiedBadge: true,
    badgeReason: 'All checks passed',
    summary: '',
    recommendations: [],
    scanTime: 0,
  };

  try {
    // Fetch skill content if URL
    let content: string;
    let files: Map<string, string> = new Map();

    if (skillSource.startsWith('http')) {
      const fetched = await fetchSkillContent(skillSource);
      content = fetched.content;
      files = fetched.files;
      result.metadata = fetched.metadata;
      result.name = fetched.metadata?.name || extractNameFromUrl(skillSource);
      result.source = fetched.format || format;
    } else {
      content = skillSource;
      files.set('inline', content);
    }

    // Run all scans
    result.malwarePatterns = scanForMalware(files);
    result.promptInjectionRisks = scanForPromptInjection(files);
    result.networkRisks = scanForNetworkRisks(files);
    result.permissionIssues = scanForPermissionIssues(content, result.metadata);

    // Optional: Get repo trust score
    if (options.includeRepoTrust && skillSource.includes('github.com')) {
      try {
        const trustResult = await performTrustScan(skillSource);
        result.repoTrustScore = trustResult.trustScore;
      } catch {
        // Trust scan failed, continue without it
      }
    }

    // Calculate risk score and verdict
    calculateRiskScore(result);

    // Generate summary
    result.summary = generateSummary(result);
    result.recommendations = generateRecommendations(result);

  } catch (err: any) {
    result.verdict = 'DANGEROUS';
    result.riskScore = 100;
    result.verifiedBadge = false;
    result.badgeReason = `Scan failed: ${err.message}`;
    result.summary = `Failed to scan skill: ${err.message}`;
  }

  result.scanTime = Date.now() - startTime;
  return result;
}

// ============================================================================
// Helper Functions
// ============================================================================

function generateSkillId(source: string): string {
  // Simple hash for skill identification
  let hash = 0;
  for (let i = 0; i < source.length; i++) {
    const char = source.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return `skill_${Math.abs(hash).toString(16)}`;
}

function extractNameFromUrl(url: string): string {
  const match = url.match(/github\.com\/[^/]+\/([^/]+)/);
  return match ? match[1] : 'Unknown';
}

async function fetchSkillContent(url: string): Promise<{
  content: string;
  files: Map<string, string>;
  metadata?: SkillMetadata;
  format?: SkillFormat;
}> {
  const files = new Map<string, string>();
  let metadata: SkillMetadata | undefined;
  let format: SkillFormat = 'auto';

  // Handle GitHub URLs
  if (url.includes('github.com')) {
    const rawUrl = url
      .replace('github.com', 'raw.githubusercontent.com')
      .replace('/blob/', '/')
      .replace('/tree/', '/');

    // Try to fetch SKILL.md (OpenClaw format)
    try {
      const skillMdUrl = rawUrl.endsWith('/')
        ? `${rawUrl}SKILL.md`
        : `${rawUrl}/SKILL.md`;

      const response = await fetch(skillMdUrl, {
        signal: AbortSignal.timeout(10000)
      });

      if (response.ok) {
        const content = await response.text();
        files.set('SKILL.md', content);
        metadata = parseSkillMd(content);
        format = 'openclaw';
      }
    } catch {
      // SKILL.md not found, try other patterns
    }

    // Try to fetch MCP config (Claude MCP format)
    if (format !== 'openclaw') {
      for (const configFile of ['mcp.json', 'claude.json', 'config.json']) {
        try {
          const configUrl = rawUrl.endsWith('/')
            ? `${rawUrl}${configFile}`
            : `${rawUrl}/${configFile}`;

          const response = await fetch(configUrl, {
            signal: AbortSignal.timeout(10000)
          });

          if (response.ok) {
            const content = await response.text();
            files.set(configFile, content);

            try {
              const config = JSON.parse(content);
              // Detect MCP format by looking for mcpServers or tools array
              if (config.mcpServers || config.tools || config.server) {
                format = 'mcp';
                metadata = metadata || {
                  name: config.name || config.mcpServers ? Object.keys(config.mcpServers)[0] : 'MCP Server',
                  description: config.description,
                };
              }
            } catch {}
          }
        } catch {
          // Config not found, continue
        }
      }
    }

    // Try to fetch package.json or index files
    for (const filename of ['index.ts', 'index.js', 'main.ts', 'main.js', 'server.ts', 'server.js', 'package.json']) {
      try {
        const fileUrl = rawUrl.endsWith('/')
          ? `${rawUrl}${filename}`
          : `${rawUrl}/${filename}`;

        const response = await fetch(fileUrl, {
          signal: AbortSignal.timeout(10000)
        });

        if (response.ok) {
          const content = await response.text();
          files.set(filename, content);

          if (filename === 'package.json') {
            try {
              const pkg = JSON.parse(content);
              metadata = metadata || {
                name: pkg.name,
                description: pkg.description,
                author: typeof pkg.author === 'string' ? pkg.author : pkg.author?.name,
                version: pkg.version,
              };
              // Detect MCP format from package.json keywords or dependencies
              const isMcp = pkg.keywords?.some((k: string) =>
                ['mcp', 'claude-mcp', 'model-context-protocol', 'claude-tools'].includes(k.toLowerCase())
              ) || pkg.dependencies?.['@anthropic-ai/sdk'] || pkg.dependencies?.['@modelcontextprotocol/sdk'];
              if (isMcp && format !== 'openclaw') {
                format = 'mcp';
              }
            } catch {}
          }
        }
      } catch {
        // File not found, continue
      }
    }
  }

  // Combine all file contents
  const allContent = Array.from(files.values()).join('\n\n');

  return {
    content: allContent,
    files,
    metadata,
    format,
  };
}

function parseSkillMd(content: string): SkillMetadata | undefined {
  // Extract YAML frontmatter
  const frontmatterMatch = content.match(/^---\n([\s\S]*?)\n---/);
  if (!frontmatterMatch) return undefined;

  const yaml = frontmatterMatch[1];
  const metadata: SkillMetadata = { name: 'Unknown' };

  // Simple YAML parsing (name, description, metadata)
  const nameMatch = yaml.match(/name:\s*(.+)/);
  if (nameMatch) metadata.name = nameMatch[1].trim();

  const descMatch = yaml.match(/description:\s*(.+)/);
  if (descMatch) metadata.description = descMatch[1].trim();

  // Parse requires
  const requiresMatch = yaml.match(/requires:\s*\{([^}]+)\}/);
  if (requiresMatch) {
    const binsMatch = requiresMatch[1].match(/bins:\s*\[([^\]]+)\]/);
    const envMatch = requiresMatch[1].match(/env:\s*\[([^\]]+)\]/);

    metadata.requires = {
      bins: binsMatch ? binsMatch[1].split(',').map(s => s.trim().replace(/["']/g, '')) : [],
      env: envMatch ? envMatch[1].split(',').map(s => s.trim().replace(/["']/g, '')) : [],
    };
  }

  return metadata;
}

function scanForMalware(files: Map<string, string>): MalwareMatch[] {
  const matches: MalwareMatch[] = [];

  for (const [filename, content] of files) {
    const isMarkdown = filename.endsWith('.md') || filename === 'inline';

    for (const patternDef of MALWARE_PATTERNS) {
      const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
      let match;

      while ((match = regex.exec(content)) !== null) {
        // Find line number
        const beforeMatch = content.slice(0, match.index);
        const lineNumber = beforeMatch.split('\n').length;

        // Get context for markdown files
        let severity = patternDef.severity;
        let skip = false;

        if (isMarkdown) {
          const context = getContentContext(content, match.index);

          // If in documentation context (not code block), skip or reduce severity
          if (context.inDocumentation && !context.inCodeBlock) {
            // Skip entirely - documentation describing threats is not a threat
            skip = true;
          } else if (!context.inCodeBlock) {
            // Not in code block and not explicitly documentation - reduce severity
            // This catches general markdown text that might mention patterns
            severity = severity === 'CRITICAL' ? 'MEDIUM' :
                      severity === 'HIGH' ? 'LOW' :
                      'LOW';
          }
          // If in a code block within markdown, keep original severity
          // (this is actual code being documented/shown)
        }

        if (!skip) {
          matches.push({
            pattern: patternDef.pattern.source,
            match: match[0],
            file: filename,
            line: lineNumber,
            severity,
            category: patternDef.category,
            description: patternDef.description,
          });
        }
      }
    }
  }

  return matches;
}

function scanForPromptInjection(files: Map<string, string>): PromptInjectionRisk[] {
  const risks: PromptInjectionRisk[] = [];

  for (const [filename, content] of files) {
    const isMarkdown = filename.endsWith('.md') || filename === 'inline';

    for (const patternDef of PROMPT_INJECTION_PATTERNS) {
      const regex = new RegExp(patternDef.pattern.source, patternDef.pattern.flags);
      let match;

      while ((match = regex.exec(content)) !== null) {
        let severity = patternDef.severity;
        let skip = false;

        if (isMarkdown) {
          const context = getContentContext(content, match.index);

          // Skip HTML comments that are legitimate OpenClaw/MCP metadata
          if (match[0].startsWith('<!--') && /requires|config|metadata|version/i.test(match[0])) {
            skip = true;
          }

          // Skip documentation context entirely
          if (context.inDocumentation && !context.inCodeBlock) {
            skip = true;
          }
        }

        if (!skip) {
          risks.push({
            pattern: patternDef.pattern.source,
            match: match[0],
            file: filename,
            severity,
            description: patternDef.description,
          });
        }
      }
    }
  }

  return risks;
}

function scanForNetworkRisks(files: Map<string, string>): NetworkRisk[] {
  const risks: NetworkRisk[] = [];

  // URL pattern
  const urlPattern = /https?:\/\/[^\s"'`<>)]+/gi;

  for (const [filename, content] of files) {
    const isMarkdown = filename.endsWith('.md') || filename === 'inline';
    let match;

    while ((match = urlPattern.exec(content)) !== null) {
      const url = match[0].replace(/[.,;:!?]+$/, ''); // Clean trailing punctuation

      // Skip whitelisted security research URLs
      if (isSecurityResearchUrl(url)) {
        continue;
      }

      // Get context for markdown files
      let skip = false;
      if (isMarkdown) {
        const context = getContentContext(content, match.index);
        // Skip URLs in documentation context (threat lists, IOC lists, etc.)
        if (context.inDocumentation && !context.inCodeBlock) {
          skip = true;
        }
      }

      if (skip) continue;

      // Check against suspicious domains
      for (const domain of SUSPICIOUS_DOMAINS) {
        if (url.toLowerCase().includes(domain)) {
          risks.push({
            url,
            file: filename,
            severity: 'HIGH',
            reason: `Suspicious domain: ${domain}`,
          });
          break;
        }
      }

      // Check for IP addresses (potential C2) - only in code blocks
      if (/\d+\.\d+\.\d+\.\d+/.test(url)) {
        const context = isMarkdown ? getContentContext(content, match.index) : { inCodeBlock: true, inDocumentation: false, lineContext: '' };
        // Only flag IP addresses in actual code, not in documentation
        if (context.inCodeBlock || !isMarkdown) {
          risks.push({
            url,
            file: filename,
            severity: 'MEDIUM',
            reason: 'Direct IP address connection',
          });
        }
      }
    }
  }

  return risks;
}

function scanForPermissionIssues(content: string, metadata?: SkillMetadata): PermissionIssue[] {
  const issues: PermissionIssue[] = [];

  // Check metadata permissions
  if (metadata?.permissions) {
    const perms = metadata.permissions;

    if (perms.filesystem?.some(p => p === '*' || p === '/')) {
      issues.push({
        permission: 'Full filesystem access',
        severity: 'CRITICAL',
        reason: 'Skill requests access to entire filesystem',
        recommendation: 'Limit to specific directories needed',
      });
    }

    if (perms.exec?.some(p => p === '*' || p === 'any')) {
      issues.push({
        permission: 'Unrestricted command execution',
        severity: 'CRITICAL',
        reason: 'Skill can execute any system command',
        recommendation: 'Allowlist specific commands only',
      });
    }
  }

  // Check code patterns for implicit permissions
  for (const permDef of DANGEROUS_PERMISSIONS) {
    if (permDef.pattern.test(content)) {
      issues.push({
        permission: permDef.permission,
        severity: permDef.severity,
        reason: permDef.reason,
        recommendation: permDef.recommendation,
      });
    }
  }

  return issues;
}

function calculateRiskScore(result: SkillScanResult): void {
  let score = 0;

  // Malware patterns
  for (const match of result.malwarePatterns) {
    switch (match.severity) {
      case 'CRITICAL': score += 40; break;
      case 'HIGH': score += 25; break;
      case 'MEDIUM': score += 10; break;
      case 'LOW': score += 5; break;
    }
  }

  // Prompt injection
  for (const risk of result.promptInjectionRisks) {
    switch (risk.severity) {
      case 'CRITICAL': score += 30; break;
      case 'HIGH': score += 20; break;
      case 'MEDIUM': score += 8; break;
      case 'LOW': score += 3; break;
    }
  }

  // Network risks
  for (const risk of result.networkRisks) {
    switch (risk.severity) {
      case 'CRITICAL': score += 35; break;
      case 'HIGH': score += 20; break;
      case 'MEDIUM': score += 10; break;
      case 'LOW': score += 5; break;
    }
  }

  // Permission issues
  for (const issue of result.permissionIssues) {
    switch (issue.severity) {
      case 'CRITICAL': score += 30; break;
      case 'HIGH': score += 15; break;
      case 'MEDIUM': score += 8; break;
      case 'LOW': score += 3; break;
    }
  }

  // Cap at 100
  result.riskScore = Math.min(100, score);

  // Determine verdict
  if (score >= 70 || result.malwarePatterns.some(m => m.severity === 'CRITICAL')) {
    result.verdict = 'BLOCKED';
    result.verifiedBadge = false;
    result.badgeReason = 'Critical security issues detected';
  } else if (score >= 40) {
    result.verdict = 'DANGEROUS';
    result.verifiedBadge = false;
    result.badgeReason = 'Multiple security issues detected';
  } else if (score >= 15) {
    result.verdict = 'WARNING';
    result.verifiedBadge = false;
    result.badgeReason = 'Security concerns require review';
  } else {
    result.verdict = 'SAFE';
    result.verifiedBadge = true;
    result.badgeReason = 'All security checks passed';
  }
}

function generateSummary(result: SkillScanResult): string {
  const parts: string[] = [];

  parts.push(`Skill: ${result.name}`);
  parts.push(`Verdict: ${result.verdict} (Risk Score: ${result.riskScore}/100)`);

  if (result.malwarePatterns.length > 0) {
    parts.push(`Malware patterns: ${result.malwarePatterns.length} found`);
  }

  if (result.promptInjectionRisks.length > 0) {
    parts.push(`Prompt injection risks: ${result.promptInjectionRisks.length} found`);
  }

  if (result.networkRisks.length > 0) {
    parts.push(`Network risks: ${result.networkRisks.length} found`);
  }

  if (result.permissionIssues.length > 0) {
    parts.push(`Permission issues: ${result.permissionIssues.length} found`);
  }

  if (result.verdict === 'SAFE') {
    parts.push('No significant security issues detected.');
  }

  return parts.join('\n');
}

function generateRecommendations(result: SkillScanResult): string[] {
  const recommendations: string[] = [];

  if (result.malwarePatterns.length > 0) {
    recommendations.push('Review code sections flagged for malware patterns');

    if (result.malwarePatterns.some(m => m.category === 'credential_theft')) {
      recommendations.push('Do not install: skill attempts to access credentials');
    }

    if (result.malwarePatterns.some(m => m.category === 'exec')) {
      recommendations.push('Verify all command execution is necessary and safe');
    }
  }

  if (result.promptInjectionRisks.length > 0) {
    recommendations.push('Review skill for prompt injection attempts');
  }

  if (result.networkRisks.length > 0) {
    recommendations.push('Verify all network endpoints are legitimate');
  }

  if (result.permissionIssues.length > 0) {
    for (const issue of result.permissionIssues) {
      recommendations.push(issue.recommendation);
    }
  }

  if (result.verdict === 'BLOCKED') {
    recommendations.unshift('DO NOT INSTALL: Critical security issues detected');
  } else if (result.verdict === 'DANGEROUS') {
    recommendations.unshift('NOT RECOMMENDED: Significant security concerns');
  } else if (result.verdict === 'WARNING') {
    recommendations.unshift('CAUTION: Review findings before installing');
  }

  return recommendations;
}

// ============================================================================
// Formatted Output
// ============================================================================

export function formatSkillScanResult(result: SkillScanResult): string {
  const lines: string[] = [];

  // Header
  const verdictEmoji =
    result.verdict === 'SAFE' ? '✅' :
    result.verdict === 'WARNING' ? '⚠️' :
    result.verdict === 'DANGEROUS' ? '🔴' : '🚫';

  lines.push(`${verdictEmoji} SKILL SCAN: ${result.name}`);
  lines.push('');
  lines.push(`Verdict: ${result.verdict}`);
  lines.push(`Risk Score: ${result.riskScore}/100`);
  lines.push(`Badge Eligible: ${result.verifiedBadge ? 'Yes ✓' : 'No ✗'}`);
  lines.push('');

  // Findings
  if (result.malwarePatterns.length > 0) {
    lines.push(`🦠 Malware Patterns: ${result.malwarePatterns.length}`);
    for (const m of result.malwarePatterns.slice(0, 5)) {
      lines.push(`  └ [${m.severity}] ${m.description}`);
      lines.push(`    File: ${m.file}${m.line ? `:${m.line}` : ''}`);
    }
    if (result.malwarePatterns.length > 5) {
      lines.push(`  └ ...and ${result.malwarePatterns.length - 5} more`);
    }
    lines.push('');
  }

  if (result.promptInjectionRisks.length > 0) {
    lines.push(`💉 Prompt Injection Risks: ${result.promptInjectionRisks.length}`);
    for (const r of result.promptInjectionRisks.slice(0, 3)) {
      lines.push(`  └ [${r.severity}] ${r.description}`);
    }
    lines.push('');
  }

  if (result.networkRisks.length > 0) {
    lines.push(`🌐 Network Risks: ${result.networkRisks.length}`);
    for (const r of result.networkRisks.slice(0, 3)) {
      lines.push(`  └ [${r.severity}] ${r.reason}`);
    }
    lines.push('');
  }

  if (result.permissionIssues.length > 0) {
    lines.push(`🔐 Permission Issues: ${result.permissionIssues.length}`);
    for (const i of result.permissionIssues.slice(0, 3)) {
      lines.push(`  └ [${i.severity}] ${i.permission}`);
    }
    lines.push('');
  }

  // Recommendations
  if (result.recommendations.length > 0) {
    lines.push('📋 Recommendations:');
    for (const rec of result.recommendations.slice(0, 5)) {
      lines.push(`  • ${rec}`);
    }
    lines.push('');
  }

  lines.push(`Scan time: ${result.scanTime}ms`);

  return lines.join('\n');
}
