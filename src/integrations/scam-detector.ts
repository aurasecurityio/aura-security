/**
 * Scam Detector - Focused on AI Crypto Projects & Solana Ecosystem
 *
 * Detects fake AI projects, Solana rug patterns, and wallet drainers.
 * Optimized for pump.fun and AI agent token ecosystem.
 */

// Known scam repo signatures - file patterns, code snippets, structure
export interface ScamSignature {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  patterns: {
    filePatterns?: string[];      // File names/paths that indicate scam
    codePatterns?: RegExp[];      // Code snippets common in scams
    readmePatterns?: RegExp[];    // README red flags
    structureHash?: string;       // Hash of file structure
  };
  reportedDate?: string;
  source?: string;
}

// Known scam signatures database - FOCUSED ON AI + SOLANA
const SCAM_SIGNATURES: ScamSignature[] = [
  // ============ FAKE AI PROJECT DETECTION (Core Value) ============
  {
    id: 'fake-ai-wrapper',
    name: 'API Wrapper Pretending to be AI',
    description: 'Project claims AI but just wraps OpenAI/Anthropic API with no real logic',
    severity: 'high',
    patterns: {
      codePatterns: [
        /openai\.chat\.completions\.create/i,
        /anthropic\.messages\.create/i,
        /new\s+OpenAI\s*\(/i,
        /new\s+Anthropic\s*\(/i,
        /ChatCompletion\.create/i,
        /client\.chat\.completions/i,
      ],
      readmePatterns: [
        /powered\s+by\s+(?:advanced\s+)?ai/i,
        /revolutionary\s+ai/i,
        /cutting[\s-]edge\s+(?:ai|ml|machine\s+learning)/i,
        /ai[\s-]driven\s+(?:trading|analysis|predictions)/i,
        /proprietary\s+ai/i,
        /our\s+(?:advanced|custom|unique)\s+ai/i,
      ]
    }
  },
  {
    id: 'fake-ai-no-ml-code',
    name: 'No Real ML Code',
    description: 'Claims AI/ML but has no actual machine learning implementation',
    severity: 'high',
    patterns: {
      readmePatterns: [
        /(?:train|trained)\s+(?:on|with)\s+(?:millions|billions)/i,
        /(?:neural|deep)\s+(?:network|learning)/i,
        /machine\s+learning\s+(?:model|algorithm)/i,
        /ai\s+(?:agent|bot|assistant)/i,
      ],
      // These are red flags when README claims AI but code doesn't have real ML
      filePatterns: ['model.py', 'train.py', 'inference.py'] // If missing = red flag
    }
  },
  {
    id: 'fake-ai-buzzwords',
    name: 'AI Buzzword Overload',
    description: 'README stuffed with AI buzzwords but no substance',
    severity: 'medium',
    patterns: {
      readmePatterns: [
        /(?:gpt|llm|transformer|neural)\s*[\-\s]*(?:powered|based|driven)/i,
        /autonomous\s+ai\s+agent/i,
        /sentient|conscious|self[\-\s]aware/i,
        /ai\s+(?:singularity|superintelligence)/i,
        /(?:first|only|most\s+advanced)\s+ai/i,
        /ai\s+that\s+(?:thinks|learns|evolves)/i,
      ]
    }
  },
  {
    id: 'fake-ai-trading-bot',
    name: 'Fake AI Trading Bot',
    description: 'Claims AI trading but likely just random or copy trades',
    severity: 'high',
    patterns: {
      readmePatterns: [
        /ai\s+(?:trading|sniper|mev)\s+bot/i,
        /(?:guaranteed|100%)\s+(?:profit|returns|win)/i,
        /never\s+(?:lose|loss)/i,
        /(?:predict|know)\s+(?:the\s+)?(?:market|price)/i,
        /insider\s+(?:ai|algorithm|bot)/i,
      ],
      codePatterns: [
        /Math\.random\(\).*(?:buy|sell|trade)/i,
        /random.*(?:amount|size|position)/i,
      ]
    }
  },
  {
    id: 'eliza-fork-unchanged',
    name: 'Unchanged Eliza/ai16z Fork',
    description: 'Direct fork of ai16z/eliza with minimal changes',
    severity: 'medium',
    patterns: {
      codePatterns: [
        /elizaLogger/i,
        /AgentRuntime.*eliza/i,
        /import.*from\s+['"]@ai16z\/eliza/i,
        /elizaConfig/i,
      ],
      filePatterns: ['eliza.config.ts', 'eliza.character.json']
    }
  },

  // ============ SOLANA RUG PATTERNS ============
  {
    id: 'solana-drain-program',
    name: 'Solana Drain Program',
    description: 'Solana program designed to drain user funds',
    severity: 'critical',
    patterns: {
      filePatterns: ['drain.rs', 'withdraw_all.rs', 'emergency_exit.rs', 'rug.rs'],
      codePatterns: [
        /withdraw_all_funds/i,
        /drain_pool/i,
        /transfer_to_admin/i,
        /close_account.*authority/i,
        /emergency.*drain/i,
        /lamports.*=.*0/i,
        /\*\*ctx\.accounts\.(?:user|victim).*lamports.*=.*0/i,
      ]
    }
  },
  {
    id: 'solana-mint-authority',
    name: 'Mint Authority Not Revoked',
    description: 'Solana token where creator can mint unlimited tokens',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /mint_authority.*Some/i,
        /MintTo\s*\{/i,
        /mint_to.*authority/i,
        /set_authority.*Mint/i,
        /token::mint_to/i,
      ]
    }
  },
  {
    id: 'solana-freeze-authority',
    name: 'Freeze Authority Retained',
    description: 'Solana token where creator can freeze accounts',
    severity: 'high',
    patterns: {
      codePatterns: [
        /freeze_authority.*Some/i,
        /FreezeAccount/i,
        /set_authority.*Freeze/i,
        /token::freeze_account/i,
      ]
    }
  },
  {
    id: 'solana-close-authority',
    name: 'Close Authority Abuse',
    description: 'Program can close user token accounts and steal funds',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /close\s*=\s*authority/i,
        /CloseAccount/i,
        /close_account.*destination/i,
        /token::close_account/i,
      ],
      filePatterns: ['close_accounts.rs']
    }
  },
  {
    id: 'pump-fun-bundle',
    name: 'Pump.fun Bundle/Snipe',
    description: 'Code for bundling or sniping pump.fun launches',
    severity: 'high',
    patterns: {
      codePatterns: [
        /pump\.fun.*bundle/i,
        /pumpfun.*snipe/i,
        /bundl.*pump/i,
        /jito.*bundle.*pump/i,
      ],
      filePatterns: ['bundle.ts', 'sniper.ts', 'pumpfun_snipe.js']
    }
  },

  // ============ WALLET DRAINERS (Frontend/JS) ============
  {
    id: 'wallet-drainer-js',
    name: 'JavaScript Wallet Drainer',
    description: 'Frontend code designed to drain connected wallets',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /signAllTransactions/i,
        /drainWallet/i,
        /transferAll.*tokens/i,
        /phantom\.solana.*signTransaction/i,
        /window\.solana.*signAllTransactions/i,
        /solflare.*signAllTransactions/i,
      ],
      filePatterns: ['drainer.js', 'drain.ts', 'stealer.js', 'siphon.js']
    }
  },
  {
    id: 'wallet-approval-abuse',
    name: 'Token Approval Abuse',
    description: 'Tricks users into approving unlimited token access',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /approve.*(?:max|unlimited|infinite)/i,
        /setApprovalForAll.*true/i,
        /allowance.*type\(uint256\)\.max/i,
        /approve.*0xffffffff/i,
      ]
    }
  },
  {
    id: 'phishing-connect',
    name: 'Phishing Wallet Connect',
    description: 'Fake wallet connect that steals credentials',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /localStorage\.getItem.*(?:key|private|seed|mnemonic|phrase)/i,
        /(?:seed|mnemonic|private).*(?:phrase|key).*(?:input|form|submit)/i,
        /fetch.*(?:seed|mnemonic|privateKey)/i,
        /XMLHttpRequest.*(?:private|key|seed|wallet)/i,
      ],
      readmePatterns: [
        /enter\s+(?:your\s+)?(?:seed|recovery|mnemonic)\s+phrase/i,
        /import\s+(?:your\s+)?wallet/i,
      ]
    }
  },
  {
    id: 'suspicious-data-exfil',
    name: 'Suspicious Data Exfiltration',
    description: 'Sends wallet data to external servers',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /fetch\s*\(.*(?:\.ru|\.cn|\.tk|\.ml|\.xyz\/api)/i,
        /axios\.post.*(?:wallet|key|seed|private)/i,
        /webhook.*(?:discord|telegram).*(?:key|seed|wallet)/i,
      ]
    }
  },

  // ============ README SCAM LANGUAGE ============
  {
    id: 'pump-dump-language',
    name: 'Pump & Dump Marketing',
    description: 'README uses classic pump and dump language',
    severity: 'high',
    patterns: {
      readmePatterns: [
        /100x\s+(?:guaranteed|potential|gem)/i,
        /1000x/i,
        /get\s+rich\s+quick/i,
        /next\s+(?:100x|1000x|moon)\s+gem/i,
        /guaranteed\s+(?:profit|returns|gains)/i,
        /early\s+investors\s+only/i,
        /(?:ape|buy)\s+(?:now|in|before)/i,
      ]
    }
  },
  {
    id: 'fomo-tactics',
    name: 'FOMO Marketing Tactics',
    description: 'Uses fear of missing out to pressure investment',
    severity: 'medium',
    patterns: {
      readmePatterns: [
        /(?:last|final)\s+chance/i,
        /don'?t\s+(?:miss|sleep\s+on)/i,
        /only\s+\d+\s+spots?\s+left/i,
        /act\s+(?:fast|now|quickly)/i,
        /limited\s+(?:time|supply|spots)/i,
        /(?:whitelist|presale)\s+(?:closing|ending)\s+soon/i,
        /stealth\s+launch/i,
        /(?:floor|price)\s+(?:is\s+)?pumping/i,
      ]
    }
  },
  {
    id: 'trust-me-bro',
    name: 'Trust Me Bro Signals',
    description: 'Vague trust signals with no verification',
    severity: 'medium',
    patterns: {
      readmePatterns: [
        /trust\s+(?:me|us|the\s+team)/i,
        /(?:team|devs?)\s+(?:is|are)\s+(?:based|legit|doxxed)/i,
        /safu|safe\s+(?:team|project|investment)/i,
        /(?:this\s+is|not)\s+(?:not\s+)?financial\s+advice/i,
        /dyor.*not\s+financial\s+advice/i,
        /liquidity\s+(?:locked|burned)/i,
        /contract\s+(?:renounced|verified)/i,
      ]
    }
  },
  {
    id: 'fake-partnership',
    name: 'Fake Partnership Claims',
    description: 'Claims partnerships that are likely fake',
    severity: 'high',
    patterns: {
      readmePatterns: [
        /partner(?:ship|ed)\s+with\s+(?:binance|coinbase|openai|anthropic|google|microsoft)/i,
        /backed\s+by\s+(?:a16z|sequoia|paradigm)/i,
        /official\s+(?:partner|collaboration)/i,
        /endorsed\s+by/i,
      ]
    }
  },

  // ============ COPY-PASTE DETECTION ============
  {
    id: 'copy-paste-readme',
    name: 'Copy-Paste README Template',
    description: 'README is clearly copied from template or other project',
    severity: 'medium',
    patterns: {
      readmePatterns: [
        /\[Project\s+Name\]/i,
        /\[Your\s+(?:Name|Project|Token)\]/i,
        /TODO:?\s*(?:add|replace|update)/i,
        /INSERT\s+(?:TOKEN|PROJECT|NAME)/i,
        /CHANGE\s+THIS/i,
      ]
    }
  },
  {
    id: 'placeholder-code',
    name: 'Placeholder Code',
    description: 'Code contains obvious placeholders indicating copy-paste',
    severity: 'medium',
    patterns: {
      codePatterns: [
        /YOUR_(?:API_KEY|TOKEN|SECRET)/i,
        /REPLACE_(?:THIS|ME|WITH)/i,
        /TODO:?\s*implement/i,
        /fixme|hack|xxx/i,
      ]
    }
  },

  // ============ OBFUSCATION ============
  {
    id: 'obfuscated-code',
    name: 'Obfuscated Code',
    description: 'Intentionally obfuscated code hiding malicious functions',
    severity: 'high',
    patterns: {
      codePatterns: [
        /\w{50,}/,  // Very long variable names
        /eval\s*\(/i,
        /Function\s*\(.*\)\s*\(/,
        /atob\s*\(.*atob/i,  // Nested base64
        /String\.fromCharCode\(.*,.*,.*,.*,/i,  // Many char codes
        /\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}.*\\x[0-9a-f]{2}/gi,  // Multiple hex
      ],
      filePatterns: ['obfuscated.js', 'packed.js', 'encoded.js']
    }
  },

  // ============ AIRDROP SCAMS ============
  {
    id: 'airdrop-scam',
    name: 'Airdrop Scam',
    description: 'Fake airdrop that requires fees or wallet approval',
    severity: 'high',
    patterns: {
      codePatterns: [
        /claim.*requires.*fee/i,
        /pay.*to.*claim/i,
        /connect.*wallet.*claim/i,
        /approve.*before.*claim/i,
      ],
      readmePatterns: [
        /free\s+airdrop/i,
        /claim\s+your\s+(?:free\s+)?tokens/i,
        /limited\s+time\s+airdrop/i,
        /airdrop.*connect.*wallet/i,
      ]
    }
  }
];

// Known scam repo URLs/hashes (community reported)
const KNOWN_SCAM_REPOS: { url: string; name: string; hash?: string }[] = [
  // Add known scam repos here as they're reported
  // { url: 'github.com/scammer/rugpull', name: 'Known Rug', hash: 'abc123' }
];

// Suspicious keywords in file names
const SUSPICIOUS_FILE_NAMES = [
  'drain', 'drainer', 'stealer', 'exploit', 'hack',
  'backdoor', 'hidden', 'secret', 'admin_only', 'emergency_exit',
  'rug', 'rugpull', 'scam', 'honeypot', 'sniper', 'bundle',
  'phish', 'steal', 'siphon', 'extract_funds'
];

// Suspicious patterns in code
const SUSPICIOUS_CODE_PATTERNS = [
  // Obfuscation
  { pattern: /eval\s*\(/, name: 'Dynamic code execution (eval)', severity: 'high' as const },
  { pattern: /Function\s*\(.*\)\s*\(/, name: 'Dynamic function creation', severity: 'high' as const },
  { pattern: /atob\s*\(|btoa\s*\(/, name: 'Base64 encoding (possible obfuscation)', severity: 'medium' as const },
  { pattern: /fromCharCode/, name: 'Character code obfuscation', severity: 'medium' as const },

  // Data exfiltration
  { pattern: /document\.cookie/, name: 'Cookie access', severity: 'high' as const },
  { pattern: /localStorage\.getItem.*(?:key|private|seed|mnemonic)/i, name: 'Accessing stored keys', severity: 'critical' as const },

  // Wallet interactions (Solana focused)
  { pattern: /signAllTransactions/, name: 'Sign all transactions (dangerous)', severity: 'critical' as const },
  { pattern: /phantom\.solana.*sign/i, name: 'Phantom wallet signing', severity: 'medium' as const },
  { pattern: /window\.solana/, name: 'Direct Solana wallet access', severity: 'medium' as const },

  // Solana program patterns
  { pattern: /invoke_signed.*transfer/i, name: 'Solana PDA transfer', severity: 'medium' as const },
  { pattern: /close_account.*lamports/i, name: 'Solana account drain', severity: 'high' as const },
  { pattern: /\*\*.*lamports.*=.*0/, name: 'Zero out lamports', severity: 'critical' as const },

  // Shell/System access
  { pattern: /require\s*\(\s*['"`]child_process/, name: 'Shell execution', severity: 'high' as const },
  { pattern: /exec\s*\(|spawn\s*\(/, name: 'Command execution', severity: 'high' as const },
];

export interface SimilarityMatch {
  signatureId: string;
  signatureName: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  matchType: 'code' | 'readme' | 'file' | 'structure';
  matchDetails: string;
  confidence: number; // 0-100
}

export interface ScamDetectionResult {
  isLikelyScam: boolean;
  scamScore: number; // 0-100 (higher = more likely scam)
  matches: SimilarityMatch[];
  suspiciousPatterns: Array<{
    pattern: string;
    severity: string;
    file?: string;
    line?: number;
  }>;
  suspiciousFiles: string[];
  codeOriginality: number; // 0-100 (lower = more copied)
  warnings: string[];
  summary: string;
}

/**
 * Calculate simple string similarity (Jaccard-like)
 */
function calculateSimilarity(str1: string, str2: string): number {
  const set1 = new Set(str1.toLowerCase().split(/\s+/));
  const set2 = new Set(str2.toLowerCase().split(/\s+/));

  const intersection = new Set([...set1].filter(x => set2.has(x)));
  const union = new Set([...set1, ...set2]);

  return union.size > 0 ? (intersection.size / union.size) * 100 : 0;
}

/**
 * Hash file structure for comparison
 */
function hashFileStructure(files: string[]): string {
  const normalized = files
    .map(f => f.toLowerCase().replace(/[^a-z0-9\/\.]/g, ''))
    .sort()
    .join('|');

  // Simple hash
  let hash = 0;
  for (let i = 0; i < normalized.length; i++) {
    const char = normalized.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash;
  }
  return hash.toString(16);
}

/**
 * Scan code content for scam patterns
 */
function scanCodeForPatterns(
  content: string,
  fileName: string
): Array<{ pattern: string; severity: string; matchDetails: string }> {
  const matches: Array<{ pattern: string; severity: string; matchDetails: string }> = [];

  // Check suspicious code patterns
  for (const { pattern, name, severity } of SUSPICIOUS_CODE_PATTERNS) {
    if (pattern.test(content)) {
      matches.push({
        pattern: name,
        severity,
        matchDetails: `Found in ${fileName}`
      });
    }
  }

  return matches;
}

/**
 * Main scam detection function
 */
export async function detectScamPatterns(
  repoData: {
    files: Array<{ path: string; content?: string }>;
    readme?: string;
    description?: string;
    name: string;
  }
): Promise<ScamDetectionResult> {
  const matches: SimilarityMatch[] = [];
  const suspiciousPatterns: Array<{ pattern: string; severity: string; file?: string }> = [];
  const suspiciousFiles: string[] = [];
  const warnings: string[] = [];

  const filePaths = repoData.files.map(f => f.path);
  const allCode = repoData.files
    .filter(f => f.content)
    .map(f => f.content)
    .join('\n');

  // Check for suspicious file names
  for (const file of filePaths) {
    const fileName = file.split('/').pop()?.toLowerCase() || '';
    for (const suspicious of SUSPICIOUS_FILE_NAMES) {
      if (fileName.includes(suspicious)) {
        suspiciousFiles.push(file);
        warnings.push(`Suspicious file name: ${file}`);
      }
    }
  }

  // Check against known scam signatures
  for (const signature of SCAM_SIGNATURES) {
    let matchCount = 0;
    let totalPatterns = 0;
    const matchDetails: string[] = [];

    // Check file patterns
    if (signature.patterns.filePatterns) {
      totalPatterns += signature.patterns.filePatterns.length;
      for (const pattern of signature.patterns.filePatterns) {
        if (filePaths.some(f => f.toLowerCase().includes(pattern.toLowerCase()))) {
          matchCount++;
          matchDetails.push(`File pattern: ${pattern}`);
        }
      }
    }

    // Check code patterns
    if (signature.patterns.codePatterns && allCode) {
      totalPatterns += signature.patterns.codePatterns.length;
      for (const pattern of signature.patterns.codePatterns) {
        if (pattern.test(allCode)) {
          matchCount++;
          matchDetails.push(`Code pattern match`);
        }
      }
    }

    // Check README patterns
    if (signature.patterns.readmePatterns && repoData.readme) {
      totalPatterns += signature.patterns.readmePatterns.length;
      for (const pattern of signature.patterns.readmePatterns) {
        if (pattern.test(repoData.readme)) {
          matchCount++;
          matchDetails.push(`README pattern match`);
        }
      }
    }

    // Calculate confidence
    if (matchCount > 0 && totalPatterns > 0) {
      const confidence = Math.min(100, (matchCount / totalPatterns) * 100 + (matchCount * 15));

      matches.push({
        signatureId: signature.id,
        signatureName: signature.name,
        description: signature.description,
        severity: signature.severity,
        matchType: 'code',
        matchDetails: matchDetails.join('; '),
        confidence: Math.round(confidence)
      });
    }
  }

  // Scan individual files for suspicious patterns
  for (const file of repoData.files) {
    if (file.content) {
      const filePatterns = scanCodeForPatterns(file.content, file.path);
      suspiciousPatterns.push(...filePatterns.map(p => ({ ...p, file: file.path })));
    }
  }

  // Calculate scam score
  let scamScore = 0;

  // Critical matches add 30 points each
  scamScore += matches.filter(m => m.severity === 'critical').length * 30;
  // High matches add 20 points each
  scamScore += matches.filter(m => m.severity === 'high').length * 20;
  // Medium matches add 10 points each
  scamScore += matches.filter(m => m.severity === 'medium').length * 10;
  // Low matches add 5 points each
  scamScore += matches.filter(m => m.severity === 'low').length * 5;

  // Suspicious patterns add points
  scamScore += suspiciousPatterns.filter(p => p.severity === 'high').length * 15;
  scamScore += suspiciousPatterns.filter(p => p.severity === 'medium').length * 8;

  // Suspicious files add points
  scamScore += suspiciousFiles.length * 10;

  // Cap at 100
  scamScore = Math.min(100, scamScore);

  // Estimate code originality (inverse of how many patterns matched)
  const codeOriginality = Math.max(0, 100 - (matches.length * 15) - (suspiciousPatterns.length * 5));

  // Determine if likely scam
  const isLikelyScam = scamScore >= 50 || matches.some(m => m.severity === 'critical' && m.confidence > 60);

  // Generate summary
  let summary = '';
  if (scamScore >= 70) {
    summary = `HIGH RISK: Multiple scam patterns detected. ${matches.length} signature matches found.`;
  } else if (scamScore >= 50) {
    summary = `CAUTION: Suspicious patterns found. Review carefully before interacting.`;
  } else if (scamScore >= 25) {
    summary = `MODERATE RISK: Some concerning patterns detected. Proceed with caution.`;
  } else if (suspiciousPatterns.length > 0 || suspiciousFiles.length > 0) {
    summary = `LOW RISK: Minor concerns found but no major red flags.`;
  } else {
    summary = `CLEAN: No known scam patterns detected.`;
  }

  return {
    isLikelyScam,
    scamScore,
    matches,
    suspiciousPatterns,
    suspiciousFiles,
    codeOriginality,
    warnings,
    summary
  };
}

/**
 * Quick scan for scam patterns (without fetching file contents)
 */
export async function quickScamScan(
  files: string[],
  readme?: string,
  description?: string
): Promise<{
  hasRedFlags: boolean;
  redFlags: string[];
  riskLevel: 'low' | 'medium' | 'high' | 'critical';
}> {
  const redFlags: string[] = [];

  // Check file names
  for (const file of files) {
    const fileName = file.split('/').pop()?.toLowerCase() || '';
    for (const suspicious of SUSPICIOUS_FILE_NAMES) {
      if (fileName.includes(suspicious)) {
        redFlags.push(`Suspicious file: ${file}`);
      }
    }
  }

  // Check README
  if (readme) {
    for (const sig of SCAM_SIGNATURES) {
      if (sig.patterns.readmePatterns) {
        for (const pattern of sig.patterns.readmePatterns) {
          if (pattern.test(readme)) {
            redFlags.push(`README red flag: ${sig.name}`);
          }
        }
      }
    }
  }

  // Determine risk level
  let riskLevel: 'low' | 'medium' | 'high' | 'critical' = 'low';
  if (redFlags.length >= 5) riskLevel = 'critical';
  else if (redFlags.length >= 3) riskLevel = 'high';
  else if (redFlags.length >= 1) riskLevel = 'medium';

  return {
    hasRedFlags: redFlags.length > 0,
    redFlags,
    riskLevel
  };
}

/**
 * Add a new scam signature to the database (for community reporting)
 */
export function addScamSignature(signature: ScamSignature): void {
  SCAM_SIGNATURES.push(signature);
}

/**
 * Get all scam signatures (for transparency)
 */
export function getScamSignatures(): ScamSignature[] {
  return [...SCAM_SIGNATURES];
}
