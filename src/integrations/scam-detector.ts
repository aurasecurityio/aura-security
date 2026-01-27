/**
 * Scam Detector - Code Similarity & Known Scam Pattern Detection
 *
 * Compares GitHub repos against known scam patterns and templates.
 * Detects copied code, rug pull templates, and suspicious patterns.
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

// Known scam signatures database
const SCAM_SIGNATURES: ScamSignature[] = [
  {
    id: 'pump-dump-template-1',
    name: 'Pump & Dump Template',
    description: 'Common pump and dump token template with hidden mint functions',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /function\s+_?mint(?:To)?Owner\s*\(/i,
        /onlyOwner.*mint.*unlimited/i,
        /hidden.*mint/i,
        /backdoor.*admin/i,
        /emergency.*withdraw.*all/i,
      ],
      readmePatterns: [
        /100x\s+guaranteed/i,
        /get\s+rich\s+quick/i,
        /next\s+100x\s+gem/i,
        /guaranteed\s+profit/i,
        /early\s+investors\s+only/i,
      ]
    }
  },
  {
    id: 'honeypot-template-1',
    name: 'Honeypot Contract',
    description: 'Contract that allows buying but prevents selling',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /require\s*\(\s*(?:msg\.sender|_from)\s*==\s*owner/i,
        /blacklist\[.*\]\s*=\s*true/i,
        /canSell\s*=\s*false/i,
        /onlySellWhenEnabled/i,
        /transferFrom.*require.*owner/i,
        /sell.*disabled/i,
      ]
    }
  },
  {
    id: 'fake-liquidity-lock',
    name: 'Fake Liquidity Lock',
    description: 'Pretends to lock liquidity but has backdoor',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /unlockLiquidity.*onlyOwner/i,
        /emergencyUnlock/i,
        /bypassLock/i,
        /lockTime\s*=\s*0/i,
        /removeLiquidity.*owner/i,
      ]
    }
  },
  {
    id: 'rug-pull-solana-1',
    name: 'Solana Rug Template',
    description: 'Common Solana program rug pull patterns',
    severity: 'critical',
    patterns: {
      filePatterns: ['drain.rs', 'withdraw_all.rs', 'emergency_exit.rs'],
      codePatterns: [
        /withdraw_all_funds/i,
        /drain_pool/i,
        /transfer_to_admin/i,
        /close_account.*authority/i,
        /emergency.*drain/i,
      ]
    }
  },
  {
    id: 'fake-ai-project-1',
    name: 'Fake AI Project',
    description: 'Claims AI but has no real AI code',
    severity: 'high',
    patterns: {
      readmePatterns: [
        /powered\s+by\s+(?:advanced\s+)?ai/i,
        /revolutionary\s+ai/i,
        /cutting[\s-]edge\s+(?:ai|ml|machine\s+learning)/i,
        /ai[\s-]driven\s+(?:trading|analysis|predictions)/i,
      ],
      codePatterns: [
        // Just imports with no actual usage
        /import.*openai.*\n(?:(?!openai|completion|chat).)*$/is,
      ]
    }
  },
  {
    id: 'copy-paste-defi-1',
    name: 'Copy-Paste DeFi',
    description: 'Exact copy of common DeFi templates with minimal changes',
    severity: 'medium',
    patterns: {
      codePatterns: [
        // Common unchanged boilerplate
        /MasterChef.*SUSHI/i,
        /PancakeRouter/i,
        /UniswapV2Router/i,
      ]
    }
  },
  {
    id: 'wallet-drainer-1',
    name: 'Wallet Drainer',
    description: 'Code designed to drain connected wallets',
    severity: 'critical',
    patterns: {
      codePatterns: [
        /signAllTransactions/i,
        /drainWallet/i,
        /transferAll.*tokens/i,
        /approveMax.*spender/i,
        /setApprovalForAll.*true/i,
        /unlimited.*approval/i,
      ],
      filePatterns: ['drainer.js', 'drain.ts', 'stealer.js']
    }
  },
  {
    id: 'airdrop-scam-1',
    name: 'Airdrop Scam',
    description: 'Fake airdrop that requires wallet connection or fees',
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
        /claim\s+your\s+tokens/i,
        /limited\s+time\s+airdrop/i,
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
  'backdoor', 'hidden', 'secret', 'admin_only', 'emergency_exit'
];

// Suspicious patterns in code that indicate potential scam
const SUSPICIOUS_CODE_PATTERNS = [
  { pattern: /eval\s*\(/, name: 'Dynamic code execution (eval)', severity: 'high' as const },
  { pattern: /Function\s*\(.*\)\s*\(/, name: 'Dynamic function creation', severity: 'high' as const },
  { pattern: /atob\s*\(|btoa\s*\(/, name: 'Base64 encoding (possible obfuscation)', severity: 'medium' as const },
  { pattern: /\\x[0-9a-f]{2}/gi, name: 'Hex encoded strings', severity: 'medium' as const },
  { pattern: /fromCharCode/, name: 'Character code obfuscation', severity: 'medium' as const },
  { pattern: /process\.env\[.*\+.*\]/, name: 'Dynamic env access', severity: 'medium' as const },
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
