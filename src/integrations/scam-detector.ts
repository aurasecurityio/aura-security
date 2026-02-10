/**
 * Scam Detector - Focused on AI Crypto Projects & Solana Ecosystem
 *
 * Detects fake AI projects, Solana rug patterns, and wallet drainers.
 * Optimized for pump.fun and AI agent token ecosystem.
 *
 * Detection signatures are loaded from private config (config/scam-signatures.json).
 * If config is missing, minimal defaults are used.
 */

import { loadConfig, toRegExp } from '../config/loader.js';

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

// Config file types (JSON-serializable)
interface ScamSignatureConfig {
  id: string;
  name: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  patterns: {
    filePatterns?: string[];
    codePatterns?: [string, string?][];
    readmePatterns?: [string, string?][];
    structureHash?: string;
  };
  reportedDate?: string;
  source?: string;
}

interface ScamConfigFile {
  signatures: ScamSignatureConfig[];
  suspiciousFileNames: string[];
  suspiciousCodePatterns: Array<{
    pattern: [string, string?];
    name: string;
    severity: 'critical' | 'high' | 'medium' | 'low';
  }>;
  knownScamRepos?: Array<{ url: string; name: string; hash?: string }>;
  scoring: {
    severityMultipliers: Record<string, number>;
    suspiciousPatternMultipliers: Record<string, number>;
    suspiciousFileScore: number;
    minimumScores: Record<string, number>;
    scamThreshold: number;
  };
}

// Minimal defaults when config file is not found
const DEFAULT_CONFIG: ScamConfigFile = {
  signatures: [],
  suspiciousFileNames: [],
  suspiciousCodePatterns: [],
  knownScamRepos: [],
  scoring: {
    severityMultipliers: { critical: 30, high: 20, medium: 10, low: 5 },
    suspiciousPatternMultipliers: { high: 15, medium: 8 },
    suspiciousFileScore: 10,
    minimumScores: { critical: 50, high: 35, medium: 20 },
    scamThreshold: 50,
  },
};

// Load and compile config
const scamConfig = loadConfig<ScamConfigFile>('scam-signatures.json', DEFAULT_CONFIG);

// Compile regex patterns from config into runtime objects
const SCAM_SIGNATURES: ScamSignature[] = scamConfig.signatures.map(sig => ({
  ...sig,
  patterns: {
    filePatterns: sig.patterns.filePatterns,
    codePatterns: sig.patterns.codePatterns?.map(p => toRegExp(p)),
    readmePatterns: sig.patterns.readmePatterns?.map(p => toRegExp(p)),
    structureHash: sig.patterns.structureHash,
  },
}));

// Suspicious keywords in file names (matched as whole words to avoid false positives like "hackathon")
const SUSPICIOUS_FILE_NAMES = scamConfig.suspiciousFileNames;

// Suspicious patterns in code
const SUSPICIOUS_CODE_PATTERNS = scamConfig.suspiciousCodePatterns.map(p => ({
  pattern: toRegExp(p.pattern),
  name: p.name,
  severity: p.severity as 'critical' | 'high' | 'medium' | 'low',
}));

// Known scam repo URLs/hashes (community reported)
const KNOWN_SCAM_REPOS = scamConfig.knownScamRepos || [];

// Scoring configuration
const SCORING = scamConfig.scoring;

// Helper: check if a file name contains a suspicious word as a whole word (not substring)
function isSuspiciousFileName(fileName: string): string | null {
  const lower = fileName.toLowerCase();
  for (const word of SUSPICIOUS_FILE_NAMES) {
    // Match whole word: "drain.js" yes, "hackathon" no
    const regex = new RegExp(`(?:^|[^a-z])${word}(?:[^a-z]|$)`, 'i');
    if (regex.test(lower)) {
      return word;
    }
  }
  return null;
}

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

  // Check for suspicious file names (whole word match to avoid false positives)
  for (const file of filePaths) {
    const fileName = file.split('/').pop() || '';
    const match = isSuspiciousFileName(fileName);
    if (match) {
      suspiciousFiles.push(file);
      warnings.push(`Suspicious file name: ${file}`);
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

    // Calculate confidence — require meaningful match threshold
    if (matchCount > 0 && totalPatterns > 0) {
      const confidence = Math.min(100, (matchCount / totalPatterns) * 100 + (matchCount * 15));

      // For high/critical severity, require at least 2 matches OR 40%+ confidence
      // A single weak README pattern match shouldn't brand a project as a scam
      const minConfidence = (signature.severity === 'critical' || signature.severity === 'high') ? 40 : 25;
      const minMatches = (signature.severity === 'critical' || signature.severity === 'high') ? 2 : 1;

      if (confidence >= minConfidence || matchCount >= minMatches) {
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
  }

  // Scan individual files for suspicious patterns
  for (const file of repoData.files) {
    if (file.content) {
      const filePatterns = scanCodeForPatterns(file.content, file.path);
      suspiciousPatterns.push(...filePatterns.map(p => ({ ...p, file: file.path })));
    }
  }

  // Calculate scam score using config-driven multipliers
  let scamScore = 0;

  // Signature matches (known scam patterns)
  const criticalMatches = matches.filter(m => m.severity === 'critical').length;
  const highMatches = matches.filter(m => m.severity === 'high').length;
  const mediumMatches = matches.filter(m => m.severity === 'medium').length;
  const lowMatches = matches.filter(m => m.severity === 'low').length;

  scamScore += criticalMatches * (SCORING.severityMultipliers.critical || 30);
  scamScore += highMatches * (SCORING.severityMultipliers.high || 20);
  scamScore += mediumMatches * (SCORING.severityMultipliers.medium || 10);
  scamScore += lowMatches * (SCORING.severityMultipliers.low || 5);

  // Suspicious patterns add points
  scamScore += suspiciousPatterns.filter(p => p.severity === 'high').length * (SCORING.suspiciousPatternMultipliers.high || 15);
  scamScore += suspiciousPatterns.filter(p => p.severity === 'medium').length * (SCORING.suspiciousPatternMultipliers.medium || 8);

  // Suspicious files add points
  scamScore += suspiciousFiles.length * (SCORING.suspiciousFileScore || 10);

  // Enforce minimum scores when known scam signatures are matched
  if (criticalMatches > 0) {
    scamScore = Math.max(scamScore, SCORING.minimumScores.critical || 50);
  } else if (highMatches > 0) {
    scamScore = Math.max(scamScore, SCORING.minimumScores.high || 35);
  } else if (mediumMatches > 0) {
    scamScore = Math.max(scamScore, SCORING.minimumScores.medium || 20);
  }

  // Cap at 100
  scamScore = Math.min(100, scamScore);

  // Estimate code originality (inverse of how many patterns matched)
  const codeOriginality = Math.max(0, 100 - (matches.length * 15) - (suspiciousPatterns.length * 5));

  // Determine if likely scam
  const isLikelyScam = scamScore >= (SCORING.scamThreshold || 50) || matches.some(m => m.severity === 'critical' && m.confidence > 60);

  // Generate summary - signature matches always override
  // Rule: if we matched a known scam pattern, NEVER say "CLEAN"
  let summary = '';
  if (matches.length > 0) {
    // We found known scam patterns - lead with the worst one
    const worstMatch = matches.sort((a, b) => {
      const order = { critical: 0, high: 1, medium: 2, low: 3 };
      return order[a.severity] - order[b.severity];
    })[0];

    if (scamScore >= 70) {
      summary = `DANGER: ${matches.length} known scam pattern(s) detected including ${worstMatch.signatureName}.`;
    } else if (scamScore >= 50) {
      summary = `WARNING: Known scam pattern detected - ${worstMatch.signatureName}. Review carefully.`;
    } else {
      summary = `CAUTION: Matched scam pattern - ${worstMatch.signatureName}. Proceed with caution.`;
    }
  } else if (scamScore >= 25) {
    summary = `MODERATE RISK: Some concerning patterns detected. Proceed with caution.`;
  } else if (suspiciousPatterns.length > 0 || suspiciousFiles.length > 0) {
    summary = `LOW RISK: Minor concerns found but no known scam patterns.`;
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

  // Check file names (whole word match to avoid false positives like "hackathon")
  for (const file of files) {
    const fileName = file.split('/').pop() || '';
    const match = isSuspiciousFileName(fileName);
    if (match) {
      redFlags.push(`Suspicious file: ${file}`);
    }
  }

  // Check README — require multiple pattern matches per signature to avoid
  // flagging legitimate projects (e.g., a real AI project mentioning "AI assistant")
  if (readme) {
    for (const sig of SCAM_SIGNATURES) {
      if (sig.patterns.readmePatterns) {
        let readmeMatchCount = 0;
        for (const pattern of sig.patterns.readmePatterns) {
          if (pattern.test(readme)) {
            readmeMatchCount++;
          }
        }
        // For critical severity: 1 match is enough (drain patterns, etc.)
        // For high/medium: require at least 2 README matches to flag
        const threshold = sig.severity === 'critical' ? 1 : 2;
        if (readmeMatchCount >= threshold) {
          redFlags.push(`README red flag: ${sig.name}`);
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
