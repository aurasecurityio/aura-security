/**
 * Rug Database - Track confirmed rugs, dev reputation, and learn from outcomes
 *
 * Features:
 * 1. Rug Registry - Community-reported confirmed rugs
 * 2. Dev Reputation - Track developers across projects
 * 3. Feedback Loop - Learn if our scans were correct
 * 4. Fork Origin - Flag repos forked from known scams
 */

import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Database setup
const DB_DIR = join(__dirname, '..', '..', '.aura-security');
const DB_PATH = join(DB_DIR, 'rug-database.db');

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (!db) {
    if (!existsSync(DB_DIR)) {
      mkdirSync(DB_DIR, { recursive: true });
    }

    db = new Database(DB_PATH);

    // Create tables
    db.exec(`
      -- Confirmed rugs reported by community
      CREATE TABLE IF NOT EXISTS rugs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_url TEXT UNIQUE NOT NULL,
        owner TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        reported_at TEXT NOT NULL,
        reported_by TEXT,
        rug_type TEXT,
        evidence TEXT,
        our_score_at_time INTEGER,
        our_verdict_at_time TEXT
      );

      -- Developer reputation tracking
      CREATE TABLE IF NOT EXISTS developers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        github_username TEXT UNIQUE NOT NULL,
        total_repos INTEGER DEFAULT 0,
        rugged_repos INTEGER DEFAULT 0,
        safe_repos INTEGER DEFAULT 0,
        reputation_score INTEGER DEFAULT 50,
        first_seen TEXT NOT NULL,
        last_seen TEXT NOT NULL,
        flagged INTEGER DEFAULT 0,
        flag_reason TEXT
      );

      -- Link devs to repos
      CREATE TABLE IF NOT EXISTS dev_repos (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        developer_id INTEGER NOT NULL,
        repo_url TEXT NOT NULL,
        role TEXT DEFAULT 'owner',
        scanned_at TEXT NOT NULL,
        outcome TEXT,
        FOREIGN KEY (developer_id) REFERENCES developers(id),
        UNIQUE(developer_id, repo_url)
      );

      -- Scan feedback - did our prediction match reality?
      CREATE TABLE IF NOT EXISTS scan_feedback (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_url TEXT NOT NULL,
        scanned_at TEXT NOT NULL,
        our_score INTEGER NOT NULL,
        our_verdict TEXT NOT NULL,
        actual_outcome TEXT,
        feedback_at TEXT,
        feedback_source TEXT,
        UNIQUE(repo_url, scanned_at)
      );

      -- Known scam repo signatures (for fork detection)
      CREATE TABLE IF NOT EXISTS scam_signatures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        repo_url TEXT UNIQUE NOT NULL,
        owner TEXT NOT NULL,
        repo_name TEXT NOT NULL,
        file_hash TEXT,
        structure_hash TEXT,
        added_at TEXT NOT NULL,
        severity TEXT DEFAULT 'high'
      );

      -- Indexes for fast lookups
      CREATE INDEX IF NOT EXISTS idx_rugs_owner ON rugs(owner);
      CREATE INDEX IF NOT EXISTS idx_rugs_repo ON rugs(repo_name);
      CREATE INDEX IF NOT EXISTS idx_devs_username ON developers(github_username);
      CREATE INDEX IF NOT EXISTS idx_devs_flagged ON developers(flagged);
      CREATE INDEX IF NOT EXISTS idx_signatures_owner ON scam_signatures(owner);
    `);

    console.log(`[RUG-DB] Database initialized at: ${DB_PATH}`);
  }

  return db;
}

// ============ RUG REGISTRY ============

export interface RugReport {
  repoUrl: string;
  owner: string;
  repoName: string;
  rugType?: string;
  evidence?: string;
  reportedBy?: string;
  ourScoreAtTime?: number;
  ourVerdictAtTime?: string;
}

/**
 * Report a confirmed rug
 */
export function reportRug(report: RugReport): boolean {
  try {
    const database = getDb();
    const stmt = database.prepare(`
      INSERT OR REPLACE INTO rugs
      (repo_url, owner, repo_name, reported_at, reported_by, rug_type, evidence, our_score_at_time, our_verdict_at_time)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      report.repoUrl.toLowerCase(),
      report.owner.toLowerCase(),
      report.repoName.toLowerCase(),
      new Date().toISOString(),
      report.reportedBy || 'anonymous',
      report.rugType || 'unknown',
      report.evidence || null,
      report.ourScoreAtTime || null,
      report.ourVerdictAtTime || null
    );

    // Update developer reputation
    updateDevReputation(report.owner, 'rugged');

    console.log(`[RUG-DB] Rug reported: ${report.repoUrl}`);
    return true;
  } catch (err) {
    console.error(`[RUG-DB] Error reporting rug:`, err);
    return false;
  }
}

/**
 * Check if a repo is a known rug
 */
export function isKnownRug(repoUrl: string): { isRug: boolean; report?: any } {
  try {
    const database = getDb();
    const stmt = database.prepare('SELECT * FROM rugs WHERE repo_url = ?');
    const result = stmt.get(repoUrl.toLowerCase());

    if (result) {
      return { isRug: true, report: result };
    }
    return { isRug: false };
  } catch {
    return { isRug: false };
  }
}

/**
 * Check if owner has rugged before
 */
export function hasOwnerRuggedBefore(owner: string): { hasRugged: boolean; rugCount: number; repos: string[] } {
  try {
    const database = getDb();
    const stmt = database.prepare('SELECT repo_url FROM rugs WHERE owner = ?');
    const results = stmt.all(owner.toLowerCase()) as Array<{ repo_url: string }>;

    return {
      hasRugged: results.length > 0,
      rugCount: results.length,
      repos: results.map(r => r.repo_url)
    };
  } catch {
    return { hasRugged: false, rugCount: 0, repos: [] };
  }
}

// ============ DEVELOPER REPUTATION ============

export interface DevReputation {
  username: string;
  totalRepos: number;
  ruggedRepos: number;
  safeRepos: number;
  reputationScore: number;
  flagged: boolean;
  flagReason?: string;
}

/**
 * Get or create developer record
 */
function getOrCreateDev(username: string): number {
  const database = getDb();
  const lowerUsername = username.toLowerCase();

  // Try to get existing
  const existing = database.prepare('SELECT id FROM developers WHERE github_username = ?').get(lowerUsername) as { id: number } | undefined;

  if (existing) {
    // Update last_seen
    database.prepare('UPDATE developers SET last_seen = ? WHERE id = ?').run(new Date().toISOString(), existing.id);
    return existing.id;
  }

  // Create new
  const now = new Date().toISOString();
  const result = database.prepare(`
    INSERT INTO developers (github_username, first_seen, last_seen)
    VALUES (?, ?, ?)
  `).run(lowerUsername, now, now);

  return result.lastInsertRowid as number;
}

/**
 * Update developer reputation after scan outcome
 */
export function updateDevReputation(username: string, outcome: 'rugged' | 'safe' | 'scanned'): void {
  try {
    const database = getDb();
    const devId = getOrCreateDev(username);

    if (outcome === 'rugged') {
      database.prepare(`
        UPDATE developers
        SET rugged_repos = rugged_repos + 1,
            total_repos = total_repos + 1,
            reputation_score = MAX(0, reputation_score - 25),
            flagged = CASE WHEN rugged_repos >= 1 THEN 1 ELSE flagged END,
            flag_reason = CASE WHEN rugged_repos >= 1 THEN 'Multiple rugged projects' ELSE flag_reason END
        WHERE id = ?
      `).run(devId);
    } else if (outcome === 'safe') {
      database.prepare(`
        UPDATE developers
        SET safe_repos = safe_repos + 1,
            total_repos = total_repos + 1,
            reputation_score = MIN(100, reputation_score + 5)
        WHERE id = ?
      `).run(devId);
    } else {
      database.prepare(`
        UPDATE developers
        SET total_repos = total_repos + 1
        WHERE id = ?
      `).run(devId);
    }

    console.log(`[RUG-DB] Dev reputation updated: ${username} (${outcome})`);
  } catch (err) {
    console.error(`[RUG-DB] Error updating dev reputation:`, err);
  }
}

/**
 * Get developer reputation
 */
export function getDevReputation(username: string): DevReputation | null {
  try {
    const database = getDb();
    const result = database.prepare(`
      SELECT github_username, total_repos, rugged_repos, safe_repos, reputation_score, flagged, flag_reason
      FROM developers WHERE github_username = ?
    `).get(username.toLowerCase()) as any;

    if (!result) return null;

    return {
      username: result.github_username,
      totalRepos: result.total_repos,
      ruggedRepos: result.rugged_repos,
      safeRepos: result.safe_repos,
      reputationScore: result.reputation_score,
      flagged: result.flagged === 1,
      flagReason: result.flag_reason
    };
  } catch {
    return null;
  }
}

/**
 * Check if developer is flagged (known bad actor)
 */
export function isDevFlagged(username: string): { flagged: boolean; reason?: string; rugCount?: number } {
  try {
    const database = getDb();
    const result = database.prepare(`
      SELECT flagged, flag_reason, rugged_repos FROM developers WHERE github_username = ?
    `).get(username.toLowerCase()) as any;

    if (!result) return { flagged: false };

    return {
      flagged: result.flagged === 1,
      reason: result.flag_reason,
      rugCount: result.rugged_repos
    };
  } catch {
    return { flagged: false };
  }
}

/**
 * Manually flag a developer
 */
export function flagDeveloper(username: string, reason: string): boolean {
  try {
    const database = getDb();
    const devId = getOrCreateDev(username);

    database.prepare(`
      UPDATE developers SET flagged = 1, flag_reason = ? WHERE id = ?
    `).run(reason, devId);

    console.log(`[RUG-DB] Developer flagged: ${username} - ${reason}`);
    return true;
  } catch {
    return false;
  }
}

// ============ SCAN FEEDBACK ============

/**
 * Record a scan for later feedback
 */
export function recordScan(repoUrl: string, score: number, verdict: string): void {
  try {
    const database = getDb();
    database.prepare(`
      INSERT OR REPLACE INTO scan_feedback (repo_url, scanned_at, our_score, our_verdict)
      VALUES (?, ?, ?, ?)
    `).run(repoUrl.toLowerCase(), new Date().toISOString(), score, verdict);
  } catch (err) {
    console.error(`[RUG-DB] Error recording scan:`, err);
  }
}

/**
 * Submit feedback on a scan (was it correct?)
 */
export function submitFeedback(repoUrl: string, actualOutcome: 'rugged' | 'safe' | 'unknown', source?: string): boolean {
  try {
    const database = getDb();

    // Update the most recent scan for this repo
    database.prepare(`
      UPDATE scan_feedback
      SET actual_outcome = ?, feedback_at = ?, feedback_source = ?
      WHERE repo_url = ? AND actual_outcome IS NULL
      ORDER BY scanned_at DESC LIMIT 1
    `).run(actualOutcome, new Date().toISOString(), source || 'user', repoUrl.toLowerCase());

    // If rugged, also add to rug registry
    if (actualOutcome === 'rugged') {
      const urlMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/i);
      if (urlMatch) {
        reportRug({
          repoUrl,
          owner: urlMatch[1],
          repoName: urlMatch[2],
          reportedBy: source || 'feedback'
        });
      }
    }

    console.log(`[RUG-DB] Feedback recorded: ${repoUrl} = ${actualOutcome}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Get accuracy stats (how often were we right?)
 */
export function getAccuracyStats(): {
  totalWithFeedback: number;
  correctPredictions: number;
  accuracy: number;
  falsePositives: number;
  falseNegatives: number;
} {
  try {
    const database = getDb();

    const stats = database.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE
          WHEN (our_verdict IN ('SAFU', 'DYOR') AND actual_outcome = 'safe')
            OR (our_verdict IN ('RISKY', 'RUG ALERT') AND actual_outcome = 'rugged')
          THEN 1 ELSE 0 END) as correct,
        SUM(CASE
          WHEN our_verdict IN ('RISKY', 'RUG ALERT') AND actual_outcome = 'safe'
          THEN 1 ELSE 0 END) as false_positives,
        SUM(CASE
          WHEN our_verdict IN ('SAFU', 'DYOR') AND actual_outcome = 'rugged'
          THEN 1 ELSE 0 END) as false_negatives
      FROM scan_feedback
      WHERE actual_outcome IS NOT NULL AND actual_outcome != 'unknown'
    `).get() as any;

    return {
      totalWithFeedback: stats.total || 0,
      correctPredictions: stats.correct || 0,
      accuracy: stats.total > 0 ? Math.round((stats.correct / stats.total) * 100) : 0,
      falsePositives: stats.false_positives || 0,
      falseNegatives: stats.false_negatives || 0
    };
  } catch {
    return { totalWithFeedback: 0, correctPredictions: 0, accuracy: 0, falsePositives: 0, falseNegatives: 0 };
  }
}

// ============ SCAM SIGNATURES (Fork Detection) ============

/**
 * Add a repo to scam signatures (for fork detection)
 */
export function addScamSignature(repoUrl: string, fileHash?: string, structureHash?: string): boolean {
  try {
    const urlMatch = repoUrl.match(/github\.com\/([^\/]+)\/([^\/]+)/i);
    if (!urlMatch) return false;

    const database = getDb();
    database.prepare(`
      INSERT OR REPLACE INTO scam_signatures (repo_url, owner, repo_name, file_hash, structure_hash, added_at, severity)
      VALUES (?, ?, ?, ?, ?, ?, 'high')
    `).run(
      repoUrl.toLowerCase(),
      urlMatch[1].toLowerCase(),
      urlMatch[2].toLowerCase(),
      fileHash || null,
      structureHash || null,
      new Date().toISOString()
    );

    return true;
  } catch {
    return false;
  }
}

/**
 * Check if a repo is forked from a known scam
 */
export function isForkedFromScam(parentRepoUrl: string): { isScam: boolean; signature?: any } {
  try {
    const database = getDb();
    const result = database.prepare('SELECT * FROM scam_signatures WHERE repo_url = ?').get(parentRepoUrl.toLowerCase());

    if (result) {
      return { isScam: true, signature: result };
    }
    return { isScam: false };
  } catch {
    return { isScam: false };
  }
}

/**
 * Check if owner has scam signatures
 */
export function ownerHasScamSignatures(owner: string): { hasScams: boolean; count: number } {
  try {
    const database = getDb();
    const result = database.prepare('SELECT COUNT(*) as count FROM scam_signatures WHERE owner = ?').get(owner.toLowerCase()) as { count: number };

    return {
      hasScams: result.count > 0,
      count: result.count
    };
  } catch {
    return { hasScams: false, count: 0 };
  }
}

// ============ STATS ============

/**
 * Get database statistics
 */
export function getDbStats(): {
  totalRugs: number;
  totalDevs: number;
  flaggedDevs: number;
  totalScans: number;
  scamSignatures: number;
} {
  try {
    const database = getDb();

    const rugs = database.prepare('SELECT COUNT(*) as count FROM rugs').get() as { count: number };
    const devs = database.prepare('SELECT COUNT(*) as count FROM developers').get() as { count: number };
    const flagged = database.prepare('SELECT COUNT(*) as count FROM developers WHERE flagged = 1').get() as { count: number };
    const scans = database.prepare('SELECT COUNT(*) as count FROM scan_feedback').get() as { count: number };
    const sigs = database.prepare('SELECT COUNT(*) as count FROM scam_signatures').get() as { count: number };

    return {
      totalRugs: rugs.count,
      totalDevs: devs.count,
      flaggedDevs: flagged.count,
      totalScans: scans.count,
      scamSignatures: sigs.count
    };
  } catch {
    return { totalRugs: 0, totalDevs: 0, flaggedDevs: 0, totalScans: 0, scamSignatures: 0 };
  }
}

/**
 * Get recent rugs
 */
export function getRecentRugs(limit = 10): Array<{ repoUrl: string; owner: string; reportedAt: string; rugType: string }> {
  try {
    const database = getDb();
    const results = database.prepare(`
      SELECT repo_url, owner, reported_at, rug_type
      FROM rugs ORDER BY reported_at DESC LIMIT ?
    `).all(limit) as any[];

    return results.map(r => ({
      repoUrl: r.repo_url,
      owner: r.owner,
      reportedAt: r.reported_at,
      rugType: r.rug_type
    }));
  } catch {
    return [];
  }
}

/**
 * Get flagged developers
 */
export function getFlaggedDevs(): Array<{ username: string; rugCount: number; reason: string }> {
  try {
    const database = getDb();
    const results = database.prepare(`
      SELECT github_username, rugged_repos, flag_reason
      FROM developers WHERE flagged = 1 ORDER BY rugged_repos DESC
    `).all() as any[];

    return results.map(r => ({
      username: r.github_username,
      rugCount: r.rugged_repos,
      reason: r.flag_reason
    }));
  } catch {
    return [];
  }
}

/**
 * Close database connection
 */
export function closeRugDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}
