/**
 * SQLite Database for aurasecurity
 *
 * Provides persistent storage for:
 * - Audit history
 * - Configuration settings
 * - Scan results
 * - Notification history
 */

import Database from 'better-sqlite3';
import { join } from 'path';
import { existsSync, mkdirSync } from 'fs';
import { createHash, randomBytes } from 'crypto';
import type { AuditorOutput } from '../types/events.js';
import type { LocalScanResult } from '../integrations/local-scanner.js';
import type { AWSScanResult } from '../integrations/aws-scanner.js';
import { calculateSecurityScore, type SecurityScore, type ScoreHistoryEntry, type ScoreTrend } from '../scoring/index.js';

// ============ TYPES ============

export interface AuditRecord {
  id: string;
  type: 'code' | 'aws' | 'audit';
  timestamp: string;
  target: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  data: string; // JSON stringified full result
}

export interface SettingsRecord {
  key: string;
  value: string;
  updated_at: string;
}

export interface NotificationRecord {
  id: number;
  type: 'slack' | 'discord' | 'webhook';
  audit_id: string;
  status: 'sent' | 'failed' | 'pending';
  message: string;
  timestamp: string;
  error?: string;
}

export interface ApiKeyRecord {
  id: string;
  name: string;
  key_hash: string;
  scopes: string[];
  created_at: string;
  last_used_at: string | null;
  expires_at: string | null;
  active: boolean;
}

// ============ DEFAULT SETTINGS ============

const DEFAULT_SETTINGS: Record<string, string> = {
  // AWS Settings
  'aws.enabled': 'false',
  'aws.region': 'us-east-1',
  'aws.accessKeyId': '',
  'aws.secretAccessKey': '',
  'aws.services': 'iam,s3,ec2,lambda,rds',

  // Slack Settings
  'slack.enabled': 'false',
  'slack.webhookUrl': '',
  'slack.channel': '',
  'slack.notifyOn': 'critical,high',

  // Discord Settings
  'discord.enabled': 'false',
  'discord.webhookUrl': '',
  'discord.notifyOn': 'critical,high',

  // GitHub Settings
  'github.enabled': 'false',
  'github.token': '',
  'github.createCheckRuns': 'true',
  'github.commentOnPR': 'true',

  // GitLab Settings
  'gitlab.enabled': 'false',
  'gitlab.token': '',
  'gitlab.url': 'https://gitlab.com',

  // Scanner Settings
  'scanner.gitleaks': 'true',
  'scanner.trivy': 'true',
  'scanner.semgrep': 'true',
  'scanner.npmAudit': 'true',

  // Thresholds
  'thresholds.failOnCritical': 'true',
  'thresholds.failOnHigh': 'false',
  'thresholds.maxCritical': '0',
  'thresholds.maxHigh': '5',

  // Server Settings
  'server.port': '3000',
  'server.visualizerPort': '8080',
};

// ============ DATABASE CLASS ============

export class AuditorDatabase {
  private db: Database.Database;
  private dbPath: string;

  constructor(dbPath?: string) {
    // Default to .aura-security directory in user home
    const dataDir = dbPath
      ? join(dbPath, '.aura-security')
      : join(process.env.HOME || process.env.USERPROFILE || '.', '.aura-security');

    if (!existsSync(dataDir)) {
      mkdirSync(dataDir, { recursive: true });
    }

    this.dbPath = join(dataDir, 'auditor.db');
    this.db = new Database(this.dbPath);

    // Enable WAL mode for better concurrent access
    this.db.pragma('journal_mode = WAL');

    // Initialize tables
    this.initTables();

    console.log(`[DB] SQLite database initialized at: ${this.dbPath}`);
  }

  private initTables(): void {
    // Audits table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS audits (
        id TEXT PRIMARY KEY,
        type TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        target TEXT NOT NULL,
        critical INTEGER DEFAULT 0,
        high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0,
        low INTEGER DEFAULT 0,
        data TEXT NOT NULL
      )
    `);

    // Settings table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS settings (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL,
        updated_at TEXT NOT NULL
      )
    `);

    // Notifications table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        type TEXT NOT NULL,
        audit_id TEXT NOT NULL,
        status TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        error TEXT,
        FOREIGN KEY (audit_id) REFERENCES audits(id)
      )
    `);

    // Score history table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS score_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        target TEXT NOT NULL,
        audit_id TEXT NOT NULL,
        score REAL NOT NULL,
        grade TEXT NOT NULL,
        critical INTEGER DEFAULT 0,
        high INTEGER DEFAULT 0,
        medium INTEGER DEFAULT 0,
        low INTEGER DEFAULT 0,
        timestamp TEXT NOT NULL,
        FOREIGN KEY (audit_id) REFERENCES audits(id)
      )
    `);

    // API Keys table
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS api_keys (
        id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        key_hash TEXT NOT NULL UNIQUE,
        scopes TEXT DEFAULT '[]',
        created_at TEXT NOT NULL,
        last_used_at TEXT,
        expires_at TEXT,
        active INTEGER DEFAULT 1
      )
    `);

    // Create indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audits_type ON audits(type);
      CREATE INDEX IF NOT EXISTS idx_notifications_audit ON notifications(audit_id);
      CREATE INDEX IF NOT EXISTS idx_score_history_target ON score_history(target);
      CREATE INDEX IF NOT EXISTS idx_score_history_timestamp ON score_history(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
    `);

    // Initialize default settings
    const insertSetting = this.db.prepare(`
      INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)
    `);

    const now = new Date().toISOString();
    for (const [key, value] of Object.entries(DEFAULT_SETTINGS)) {
      insertSetting.run(key, value, now);
    }
  }

  // ============ AUDIT METHODS ============

  saveAudit(
    type: 'code' | 'aws' | 'audit',
    target: string,
    result: LocalScanResult | AWSScanResult | AuditorOutput
  ): string {
    const id = `${type}-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
    const timestamp = new Date().toISOString();

    // Extract summary counts based on type
    let critical = 0, high = 0, medium = 0, low = 0;

    if (type === 'code') {
      const r = result as LocalScanResult;
      critical = r.secrets.filter(s => s.severity === 'critical').length +
                 r.packages.filter(p => p.severity === 'critical').length;
      high = r.secrets.filter(s => s.severity === 'high').length +
             r.packages.filter(p => p.severity === 'high').length;
      medium = r.secrets.filter(s => s.severity === 'medium').length +
               r.packages.filter(p => p.severity === 'medium').length;
      low = r.secrets.filter(s => s.severity === 'low').length +
            r.packages.filter(p => p.severity === 'low').length;
    } else if (type === 'aws') {
      const r = result as AWSScanResult;
      critical = r.summary.critical;
      high = r.summary.high;
      medium = r.summary.medium;
      low = r.summary.low;
    } else if (type === 'audit') {
      const r = result as AuditorOutput;
      for (const event of r.events) {
        if (event.payload?.severity === 'critical') critical++;
        else if (event.payload?.severity === 'high') high++;
        else if (event.payload?.severity === 'medium') medium++;
        else if (event.payload?.severity === 'low') low++;
      }
    }

    const stmt = this.db.prepare(`
      INSERT INTO audits (id, type, timestamp, target, critical, high, medium, low, data)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(id, type, timestamp, target, critical, high, medium, low, JSON.stringify(result));

    console.log(`[DB] Saved audit: ${id} (${type})`);
    return id;
  }

  getAudit(id: string): AuditRecord | null {
    const stmt = this.db.prepare(`
      SELECT id, type, timestamp, target, critical, high, medium, low, data
      FROM audits WHERE id = ?
    `);

    const row = stmt.get(id) as any;
    if (!row) return null;

    return {
      id: row.id,
      type: row.type,
      timestamp: row.timestamp,
      target: row.target,
      summary: {
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low,
      },
      data: row.data,
    };
  }

  getAudits(limit = 50, offset = 0, type?: string): AuditRecord[] {
    let query = `
      SELECT id, type, timestamp, target, critical, high, medium, low, data
      FROM audits
    `;
    const params: any[] = [];

    if (type) {
      query += ' WHERE type = ?';
      params.push(type);
    }

    query += ' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
    params.push(limit, offset);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map(row => ({
      id: row.id,
      type: row.type,
      timestamp: row.timestamp,
      target: row.target,
      summary: {
        critical: row.critical,
        high: row.high,
        medium: row.medium,
        low: row.low,
      },
      data: row.data,
    }));
  }

  getAuditCount(type?: string): number {
    let query = 'SELECT COUNT(*) as count FROM audits';
    const params: any[] = [];

    if (type) {
      query += ' WHERE type = ?';
      params.push(type);
    }

    const stmt = this.db.prepare(query);
    const row = stmt.get(...params) as any;
    return row.count;
  }

  deleteAudit(id: string): boolean {
    const stmt = this.db.prepare('DELETE FROM audits WHERE id = ?');
    const result = stmt.run(id);
    return result.changes > 0;
  }

  // ============ SETTINGS METHODS ============

  getSetting(key: string): string | null {
    const stmt = this.db.prepare('SELECT value FROM settings WHERE key = ?');
    const row = stmt.get(key) as any;
    return row ? row.value : null;
  }

  getSettings(prefix?: string): Record<string, string> {
    let query = 'SELECT key, value FROM settings';
    const params: any[] = [];

    if (prefix) {
      query += ' WHERE key LIKE ?';
      params.push(`${prefix}%`);
    }

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    const settings: Record<string, string> = {};
    for (const row of rows) {
      settings[row.key] = row.value;
    }
    return settings;
  }

  getAllSettings(): Record<string, string> {
    return this.getSettings();
  }

  setSetting(key: string, value: string): void {
    const stmt = this.db.prepare(`
      INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
    `);

    const now = new Date().toISOString();
    stmt.run(key, value, now, value, now);
  }

  setSettings(settings: Record<string, string>): void {
    const stmt = this.db.prepare(`
      INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
      ON CONFLICT(key) DO UPDATE SET value = ?, updated_at = ?
    `);

    const now = new Date().toISOString();
    const transaction = this.db.transaction(() => {
      for (const [key, value] of Object.entries(settings)) {
        stmt.run(key, value, now, value, now);
      }
    });

    transaction();
  }

  // ============ NOTIFICATION METHODS ============

  saveNotification(
    type: 'slack' | 'discord' | 'webhook',
    auditId: string,
    status: 'sent' | 'failed' | 'pending',
    message: string,
    error?: string
  ): number {
    const stmt = this.db.prepare(`
      INSERT INTO notifications (type, audit_id, status, message, timestamp, error)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    const result = stmt.run(type, auditId, status, message, new Date().toISOString(), error || null);
    return result.lastInsertRowid as number;
  }

  recordNotification(auditId: string, channels: string, success: boolean, error?: string): void {
    const timestamp = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO notifications (type, audit_id, status, message, timestamp, error)
      VALUES (?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      channels || 'unknown',
      auditId,
      success ? 'sent' : 'failed',
      success ? `Notification sent via ${channels}` : 'Notification failed',
      timestamp,
      error || null
    );
  }

  getNotifications(auditId?: string, limit = 50): NotificationRecord[] {
    let query = `
      SELECT id, type, audit_id, status, message, timestamp, error
      FROM notifications
    `;
    const params: any[] = [];

    if (auditId) {
      query += ' WHERE audit_id = ?';
      params.push(auditId);
    }

    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map(row => ({
      id: row.id,
      type: row.type,
      audit_id: row.audit_id,
      status: row.status,
      message: row.message,
      timestamp: row.timestamp,
      error: row.error,
    }));
  }

  // ============ STATS METHODS ============

  getStats(): {
    totalAudits: number;
    byType: Record<string, number>;
    byDay: Array<{ date: string; count: number }>;
    severityCounts: { critical: number; high: number; medium: number; low: number };
  } {
    // Total audits
    const totalStmt = this.db.prepare('SELECT COUNT(*) as count FROM audits');
    const totalRow = totalStmt.get() as any;

    // By type
    const typeStmt = this.db.prepare(`
      SELECT type, COUNT(*) as count FROM audits GROUP BY type
    `);
    const typeRows = typeStmt.all() as any[];
    const byType: Record<string, number> = {};
    for (const row of typeRows) {
      byType[row.type] = row.count;
    }

    // By day (last 30 days)
    const dayStmt = this.db.prepare(`
      SELECT DATE(timestamp) as date, COUNT(*) as count
      FROM audits
      WHERE timestamp >= DATE('now', '-30 days')
      GROUP BY DATE(timestamp)
      ORDER BY date DESC
    `);
    const dayRows = dayStmt.all() as any[];
    const byDay = dayRows.map(row => ({ date: row.date, count: row.count }));

    // Severity totals
    const sevStmt = this.db.prepare(`
      SELECT
        SUM(critical) as critical,
        SUM(high) as high,
        SUM(medium) as medium,
        SUM(low) as low
      FROM audits
    `);
    const sevRow = sevStmt.get() as any;

    return {
      totalAudits: totalRow.count,
      byType,
      byDay,
      severityCounts: {
        critical: sevRow.critical || 0,
        high: sevRow.high || 0,
        medium: sevRow.medium || 0,
        low: sevRow.low || 0,
      },
    };
  }

  // ============ SCORE METHODS ============

  saveScore(
    target: string,
    auditId: string,
    counts: { critical: number; high: number; medium: number; low: number }
  ): SecurityScore {
    const score = calculateSecurityScore(counts);
    const timestamp = new Date().toISOString();

    const stmt = this.db.prepare(`
      INSERT INTO score_history (target, audit_id, score, grade, critical, high, medium, low, timestamp)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    stmt.run(
      target,
      auditId,
      score.score,
      score.grade,
      counts.critical,
      counts.high,
      counts.medium,
      counts.low,
      timestamp
    );

    console.log(`[DB] Saved score: ${score.score} (${score.grade}) for ${target}`);
    return score;
  }

  getScoreHistory(target?: string, limit = 50): ScoreHistoryEntry[] {
    let query = `
      SELECT id, target, audit_id, score, grade, critical, high, medium, low, timestamp
      FROM score_history
    `;
    const params: any[] = [];

    if (target) {
      query += ' WHERE target = ?';
      params.push(target);
    }

    query += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(limit);

    const stmt = this.db.prepare(query);
    const rows = stmt.all(...params) as any[];

    return rows.map(row => ({
      id: row.id,
      target: row.target,
      auditId: row.audit_id,
      score: row.score,
      grade: row.grade,
      critical: row.critical,
      high: row.high,
      medium: row.medium,
      low: row.low,
      timestamp: row.timestamp,
    }));
  }

  getLatestScore(target?: string): ScoreHistoryEntry | null {
    let query = `
      SELECT id, target, audit_id, score, grade, critical, high, medium, low, timestamp
      FROM score_history
    `;
    const params: any[] = [];

    if (target) {
      query += ' WHERE target = ?';
      params.push(target);
    }

    query += ' ORDER BY timestamp DESC LIMIT 1';

    const stmt = this.db.prepare(query);
    const row = stmt.get(...params) as any;

    if (!row) return null;

    return {
      id: row.id,
      target: row.target,
      auditId: row.audit_id,
      score: row.score,
      grade: row.grade,
      critical: row.critical,
      high: row.high,
      medium: row.medium,
      low: row.low,
      timestamp: row.timestamp,
    };
  }

  getScoreTrend(target?: string, limit = 10): ScoreTrend {
    const history = this.getScoreHistory(target, limit);

    if (history.length === 0) {
      return {
        currentScore: 100,
        previousScore: null,
        change: 0,
        direction: 'same',
        history: []
      };
    }

    const current = history[0];
    const previous = history.length > 1 ? history[1] : null;
    const change = previous ? current.score - previous.score : 0;

    let direction: 'up' | 'down' | 'same' = 'same';
    if (change > 0) direction = 'up';
    else if (change < 0) direction = 'down';

    return {
      currentScore: current.score,
      previousScore: previous?.score || null,
      change: Math.abs(change),
      direction,
      history: history.map(h => ({ timestamp: h.timestamp, score: h.score }))
    };
  }

  getAggregateScore(): SecurityScore & { trend: ScoreTrend } {
    // Get the latest score from score_history (most recent scan)
    const latest = this.getLatestScore();
    const trend = this.getScoreTrend(undefined, 10);

    if (latest) {
      const score = calculateSecurityScore({
        critical: latest.critical,
        high: latest.high,
        medium: latest.medium,
        low: latest.low
      });
      return { ...score, trend };
    }

    // No scores yet - return perfect score
    const score = calculateSecurityScore({ critical: 0, high: 0, medium: 0, low: 0 });
    return { ...score, trend };
  }

  // ============ API KEY METHODS ============

  private hashApiKey(key: string): string {
    return createHash('sha256').update(key).digest('hex');
  }

  /**
   * Create a new API key. Returns the plaintext key (only shown once).
   */
  createApiKey(
    name: string,
    scopes: string[] = ['read', 'write', 'scan'],
    expiresInDays?: number
  ): { id: string; key: string; name: string; scopes: string[]; expiresAt: string | null } {
    const id = `aura_key_${Date.now()}_${randomBytes(4).toString('hex')}`;
    const plainKey = `aura_${randomBytes(32).toString('hex')}`;
    const keyHash = this.hashApiKey(plainKey);
    const now = new Date().toISOString();
    const expiresAt = expiresInDays
      ? new Date(Date.now() + expiresInDays * 86400000).toISOString()
      : null;

    const stmt = this.db.prepare(`
      INSERT INTO api_keys (id, name, key_hash, scopes, created_at, expires_at, active)
      VALUES (?, ?, ?, ?, ?, ?, 1)
    `);
    stmt.run(id, name, keyHash, JSON.stringify(scopes), now, expiresAt);

    console.log(`[DB] Created API key "${name}" (${id})`);
    return { id, key: plainKey, name, scopes, expiresAt };
  }

  /**
   * Validate an API key. Returns the key record if valid, null otherwise.
   */
  validateApiKey(plainKey: string): ApiKeyRecord | null {
    const keyHash = this.hashApiKey(plainKey);
    const now = new Date().toISOString();

    const stmt = this.db.prepare(`
      SELECT id, name, key_hash, scopes, created_at, last_used_at, expires_at, active
      FROM api_keys
      WHERE key_hash = ? AND active = 1 AND (expires_at IS NULL OR expires_at > ?)
    `);
    const row = stmt.get(keyHash, now) as any;
    if (!row) return null;

    // Update last_used_at
    const update = this.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?');
    update.run(now, row.id);

    return {
      id: row.id,
      name: row.name,
      key_hash: row.key_hash,
      scopes: JSON.parse(row.scopes || '[]'),
      created_at: row.created_at,
      last_used_at: now,
      expires_at: row.expires_at,
      active: !!row.active,
    };
  }

  /**
   * List all API keys (without hashes).
   */
  listApiKeys(): Array<Omit<ApiKeyRecord, 'key_hash'>> {
    const stmt = this.db.prepare(`
      SELECT id, name, scopes, created_at, last_used_at, expires_at, active
      FROM api_keys ORDER BY created_at DESC
    `);
    const rows = stmt.all() as any[];
    return rows.map(row => ({
      id: row.id,
      name: row.name,
      scopes: JSON.parse(row.scopes || '[]'),
      created_at: row.created_at,
      last_used_at: row.last_used_at,
      expires_at: row.expires_at,
      active: !!row.active,
    }));
  }

  /**
   * Revoke an API key.
   */
  revokeApiKey(id: string): boolean {
    const stmt = this.db.prepare('UPDATE api_keys SET active = 0 WHERE id = ?');
    const result = stmt.run(id);
    if (result.changes > 0) {
      console.log(`[DB] Revoked API key ${id}`);
    }
    return result.changes > 0;
  }

  // ============ CLEANUP ============

  close(): void {
    this.db.close();
  }

  vacuum(): void {
    this.db.exec('VACUUM');
  }

  deleteOldAudits(daysToKeep = 90): number {
    const stmt = this.db.prepare(`
      DELETE FROM audits WHERE timestamp < DATE('now', '-' || ? || ' days')
    `);
    const result = stmt.run(daysToKeep);
    return result.changes;
  }
}

// Singleton instance
let dbInstance: AuditorDatabase | null = null;

export function getDatabase(dbPath?: string): AuditorDatabase {
  if (!dbInstance) {
    dbInstance = new AuditorDatabase(dbPath);
  }
  return dbInstance;
}

export function closeDatabase(): void {
  if (dbInstance) {
    dbInstance.close();
    dbInstance = null;
  }
}
