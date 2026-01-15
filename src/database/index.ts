/**
 * SQLite Database for SLOP Auditor
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
import type { AuditorOutput } from '../types/events.js';
import type { LocalScanResult } from '../integrations/local-scanner.js';
import type { AWSScanResult } from '../integrations/aws-scanner.js';

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
    // Default to .slop-auditor directory in user home
    const dataDir = dbPath
      ? join(dbPath, '.slop-auditor')
      : join(process.env.HOME || process.env.USERPROFILE || '.', '.slop-auditor');

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

    // Create indexes
    this.db.exec(`
      CREATE INDEX IF NOT EXISTS idx_audits_timestamp ON audits(timestamp DESC);
      CREATE INDEX IF NOT EXISTS idx_audits_type ON audits(type);
      CREATE INDEX IF NOT EXISTS idx_notifications_audit ON notifications(audit_id);
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
