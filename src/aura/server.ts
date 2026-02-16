// Aura Server - Minimal implementation for auditor pipeline
// Exposes /tools, /memory, /info, /settings, /audits, /stats endpoints

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { timingSafeEqual } from 'crypto';
import { getDatabase, type AuditorDatabase } from '../database/index.js';
import { NotificationService, createNotificationFromAudit } from '../integrations/notifications.js';
import { generateScoreBadge } from '../scoring/index.js';

export interface AuraTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface AuraServerConfig {
  port: number;
  host?: string;
  dbPath?: string;
  authEnabled?: boolean;
  /** A master key that grants full access without DB lookup */
  masterKey?: string;
}

interface AuthResult {
  valid: boolean;
  status: number;
  message: string;
  keyName?: string;
  scopes?: string[];
}

export class AuraServer {
  private server: ReturnType<typeof createServer> | null = null;
  private tools = new Map<string, AuraTool>();
  private memory = new Map<string, unknown>();
  private config: Required<AuraServerConfig>;
  private db: AuditorDatabase;
  private notificationService: NotificationService;

  // Auth failure rate limiting — per IP
  private static readonly AUTH_MAX_FAILURES = 10;
  private static readonly AUTH_LOCKOUT_MS = 15 * 60 * 1000; // 15 minutes
  private authFailures = new Map<string, { count: number; lastAttempt: number }>();

  constructor(config: AuraServerConfig) {
    this.config = {
      port: config.port,
      host: config.host ?? '127.0.0.1',
      dbPath: config.dbPath ?? process.cwd(),
      authEnabled: config.authEnabled ?? false,
      masterKey: config.masterKey ?? '',
    };
    // Initialize database
    this.db = getDatabase(this.config.dbPath);
    // Initialize notification service
    this.notificationService = new NotificationService({}, this.config.dbPath);
    this.notificationService.loadFromDatabase();
  }

  getNotificationService(): NotificationService {
    return this.notificationService;
  }

  reloadNotifications(): void {
    this.notificationService.loadFromDatabase();
  }

  registerTool(tool: AuraTool): void {
    this.tools.set(tool.name, tool);
  }

  getTool(name: string): AuraTool | undefined {
    return this.tools.get(name);
  }

  getDatabase(): AuditorDatabase {
    return this.db;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;

    // CORS headers — restrict to known origins in production
    const allowedOrigins = [
      'https://app.aurasecurity.io',
      'https://aurasecurity.io',
      'http://127.0.0.1:8080',
      'http://localhost:8080',
    ];
    const origin = req.headers.origin;
    if (origin && allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
    } else if (!origin) {
      // Non-browser requests (curl, server-to-server) don't send Origin
      res.setHeader('Access-Control-Allow-Origin', 'https://app.aurasecurity.io');
    }
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    // Public endpoints that never require auth (scanning is the product)
    // POST /tools has per-tool auth enforcement inside handleCallTool
    const isPublic = path === '/health' || path === '/info' || path.startsWith('/badge/')
      || path === '/tools' || path.startsWith('/score');

    // Auth check (when enabled)
    let authScopes: string[] = [];
    if (this.config.authEnabled && !isPublic) {
      // Auth key management endpoints use master key only
      const isAuthEndpoint = path.startsWith('/auth/');

      const authResult = this.validateAuth(req, isAuthEndpoint);
      if (!authResult.valid) {
        res.statusCode = authResult.status;
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }
      authScopes = authResult.scopes || [];

      // Scope enforcement — determine required scope for this request
      const requiredScope = this.getRequiredScope(path, req.method || 'GET');
      if (requiredScope && !authScopes.includes('admin') && !authScopes.includes(requiredScope)) {
        res.statusCode = 403;
        res.end(JSON.stringify({ error: `Insufficient permissions. Required scope: ${requiredScope}` }));
        return;
      }
    }

    try {
      // Auth key management endpoints
      if (path === '/auth/keys' && req.method === 'POST') {
        await this.handleCreateApiKey(req, res);
      } else if (path === '/auth/keys' && req.method === 'GET') {
        await this.handleListApiKeys(res);
      } else if (path.startsWith('/auth/keys/') && req.method === 'DELETE') {
        const keyId = path.slice(11); // "/auth/keys/".length
        await this.handleRevokeApiKey(keyId, res);
      }
      // Core Aura endpoints
      else if (path === '/info' && req.method === 'GET') {
        await this.handleInfo(res);
      } else if (path === '/tools' && req.method === 'GET') {
        await this.handleListTools(req, res);
      } else if (path === '/tools' && req.method === 'POST') {
        await this.handleCallTool(req, res);
      } else if (path === '/memory' && req.method === 'POST') {
        await this.handleMemoryWrite(req, res);
      } else if (path === '/memory' && req.method === 'GET') {
        await this.handleMemoryRead(url, res);
      }
      // Settings endpoints
      else if (path === '/settings' && req.method === 'GET') {
        await this.handleGetSettings(url, res);
      } else if (path === '/settings' && req.method === 'POST') {
        await this.handleSaveSettings(req, res);
      }
      // Audit history endpoints
      else if (path === '/audits' && req.method === 'GET') {
        await this.handleGetAudits(url, res);
      } else if (path.startsWith('/audits/') && req.method === 'GET') {
        const id = path.slice(8);
        await this.handleGetAudit(id, res);
      } else if (path.startsWith('/audits/') && req.method === 'DELETE') {
        const id = path.slice(8);
        await this.handleDeleteAudit(id, res);
      }
      // Stats endpoint
      else if (path === '/stats' && req.method === 'GET') {
        await this.handleGetStats(res);
      }
      // Notifications endpoints
      else if (path === '/notifications' && req.method === 'GET') {
        await this.handleGetNotifications(url, res);
      } else if (path === '/notifications/test' && req.method === 'POST') {
        await this.handleTestNotification(req, res);
      } else if (path === '/notifications/send' && req.method === 'POST') {
        await this.handleSendNotification(req, res);
      }
      // Score endpoints
      else if (path === '/score' && req.method === 'GET') {
        await this.handleGetScore(url, res);
      } else if (path.match(/^\/score\/(.+)\/history$/) && req.method === 'GET') {
        const target = decodeURIComponent(path.slice(7, -8));
        await this.handleGetScoreHistory(target, url, res);
      } else if (path.match(/^\/score\/(.+)\/trend$/) && req.method === 'GET') {
        const target = decodeURIComponent(path.slice(7, -6));
        await this.handleGetScoreTrend(target, url, res);
      }
      // Badge endpoints
      else if (path === '/badge/score' && req.method === 'GET') {
        await this.handleGetBadge(res);
      } else if (path.startsWith('/badge/') && req.method === 'GET') {
        const target = decodeURIComponent(path.slice(7));
        await this.handleGetBadgeForTarget(target, res);
      }
      // Health check endpoint
      else if (path === '/health' && req.method === 'GET') {
        await this.handleHealthCheck(res);
      }
      else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Not found' }));
      }
    } catch (err) {
      console.error('[SERVER] Request error on', path);
      // Fail-closed: return 500 — never leak internal error details
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'Internal server error' }));
    }
  }

  private async handleInfo(res: ServerResponse): Promise<void> {
    res.statusCode = 200;
    res.end(JSON.stringify({
      name: 'aura-security',
      tools: Array.from(this.tools.keys()).filter(t => AuraServer.PUBLIC_TOOLS.has(t)),
    }));
  }

  private async handleListTools(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // Check if caller provided valid auth — but do NOT count failures
    // (this is a public endpoint, don't let it be weaponized for lockouts)
    let isAuthed = false;
    if (this.config.authEnabled && req.headers.authorization) {
      const token = req.headers.authorization.split(' ')[1];
      if (token && this.config.masterKey && this.safeCompare(token, this.config.masterKey)) {
        isAuthed = true;
      } else if (token) {
        const keyRecord = this.db.validateApiKey(token);
        if (keyRecord) isAuthed = true;
      }
    } else if (!this.config.authEnabled) {
      isAuthed = true;
    }
    const toolList = Array.from(this.tools.values())
      .filter(t => isAuthed || AuraServer.PUBLIC_TOOLS.has(t.name))
      .map(t => ({
        name: t.name,
        description: t.description,
        parameters: t.parameters
      }));

    res.statusCode = 200;
    res.end(JSON.stringify({ tools: toolList }));
  }

  // Tools that can be called without authentication (public scanning endpoints)
  private static readonly PUBLIC_TOOLS = new Set([
    'audit', 'trust-scan', 'scam-scan', 'scan-local', 'scan-aura',
    'ai-check', 'compare', 'x-scan', 'generate-report',
    'skill-scan', 'probe', 'full-probe',
  ]);

  private async handleCallTool(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);

    let parsed: any;
    try {
      parsed = JSON.parse(body);
    } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }

    // Reject deeply nested payloads (DoS prevention)
    if (body.length > 0 && AuraServer.jsonDepth(body) > 20) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Request too deeply nested' }));
      return;
    }

    const { tool, arguments: args } = parsed;

    // Sanitize tool name — alphanumeric, hyphens, underscores only
    const sanitizedTool = typeof tool === 'string' ? tool.replace(/[^a-zA-Z0-9_-]/g, '') : '';
    const toolDef = this.tools.get(sanitizedTool);
    if (!toolDef) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Tool not found' }));
      return;
    }

    // Per-tool auth: non-public tools require authentication
    if (this.config.authEnabled && !AuraServer.PUBLIC_TOOLS.has(sanitizedTool)) {
      const authResult = this.validateAuth(req);
      if (!authResult.valid) {
        res.statusCode = authResult.status;
        res.end(JSON.stringify({ error: authResult.message }));
        return;
      }
    }

    try {
      const result = await toolDef.handler(args ?? {});
      res.statusCode = 200;
      res.end(JSON.stringify({ result }));
    } catch (err) {
      console.error(`[AURA] Tool "${sanitizedTool}" error:`, err);
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'Tool execution failed' }));
    }
  }

  /** Estimate JSON nesting depth without full parse (DoS prevention) */
  private static jsonDepth(s: string): number {
    let max = 0, depth = 0;
    for (let i = 0; i < s.length; i++) {
      const c = s[i];
      if (c === '{' || c === '[') { depth++; if (depth > max) max = depth; }
      else if (c === '}' || c === ']') { depth--; }
    }
    return max;
  }

  private async handleMemoryWrite(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;
    try { parsed = JSON.parse(body); } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const { key, value, metadata } = parsed;

    this.memory.set(key, { value, metadata, timestamp: new Date().toISOString() });

    res.statusCode = 201;
    res.end(JSON.stringify({ status: 'stored', key }));
  }

  private async handleMemoryRead(url: URL, res: ServerResponse): Promise<void> {
    const key = url.searchParams.get('key');

    if (key) {
      const entry = this.memory.get(key);
      if (entry) {
        res.statusCode = 200;
        res.end(JSON.stringify(entry));
      } else {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Key not found' }));
      }
    } else {
      res.statusCode = 200;
      res.end(JSON.stringify({ keys: Array.from(this.memory.keys()) }));
    }
  }

  // ============ SETTINGS ENDPOINTS ============

  private async handleGetSettings(url: URL, res: ServerResponse): Promise<void> {
    const prefix = url.searchParams.get('prefix');

    let settings: Record<string, string>;
    if (prefix) {
      settings = this.db.getSettings(prefix);
    } else {
      settings = this.db.getAllSettings();
    }

    res.statusCode = 200;
    res.end(JSON.stringify({ settings }));
  }

  private async handleSaveSettings(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;
    try { parsed = JSON.parse(body); } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const { settings } = parsed;

    if (!settings || typeof settings !== 'object') {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid settings object' }));
      return;
    }

    this.db.setSettings(settings);

    res.statusCode = 200;
    res.end(JSON.stringify({ status: 'saved', count: Object.keys(settings).length }));
  }

  // ============ AUDIT HISTORY ENDPOINTS ============

  private async handleGetAudits(url: URL, res: ServerResponse): Promise<void> {
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);
    const offset = parseInt(url.searchParams.get('offset') || '0', 10);
    const type = url.searchParams.get('type') || undefined;

    const audits = this.db.getAudits(limit, offset, type);
    const total = this.db.getAuditCount(type);

    // Return without full data for list view (lighter response)
    const auditList = audits.map(a => ({
      id: a.id,
      type: a.type,
      timestamp: a.timestamp,
      target: a.target,
      summary: a.summary
    }));

    res.statusCode = 200;
    res.end(JSON.stringify({ audits: auditList, total, limit, offset }));
  }

  private async handleGetAudit(id: string, res: ServerResponse): Promise<void> {
    const audit = this.db.getAudit(id);

    if (!audit) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Audit not found' }));
      return;
    }

    // Parse the stored JSON data
    let data;
    try {
      data = JSON.parse(audit.data);
    } catch {
      data = audit.data;
    }

    res.statusCode = 200;
    res.end(JSON.stringify({
      id: audit.id,
      type: audit.type,
      timestamp: audit.timestamp,
      target: audit.target,
      summary: audit.summary,
      data
    }));
  }

  private async handleDeleteAudit(id: string, res: ServerResponse): Promise<void> {
    const deleted = this.db.deleteAudit(id);

    if (!deleted) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'Audit not found' }));
      return;
    }

    res.statusCode = 200;
    res.end(JSON.stringify({ status: 'deleted', id }));
  }

  // ============ STATS ENDPOINT ============

  private async handleGetStats(res: ServerResponse): Promise<void> {
    const stats = this.db.getStats();

    res.statusCode = 200;
    res.end(JSON.stringify(stats));
  }

  // ============ NOTIFICATIONS ENDPOINT ============

  private async handleGetNotifications(url: URL, res: ServerResponse): Promise<void> {
    const auditId = url.searchParams.get('audit_id') || undefined;
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);

    const notifications = this.db.getNotifications(auditId, limit);

    res.statusCode = 200;
    res.end(JSON.stringify({ notifications }));
  }

  private async handleTestNotification(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;
    try { parsed = JSON.parse(body); } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const { channel } = parsed;

    if (!channel || !['slack', 'discord', 'webhook'].includes(channel)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid channel. Must be: slack, discord, or webhook' }));
      return;
    }

    // Reload settings before testing
    this.notificationService.loadFromDatabase();

    const result = await this.notificationService.testChannel(channel as 'slack' | 'discord' | 'webhook');

    res.statusCode = result.success ? 200 : 400;
    res.end(JSON.stringify(result));
  }

  private async handleSendNotification(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    let parsed: any;
    try { parsed = JSON.parse(body); } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const { auditId, title, message, severity } = parsed;

    // If auditId provided, create notification from audit data
    let payload;
    if (auditId) {
      const audit = this.db.getAudit(auditId);
      if (!audit) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'Audit not found' }));
        return;
      }
      payload = createNotificationFromAudit(
        audit.id,
        audit.type,
        audit.target,
        audit.summary
      );
    } else {
      // Manual notification
      payload = {
        title: title || 'Manual Notification',
        message: message || 'Test notification from Aura Auditor',
        severity: severity || 'low'
      };
    }

    // Reload settings and send
    this.notificationService.loadFromDatabase();
    const result = await this.notificationService.notify(payload);

    res.statusCode = 200;
    res.end(JSON.stringify(result));
  }

  // ============ SCORE ENDPOINTS ============

  private async handleGetScore(url: URL, res: ServerResponse): Promise<void> {
    const target = url.searchParams.get('target') || undefined;

    if (target) {
      // Get score for specific target
      const latest = this.db.getLatestScore(target);
      const trend = this.db.getScoreTrend(target, 10);

      if (!latest) {
        res.statusCode = 404;
        res.end(JSON.stringify({ error: 'No score history for target' }));
        return;
      }

      res.statusCode = 200;
      res.end(JSON.stringify({
        score: latest.score,
        grade: latest.grade,
        target: latest.target,
        breakdown: {
          critical: latest.critical,
          high: latest.high,
          medium: latest.medium,
          low: latest.low
        },
        trend,
        lastUpdated: latest.timestamp
      }));
    } else {
      // Get aggregate score
      const aggregate = this.db.getAggregateScore();

      res.statusCode = 200;
      res.end(JSON.stringify({
        score: aggregate.score,
        grade: aggregate.grade,
        gradeColor: aggregate.gradeColor,
        breakdown: aggregate.breakdown,
        trend: aggregate.trend,
        lastUpdated: new Date().toISOString()
      }));
    }
  }

  private async handleGetScoreHistory(target: string, url: URL, res: ServerResponse): Promise<void> {
    const limit = parseInt(url.searchParams.get('limit') || '50', 10);

    const history = this.db.getScoreHistory(target, limit);

    res.statusCode = 200;
    res.end(JSON.stringify({ target, history }));
  }

  private async handleGetScoreTrend(target: string, url: URL, res: ServerResponse): Promise<void> {
    const limit = parseInt(url.searchParams.get('limit') || '10', 10);

    const trend = this.db.getScoreTrend(target, limit);

    res.statusCode = 200;
    res.end(JSON.stringify({ target, ...trend }));
  }

  // ============ BADGE ENDPOINTS ============

  private async handleGetBadge(res: ServerResponse): Promise<void> {
    const aggregate = this.db.getAggregateScore();
    const svg = generateScoreBadge(aggregate.score, aggregate.grade, aggregate.gradeColor);

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.statusCode = 200;
    res.end(svg);
  }

  private async handleGetBadgeForTarget(target: string, res: ServerResponse): Promise<void> {
    const latest = this.db.getLatestScore(target);

    if (!latest) {
      // Return a "no data" badge
      const svg = generateScoreBadge(0, '?', '#6e7681');
      res.setHeader('Content-Type', 'image/svg+xml');
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
      res.statusCode = 200;
      res.end(svg);
      return;
    }

    // Get grade color based on score
    let gradeColor = '#f85149'; // F - red
    if (latest.score >= 90) gradeColor = '#3fb950'; // A - green
    else if (latest.score >= 70) gradeColor = '#58a6ff'; // B - blue
    else if (latest.score >= 50) gradeColor = '#d29922'; // C - yellow

    const svg = generateScoreBadge(latest.score, latest.grade, gradeColor);

    res.setHeader('Content-Type', 'image/svg+xml');
    res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate');
    res.statusCode = 200;
    res.end(svg);
  }

  private async handleHealthCheck(res: ServerResponse): Promise<void> {
    // Public health check — only expose status, no internal details
    const health: Record<string, any> = {
      status: 'healthy',
    };

    // Check GitHub API reachability (internal only — don't expose details)
    try {
      const ghRes = await fetch('https://api.github.com/rate_limit', {
        headers: process.env.GITHUB_TOKEN
          ? { 'Authorization': `token ${process.env.GITHUB_TOKEN}`, 'User-Agent': 'AuraSecurity' }
          : { 'User-Agent': 'AuraSecurity' },
        signal: AbortSignal.timeout(5000),
      });
      if (!ghRes.ok) {
        health.status = 'degraded';
      }
    } catch {
      health.status = 'degraded';
    }

    // Database check (internal only — don't expose details)
    try {
      const db = this.db;
      db.getStats();
    } catch {
      health.status = 'degraded';
    }

    res.statusCode = health.status === 'healthy' ? 200 : 503;
    res.end(JSON.stringify(health));
  }

  // ============ AUTH METHODS ============

  private getRequiredScope(path: string, method: string): string | null {
    // Auth endpoints require admin (already enforced via requireMaster)
    if (path.startsWith('/auth/')) return 'admin';
    // Settings write requires admin
    if (path === '/settings' && method === 'POST') return 'admin';
    // Delete operations require admin
    if (method === 'DELETE') return 'admin';
    // POST /tools = running scans
    if (path === '/tools' && method === 'POST') return 'scan';
    // Write operations
    if (path === '/memory' && method === 'POST') return 'write';
    if (path.startsWith('/notifications') && method === 'POST') return 'write';
    // Read operations
    if (method === 'GET') return 'read';
    return null;
  }

  private validateAuth(req: IncomingMessage, requireMaster = false): AuthResult {
    // Rate limit auth failures per IP
    const ip = (req.headers['x-real-ip'] as string) || req.socket.remoteAddress || 'unknown';
    const failure = this.authFailures.get(ip);
    if (failure && failure.count >= AuraServer.AUTH_MAX_FAILURES) {
      if (Date.now() - failure.lastAttempt < AuraServer.AUTH_LOCKOUT_MS) {
        return { valid: false, status: 429, message: 'Too many failed attempts. Try again later.' };
      }
      this.authFailures.delete(ip); // lockout expired
    }

    const authHeader = req.headers.authorization;

    if (!authHeader) {
      this.recordAuthFailure(ip);
      return { valid: false, status: 401, message: 'Authorization required' };
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0].toLowerCase() !== 'bearer') {
      this.recordAuthFailure(ip);
      return { valid: false, status: 401, message: 'Invalid authorization format' };
    }

    const token = parts[1];

    // Check master key first (constant-time comparison to prevent timing attacks)
    if (this.config.masterKey && this.safeCompare(token, this.config.masterKey)) {
      this.authFailures.delete(ip); // reset on success
      return { valid: true, status: 200, message: 'OK', keyName: 'master', scopes: ['admin', 'read', 'write', 'scan'] };
    }

    // Auth management endpoints require master key
    if (requireMaster) {
      this.recordAuthFailure(ip);
      return { valid: false, status: 403, message: 'Master key required for auth management' };
    }

    // Validate against database
    const keyRecord = this.db.validateApiKey(token);
    if (!keyRecord) {
      this.recordAuthFailure(ip);
      return { valid: false, status: 401, message: 'Invalid or expired API key' };
    }

    this.authFailures.delete(ip); // reset on success
    return {
      valid: true,
      status: 200,
      message: 'OK',
      keyName: keyRecord.name,
      scopes: keyRecord.scopes,
    };
  }

  private recordAuthFailure(ip: string): void {
    const existing = this.authFailures.get(ip);
    this.authFailures.set(ip, {
      count: (existing?.count ?? 0) + 1,
      lastAttempt: Date.now(),
    });
  }

  private safeCompare(a: string, b: string): boolean {
    const bufA = Buffer.from(a);
    const bufB = Buffer.from(b);
    if (bufA.length !== bufB.length) {
      // Still do a comparison to avoid leaking length info via timing
      timingSafeEqual(bufA, bufA);
      return false;
    }
    return timingSafeEqual(bufA, bufB);
  }

  private async handleCreateApiKey(req: IncomingMessage, res: ServerResponse): Promise<void> {
    let body: any;
    try { body = JSON.parse(await this.readBody(req)); } catch {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid JSON' }));
      return;
    }
    const name = body.name;
    if (!name || typeof name !== 'string') {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'name is required' }));
      return;
    }
    // Validate key name: alphanumeric, hyphens, underscores only, max 64 chars
    if (!/^[a-zA-Z0-9_-]{1,64}$/.test(name)) {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'Invalid key name. Use only letters, numbers, hyphens, and underscores (max 64 chars).' }));
      return;
    }
    const scopes = Array.isArray(body.scopes) ? body.scopes : ['read', 'write', 'scan'];
    const expiresInDays = typeof body.expiresInDays === 'number' ? body.expiresInDays : undefined;

    const result = this.db.createApiKey(name, scopes, expiresInDays);
    res.statusCode = 201;
    res.end(JSON.stringify({
      message: 'API key created. Save the key — it cannot be retrieved again.',
      ...result,
    }));
  }

  private async handleListApiKeys(res: ServerResponse): Promise<void> {
    const keys = this.db.listApiKeys();
    res.statusCode = 200;
    res.end(JSON.stringify({ keys }));
  }

  private async handleRevokeApiKey(keyId: string, res: ServerResponse): Promise<void> {
    const revoked = this.db.revokeApiKey(keyId);
    if (!revoked) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: 'API key not found' }));
      return;
    }
    res.statusCode = 200;
    res.end(JSON.stringify({ message: 'API key revoked', id: keyId }));
  }

  private static readonly MAX_BODY_SIZE = 100 * 1024; // 100 KB

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      let totalSize = 0;
      req.on('data', (chunk: Buffer) => {
        totalSize += chunk.length;
        if (totalSize > AuraServer.MAX_BODY_SIZE) {
          req.destroy();
          reject(new Error('BODY_TOO_LARGE'));
          return;
        }
        chunks.push(chunk);
      });
      req.on('end', () => resolve(Buffer.concat(chunks).toString()));
      req.on('error', reject);
    });
  }

  async start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.server = createServer((req, res) => {
        this.handleRequest(req, res).catch(() => {
          res.statusCode = 500;
          res.end(JSON.stringify({ error: 'Internal error', blocked: true }));
        });
      });

      this.server.on('error', reject);
      this.server.listen(this.config.port, this.config.host, () => {
        resolve();
      });
    });
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.server) {
        this.server.close(() => resolve());
      } else {
        resolve();
      }
    });
  }

  getMemorySnapshot(): Map<string, unknown> {
    return new Map(this.memory);
  }
}
