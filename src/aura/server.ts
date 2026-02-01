// Aura Server - Minimal implementation for auditor pipeline
// Exposes /tools, /memory, /info, /settings, /audits, /stats endpoints

import { createServer, IncomingMessage, ServerResponse } from 'http';
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

    // CORS headers for visualizer access
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    // Public endpoints that never require auth
    const isPublic = path === '/health' || path === '/info' || path.startsWith('/badge/');

    // Auth check (when enabled)
    if (this.config.authEnabled && !isPublic) {
      // Auth key management endpoints use master key only
      const isAuthEndpoint = path.startsWith('/auth/');

      const authResult = this.validateAuth(req, isAuthEndpoint);
      if (!authResult.valid) {
        res.statusCode = authResult.status;
        res.end(JSON.stringify({ error: authResult.message }));
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
        await this.handleListTools(res);
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
      console.error('[SERVER] Error:', err);
      // Fail-closed: return 500 on any error
      res.statusCode = 500;
      res.end(JSON.stringify({
        error: 'Internal server error',
        message: err instanceof Error ? err.message : 'Unknown error',
        blocked: true
      }));
    }
  }

  private async handleInfo(res: ServerResponse): Promise<void> {
    res.statusCode = 200;
    res.end(JSON.stringify({
      name: 'aura-security',
      version: '0.6.0',
      endpoints: ['/info', '/tools', '/memory', '/settings', '/audits', '/stats', '/notifications', '/score', '/badge', '/auth/keys'],
      tools: Array.from(this.tools.keys()),
      database: true,
      auth: this.config.authEnabled ? 'enabled' : 'disabled'
    }));
  }

  private async handleListTools(res: ServerResponse): Promise<void> {
    const toolList = Array.from(this.tools.values()).map(t => ({
      name: t.name,
      description: t.description,
      parameters: t.parameters
    }));

    res.statusCode = 200;
    res.end(JSON.stringify({ tools: toolList }));
  }

  private async handleCallTool(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const { tool, arguments: args } = JSON.parse(body);

    const toolDef = this.tools.get(tool);
    if (!toolDef) {
      res.statusCode = 404;
      res.end(JSON.stringify({ error: `Tool not found: ${tool}` }));
      return;
    }

    const result = await toolDef.handler(args ?? {});
    res.statusCode = 200;
    res.end(JSON.stringify({ result }));
  }

  private async handleMemoryWrite(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = await this.readBody(req);
    const { key, value, metadata } = JSON.parse(body);

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
    const { settings } = JSON.parse(body);

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
    const { channel } = JSON.parse(body);

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
    const { auditId, title, message, severity } = JSON.parse(body);

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
    const health: Record<string, any> = {
      status: 'healthy',
      uptime: process.uptime(),
      timestamp: new Date().toISOString(),
      memory_mb: Math.round(process.memoryUsage().rss / 1024 / 1024),
      env: {
        github_token: !!process.env.GITHUB_TOKEN,
        x_bearer_token: !!process.env.X_BEARER_TOKEN,
      },
    };

    // Check GitHub API reachability
    try {
      const ghRes = await fetch('https://api.github.com/rate_limit', {
        headers: process.env.GITHUB_TOKEN
          ? { 'Authorization': `token ${process.env.GITHUB_TOKEN}`, 'User-Agent': 'AuraSecurity' }
          : { 'User-Agent': 'AuraSecurity' },
        signal: AbortSignal.timeout(5000),
      });
      const ghData = await ghRes.json() as any;
      health.github_api = {
        status: 'ok',
        rate_remaining: ghData?.rate?.remaining ?? 'unknown',
        rate_limit: ghData?.rate?.limit ?? 'unknown',
      };
    } catch {
      health.github_api = { status: 'unreachable' };
      health.status = 'degraded';
    }

    // Check disk space (basic — check /tmp since that's where scans go)
    try {
      const { spawnSync } = await import('child_process');
      const df = spawnSync('df', ['-m', '/tmp'], { encoding: 'utf-8', timeout: 3000 });
      if (df.stdout) {
        const lines = df.stdout.trim().split('\n');
        if (lines.length > 1) {
          const parts = lines[1].split(/\s+/);
          health.disk_tmp_available_mb = parseInt(parts[3]) || 'unknown';
        }
      }
    } catch { /* ignore */ }

    // Database check
    try {
      const db = this.db;
      const stats = db.getStats();
      health.database = { status: 'ok', total_audits: stats.totalAudits ?? 0 };
    } catch {
      health.database = { status: 'error' };
      health.status = 'degraded';
    }

    res.statusCode = health.status === 'healthy' ? 200 : 503;
    res.end(JSON.stringify(health));
  }

  // ============ AUTH METHODS ============

  private validateAuth(req: IncomingMessage, requireMaster = false): AuthResult {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
      return { valid: false, status: 401, message: 'Authorization header required. Use: Bearer <api-key>' };
    }

    const parts = authHeader.split(' ');
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      return { valid: false, status: 401, message: 'Invalid authorization format. Use: Bearer <api-key>' };
    }

    const token = parts[1];

    // Check master key first
    if (this.config.masterKey && token === this.config.masterKey) {
      return { valid: true, status: 200, message: 'OK', keyName: 'master', scopes: ['admin', 'read', 'write', 'scan'] };
    }

    // Auth management endpoints require master key
    if (requireMaster) {
      return { valid: false, status: 403, message: 'Master key required for auth management' };
    }

    // Validate against database
    const keyRecord = this.db.validateApiKey(token);
    if (!keyRecord) {
      return { valid: false, status: 401, message: 'Invalid or expired API key' };
    }

    return {
      valid: true,
      status: 200,
      message: 'OK',
      keyName: keyRecord.name,
      scopes: keyRecord.scopes,
    };
  }

  private async handleCreateApiKey(req: IncomingMessage, res: ServerResponse): Promise<void> {
    const body = JSON.parse(await this.readBody(req));
    const name = body.name;
    if (!name || typeof name !== 'string') {
      res.statusCode = 400;
      res.end(JSON.stringify({ error: 'name is required' }));
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

  private readBody(req: IncomingMessage): Promise<string> {
    return new Promise((resolve, reject) => {
      const chunks: Buffer[] = [];
      req.on('data', chunk => chunks.push(chunk));
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
