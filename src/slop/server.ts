// SLOP Server - Minimal implementation for auditor pipeline
// Exposes /tools, /memory, /info, /settings, /audits, /stats endpoints

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { getDatabase, type AuditorDatabase } from '../database/index.js';
import { NotificationService, createNotificationFromAudit } from '../integrations/notifications.js';

export interface SlopTool {
  name: string;
  description: string;
  parameters: Record<string, unknown>;
  handler: (args: Record<string, unknown>) => Promise<unknown>;
}

export interface SlopServerConfig {
  port: number;
  host?: string;
  dbPath?: string;
}

export class SlopServer {
  private server: ReturnType<typeof createServer> | null = null;
  private tools = new Map<string, SlopTool>();
  private memory = new Map<string, unknown>();
  private config: Required<SlopServerConfig>;
  private db: AuditorDatabase;
  private notificationService: NotificationService;

  constructor(config: SlopServerConfig) {
    this.config = {
      port: config.port,
      host: config.host ?? '127.0.0.1',
      dbPath: config.dbPath ?? process.cwd()
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

  registerTool(tool: SlopTool): void {
    this.tools.set(tool.name, tool);
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
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
    res.setHeader('Content-Type', 'application/json');

    // Handle preflight
    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    try {
      // Core SLOP endpoints
      if (path === '/info' && req.method === 'GET') {
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
      name: 'slop-auditor',
      version: '0.2.0',
      endpoints: ['/info', '/tools', '/memory', '/settings', '/audits', '/stats', '/notifications'],
      tools: Array.from(this.tools.keys()),
      database: true
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
        message: message || 'Test notification from SLOP Auditor',
        severity: severity || 'low'
      };
    }

    // Reload settings and send
    this.notificationService.loadFromDatabase();
    const result = await this.notificationService.notify(payload);

    res.statusCode = 200;
    res.end(JSON.stringify(result));
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
