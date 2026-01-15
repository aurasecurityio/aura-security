// Webhook Server - Receive events from external systems
// Supports GitHub, GitLab, Jenkins, and custom webhooks

import { createServer, IncomingMessage, ServerResponse } from 'http';
import { createHmac } from 'crypto';
import type { AuditorInput, ChangeEvent } from '../types/events.js';

export interface WebhookConfig {
  port: number;
  secret?: string;  // For webhook signature verification
  allowedSources?: string[];  // IP whitelist
}

export interface WebhookEvent {
  source: 'github' | 'gitlab' | 'jenkins' | 'custom';
  type: string;
  payload: Record<string, unknown>;
  timestamp: string;
  signature?: string;
}

export type WebhookHandler = (event: WebhookEvent) => Promise<AuditorInput | null>;

export class WebhookServer {
  private server: ReturnType<typeof createServer> | null = null;
  private config: WebhookConfig;
  private handlers: Map<string, WebhookHandler> = new Map();
  private onAuditRequest: ((input: AuditorInput) => Promise<void>) | null = null;

  constructor(config: WebhookConfig) {
    this.config = config;
  }

  // Register handler for specific event types
  registerHandler(eventType: string, handler: WebhookHandler): void {
    this.handlers.set(eventType, handler);
  }

  // Set callback for when audit should be triggered
  onAudit(callback: (input: AuditorInput) => Promise<void>): void {
    this.onAuditRequest = callback;
  }

  private async handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
    // CORS
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Hub-Signature-256, X-GitLab-Token');
    res.setHeader('Content-Type', 'application/json');

    if (req.method === 'OPTIONS') {
      res.statusCode = 204;
      res.end();
      return;
    }

    if (req.method !== 'POST') {
      res.statusCode = 405;
      res.end(JSON.stringify({ error: 'Method not allowed' }));
      return;
    }

    const url = new URL(req.url ?? '/', `http://${req.headers.host}`);
    const path = url.pathname;

    try {
      const body = await this.readBody(req);
      const payload = JSON.parse(body);

      // Detect source and verify signature
      const source = this.detectSource(req, path);
      const signature = this.getSignature(req);

      if (this.config.secret && !this.verifySignature(body, signature, source)) {
        res.statusCode = 401;
        res.end(JSON.stringify({ error: 'Invalid signature' }));
        return;
      }

      // Create webhook event
      const event: WebhookEvent = {
        source,
        type: this.getEventType(req, source, payload),
        payload,
        timestamp: new Date().toISOString(),
        signature
      };

      console.log(`[Webhook] Received ${event.source}:${event.type}`);

      // Find handler
      const handler = this.handlers.get(`${event.source}:${event.type}`) ||
                      this.handlers.get(event.source) ||
                      this.handlers.get('*');

      if (handler) {
        const auditInput = await handler(event);

        if (auditInput && this.onAuditRequest) {
          await this.onAuditRequest(auditInput);
          res.statusCode = 200;
          res.end(JSON.stringify({ status: 'audit_triggered', event_id: auditInput.change_event.id }));
          return;
        }
      }

      res.statusCode = 200;
      res.end(JSON.stringify({ status: 'received', processed: !!handler }));

    } catch (err) {
      console.error('[Webhook] Error:', err);
      res.statusCode = 500;
      res.end(JSON.stringify({ error: 'Internal error' }));
    }
  }

  private detectSource(req: IncomingMessage, path: string): WebhookEvent['source'] {
    if (req.headers['x-github-event'] || path.includes('github')) return 'github';
    if (req.headers['x-gitlab-event'] || path.includes('gitlab')) return 'gitlab';
    if (req.headers['x-jenkins-event'] || path.includes('jenkins')) return 'jenkins';
    return 'custom';
  }

  private getSignature(req: IncomingMessage): string | undefined {
    return (req.headers['x-hub-signature-256'] as string) ||
           (req.headers['x-gitlab-token'] as string) ||
           (req.headers['x-signature'] as string);
  }

  private getEventType(req: IncomingMessage, source: string, payload: Record<string, unknown>): string {
    if (source === 'github') {
      return req.headers['x-github-event'] as string || 'unknown';
    }
    if (source === 'gitlab') {
      return (payload.object_kind as string) || req.headers['x-gitlab-event'] as string || 'unknown';
    }
    if (source === 'jenkins') {
      const build = payload.build as Record<string, unknown> | undefined;
      return (build?.phase as string) || 'build';
    }
    return (payload.type as string) || 'unknown';
  }

  private verifySignature(body: string, signature: string | undefined, source: string): boolean {
    if (!signature || !this.config.secret) return false;

    if (source === 'github') {
      const expected = 'sha256=' + createHmac('sha256', this.config.secret).update(body).digest('hex');
      return signature === expected;
    }

    if (source === 'gitlab') {
      return signature === this.config.secret;
    }

    // Generic HMAC verification
    const expected = createHmac('sha256', this.config.secret).update(body).digest('hex');
    return signature === expected;
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
          res.end(JSON.stringify({ error: 'Internal error' }));
        });
      });

      this.server.on('error', reject);
      this.server.listen(this.config.port, '0.0.0.0', () => {
        console.log(`[Webhook] Server listening on port ${this.config.port}`);
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
}

// Default handlers for common webhook types
export const defaultHandlers = {
  // GitHub Pull Request
  'github:pull_request': async (event: WebhookEvent): Promise<AuditorInput | null> => {
    const pr = event.payload.pull_request as Record<string, unknown>;
    const repo = event.payload.repository as Record<string, unknown>;
    const action = event.payload.action as string;

    if (!['opened', 'synchronize', 'reopened'].includes(action)) {
      return null;
    }

    return {
      change_event: {
        id: `github-pr-${pr.number}`,
        type: 'pull_request',
        environment: (pr.base as Record<string, unknown>)?.ref === 'main' ? 'prod' : 'staging',
        repo: repo.full_name as string,
        commit: (pr.head as Record<string, unknown>)?.sha as string,
        files_changed: [], // Would need separate API call
        diff: '' // Would need separate API call
      },
      evidence_bundle: {},
      policy_context: {
        critical_assets: ['auth', 'billing', 'database', 'secrets'],
        risk_tolerance: 'medium'
      }
    };
  },

  // GitHub Push
  'github:push': async (event: WebhookEvent): Promise<AuditorInput | null> => {
    const repo = event.payload.repository as Record<string, unknown>;
    const commits = event.payload.commits as Array<Record<string, unknown>> || [];
    const ref = event.payload.ref as string;

    const isProd = ref === 'refs/heads/main' || ref === 'refs/heads/master';

    return {
      change_event: {
        id: `github-push-${event.payload.after}`,
        type: isProd ? 'deploy' : 'pull_request',
        environment: isProd ? 'prod' : 'dev',
        repo: repo.full_name as string,
        commit: event.payload.after as string,
        files_changed: commits.flatMap(c => [
          ...(c.added as string[] || []),
          ...(c.modified as string[] || [])
        ]),
        diff: commits.map(c => c.message).join('\n')
      },
      evidence_bundle: {},
      policy_context: {
        critical_assets: ['auth', 'billing', 'database', 'secrets'],
        risk_tolerance: isProd ? 'low' : 'medium'
      }
    };
  },

  // GitLab Merge Request
  'gitlab:merge_request': async (event: WebhookEvent): Promise<AuditorInput | null> => {
    const mr = event.payload.object_attributes as Record<string, unknown>;
    const project = event.payload.project as Record<string, unknown>;

    if (!['open', 'reopen', 'update'].includes(mr.action as string)) {
      return null;
    }

    return {
      change_event: {
        id: `gitlab-mr-${mr.iid}`,
        type: 'pull_request',
        environment: mr.target_branch === 'main' ? 'prod' : 'staging',
        repo: project.path_with_namespace as string,
        commit: mr.last_commit as string,
        files_changed: [],
        diff: ''
      },
      evidence_bundle: {},
      policy_context: {
        critical_assets: ['auth', 'billing', 'database', 'secrets'],
        risk_tolerance: 'medium'
      }
    };
  },

  // Jenkins Build
  'jenkins:build': async (event: WebhookEvent): Promise<AuditorInput | null> => {
    const build = event.payload.build as Record<string, unknown> || {};
    const params = (build.parameters as Record<string, unknown>) || {};
    const envVal = params.ENVIRONMENT as string;
    const environment = (envVal === 'prod' || envVal === 'staging' || envVal === 'dev') ? envVal : 'staging';

    return {
      change_event: {
        id: `jenkins-${build.number || Date.now()}`,
        type: 'deploy',
        environment,
        repo: event.payload.name as string || 'unknown',
        commit: ((build.scm as Record<string, unknown>)?.commit as string) || '',
        files_changed: [],
        diff: ''
      },
      evidence_bundle: {},
      policy_context: {
        critical_assets: ['auth', 'billing', 'database', 'secrets'],
        risk_tolerance: 'medium'
      }
    };
  }
};
