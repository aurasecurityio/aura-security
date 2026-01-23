/**
 * SLOP Agent Base Class
 *
 * Base class for all SLOP-native agents.
 * Each agent runs as a standalone HTTP server with /info, /tools, /memory endpoints.
 */

import { createServer, IncomingMessage, ServerResponse } from 'http';
import {
  SLOPAgentConfig,
  SLOPInfo,
  SLOPTool,
  SLOPToolCall,
  SLOPToolResult,
  SLOPMemoryEntry,
  AgentMessage,
} from './types.js';

export abstract class SLOPAgent {
  protected server: ReturnType<typeof createServer> | null = null;
  protected memory: Map<string, SLOPMemoryEntry> = new Map();
  protected messageLog: AgentMessage[] = [];
  protected isRunning = false;

  constructor(
    protected config: SLOPAgentConfig,
    protected tools: SLOPTool[]
  ) {}

  /**
   * Get agent info (SLOP /info endpoint)
   */
  getInfo(): SLOPInfo {
    return {
      name: this.config.name,
      version: '1.0.0',
      description: this.config.description,
      tools: this.tools,
      capabilities: ['slop-v1', 'agent-communication'],
      status: this.isRunning ? 'ready' : 'error',
    };
  }

  /**
   * Handle tool call (SLOP /tools endpoint)
   */
  abstract handleToolCall(call: SLOPToolCall): Promise<SLOPToolResult>;

  /**
   * Call another agent's tool via SLOP
   */
  async callAgent(
    agentUrl: string,
    tool: string,
    args: Record<string, unknown>
  ): Promise<unknown> {
    const message: AgentMessage = {
      id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
      from: this.config.id,
      to: agentUrl,
      type: 'request',
      tool,
      arguments: args,
      timestamp: Date.now(),
    };
    this.messageLog.push(message);

    console.log(`[${this.config.name}] Calling ${agentUrl}/tools: ${tool}`);

    try {
      const response = await fetch(`${agentUrl}/tools`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ tool, arguments: args }),
      });

      const result = await response.json();

      const responseMessage: AgentMessage = {
        id: `msg-${Date.now()}-${Math.random().toString(36).slice(2, 9)}`,
        from: agentUrl,
        to: this.config.id,
        type: 'response',
        tool,
        result: result.result,
        error: result.error,
        timestamp: Date.now(),
      };
      this.messageLog.push(responseMessage);

      if (result.error) {
        throw new Error(result.error);
      }

      return result.result;
    } catch (error) {
      console.error(`[${this.config.name}] Error calling ${agentUrl}:`, error);
      throw error;
    }
  }

  /**
   * Write to shared memory (via coordinator or local)
   */
  async writeMemory(key: string, value: unknown): Promise<void> {
    const entry: SLOPMemoryEntry = {
      key,
      value,
      timestamp: Date.now(),
      agent: this.config.id,
    };

    if (this.config.coordinatorUrl) {
      // Write to coordinator's memory
      await fetch(`${this.config.coordinatorUrl}/memory`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(entry),
      });
    } else {
      // Write to local memory
      this.memory.set(key, entry);
    }
  }

  /**
   * Read from shared memory (via coordinator or local)
   */
  async readMemory(key: string): Promise<unknown | null> {
    if (this.config.coordinatorUrl) {
      const response = await fetch(
        `${this.config.coordinatorUrl}/memory?key=${encodeURIComponent(key)}`
      );
      if (response.ok) {
        const entry = await response.json();
        return entry?.value ?? null;
      }
      return null;
    } else {
      return this.memory.get(key)?.value ?? null;
    }
  }

  /**
   * Start the SLOP server
   */
  async start(): Promise<void> {
    if (this.isRunning) {
      console.log(`[${this.config.name}] Already running on port ${this.config.port}`);
      return;
    }

    this.server = createServer(async (req, res) => {
      // CORS headers
      res.setHeader('Access-Control-Allow-Origin', '*');
      res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
      res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

      if (req.method === 'OPTIONS') {
        res.writeHead(204);
        res.end();
        return;
      }

      const url = new URL(req.url || '/', `http://localhost:${this.config.port}`);

      try {
        if (url.pathname === '/info' && req.method === 'GET') {
          this.sendJson(res, this.getInfo());
        } else if (url.pathname === '/tools' && req.method === 'GET') {
          this.sendJson(res, { tools: this.tools });
        } else if (url.pathname === '/tools' && req.method === 'POST') {
          const body = await this.parseBody(req);
          const result = await this.handleToolCall(body as SLOPToolCall);
          this.sendJson(res, result);
        } else if (url.pathname === '/memory' && req.method === 'GET') {
          const key = url.searchParams.get('key');
          if (key) {
            const entry = this.memory.get(key);
            this.sendJson(res, entry || null);
          } else {
            // Return all memory entries
            const entries = Array.from(this.memory.entries()).map(([k, v]) => ({
              memoryKey: k,
              ...v,
            }));
            this.sendJson(res, { entries });
          }
        } else if (url.pathname === '/memory' && req.method === 'POST') {
          const body = (await this.parseBody(req)) as SLOPMemoryEntry;
          this.memory.set(body.key, body);
          this.sendJson(res, { success: true });
        } else if (url.pathname === '/messages' && req.method === 'GET') {
          this.sendJson(res, { messages: this.messageLog.slice(-100) });
        } else {
          res.writeHead(404);
          res.end(JSON.stringify({ error: 'Not found' }));
        }
      } catch (error) {
        console.error(`[${this.config.name}] Error:`, error);
        res.writeHead(500);
        res.end(JSON.stringify({ error: String(error) }));
      }
    });

    return new Promise((resolve) => {
      this.server!.listen(this.config.port, () => {
        this.isRunning = true;
        console.log(`[${this.config.name}] SLOP Agent running on http://localhost:${this.config.port}`);
        console.log(`  /info   - Agent information`);
        console.log(`  /tools  - Available tools`);
        console.log(`  /memory - Shared memory`);
        resolve();
      });
    });
  }

  /**
   * Stop the SLOP server
   */
  async stop(): Promise<void> {
    if (this.server) {
      return new Promise((resolve) => {
        this.server!.close(() => {
          this.isRunning = false;
          console.log(`[${this.config.name}] Stopped`);
          resolve();
        });
      });
    }
  }

  private sendJson(res: ServerResponse, data: unknown): void {
    res.setHeader('Content-Type', 'application/json');
    res.writeHead(200);
    res.end(JSON.stringify(data, null, 2));
  }

  private parseBody(req: IncomingMessage): Promise<unknown> {
    return new Promise((resolve, reject) => {
      let body = '';
      req.on('data', (chunk) => (body += chunk));
      req.on('end', () => {
        try {
          resolve(JSON.parse(body));
        } catch {
          resolve({});
        }
      });
      req.on('error', reject);
    });
  }
}
