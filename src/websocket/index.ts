/**
 * WebSocket Server for SLOP Auditor
 *
 * Provides real-time updates to connected clients:
 * - Audit started/completed events
 * - Finding notifications
 * - Settings changes
 * - Server status updates
 */

import { WebSocketServer, WebSocket } from 'ws';
import { IncomingMessage } from 'http';

export interface WSMessage {
  type: 'audit_started' | 'audit_completed' | 'finding' | 'settings_changed' | 'status' | 'ping' | 'pong';
  payload: unknown;
  timestamp: string;
}

export interface AuditStartedPayload {
  auditId: string;
  type: string;
  target: string;
}

export interface AuditCompletedPayload {
  auditId: string;
  type: string;
  target: string;
  summary: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
  duration?: number;
}

export interface FindingPayload {
  auditId: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  type: string;
  message: string;
  file?: string;
  line?: number;
}

export class AuditorWebSocket {
  private wss: WebSocketServer | null = null;
  private clients = new Set<WebSocket>();
  private pingInterval: ReturnType<typeof setInterval> | null = null;

  constructor(private port: number = 3001) {}

  /**
   * Start the WebSocket server
   */
  start(): Promise<void> {
    return new Promise((resolve, reject) => {
      this.wss = new WebSocketServer({ port: this.port });

      this.wss.on('connection', (ws: WebSocket, req: IncomingMessage) => {
        console.log(`[WS] Client connected from ${req.socket.remoteAddress}`);
        this.clients.add(ws);

        // Send welcome message
        this.sendTo(ws, {
          type: 'status',
          payload: { connected: true, clientCount: this.clients.size },
          timestamp: new Date().toISOString()
        });

        ws.on('message', (data: Buffer) => {
          try {
            const message = JSON.parse(data.toString());
            this.handleMessage(ws, message);
          } catch (err) {
            console.error('[WS] Invalid message:', err);
          }
        });

        ws.on('close', () => {
          console.log('[WS] Client disconnected');
          this.clients.delete(ws);
        });

        ws.on('error', (err) => {
          console.error('[WS] Client error:', err);
          this.clients.delete(ws);
        });
      });

      this.wss.on('error', (err) => {
        console.error('[WS] Server error:', err);
        reject(err);
      });

      this.wss.on('listening', () => {
        console.log(`[WS] WebSocket server running on ws://127.0.0.1:${this.port}`);

        // Start ping interval to keep connections alive
        this.pingInterval = setInterval(() => {
          this.broadcast({
            type: 'ping',
            payload: { time: Date.now() },
            timestamp: new Date().toISOString()
          });
        }, 30000);

        resolve();
      });
    });
  }

  /**
   * Stop the WebSocket server
   */
  stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.pingInterval) {
        clearInterval(this.pingInterval);
        this.pingInterval = null;
      }

      if (this.wss) {
        // Close all client connections
        for (const client of this.clients) {
          client.close(1000, 'Server shutting down');
        }
        this.clients.clear();

        this.wss.close(() => {
          console.log('[WS] WebSocket server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  /**
   * Handle incoming messages from clients
   */
  private handleMessage(ws: WebSocket, message: WSMessage): void {
    switch (message.type) {
      case 'ping':
        this.sendTo(ws, {
          type: 'pong',
          payload: { time: Date.now() },
          timestamp: new Date().toISOString()
        });
        break;
      case 'pong':
        // Client responded to ping
        break;
      default:
        console.log('[WS] Received:', message.type);
    }
  }

  /**
   * Send message to a specific client
   */
  private sendTo(ws: WebSocket, message: WSMessage): void {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify(message));
    }
  }

  /**
   * Broadcast message to all connected clients
   */
  broadcast(message: WSMessage): void {
    const data = JSON.stringify(message);
    for (const client of this.clients) {
      if (client.readyState === WebSocket.OPEN) {
        client.send(data);
      }
    }
  }

  /**
   * Notify clients that an audit has started
   */
  notifyAuditStarted(payload: AuditStartedPayload): void {
    this.broadcast({
      type: 'audit_started',
      payload,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Notify clients that an audit has completed
   */
  notifyAuditCompleted(payload: AuditCompletedPayload): void {
    this.broadcast({
      type: 'audit_completed',
      payload,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Notify clients of a finding during an audit
   */
  notifyFinding(payload: FindingPayload): void {
    this.broadcast({
      type: 'finding',
      payload,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Notify clients that settings have changed
   */
  notifySettingsChanged(section?: string): void {
    this.broadcast({
      type: 'settings_changed',
      payload: { section },
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Get the number of connected clients
   */
  getClientCount(): number {
    return this.clients.size;
  }
}

// Singleton instance
let wsServer: AuditorWebSocket | null = null;

export function getWebSocketServer(port?: number): AuditorWebSocket {
  if (!wsServer) {
    wsServer = new AuditorWebSocket(port);
  }
  return wsServer;
}

export function closeWebSocketServer(): Promise<void> {
  if (wsServer) {
    const server = wsServer;
    wsServer = null;
    return server.stop();
  }
  return Promise.resolve();
}
