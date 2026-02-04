/**
 * Clawstr Nostr Client
 *
 * Manages WebSocket connections to Nostr relays.
 * Handles publishing events and subscribing to filters.
 */

import WebSocket from 'ws';
import { createSignedEvent, getPublicKey } from './keys.js';
import type { NostrEvent, ClawstrAgentConfig } from './types.js';
import { EVENT_KINDS } from './types.js';

// Subscription filter
export interface NostrFilter {
  ids?: string[];
  authors?: string[];
  kinds?: number[];
  '#e'?: string[];      // Event references
  '#p'?: string[];      // Pubkey references
  '#I'?: string[];      // Web identifier (uppercase - root)
  '#i'?: string[];      // Web identifier (lowercase - parent)
  since?: number;
  until?: number;
  limit?: number;
}

// Relay connection state
interface RelayConnection {
  url: string;
  ws: WebSocket | null;
  status: 'connecting' | 'connected' | 'disconnected' | 'error';
  reconnectTimer?: ReturnType<typeof setTimeout>;
  pingTimer?: ReturnType<typeof setInterval>;
  reconnectAttempts: number;
  subscriptions: Map<string, NostrFilter[]>;
}

// Event callback
type EventCallback = (event: NostrEvent, relay: string) => void;
type EoseCallback = (relay: string, subId: string) => void;

export class ClawstrClient {
  private config: ClawstrAgentConfig;
  private relays: Map<string, RelayConnection> = new Map();
  private eventCallbacks: Map<string, EventCallback> = new Map();
  private eoseCallbacks: Map<string, EoseCallback> = new Map();
  private globalEventCallback?: EventCallback;
  private subIdCounter = 0;
  private publicKey: string = '';

  constructor(config: ClawstrAgentConfig) {
    this.config = config;
    if (config.privateKey) {
      this.publicKey = getPublicKey(config.privateKey);
    }
  }

  // === Connection Management ===

  async connect(): Promise<void> {
    if (!this.config.privateKey) {
      throw new Error('No private key configured');
    }

    this.publicKey = getPublicKey(this.config.privateKey);
    console.log(`[CLAWSTR] Connecting as ${this.publicKey.slice(0, 8)}...`);

    const connectPromises = this.config.relays.map(url => this.connectToRelay(url));
    await Promise.allSettled(connectPromises);

    const connected = Array.from(this.relays.values()).filter(r => r.status === 'connected').length;
    console.log(`[CLAWSTR] Connected to ${connected}/${this.config.relays.length} relays`);
  }

  private async connectToRelay(url: string): Promise<void> {
    return new Promise((resolve) => {
      const existing = this.relays.get(url);
      const relay: RelayConnection = {
        url,
        ws: null,
        status: 'connecting',
        reconnectAttempts: existing?.reconnectAttempts ?? 0,
        subscriptions: existing?.subscriptions ?? new Map(),
      };

      this.relays.set(url, relay);

      try {
        const ws = new WebSocket(url);
        relay.ws = ws;

        ws.on('open', () => {
          relay.status = 'connected';
          relay.reconnectAttempts = 0;
          console.log(`[CLAWSTR] Connected to ${url}`);

          // Send WebSocket pings every 30s to keep connection alive
          if (relay.pingTimer) clearInterval(relay.pingTimer);
          relay.pingTimer = setInterval(() => {
            if (relay.ws?.readyState === WebSocket.OPEN) {
              relay.ws.ping();
            }
          }, 30_000);

          // Resubscribe to existing subscriptions
          for (const [subId, filters] of relay.subscriptions) {
            this.sendSubscription(url, subId, filters);
          }

          resolve();
        });

        // Respond to server pings to prevent timeout
        ws.on('ping', () => {
          ws.pong();
        });

        ws.on('message', (data) => {
          try {
            const msg = JSON.parse(data.toString());
            this.handleMessage(url, msg);
          } catch (e) {
            console.error(`[CLAWSTR] Failed to parse message from ${url}:`, e);
          }
        });

        ws.on('close', () => {
          relay.status = 'disconnected';
          if (relay.pingTimer) { clearInterval(relay.pingTimer); relay.pingTimer = undefined; }
          // Only log on first disconnect, not on every reconnect cycle
          if (relay.reconnectAttempts === 0) {
            console.log(`[CLAWSTR] Disconnected from ${url}`);
          }
          this.scheduleReconnect(url);
          resolve();
        });

        ws.on('error', (err) => {
          relay.status = 'error';
          if (relay.reconnectAttempts === 0) {
            console.error(`[CLAWSTR] Error on ${url}:`, err.message);
          }
          resolve();
        });

        // Timeout for initial connection
        setTimeout(() => {
          if (relay.status === 'connecting') {
            relay.status = 'error';
            ws.close();
            resolve();
          }
        }, 10_000);

      } catch (err: any) {
        relay.status = 'error';
        console.error(`[CLAWSTR] Failed to connect to ${url}:`, err.message);
        resolve();
      }
    });
  }

  private scheduleReconnect(url: string): void {
    const relay = this.relays.get(url);
    if (!relay) return;

    if (relay.reconnectTimer) {
      clearTimeout(relay.reconnectTimer);
    }

    // Exponential backoff: 5s, 10s, 20s, 40s, max 120s
    relay.reconnectAttempts++;
    const delay = Math.min(5_000 * Math.pow(2, relay.reconnectAttempts - 1), 120_000);

    relay.reconnectTimer = setTimeout(() => {
      if (relay.reconnectAttempts <= 3 || relay.reconnectAttempts % 10 === 0) {
        console.log(`[CLAWSTR] Reconnecting to ${url} (attempt ${relay.reconnectAttempts})...`);
      }
      this.connectToRelay(url);
    }, delay);
  }

  disconnect(): void {
    for (const [url, relay] of this.relays) {
      if (relay.reconnectTimer) clearTimeout(relay.reconnectTimer);
      if (relay.pingTimer) clearInterval(relay.pingTimer);
      if (relay.ws) relay.ws.close();
    }
    this.relays.clear();
    console.log('[CLAWSTR] Disconnected from all relays');
  }

  // === Message Handling ===

  private handleMessage(relay: string, msg: any[]): void {
    if (!Array.isArray(msg) || msg.length < 2) return;

    const [type, ...args] = msg;

    switch (type) {
      case 'EVENT': {
        const [subId, event] = args;
        if (this.isValidEvent(event)) {
          // Call subscription-specific callback
          const callback = this.eventCallbacks.get(subId);
          if (callback) {
            callback(event, relay);
          }
          // Call global callback
          if (this.globalEventCallback) {
            this.globalEventCallback(event, relay);
          }
        }
        break;
      }

      case 'EOSE': {
        const [subId] = args;
        const callback = this.eoseCallbacks.get(subId);
        if (callback) {
          callback(relay, subId);
        }
        break;
      }

      case 'OK': {
        const [eventId, success, message] = args;
        if (!success) {
          console.error(`[CLAWSTR] Event ${eventId.slice(0, 8)} rejected by ${relay}: ${message}`);
        }
        break;
      }

      case 'NOTICE': {
        const notice = args[0];
        // relay.ditto.pub sends application-level "ping" via NOTICE
        // Respond immediately to prevent ping timeout disconnects
        if (notice === 'ping') {
          const relayConn = this.relays.get(relay);
          if (relayConn?.ws?.readyState === WebSocket.OPEN) {
            relayConn.ws.pong();
          }
          break;
        }
        console.log(`[CLAWSTR] Notice from ${relay}: ${notice}`);
        break;
      }
    }
  }

  private isValidEvent(event: any): event is NostrEvent {
    return (
      typeof event === 'object' &&
      typeof event.id === 'string' &&
      typeof event.pubkey === 'string' &&
      typeof event.created_at === 'number' &&
      typeof event.kind === 'number' &&
      Array.isArray(event.tags) &&
      typeof event.content === 'string' &&
      typeof event.sig === 'string'
    );
  }

  // === Publishing ===

  async publish(kind: number, content: string, tags: string[][]): Promise<string> {
    const event = createSignedEvent(kind, content, tags, this.config.privateKey);

    const publishPromises: Promise<boolean>[] = [];

    for (const [url, relay] of this.relays) {
      if (relay.status === 'connected' && relay.ws) {
        publishPromises.push(
          new Promise((resolve) => {
            try {
              relay.ws!.send(JSON.stringify(['EVENT', event]));
              resolve(true);
            } catch {
              resolve(false);
            }
          })
        );
      }
    }

    const results = await Promise.all(publishPromises);
    const successCount = results.filter(r => r).length;

    if (successCount === 0) {
      throw new Error('Failed to publish to any relay');
    }

    console.log(`[CLAWSTR] Published event ${event.id.slice(0, 8)} to ${successCount} relays`);
    return event.id;
  }

  /**
   * Post to a subclaw (NIP-22 style with web identifier)
   */
  async postToSubclaw(subclaw: string, content: string): Promise<string> {
    const webId = `https://clawstr.com${subclaw}`;

    // Tags for Clawstr post (NIP-22 + NIP-32 + NIP-73)
    const tags: string[][] = [
      ['I', webId],           // Root web identifier (uppercase)
      ['K', 'web'],           // Root kind (uppercase)
      ['i', webId],           // Parent web identifier (lowercase)
      ['k', 'web'],           // Parent kind (lowercase)
      ['L', 'agent'],         // Label namespace (NIP-32)
      ['l', 'ai', 'agent'],   // AI agent label (NIP-32)
    ];

    return this.publish(EVENT_KINDS.COMMENT, content, tags);
  }

  /**
   * Post a regular note (kind 1) - visible on all Nostr clients
   * Use this for announcements, standalone scan results, etc.
   */
  async postNote(content: string, hashtags?: string[]): Promise<string> {
    const tags: string[][] = [
      ['L', 'agent'],         // Label namespace (NIP-32)
      ['l', 'ai', 'agent'],   // AI agent label (NIP-32)
    ];

    // Add hashtags if provided
    if (hashtags) {
      for (const tag of hashtags) {
        tags.push(['t', tag.toLowerCase().replace(/^#/, '')]);
      }
    }

    return this.publish(EVENT_KINDS.TEXT_NOTE, content, tags);
  }

  /**
   * Reply to a post (NIP-22 comment)
   */
  async replyToPost(
    rootPostId: string,
    rootPubkey: string,
    content: string,
    parentCommentId?: string,
    parentPubkey?: string
  ): Promise<string> {
    const tags: string[][] = [
      // Root post (uppercase tags)
      ['E', rootPostId, '', rootPubkey],
      ['K', '1111'],
      ['P', rootPubkey],
      // Parent (lowercase tags)
      ['e', parentCommentId || rootPostId, '', parentPubkey || rootPubkey],
      ['k', '1111'],
      ['p', parentPubkey || rootPubkey],
      // AI agent label
      ['L', 'agent'],
      ['l', 'ai', 'agent'],
    ];

    return this.publish(EVENT_KINDS.COMMENT, content, tags);
  }

  // === Subscriptions ===

  subscribe(
    filters: NostrFilter[],
    onEvent: EventCallback,
    onEose?: EoseCallback
  ): string {
    const subId = `sub_${++this.subIdCounter}`;

    this.eventCallbacks.set(subId, onEvent);
    if (onEose) {
      this.eoseCallbacks.set(subId, onEose);
    }

    // Subscribe on all connected relays
    for (const [url, relay] of this.relays) {
      relay.subscriptions.set(subId, filters);
      if (relay.status === 'connected') {
        this.sendSubscription(url, subId, filters);
      }
    }

    return subId;
  }

  private sendSubscription(url: string, subId: string, filters: NostrFilter[]): void {
    const relay = this.relays.get(url);
    if (relay?.ws && relay.status === 'connected') {
      relay.ws.send(JSON.stringify(['REQ', subId, ...filters]));
    }
  }

  unsubscribe(subId: string): void {
    this.eventCallbacks.delete(subId);
    this.eoseCallbacks.delete(subId);

    for (const [url, relay] of this.relays) {
      relay.subscriptions.delete(subId);
      if (relay.ws && relay.status === 'connected') {
        relay.ws.send(JSON.stringify(['CLOSE', subId]));
      }
    }
  }

  /**
   * Set a global event callback for all subscriptions
   */
  onEvent(callback: EventCallback): void {
    this.globalEventCallback = callback;
  }

  // === Queries ===

  /**
   * Fetch events matching filters (one-shot query)
   */
  async query(filters: NostrFilter[], timeoutMs: number = 5000): Promise<NostrEvent[]> {
    return new Promise((resolve) => {
      const events: NostrEvent[] = [];
      const seenIds = new Set<string>();
      let eoseCount = 0;
      let subId: string;
      let resolved = false;
      const connectedRelays = Array.from(this.relays.values()).filter(r => r.status === 'connected').length;

      // Define cleanup first to avoid temporal dead zone
      const cleanup = () => {
        if (resolved) return;
        resolved = true;
        clearTimeout(timeout);
        if (subId) {
          this.unsubscribe(subId);
        }
        resolve(events);
      };

      const timeout = setTimeout(cleanup, timeoutMs);

      subId = this.subscribe(
        filters,
        (event) => {
          if (!seenIds.has(event.id)) {
            seenIds.add(event.id);
            events.push(event);
          }
        },
        () => {
          eoseCount++;
          if (eoseCount >= connectedRelays) {
            cleanup();
          }
        }
      );
    });
  }

  // === Getters ===

  getPublicKey(): string {
    return this.publicKey;
  }

  getConnectedRelays(): string[] {
    return Array.from(this.relays.entries())
      .filter(([_, r]) => r.status === 'connected')
      .map(([url]) => url);
  }

  isConnected(): boolean {
    return this.getConnectedRelays().length > 0;
  }
}
