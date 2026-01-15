// SLOP Client - Publish-only client for auditor pipeline
// Implements: /tools, /memory endpoints per SLOP spec

export interface SlopClientConfig {
  baseUrl: string;
  apiKey?: string;
  timeout?: number;
}

export interface SlopToolCall {
  tool: string;
  arguments: Record<string, unknown>;
}

export interface SlopMemoryEntry {
  key: string;
  value: unknown;
  metadata?: Record<string, unknown>;
}

export class SlopConnectionError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SlopConnectionError';
  }
}

export class SlopClient {
  private config: Required<SlopClientConfig>;
  private _connected = false;

  constructor(config: SlopClientConfig) {
    this.config = {
      baseUrl: config.baseUrl.replace(/\/$/, ''),
      apiKey: config.apiKey ?? '',
      timeout: config.timeout ?? 30000
    };
  }

  get connected(): boolean {
    return this._connected;
  }

  private headers(): Record<string, string> {
    const h: Record<string, string> = {
      'Content-Type': 'application/json'
    };
    if (this.config.apiKey) {
      h['Authorization'] = `Bearer ${this.config.apiKey}`;
    }
    return h;
  }

  async connect(): Promise<void> {
    // Verify SLOP server is available via /info
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const res = await fetch(`${this.config.baseUrl}/info`, {
        method: 'GET',
        headers: this.headers(),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new SlopConnectionError(`SLOP server returned ${res.status}`);
      }

      this._connected = true;
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof SlopConnectionError) throw err;
      throw new SlopConnectionError(`Failed to connect to SLOP server: ${err}`);
    }
  }

  async disconnect(): Promise<void> {
    this._connected = false;
  }

  // Fail-closed: throws on any error
  async publishToMemory(entry: SlopMemoryEntry): Promise<void> {
    if (!this._connected) {
      throw new SlopConnectionError('Not connected to SLOP server');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const res = await fetch(`${this.config.baseUrl}/memory`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(entry),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new SlopConnectionError(`Memory publish failed: ${res.status}`);
      }
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof SlopConnectionError) throw err;
      throw new SlopConnectionError(`Memory publish error: ${err}`);
    }
  }

  async callTool(call: SlopToolCall): Promise<unknown> {
    if (!this._connected) {
      throw new SlopConnectionError('Not connected to SLOP server');
    }

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const res = await fetch(`${this.config.baseUrl}/tools`, {
        method: 'POST',
        headers: this.headers(),
        body: JSON.stringify(call),
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new SlopConnectionError(`Tool call failed: ${res.status}`);
      }

      return await res.json();
    } catch (err) {
      clearTimeout(timeoutId);
      if (err instanceof SlopConnectionError) throw err;
      throw new SlopConnectionError(`Tool call error: ${err}`);
    }
  }

  async healthCheck(): Promise<boolean> {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 5000);

      const res = await fetch(`${this.config.baseUrl}/info`, {
        method: 'GET',
        headers: this.headers(),
        signal: controller.signal
      });

      clearTimeout(timeoutId);
      return res.ok;
    } catch {
      return false;
    }
  }
}
