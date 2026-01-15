// SLOP Client SDK - High-level API for interacting with the auditor
// Provides typed methods, automatic retries, and event streaming

import type { AuditorInput, AuditorOutput, ChangeEvent, EvidenceBundle, PolicyContext } from '../types/events.js';

export interface AuditClientConfig {
  serverUrl?: string;
  apiKey?: string;
  timeout?: number;
  retries?: number;
}

export interface AuditRequest {
  changeEvent: ChangeEvent;
  evidenceBundle?: Partial<EvidenceBundle>;
  policyContext?: Partial<PolicyContext>;
}

export interface AuditResult {
  success: boolean;
  output?: AuditorOutput;
  error?: string;
  duration: number;
}

export interface ServerInfo {
  name: string;
  version: string;
  endpoints: string[];
  tools: string[];
}

export class AuditClient {
  private config: Required<AuditClientConfig>;

  constructor(config: AuditClientConfig = {}) {
    this.config = {
      serverUrl: config.serverUrl ?? 'http://127.0.0.1:3000',
      apiKey: config.apiKey ?? '',
      timeout: config.timeout ?? 30000,
      retries: config.retries ?? 3
    };
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

  private async fetchWithRetry<T>(
    url: string,
    options: RequestInit,
    retries = this.config.retries
  ): Promise<T> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.config.timeout);

    try {
      const res = await fetch(url, {
        ...options,
        signal: controller.signal
      });

      clearTimeout(timeoutId);

      if (!res.ok) {
        throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      }

      return await res.json() as T;
    } catch (err) {
      clearTimeout(timeoutId);

      if (retries > 0 && !(err instanceof DOMException && err.name === 'AbortError')) {
        await this.delay(1000);
        return this.fetchWithRetry(url, options, retries - 1);
      }

      throw err;
    }
  }

  private delay(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async getServerInfo(): Promise<ServerInfo> {
    return this.fetchWithRetry<ServerInfo>(
      `${this.config.serverUrl}/info`,
      { method: 'GET', headers: this.headers() }
    );
  }

  async isHealthy(): Promise<boolean> {
    try {
      await this.getServerInfo();
      return true;
    } catch {
      return false;
    }
  }

  async audit(request: AuditRequest): Promise<AuditResult> {
    const startTime = Date.now();

    const input: AuditorInput = {
      change_event: request.changeEvent,
      evidence_bundle: {
        sbom: request.evidenceBundle?.sbom,
        vuln_scan: request.evidenceBundle?.vuln_scan,
        sast_results: request.evidenceBundle?.sast_results,
        iac_scan: request.evidenceBundle?.iac_scan,
        provenance: request.evidenceBundle?.provenance,
        runtime_delta: request.evidenceBundle?.runtime_delta
      },
      policy_context: {
        critical_assets: request.policyContext?.critical_assets ?? ['auth', 'billing', 'phi', 'infra'],
        risk_tolerance: request.policyContext?.risk_tolerance ?? 'medium'
      }
    };

    try {
      const response = await this.fetchWithRetry<{ result: AuditorOutput }>(
        `${this.config.serverUrl}/tools`,
        {
          method: 'POST',
          headers: this.headers(),
          body: JSON.stringify({ tool: 'audit', arguments: input })
        }
      );

      return {
        success: true,
        output: response.result,
        duration: Date.now() - startTime
      };
    } catch (err) {
      return {
        success: false,
        error: err instanceof Error ? err.message : String(err),
        duration: Date.now() - startTime
      };
    }
  }

  async getAuditLogs(): Promise<string[]> {
    const response = await this.fetchWithRetry<{ keys: string[] }>(
      `${this.config.serverUrl}/memory`,
      { method: 'GET', headers: this.headers() }
    );
    return response.keys;
  }

  async getAuditEntry(key: string): Promise<AuditorOutput | null> {
    try {
      const response = await this.fetchWithRetry<{ value: AuditorOutput }>(
        `${this.config.serverUrl}/memory?key=${encodeURIComponent(key)}`,
        { method: 'GET', headers: this.headers() }
      );
      return response.value;
    } catch {
      return null;
    }
  }

  // Stream audit logs in real-time
  async *watchAudits(pollInterval = 2000): AsyncGenerator<AuditorOutput> {
    let lastCount = 0;
    const seenKeys = new Set<string>();

    while (true) {
      try {
        const keys = await this.getAuditLogs();

        if (keys.length > lastCount) {
          for (const key of keys) {
            if (!seenKeys.has(key)) {
              seenKeys.add(key);
              const entry = await this.getAuditEntry(key);
              if (entry) {
                yield entry;
              }
            }
          }
          lastCount = keys.length;
        }
      } catch {
        // Ignore errors in watch mode
      }

      await this.delay(pollInterval);
    }
  }
}

// Helper functions for building audit requests
export function createPullRequestEvent(
  repo: string,
  commit: string,
  filesChanged: string[],
  diff: string,
  environment: 'dev' | 'staging' | 'prod' = 'dev'
): ChangeEvent {
  return {
    id: `pr-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: 'pull_request',
    environment,
    repo,
    commit,
    files_changed: filesChanged,
    diff
  };
}

export function createDeployEvent(
  repo: string,
  commit: string,
  environment: 'dev' | 'staging' | 'prod'
): ChangeEvent {
  return {
    id: `deploy-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: 'deploy',
    environment,
    repo,
    commit,
    files_changed: [],
    diff: ''
  };
}

export function createInfraChangeEvent(
  repo: string,
  commit: string,
  filesChanged: string[],
  diff: string
): ChangeEvent {
  return {
    id: `infra-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    type: 'infra_change',
    environment: 'prod',
    repo,
    commit,
    files_changed: filesChanged,
    diff
  };
}

export { AuditorInput, AuditorOutput, ChangeEvent, EvidenceBundle, PolicyContext };
