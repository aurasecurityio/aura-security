// Configuration System - Load and validate auditor configuration
// Supports: JSON, YAML (with js-yaml), and environment variables

import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

export interface ModuleConfig {
  id: string;
  name: string;
  description?: string;
  critical_paths?: string[];  // File patterns that trigger alerts
  connections?: string[];     // Other modules this connects to
}

export interface IntegrationConfig {
  github?: {
    enabled: boolean;
    token?: string;  // Or use GITHUB_TOKEN env
    webhook_secret?: string;
  };
  gitlab?: {
    enabled: boolean;
    token?: string;  // Or use GITLAB_TOKEN env
    api_url?: string;
  };
  scanners?: {
    snyk?: { enabled: boolean };
    trivy?: { enabled: boolean };
    semgrep?: { enabled: boolean };
    npm_audit?: { enabled: boolean };
  };
}

export interface AuditorConfig {
  version: string;
  name?: string;
  description?: string;

  // Server settings
  server: {
    port: number;
    host?: string;
  };

  // Webhook settings
  webhook?: {
    enabled: boolean;
    port: number;
    secret?: string;
  };

  // Visualizer settings
  visualizer?: {
    enabled: boolean;
    port: number;
  };

  // Modules to monitor
  modules: ModuleConfig[];

  // Default policy
  policy: {
    critical_assets: string[];
    risk_tolerance: 'low' | 'medium' | 'high';
  };

  // Integrations
  integrations?: IntegrationConfig;
}

const DEFAULT_CONFIG: AuditorConfig = {
  version: '1.0',
  server: {
    port: 3000,
    host: '127.0.0.1'
  },
  webhook: {
    enabled: false,
    port: 3001
  },
  visualizer: {
    enabled: true,
    port: 8080
  },
  modules: [
    { id: 'auth', name: 'AUTH', description: 'Authentication & Identity', critical_paths: ['**/auth/**', '**/login/**', '**/oauth/**'] },
    { id: 'database', name: 'DATABASE', description: 'Data Storage', critical_paths: ['**/db/**', '**/database/**', '**/models/**'] },
    { id: 'api', name: 'API', description: 'External Endpoints', critical_paths: ['**/api/**', '**/routes/**', '**/controllers/**'] },
    { id: 'infra', name: 'INFRA', description: 'Infrastructure', critical_paths: ['**/*.tf', '**/terraform/**', '**/k8s/**', '**/docker/**'] },
    { id: 'billing', name: 'BILLING', description: 'Payment Processing', critical_paths: ['**/billing/**', '**/payment/**', '**/stripe/**'] },
    { id: 'secrets', name: 'SECRETS', description: 'Credentials & Keys', critical_paths: ['**/.env*', '**/secrets/**', '**/config/**'] }
  ],
  policy: {
    critical_assets: ['auth', 'billing', 'database', 'secrets'],
    risk_tolerance: 'medium'
  },
  integrations: {
    github: { enabled: false },
    gitlab: { enabled: false },
    scanners: {
      snyk: { enabled: false },
      trivy: { enabled: false },
      semgrep: { enabled: false },
      npm_audit: { enabled: true }
    }
  }
};

export class ConfigLoader {
  private config: AuditorConfig;

  constructor() {
    this.config = { ...DEFAULT_CONFIG };
  }

  // Load from file
  loadFromFile(filePath: string): AuditorConfig {
    if (!existsSync(filePath)) {
      console.warn(`[Config] File not found: ${filePath}, using defaults`);
      return this.config;
    }

    const content = readFileSync(filePath, 'utf-8');
    const ext = filePath.split('.').pop()?.toLowerCase();

    let parsed: Partial<AuditorConfig>;

    if (ext === 'json') {
      parsed = JSON.parse(content);
    } else if (ext === 'yaml' || ext === 'yml') {
      // Simple YAML parsing (key: value format)
      parsed = this.parseSimpleYaml(content);
    } else {
      throw new Error(`Unsupported config format: ${ext}`);
    }

    this.config = this.mergeConfig(this.config, parsed);
    return this.config;
  }

  // Load from environment variables
  loadFromEnv(): AuditorConfig {
    const env = process.env;

    if (env.SLOP_PORT) {
      this.config.server.port = parseInt(env.SLOP_PORT, 10);
    }
    if (env.SLOP_HOST) {
      this.config.server.host = env.SLOP_HOST;
    }
    if (env.WEBHOOK_PORT) {
      this.config.webhook = { ...this.config.webhook!, enabled: true, port: parseInt(env.WEBHOOK_PORT, 10) };
    }
    if (env.WEBHOOK_SECRET) {
      this.config.webhook = { ...this.config.webhook!, secret: env.WEBHOOK_SECRET };
    }
    if (env.VISUALIZER_PORT) {
      this.config.visualizer = { ...this.config.visualizer!, port: parseInt(env.VISUALIZER_PORT, 10) };
    }
    if (env.GITHUB_TOKEN) {
      this.config.integrations = {
        ...this.config.integrations,
        github: { enabled: true, token: env.GITHUB_TOKEN }
      };
    }
    if (env.GITLAB_TOKEN) {
      this.config.integrations = {
        ...this.config.integrations,
        gitlab: { enabled: true, token: env.GITLAB_TOKEN }
      };
    }
    if (env.RISK_TOLERANCE) {
      this.config.policy.risk_tolerance = env.RISK_TOLERANCE as 'low' | 'medium' | 'high';
    }

    return this.config;
  }

  // Auto-detect and load config
  autoLoad(basePath: string = process.cwd()): AuditorConfig {
    const configFiles = [
      'slop.config.json',
      'slop.config.yaml',
      'slop.config.yml',
      '.sloprc.json',
      '.sloprc'
    ];

    for (const file of configFiles) {
      const fullPath = join(basePath, file);
      if (existsSync(fullPath)) {
        console.log(`[Config] Loading from ${file}`);
        this.loadFromFile(fullPath);
        break;
      }
    }

    // Override with env vars
    this.loadFromEnv();

    return this.config;
  }

  getConfig(): AuditorConfig {
    return this.config;
  }

  // Validate configuration
  validate(): string[] {
    const errors: string[] = [];

    if (!this.config.server?.port) {
      errors.push('server.port is required');
    }
    if (this.config.server.port < 1 || this.config.server.port > 65535) {
      errors.push('server.port must be between 1 and 65535');
    }
    if (!this.config.modules || this.config.modules.length === 0) {
      errors.push('At least one module must be configured');
    }
    if (!this.config.policy?.critical_assets) {
      errors.push('policy.critical_assets is required');
    }

    return errors;
  }

  private parseSimpleYaml(content: string): Partial<AuditorConfig> {
    // Very basic YAML parser for simple configs
    const result: Record<string, unknown> = {};
    const lines = content.split('\n');
    let currentSection = result;
    let sectionStack: Record<string, unknown>[] = [result];
    let indentStack: number[] = [0];

    for (const line of lines) {
      if (line.trim() === '' || line.trim().startsWith('#')) continue;

      const indent = line.search(/\S/);
      const trimmed = line.trim();

      // Handle section end
      while (indent <= indentStack[indentStack.length - 1] && indentStack.length > 1) {
        sectionStack.pop();
        indentStack.pop();
        currentSection = sectionStack[sectionStack.length - 1];
      }

      if (trimmed.endsWith(':')) {
        // New section
        const key = trimmed.slice(0, -1);
        currentSection[key] = {};
        sectionStack.push(currentSection[key] as Record<string, unknown>);
        indentStack.push(indent);
        currentSection = currentSection[key] as Record<string, unknown>;
      } else if (trimmed.includes(':')) {
        // Key-value pair
        const [key, ...valueParts] = trimmed.split(':');
        let value: unknown = valueParts.join(':').trim();

        // Parse value type
        if (value === 'true') value = true;
        else if (value === 'false') value = false;
        else if (!isNaN(Number(value))) value = Number(value);
        else if ((value as string).startsWith('[')) {
          // Simple array
          value = (value as string).slice(1, -1).split(',').map(v => v.trim().replace(/['"]/g, ''));
        }

        currentSection[key.trim()] = value;
      }
    }

    return result as unknown as Partial<AuditorConfig>;
  }

  private mergeConfig(base: AuditorConfig, override: Partial<AuditorConfig>): AuditorConfig {
    return {
      version: override.version || base.version,
      name: override.name || base.name,
      description: override.description || base.description,
      server: { ...base.server, ...override.server },
      webhook: base.webhook && override.webhook
        ? { ...base.webhook, ...override.webhook }
        : (override.webhook || base.webhook),
      visualizer: base.visualizer && override.visualizer
        ? { ...base.visualizer, ...override.visualizer }
        : (override.visualizer || base.visualizer),
      modules: override.modules || base.modules,
      policy: { ...base.policy, ...override.policy },
      integrations: override.integrations
        ? { ...base.integrations, ...override.integrations }
        : base.integrations
    };
  }
}

// Export singleton loader
export const configLoader = new ConfigLoader();
