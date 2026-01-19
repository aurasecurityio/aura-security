/**
 * Aura Protocol - Agent Types
 *
 * Agents are specialized workers that execute within zones.
 * Each agent has a specific role and can only operate within its assigned zone.
 */

import { ZoneContext, ZoneFinding, AgentResult } from '../zones/types.js';

// Re-export AgentResult so it can be imported from agents/types
export { AgentResult } from '../zones/types.js';

export type AgentRole = 'scanner' | 'policy' | 'validator' | 'reporter' | 'notifier';

export type AgentStatus = 'idle' | 'running' | 'complete' | 'error' | 'disabled';

export interface AgentConfig {
  id: string;
  name: string;
  role: AgentRole;
  description: string;
  // Whether this agent is enabled
  enabled: boolean;
  // External tool this agent wraps (if any)
  externalTool?: string;
  // Agent-specific configuration
  config?: Record<string, unknown>;
}

export interface AgentCapabilities {
  // File types this agent can scan
  fileTypes?: string[];
  // Languages this agent supports
  languages?: string[];
  // Whether this agent requires external tools
  requiresExternalTool: boolean;
  // Whether this agent can run in parallel with others
  supportsParallel: boolean;
}

/**
 * Base Agent Interface
 *
 * All agents must implement this interface.
 */
export interface Agent {
  readonly config: AgentConfig;
  readonly capabilities: AgentCapabilities;

  /**
   * Check if the agent is available (external tools installed, etc.)
   */
  isAvailable(): Promise<boolean>;

  /**
   * Execute the agent within a zone context
   */
  execute(context: ZoneContext): Promise<AgentResult>;

  /**
   * Get agent status
   */
  getStatus(): AgentStatus;
}

/**
 * Scanner Agent Interface
 *
 * Agents that scan for secrets, vulnerabilities, etc.
 */
export interface ScannerAgent extends Agent {
  readonly config: AgentConfig & { role: 'scanner' };

  /**
   * Run the scan and return findings
   */
  scan(targetPath: string, context: ZoneContext): Promise<ZoneFinding[]>;
}

/**
 * Policy Agent Interface
 *
 * Agents that evaluate policies and context
 */
export interface PolicyAgent extends Agent {
  readonly config: AgentConfig & { role: 'policy' };

  /**
   * Evaluate findings against policies
   */
  evaluate(
    findings: ZoneFinding[],
    context: ZoneContext
  ): Promise<{
    filtered: ZoneFinding[];
    falsePositives: ZoneFinding[];
    escalated: ZoneFinding[];
  }>;
}

/**
 * Validator Agent Interface
 *
 * Agents that validate and deduplicate findings
 */
export interface IValidatorAgent extends Agent {
  readonly config: AgentConfig & { role: 'validator' };

  /**
   * Validate findings and remove false positives
   */
  validate(findings: ZoneFinding[], context: ZoneContext): Promise<ZoneFinding[]>;
}

/**
 * Reporter Agent Interface
 *
 * Agents that generate reports
 */
export interface ReporterAgent extends Agent {
  readonly config: AgentConfig & { role: 'reporter' };

  /**
   * Generate a report from findings
   */
  generateReport(
    findings: ZoneFinding[],
    format: 'sarif' | 'json' | 'html' | 'markdown',
    context: ZoneContext
  ): Promise<string>;
}

/**
 * Notifier Agent Interface
 *
 * Agents that send notifications
 */
export interface NotifierAgent extends Agent {
  readonly config: AgentConfig & { role: 'notifier' };

  /**
   * Send notification about findings
   */
  notify(
    findings: ZoneFinding[],
    channel: string,
    context: ZoneContext
  ): Promise<boolean>;
}

/**
 * Agent Registry
 *
 * Stores all available agents
 */
export interface AgentRegistry {
  register(agent: Agent): void;
  unregister(agentId: string): void;
  get(agentId: string): Agent | undefined;
  getAll(): Agent[];
  getByRole(role: AgentRole): Agent[];
  getAvailable(): Promise<Agent[]>;
}

/**
 * Default agent configurations
 */
export const DEFAULT_AGENTS: AgentConfig[] = [
  // Scanner agents
  {
    id: 'gitleaks',
    name: 'Gitleaks',
    role: 'scanner',
    description: 'Detect secrets and API keys in code',
    enabled: true,
    externalTool: 'gitleaks',
  },
  {
    id: 'trivy',
    name: 'Trivy',
    role: 'scanner',
    description: 'Scan for vulnerabilities in dependencies and containers',
    enabled: true,
    externalTool: 'trivy',
  },
  {
    id: 'semgrep',
    name: 'Semgrep',
    role: 'scanner',
    description: 'Static analysis for security patterns',
    enabled: true,
    externalTool: 'semgrep',
  },
  {
    id: 'grype',
    name: 'Grype',
    role: 'scanner',
    description: 'Vulnerability scanner for container images and filesystems',
    enabled: true,
    externalTool: 'grype',
  },
  {
    id: 'npm-audit',
    name: 'NPM Audit',
    role: 'scanner',
    description: 'Audit npm packages for vulnerabilities',
    enabled: true,
    externalTool: 'npm',
  },
  // Policy agents
  {
    id: 'policy-evaluator',
    name: 'Policy Evaluator',
    role: 'policy',
    description: 'Evaluate findings against security policies',
    enabled: true,
  },
  // Validator agents
  {
    id: 'validator',
    name: 'Finding Validator',
    role: 'validator',
    description: 'Validate and deduplicate findings, remove false positives',
    enabled: true,
  },
  // Reporter agents
  {
    id: 'sarif-reporter',
    name: 'SARIF Reporter',
    role: 'reporter',
    description: 'Generate SARIF format reports',
    enabled: true,
  },
  // Notifier agents
  {
    id: 'slack-notifier',
    name: 'Slack Notifier',
    role: 'notifier',
    description: 'Send notifications to Slack',
    enabled: true,
  },
  {
    id: 'discord-notifier',
    name: 'Discord Notifier',
    role: 'notifier',
    description: 'Send notifications to Discord',
    enabled: true,
  },
];
