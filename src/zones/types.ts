/**
 * Aura Protocol - Zone Types
 *
 * Zones are isolated execution environments that contain agents.
 * Each zone has its own memory space and can run in parallel with other zones.
 */

export type ZoneStatus = 'idle' | 'running' | 'complete' | 'error';

export type ZoneType = 'scanner' | 'policy' | 'remediation' | 'reporting';

export interface ZoneConfig {
  id: string;
  name: string;
  type: ZoneType;
  color: string;
  description?: string;
  // Agents assigned to this zone
  agentIds: string[];
  // Zone-specific configuration
  config?: Record<string, unknown>;
}

export interface ZoneMemory {
  // Isolated key-value store for zone
  data: Map<string, unknown>;
  // Findings collected by agents in this zone
  findings: ZoneFinding[];
  // Logs from zone execution
  logs: ZoneLog[];
}

export interface ZoneFinding {
  id: string;
  agentId: string;
  type: 'secret' | 'vulnerability' | 'policy_violation' | 'recommendation';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  file?: string;
  line?: number;
  metadata?: Record<string, unknown>;
  timestamp: number;
}

export interface ZoneLog {
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  agentId?: string;
  timestamp: number;
}

export interface Zone {
  config: ZoneConfig;
  status: ZoneStatus;
  memory: ZoneMemory;
  // Execution timing
  startTime?: number;
  endTime?: number;
  // Error if status is 'error'
  error?: string;
}

export interface ZoneResult {
  zoneId: string;
  zoneName: string;
  zoneType: ZoneType;
  status: ZoneStatus;
  findings: ZoneFinding[];
  logs: ZoneLog[];
  duration: number;
  agentResults: AgentResult[];
  error?: string;
}

export interface AgentResult {
  agentId: string;
  agentName: string;
  status: 'success' | 'error' | 'skipped';
  findings: ZoneFinding[];
  duration: number;
  error?: string;
}

// Zone execution context passed to agents
export interface ZoneContext {
  zoneId: string;
  zoneName: string;
  zoneType: ZoneType;
  targetPath: string;
  memory: ZoneMemory;
  config: Record<string, unknown>;
  // Callback to add findings
  addFinding: (finding: Omit<ZoneFinding, 'id' | 'timestamp'>) => void;
  // Callback to log
  log: (level: ZoneLog['level'], message: string) => void;
}

// Default zone configurations
export const DEFAULT_ZONES: ZoneConfig[] = [
  {
    id: 'scanner-zone',
    name: 'Scanner Zone',
    type: 'scanner',
    color: '#22c55e', // Green
    description: 'Fast parallel scanning for secrets and vulnerabilities',
    agentIds: ['gitleaks', 'trivy', 'semgrep', 'grype', 'npm-audit'],
  },
  {
    id: 'policy-zone',
    name: 'Policy Zone',
    type: 'policy',
    color: '#ef4444', // Red
    description: 'Context-aware policy evaluation and false positive elimination',
    agentIds: ['policy-evaluator', 'validator'],
  },
  {
    id: 'reporting-zone',
    name: 'Reporting Zone',
    type: 'reporting',
    color: '#3b82f6', // Blue
    description: 'Generate reports and send notifications',
    agentIds: ['sarif-reporter', 'slack-notifier', 'discord-notifier'],
  },
];
