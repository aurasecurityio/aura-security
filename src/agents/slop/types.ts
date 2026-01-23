/**
 * SLOP Agent Types
 *
 * Types for SLOP-native multi-agent communication
 */

// SLOP Protocol standard types
export interface SLOPInfo {
  name: string;
  version: string;
  description: string;
  tools: SLOPTool[];
  capabilities?: string[];
  status?: 'ready' | 'busy' | 'error';
}

export interface SLOPTool {
  name: string;
  description: string;
  parameters?: Record<string, SLOPParameter>;
}

export interface SLOPParameter {
  type: 'string' | 'number' | 'boolean' | 'object' | 'array';
  description: string;
  required?: boolean;
  default?: unknown;
}

export interface SLOPToolCall {
  tool: string;
  arguments: Record<string, unknown>;
}

export interface SLOPToolResult {
  result?: unknown;
  error?: string;
}

export interface SLOPMemoryEntry {
  key: string;
  value: unknown;
  timestamp: number;
  agent?: string;
}

// Agent-specific message types
export interface AgentMessage {
  id: string;
  from: string;
  to: string;
  type: 'request' | 'response' | 'broadcast';
  tool?: string;
  arguments?: Record<string, unknown>;
  result?: unknown;
  error?: string;
  timestamp: number;
}

// Finding types for inter-agent communication
export interface Finding {
  id: string;
  type: 'secret' | 'vulnerability' | 'code-issue' | 'iac' | 'docker';
  severity: 'critical' | 'high' | 'medium' | 'low';
  title: string;
  description: string;
  file?: string;
  line?: number;
  package?: string;
  version?: string;
  cve?: string;
  cwe?: string;
  metadata?: Record<string, unknown>;
}

export interface TriageResult {
  finding: Finding;
  validated: boolean;
  adjustedSeverity?: 'critical' | 'high' | 'medium' | 'low';
  falsePositive: boolean;
  reason: string;
  recommendFix: boolean;
  confidence: number;
}

export interface FixSuggestion {
  finding: Finding;
  strategy: 'version-bump' | 'code-change' | 'config-change' | 'manual';
  description: string;
  diff?: string;
  commands?: string[];
  confidence: number;
}

// Detailed fix types for Fixer Agent
export type FixStrategy = 'version-bump' | 'code-change' | 'config-change' | 'env-var' | 'remove' | 'manual';

export interface FixResult {
  findingId: string;
  finding: Finding;
  fixable: boolean;
  strategy: FixStrategy;
  // For version bumps
  package?: string;
  currentVersion?: string;
  fixedVersion?: string;
  // The actual fix
  description: string;
  explanation: string;
  commands: string[];
  diff?: string;
  // Metadata
  confidence: number;
  breakingChangeRisk: 'none' | 'low' | 'medium' | 'high';
  testRequired: boolean;
  autoFixSafe: boolean;
}

export interface FixBatchResult {
  total: number;
  fixable: number;
  unfixable: number;
  fixes: FixResult[];
  summary: {
    versionBumps: number;
    codeChanges: number;
    configChanges: number;
    manual: number;
  };
  // Combined commands to fix all
  allCommands: string[];
}

export interface ApplyFixResult {
  findingId: string;
  success: boolean;
  applied: boolean;
  output?: string;
  error?: string;
}

export interface PRResult {
  findingId?: string;
  success: boolean;
  prUrl?: string;
  prNumber?: number;
  branch?: string;
  error?: string;
}

// Agent configuration
export interface SLOPAgentConfig {
  id: string;
  name: string;
  port: number;
  description: string;
  // Other agents this agent can communicate with
  peers?: { id: string; url: string }[];
  // Coordinator URL (if not the coordinator itself)
  coordinatorUrl?: string;
}

// Pipeline types
export interface PipelineStage {
  agent: string;
  tool: string;
  dependsOn?: string[];
}

export interface PipelineResult {
  stages: {
    agent: string;
    tool: string;
    result: unknown;
    duration: number;
  }[];
  totalDuration: number;
  success: boolean;
  error?: string;
}
