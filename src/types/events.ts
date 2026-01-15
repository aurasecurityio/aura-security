// SLOP Event Types - Strict schema definitions

export type ChangeEventType = 'pull_request' | 'deploy' | 'infra_change';
export type Environment = 'dev' | 'staging' | 'prod';
export type RiskTolerance = 'low' | 'medium' | 'high';
export type Severity = 'low' | 'medium' | 'high' | 'critical';
export type AgentState = 'idle' | 'analyzing' | 'conflict' | 'escalated' | 'blocked';
export type EventType = 'analysis_started' | 'finding_raised' | 'conflict_detected' | 'escalation_triggered';
export type EvidenceType = 'diff' | 'sbom' | 'scan' | 'provenance' | 'runtime';
export type AssuranceBreak = 'integrity' | 'access_control' | 'isolation' | 'auditability';

export interface ChangeEvent {
  id: string;
  type: ChangeEventType;
  environment: Environment;
  repo: string;
  commit: string;
  files_changed: string[];
  diff: string;
}

export interface EvidenceBundle {
  sbom?: string;
  vuln_scan?: string;
  sast_results?: string;
  iac_scan?: string;
  provenance?: string;
  runtime_delta?: string;
}

export interface PolicyContext {
  critical_assets: string[];
  risk_tolerance: RiskTolerance;
}

export interface AuditorInput {
  change_event: ChangeEvent;
  evidence_bundle: EvidenceBundle;
  policy_context: PolicyContext;
}

export interface EvidenceRef {
  type: EvidenceType;
  pointer: string;
}

export interface FindingPayload {
  severity: Severity;
  claim: string;
  attack_path: string[];
  affected_assets: string[];
  evidence_refs: EvidenceRef[];
  assurance_break: AssuranceBreak[];
  confidence: number;
}

export interface AuditEvent {
  event_type: EventType;
  target: string;
  payload: FindingPayload;
  timestamp: string;
}

export interface AuditorOutput {
  agent_id: string;
  agent_state: AgentState;
  events: AuditEvent[];
  meta: {
    assumptions: string[];
    uncertainties: string[];
  };
}
