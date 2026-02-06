// Integration Hub - Connect external systems to aurasecurity
// Supports: GitHub, GitLab, Jenkins, Snyk, Trivy, Local System, and custom webhooks

export { WebhookServer, WebhookHandler } from './webhook.js';
export { GitHubIntegration } from './github.js';
export { GitLabIntegration } from './gitlab.js';
export { ScannerParser, SnykParser, TrivyParser, SemgrepParser } from './scanners.js';
export { ConfigLoader, AuditorConfig } from './config.js';
export { LocalScanner, quickLocalScan } from './local-scanner.js';
export type { LocalScanConfig, LocalScanResult, SecretFinding, PackageFinding, SastFinding, GitInfo, EnvFileFinding, SystemInfo, DiscoveredService, DiscoveredModule } from './local-scanner.js';
export { NotificationService, createNotificationFromAudit } from './notifications.js';

// AI Verifier - Detect real vs fake AI projects
export { performAIVerification } from './ai-verifier.js';
export type { AIVerifyResult } from './ai-verifier.js';

// Scam Detector - Code similarity & known scam pattern detection
export { detectScamPatterns, quickScamScan, getScamSignatures, addScamSignature } from './scam-detector.js';
export type { ScamSignature, ScamDetectionResult, SimilarityMatch } from './scam-detector.js';

// Aura Protocol Scanner (multi-agent architecture)
export { auraScan, getAuraState, getAvailableAgents, orchestrator } from './aura-scanner.js';
export type { AuraScanConfig, AuraScanResult } from './aura-scanner.js';
export type { NotificationConfig, NotificationPayload } from './notifications.js';

// Rug Database - Track confirmed rugs, dev reputation, feedback loop
export {
  reportRug,
  isKnownRug,
  hasOwnerRuggedBefore,
  getDevReputation,
  updateDevReputation,
  isDevFlagged,
  flagDeveloper,
  recordScan,
  submitFeedback,
  getAccuracyStats,
  addScamSignature as addScamSignatureToDb,
  isForkedFromScam,
  ownerHasScamSignatures,
  getDbStats,
  getRecentRugs,
  getFlaggedDevs,
  // X Account tracking (Phase 3)
  getXAccountReputation,
  updateXAccountReputation,
  recordXScan,
  isXAccountFlagged,
  flagXAccount,
  linkXToGithub,
  linkXToProject,
  submitXFeedback,
  getXScanHistory,
  getXDbStats
} from './rug-database.js';
export type { RugReport, DevReputation, XAccountReputation } from './rug-database.js';

// Enhanced Scanner - Trust scan with rug database intelligence
export { performEnhancedTrustScan, quickRugDbCheck } from './enhanced-scanner.js';
export type { EnhancedTrustResult } from './enhanced-scanner.js';

// Clawstr Integration - Nostr-based AI agent social network
export {
  ClawstrAgent,
  ClawstrClient,
  ClawstrMonitor,
  startClawstrAgent,
  generateClawstrKeys,
  formatScanResult as formatClawstrScanResult,
  makePostDecision as makeClawstrPostDecision,
  EVENT_KINDS as CLAWSTR_EVENT_KINDS,
  DEFAULT_CONFIG as CLAWSTR_DEFAULT_CONFIG,
} from './clawstr/index.js';
export type {
  ClawstrAgentStatus,
  ClawstrAgentConfig,
  NostrEvent,
  NostrKeyPair,
  ClawstrPost,
  ScanRequest as ClawstrScanRequest,
  MentionRequest as ClawstrMentionRequest,
} from './clawstr/index.js';

// Website Probe - Detect static vs active sites (rug detection)
export { probeWebsite, formatProbeResult } from './website-probe.js';
export type { ProbeResult, NetworkRequest } from './website-probe.js';
