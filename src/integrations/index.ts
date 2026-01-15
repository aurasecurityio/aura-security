// Integration Hub - Connect external systems to SLOP Auditor
// Supports: GitHub, GitLab, Jenkins, Snyk, Trivy, Local System, and custom webhooks

export { WebhookServer, WebhookHandler } from './webhook.js';
export { GitHubIntegration } from './github.js';
export { GitLabIntegration } from './gitlab.js';
export { ScannerParser, SnykParser, TrivyParser, SemgrepParser } from './scanners.js';
export { ConfigLoader, AuditorConfig } from './config.js';
export { LocalScanner, quickLocalScan } from './local-scanner.js';
export type { LocalScanConfig, LocalScanResult, SecretFinding, PackageFinding, SastFinding, GitInfo, EnvFileFinding, SystemInfo, DiscoveredService, DiscoveredModule } from './local-scanner.js';
export { NotificationService, createNotificationFromAudit } from './notifications.js';
export type { NotificationConfig, NotificationPayload } from './notifications.js';
