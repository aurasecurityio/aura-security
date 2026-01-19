/**
 * Aura Protocol - Scanner Agents
 *
 * Export all scanner agents.
 */

export { GitleaksAgent } from './gitleaks.js';
export { TrivyAgent } from './trivy.js';
export { SemgrepAgent } from './semgrep.js';
export { GrypeAgent } from './grype.js';
export { NpmAuditAgent } from './npm-audit.js';

import { GitleaksAgent } from './gitleaks.js';
import { TrivyAgent } from './trivy.js';
import { SemgrepAgent } from './semgrep.js';
import { GrypeAgent } from './grype.js';
import { NpmAuditAgent } from './npm-audit.js';
import { Agent } from '../types.js';

/**
 * Create all scanner agents
 */
export function createScannerAgents(): Agent[] {
  return [
    new GitleaksAgent(),
    new TrivyAgent(),
    new SemgrepAgent(),
    new GrypeAgent(),
    new NpmAuditAgent(),
  ];
}
