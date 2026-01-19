/**
 * Aura Protocol - Agents
 *
 * Export all agents and agent utilities.
 */

export * from './types.js';
export * from './base.js';
export * from './scanners/index.js';
export * from './policy/index.js';

import { createScannerAgents } from './scanners/index.js';
import { createPolicyAgents } from './policy/index.js';
import { Agent } from './types.js';

/**
 * Create all default agents
 */
export function createAllAgents(): Agent[] {
  return [...createScannerAgents(), ...createPolicyAgents()];
}
