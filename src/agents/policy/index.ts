/**
 * Aura Protocol - Policy Agents
 *
 * Export all policy agents.
 */

export { PolicyEvaluatorAgent } from './evaluator.js';
export { ValidatorAgent } from './validator.js';

import { PolicyEvaluatorAgent } from './evaluator.js';
import { ValidatorAgent } from './validator.js';
import { Agent } from '../types.js';

/**
 * Create all policy agents
 */
export function createPolicyAgents(): Agent[] {
  return [new PolicyEvaluatorAgent(), new ValidatorAgent()];
}
