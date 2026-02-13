/**
 * ERC-7710 Security-Gated Delegation
 *
 * Aura Security attestations on EAS (Base) + SecurityScanEnforcer caveat enforcer.
 */

export * from './types.js';
export { AURA_SCHEMA, AURA_SCHEMA_UID, BASE_CONFIG, EAS_ABI, SCHEMA_REGISTRY_ABI } from './schema.js';
export { scanAndAttest, getAttesterAddress } from './attestation.js';
