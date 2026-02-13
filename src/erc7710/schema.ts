/**
 * EAS Schema Definition for Aura Security Attestations
 *
 * Schema: bytes32 codeHash, uint256 criticalCount, uint256 highCount, uint256 mediumCount, bytes32 reportHash
 * Deployed on Base mainnet via EAS SchemaRegistry.
 */

import type { BaseChainConfig } from './types.js';

/** The schema string registered with EAS */
export const AURA_SCHEMA = 'bytes32 codeHash, uint256 criticalCount, uint256 highCount, uint256 mediumCount, bytes32 reportHash';

/**
 * Schema UID — set after registration via scripts/register-schema.ts.
 * Update this value after running the registration script.
 */
export const AURA_SCHEMA_UID: `0x${string}` = (process.env.EAS_SCHEMA_UID as `0x${string}`) ||
  '0x0000000000000000000000000000000000000000000000000000000000000000';

/** EAS contract addresses on Base mainnet */
export const BASE_CONFIG: BaseChainConfig = {
  rpcUrl: process.env.BASE_RPC_URL || 'https://mainnet.base.org',
  chainId: 8453,
  easContractAddress: '0x4200000000000000000000000000000000000021',
  schemaRegistryAddress: '0x4200000000000000000000000000000000000020',
  explorerUrl: 'https://basescan.org',
  easExplorerUrl: 'https://base.easscan.org'
};

/** ABI for EAS SchemaRegistry.register() */
export const SCHEMA_REGISTRY_ABI = [
  {
    name: 'register',
    type: 'function',
    stateMutability: 'nonpayable',
    inputs: [
      { name: 'schema', type: 'string' },
      { name: 'resolver', type: 'address' },
      { name: 'revocable', type: 'bool' }
    ],
    outputs: [{ name: '', type: 'bytes32' }]
  }
] as const;

/** ABI for EAS.attest() */
export const EAS_ABI = [
  {
    name: 'attest',
    type: 'function',
    stateMutability: 'payable',
    inputs: [
      {
        name: 'request',
        type: 'tuple',
        components: [
          { name: 'schema', type: 'bytes32' },
          {
            name: 'data',
            type: 'tuple',
            components: [
              { name: 'recipient', type: 'address' },
              { name: 'expirationTime', type: 'uint64' },
              { name: 'revocable', type: 'bool' },
              { name: 'refUID', type: 'bytes32' },
              { name: 'data', type: 'bytes' },
              { name: 'value', type: 'uint256' }
            ]
          }
        ]
      }
    ],
    outputs: [{ name: '', type: 'bytes32' }]
  },
  {
    name: 'getAttestation',
    type: 'function',
    stateMutability: 'view',
    inputs: [{ name: 'uid', type: 'bytes32' }],
    outputs: [
      {
        name: '',
        type: 'tuple',
        components: [
          { name: 'uid', type: 'bytes32' },
          { name: 'schema', type: 'bytes32' },
          { name: 'time', type: 'uint64' },
          { name: 'expirationTime', type: 'uint64' },
          { name: 'revocationTime', type: 'uint64' },
          { name: 'refUID', type: 'bytes32' },
          { name: 'recipient', type: 'address' },
          { name: 'attester', type: 'address' },
          { name: 'revocable', type: 'bool' },
          { name: 'data', type: 'bytes' }
        ]
      }
    ]
  }
] as const;
