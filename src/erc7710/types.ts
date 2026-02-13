/**
 * ERC-7710 Security-Gated Delegation Types
 *
 * Types for Aura Security attestations published to EAS on Base,
 * and for the SecurityScanEnforcer caveat enforcer contract.
 */

/** Scan types that can produce attestations */
export type AttestScanType = 'rugcheck' | 'scamcheck' | 'fullprobe';

/** Input to the /v1/attest endpoint */
export interface AttestInput {
  /** Target to scan — GitHub URL or website URL */
  target: string;
  /** Which scan to run */
  scanType: AttestScanType;
}

/** Severity counts extracted from scan results */
export interface FindingCounts {
  critical: number;
  high: number;
  medium: number;
}

/** Data encoded into the EAS attestation */
export interface AttestationData {
  /** keccak256 of the scan target identifier */
  codeHash: `0x${string}`;
  /** Number of critical findings */
  criticalCount: bigint;
  /** Number of high findings */
  highCount: bigint;
  /** Number of medium findings */
  mediumCount: bigint;
  /** keccak256 of the full scan result JSON */
  reportHash: `0x${string}`;
}

/** Result returned from scanAndAttest */
export interface AttestResult {
  /** EAS attestation UID */
  attestationUID: string;
  /** Chain where attestation was published */
  chain: 'base';
  /** The encoded attestation data */
  attestationData: AttestationData;
  /** Summary of scan results */
  scanSummary: any;
  /** Link to view attestation on EAS explorer */
  easExplorerUrl: string;
}

/** Terms for the SecurityScanEnforcer contract */
export interface ScanTerms {
  /** Hash of code being delegated to */
  targetCodeHash: `0x${string}`;
  /** Max seconds since scan */
  maxAge: bigint;
  /** Max critical findings allowed (usually 0) */
  maxCritical: bigint;
  /** Max high findings allowed */
  maxHigh: bigint;
}

/** Base chain configuration */
export interface BaseChainConfig {
  rpcUrl: string;
  chainId: number;
  easContractAddress: `0x${string}`;
  schemaRegistryAddress: `0x${string}`;
  explorerUrl: string;
  easExplorerUrl: string;
}
