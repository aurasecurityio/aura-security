/**
 * EAS Attestation Publisher for Aura Security
 *
 * Runs existing Aura scans (trust/scam/fullprobe), hashes the results,
 * and publishes attestations to EAS on Base mainnet.
 *
 * Flow:
 *   1. Accept scan request (target + scanType)
 *   2. Run the appropriate Aura scan
 *   3. Count findings by severity
 *   4. Hash target identifier and full report
 *   5. ABI-encode attestation data
 *   6. Publish to EAS via Base RPC
 *   7. Return attestation UID
 */

import {
  createWalletClient,
  createPublicClient,
  http,
  encodeAbiParameters,
  keccak256,
  toBytes,
  parseAbiParameters
} from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';

import { performTrustScan } from '../integrations/trust-scanner.js';
import { quickScamScan } from '../integrations/scam-detector.js';
import { probeWebsite } from '../integrations/website-probe.js';

import { AURA_SCHEMA_UID, BASE_CONFIG, EAS_ABI } from './schema.js';
import type { AttestInput, AttestResult, AttestationData, FindingCounts, AttestScanType } from './types.js';

const ZERO_BYTES32 = '0x0000000000000000000000000000000000000000000000000000000000000000' as `0x${string}`;
const ZERO_ADDRESS = '0x0000000000000000000000000000000000000000' as `0x${string}`;

/**
 * Get the Base wallet account from environment
 */
function getAccount() {
  const privateKey = process.env.BASE_PRIVATE_KEY;
  if (!privateKey) {
    throw new Error('BASE_PRIVATE_KEY not set. Generate a wallet and fund it with ETH on Base.');
  }
  const key = privateKey.startsWith('0x') ? privateKey as `0x${string}` : `0x${privateKey}` as `0x${string}`;
  return privateKeyToAccount(key);
}

/**
 * Create viem clients for Base
 */
function createClients() {
  const account = getAccount();
  const transport = http(BASE_CONFIG.rpcUrl);

  const walletClient = createWalletClient({
    account,
    chain: base,
    transport
  });

  const publicClient = createPublicClient({
    chain: base,
    transport
  });

  return { walletClient, publicClient, account };
}

/**
 * Run a scan and return raw results
 */
async function runScan(scanType: AttestScanType, target: string): Promise<any> {
  console.log(`[ERC7710] Running ${scanType} scan on: ${target}`);

  switch (scanType) {
    case 'rugcheck': {
      return await performTrustScan(target);
    }

    case 'scamcheck': {
      // Parse GitHub URL to fetch files for scam scan
      const githubMatch = target.match(/github\.com\/([^/]+)\/([^/]+)/);
      if (!githubMatch) {
        throw new Error('scamcheck requires a GitHub URL');
      }

      const owner = githubMatch[1];
      const repoName = githubMatch[2].replace(/\.git$/, '');

      const headers: Record<string, string> = {
        'User-Agent': 'AuraSecurityBot/1.0',
        'Accept': 'application/vnd.github.v3+json'
      };
      if (process.env.GITHUB_TOKEN) {
        headers['Authorization'] = `token ${process.env.GITHUB_TOKEN}`;
      }

      const treeRes = await fetch(
        `https://api.github.com/repos/${owner}/${repoName}/git/trees/HEAD?recursive=1`,
        { headers }
      );

      if (!treeRes.ok) {
        throw new Error(`Failed to fetch repository: ${treeRes.status}`);
      }

      const treeData = await treeRes.json();
      const files = treeData.tree?.filter((f: any) => f.type === 'blob').map((f: any) => f.path) || [];

      // Fetch README
      let readme = '';
      const readmeFile = files.find((f: string) => f.toLowerCase().includes('readme'));
      if (readmeFile) {
        try {
          const readmeRes = await fetch(
            `https://api.github.com/repos/${owner}/${repoName}/contents/${readmeFile}`,
            { headers }
          );
          if (readmeRes.ok) {
            const readmeData = await readmeRes.json();
            if (readmeData.content) {
              readme = Buffer.from(readmeData.content, 'base64').toString('utf-8');
            }
          }
        } catch { /* skip */ }
      }

      return await quickScamScan(files, readme, undefined, repoName);
    }

    case 'fullprobe': {
      const probeResult = await probeWebsite(target);

      // Also try trust scan if we can find a GitHub link
      let trustResult = null;
      const allUrls = [...probeResult.apiCalls.map((a: any) => a.url), target];
      for (const u of allUrls) {
        const githubMatch = u.match(/github\.com\/([^/]+\/[^/\s]+)/i);
        if (githubMatch) {
          try {
            trustResult = await performTrustScan(`https://github.com/${githubMatch[1]}`);
          } catch { /* skip */ }
          break;
        }
      }

      return { probe: probeResult, trust: trustResult };
    }

    default:
      throw new Error(`Unknown scan type: ${scanType}`);
  }
}

/**
 * Count findings by severity from scan results
 */
function countFindings(scanType: AttestScanType, scanResult: any): FindingCounts {
  switch (scanType) {
    case 'rugcheck': {
      // Trust scanner uses status: 'bad' (critical/high) and 'warn' (medium)
      const checks = scanResult.checks || [];
      const bad = checks.filter((c: any) => c.status === 'bad').length;
      const warn = checks.filter((c: any) => c.status === 'warn').length;

      // Trust score below 30 = critical, below 50 = high
      const critical = scanResult.trustScore < 30 ? bad : 0;
      const high = scanResult.trustScore < 30 ? 0 : bad;

      return { critical, high, medium: warn };
    }

    case 'scamcheck': {
      // Quick scam scan returns riskLevel
      const riskLevel = scanResult.riskLevel || 'low';
      const flagCount = (scanResult.redFlags || []).length;

      if (riskLevel === 'critical') return { critical: flagCount, high: 0, medium: 0 };
      if (riskLevel === 'high') return { critical: 0, high: flagCount, medium: 0 };
      if (riskLevel === 'medium') return { critical: 0, high: 0, medium: flagCount };
      return { critical: 0, high: 0, medium: 0 };
    }

    case 'fullprobe': {
      let critical = 0, high = 0, medium = 0;

      // From probe
      const probe = scanResult.probe;
      if (probe) {
        if (probe.riskLevel === 'HIGH') critical++;
        else if (probe.riskLevel === 'MEDIUM') high++;
        if (probe.verdict === 'SUSPICIOUS') critical++;
      }

      // From trust scan (if available)
      const trust = scanResult.trust;
      if (trust) {
        const badChecks = (trust.checks || []).filter((c: any) => c.status === 'bad').length;
        const warnChecks = (trust.checks || []).filter((c: any) => c.status === 'warn').length;
        if (trust.trustScore < 30) critical += badChecks;
        else high += badChecks;
        medium += warnChecks;
      }

      return { critical, high, medium };
    }

    default:
      return { critical: 0, high: 0, medium: 0 };
  }
}

/**
 * Run a scan and publish the results as an EAS attestation on Base
 */
export async function scanAndAttest(input: AttestInput): Promise<AttestResult> {
  const { target, scanType } = input;

  // 1. Run the scan
  const scanResult = await runScan(scanType, target);

  // 2. Count findings
  const findings = countFindings(scanType, scanResult);

  // 3. Compute hashes
  const codeHash = keccak256(toBytes(target));
  const reportHash = keccak256(toBytes(JSON.stringify(scanResult)));

  // 4. ABI-encode attestation data
  const encodedData = encodeAbiParameters(
    parseAbiParameters('bytes32, uint256, uint256, uint256, bytes32'),
    [codeHash, BigInt(findings.critical), BigInt(findings.high), BigInt(findings.medium), reportHash]
  );

  // 5. Publish to EAS on Base
  const { walletClient, publicClient } = createClients();

  const attestationData: AttestationData = {
    codeHash,
    criticalCount: BigInt(findings.critical),
    highCount: BigInt(findings.high),
    mediumCount: BigInt(findings.medium),
    reportHash
  };

  console.log(`[ERC7710] Publishing attestation to EAS on Base...`);
  console.log(`[ERC7710]   codeHash: ${codeHash}`);
  console.log(`[ERC7710]   findings: ${findings.critical}C / ${findings.high}H / ${findings.medium}M`);

  // Call EAS.attest()
  const txHash = await walletClient.writeContract({
    address: BASE_CONFIG.easContractAddress,
    abi: EAS_ABI,
    functionName: 'attest',
    args: [{
      schema: AURA_SCHEMA_UID,
      data: {
        recipient: ZERO_ADDRESS,
        expirationTime: 0n,
        revocable: true,
        refUID: ZERO_BYTES32,
        data: encodedData,
        value: 0n
      }
    }]
  });

  console.log(`[ERC7710] Transaction submitted: ${txHash}`);

  // Wait for receipt
  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  // Extract attestation UID from logs
  // EAS emits Attested(address indexed recipient, address indexed attester, bytes32 uid, bytes32 indexed schema)
  // The UID is in the third topic or data — we extract from the first log's data
  let attestationUID = ZERO_BYTES32;
  if (receipt.logs.length > 0) {
    const log = receipt.logs[0];
    // The UID is typically the non-indexed parameter in the event data
    if (log.data && log.data.length >= 66) {
      attestationUID = `0x${log.data.slice(2, 66)}` as `0x${string}`;
    }
    // Fallback: check topics
    if (attestationUID === ZERO_BYTES32 && log.topics && log.topics.length > 2) {
      attestationUID = log.topics[2] as `0x${string}`;
    }
  }

  console.log(`[ERC7710] Attestation published: ${attestationUID}`);

  const easExplorerUrl = `${BASE_CONFIG.easExplorerUrl}/attestation/view/${attestationUID}`;

  return {
    attestationUID,
    chain: 'base',
    attestationData,
    scanSummary: scanResult,
    easExplorerUrl
  };
}

/**
 * Get the Aura attester address (for enforcer deployment)
 */
export function getAttesterAddress(): `0x${string}` {
  const account = getAccount();
  return account.address;
}
