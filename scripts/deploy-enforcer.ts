/**
 * Deploy SecurityScanEnforcer to Base
 *
 * Deploys the compiled SecurityScanEnforcer contract to Base mainnet.
 * Requires the compiled bytecode (from solc or pre-compiled).
 *
 * Usage: npx tsx scripts/deploy-enforcer.ts
 *
 * Prerequisites:
 *   1. BASE_PRIVATE_KEY in .env (funded with ETH on Base)
 *   2. EAS_SCHEMA_UID in .env (from register-schema.ts)
 *   3. Compiled contract bytecode
 */

import { createWalletClient, createPublicClient, http, encodeAbiParameters, parseAbiParameters } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Load .env
const envPath = join(__dirname, '..', '.env');
if (existsSync(envPath)) {
  const envContent = readFileSync(envPath, 'utf-8');
  for (const line of envContent.split('\n')) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const eqIndex = trimmed.indexOf('=');
      if (eqIndex > 0) {
        const key = trimmed.slice(0, eqIndex).trim();
        let value = trimmed.slice(eqIndex + 1).trim();
        if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) {
          value = value.slice(1, -1);
        }
        if (!process.env[key]) {
          process.env[key] = value;
        }
      }
    }
  }
}

/** EAS contract address on Base */
const EAS_ADDRESS = '0x4200000000000000000000000000000000000021' as const;

/**
 * SecurityScanEnforcer ABI (for verification after deployment)
 */
const ENFORCER_ABI = [
  {
    name: 'eas',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }]
  },
  {
    name: 'auraAttester',
    type: 'function',
    stateMutability: 'view',
    inputs: [],
    outputs: [{ name: '', type: 'address' }]
  },
  {
    name: 'beforeHook',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'terms', type: 'bytes' },
      { name: 'args', type: 'bytes' },
      { name: 'delegationHash', type: 'bytes32' }
    ],
    outputs: []
  },
  {
    name: 'afterHook',
    type: 'function',
    stateMutability: 'view',
    inputs: [
      { name: 'terms', type: 'bytes' },
      { name: 'args', type: 'bytes' },
      { name: 'delegationHash', type: 'bytes32' }
    ],
    outputs: []
  }
] as const;

async function main() {
  const privateKey = process.env.BASE_PRIVATE_KEY;
  if (!privateKey) {
    console.error('Set BASE_PRIVATE_KEY in .env');
    process.exit(1);
  }

  const key = privateKey.startsWith('0x') ? privateKey as `0x${string}` : `0x${privateKey}` as `0x${string}`;
  const account = privateKeyToAccount(key);
  const transport = http(process.env.BASE_RPC_URL || 'https://mainnet.base.org');

  const walletClient = createWalletClient({ account, chain: base, transport });
  const publicClient = createPublicClient({ chain: base, transport });

  const auraAttester = account.address;

  console.log(`Deploying SecurityScanEnforcer to Base...`);
  console.log(`  Deployer: ${account.address}`);
  console.log(`  EAS: ${EAS_ADDRESS}`);
  console.log(`  Aura Attester: ${auraAttester}`);

  // Load compiled bytecode
  // To compile: solc --optimize --bin contracts/SecurityScanEnforcer.sol -o contracts/build/
  const bytecodePath = join(__dirname, '..', 'contracts', 'build', 'SecurityScanEnforcer.bin');

  if (!existsSync(bytecodePath)) {
    console.error(`\nCompiled bytecode not found at: ${bytecodePath}`);
    console.error(`\nCompile the contract first:`);
    console.error(`  solc --optimize --bin --abi contracts/SecurityScanEnforcer.sol -o contracts/build/`);
    console.error(`\nOr install solc:`);
    console.error(`  npm install -g solc`);
    process.exit(1);
  }

  const bytecode = `0x${readFileSync(bytecodePath, 'utf-8').trim()}` as `0x${string}`;

  // Encode constructor arguments: (address _eas, address _auraAttester)
  const constructorArgs = encodeAbiParameters(
    parseAbiParameters('address, address'),
    [EAS_ADDRESS, auraAttester]
  );

  // Deploy: bytecode + constructor args
  const deployData = `${bytecode}${constructorArgs.slice(2)}` as `0x${string}`;

  const txHash = await walletClient.sendTransaction({
    data: deployData
  });

  console.log(`\nTransaction submitted: ${txHash}`);

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });

  if (!receipt.contractAddress) {
    console.error('Deployment failed — no contract address in receipt');
    process.exit(1);
  }

  console.log(`\nSecurityScanEnforcer deployed!`);
  console.log(`  Address: ${receipt.contractAddress}`);
  console.log(`  Block: ${receipt.blockNumber}`);
  console.log(`  Gas used: ${receipt.gasUsed}`);

  // Verify constructor args
  const easAddr = await publicClient.readContract({
    address: receipt.contractAddress,
    abi: ENFORCER_ABI,
    functionName: 'eas'
  });

  const attesterAddr = await publicClient.readContract({
    address: receipt.contractAddress,
    abi: ENFORCER_ABI,
    functionName: 'auraAttester'
  });

  console.log(`\nVerification:`);
  console.log(`  eas(): ${easAddr} ${easAddr === EAS_ADDRESS ? '(correct)' : '(MISMATCH!)'}`);
  console.log(`  auraAttester(): ${attesterAddr} ${attesterAddr === auraAttester ? '(correct)' : '(MISMATCH!)'}`);

  console.log(`\nAdd to .env:`);
  console.log(`  ENFORCER_ADDRESS=${receipt.contractAddress}`);
  console.log(`\nView on BaseScan:`);
  console.log(`  https://basescan.org/address/${receipt.contractAddress}`);
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
