/**
 * Register Aura Security EAS Schema on Base
 *
 * Run once to register the attestation schema with EAS SchemaRegistry.
 * Save the returned schema UID in your .env as EAS_SCHEMA_UID.
 *
 * Usage: npx tsx scripts/register-schema.ts
 */

import { createWalletClient, createPublicClient, http } from 'viem';
import { privateKeyToAccount } from 'viem/accounts';
import { base } from 'viem/chains';

// Load .env
import { readFileSync, existsSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

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

const SCHEMA = 'bytes32 codeHash, uint256 criticalCount, uint256 highCount, uint256 mediumCount, bytes32 reportHash';

const SCHEMA_REGISTRY_ADDRESS = '0x4200000000000000000000000000000000000020' as const;

const SCHEMA_REGISTRY_ABI = [
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

  console.log(`Registering schema with EAS SchemaRegistry on Base...`);
  console.log(`  Attester: ${account.address}`);
  console.log(`  Schema: ${SCHEMA}`);
  console.log(`  Resolver: none`);
  console.log(`  Revocable: true`);

  const txHash = await walletClient.writeContract({
    address: SCHEMA_REGISTRY_ADDRESS,
    abi: SCHEMA_REGISTRY_ABI,
    functionName: 'register',
    args: [
      SCHEMA,
      '0x0000000000000000000000000000000000000000',  // No resolver
      true  // Revocable
    ]
  });

  console.log(`\nTransaction submitted: ${txHash}`);

  const receipt = await publicClient.waitForTransactionReceipt({ hash: txHash });
  console.log(`Transaction confirmed in block ${receipt.blockNumber}`);

  // Extract schema UID from logs
  if (receipt.logs.length > 0) {
    const schemaUID = receipt.logs[0].topics?.[1] || receipt.logs[0].data?.slice(0, 66);
    console.log(`\nSchema UID: ${schemaUID}`);
    console.log(`\nAdd to .env:`);
    console.log(`  EAS_SCHEMA_UID=${schemaUID}`);
    console.log(`\nView on EAS Explorer:`);
    console.log(`  https://base.easscan.org/schema/view/${schemaUID}`);
  }

  console.log(`\nGas used: ${receipt.gasUsed}`);
}

main().catch(err => {
  console.error('Failed:', err);
  process.exit(1);
});
