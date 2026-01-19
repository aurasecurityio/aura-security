// Test script - demonstrates auditor pipeline usage

import { AuraClient } from '../src/aura/client.js';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const AURA_URL = process.env.AURA_URL ?? 'http://127.0.0.1:3000';

async function testAudit(): Promise<void> {
  const client = new AuraClient({ baseUrl: AURA_URL });

  // Connect to Aura server
  try {
    await client.connect();
    console.log('Connected to Aura server');
  } catch (err) {
    console.error('Failed to connect:', err);
    process.exit(1);
  }

  // Load sample input
  const sampleInput = JSON.parse(
    readFileSync(join(__dirname, 'sample-input.json'), 'utf-8')
  );

  // Call audit tool
  console.log('\nCalling audit tool...\n');

  const result = await client.callTool({
    tool: 'audit',
    arguments: sampleInput
  });

  // Output result (pure JSON, no formatting)
  console.log(JSON.stringify(result, null, 2));

  await client.disconnect();
}

testAudit().catch(console.error);
