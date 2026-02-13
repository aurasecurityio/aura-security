import { createPublicClient, http, formatEther } from 'viem';
import { base } from 'viem/chains';

async function main() {
  const client = createPublicClient({ chain: base, transport: http('https://mainnet.base.org') });
  const address = '0xf59f965E9e339EadF2CDEACA1950E48cfa00DCd1';
  const balance = await client.getBalance({ address });
  console.log(`Address: ${address}`);
  console.log(`Balance: ${formatEther(balance)} ETH`);
  console.log(`Balance (wei): ${balance.toString()}`);

  if (balance === 0n) {
    console.log('\nWallet needs funding. Send ~$5 worth of ETH on Base to:');
    console.log(`  ${address}`);
    console.log('\nYou can bridge ETH to Base via:');
    console.log('  - https://bridge.base.org');
    console.log('  - Coinbase (native Base withdrawals)');
  }
}

main().catch(console.error);
