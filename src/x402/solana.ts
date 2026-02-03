/**
 * Solana Payment Verification
 *
 * Verifies SOL payments on-chain.
 */

import { getPayment, markPaymentPaid } from './payments.js';

const SOLANA_RPC_URL = process.env.SOLANA_RPC_URL || 'https://api.mainnet-beta.solana.com';
const SOLANA_WALLET = process.env.SOLANA_WALLET || 'AuRaSecurityPayments111111111111111111111';

interface SolanaTransaction {
  slot: number;
  transaction: {
    message: {
      accountKeys: string[];
      instructions: Array<{
        programIdIndex: number;
        accounts: number[];
        data: string;
      }>;
    };
    signatures: string[];
  };
  meta: {
    err: any;
    fee: number;
    preBalances: number[];
    postBalances: number[];
    preTokenBalances: any[];
    postTokenBalances: any[];
    logMessages: string[];
  } | null;
  blockTime: number;
}

/**
 * Fetch transaction from Solana RPC
 */
async function getTransaction(signature: string): Promise<SolanaTransaction | null> {
  try {
    const response = await fetch(SOLANA_RPC_URL, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'getTransaction',
        params: [
          signature,
          {
            encoding: 'json',
            commitment: 'finalized',
            maxSupportedTransactionVersion: 0
          }
        ]
      })
    });

    const data = await response.json();
    return data.result || null;
  } catch (err) {
    console.error('[X402] Solana RPC error:', err);
    return null;
  }
}

/**
 * Decode memo from transaction logs
 */
function extractMemo(tx: SolanaTransaction): string | null {
  if (!tx.meta?.logMessages) return null;

  for (const log of tx.meta.logMessages) {
    // Memo program logs look like: "Program log: Memo (len X): <memo>"
    const memoMatch = log.match(/Memo \(len \d+\): (.+)/);
    if (memoMatch) {
      return memoMatch[1];
    }
  }

  return null;
}

/**
 * Verify a Solana payment
 */
export async function verifySolanaPayment(
  signature: string,
  paymentId: string
): Promise<{ valid: boolean; error?: string }> {
  // Get payment details
  const payment = getPayment(paymentId);
  if (!payment) {
    return { valid: false, error: 'Payment not found' };
  }

  if (payment.status === 'paid' || payment.status === 'used') {
    // Already verified
    return { valid: true };
  }

  if (payment.status === 'expired') {
    return { valid: false, error: 'Payment expired' };
  }

  // Fetch transaction from chain
  console.log(`[X402] Verifying Solana tx: ${signature}`);
  const tx = await getTransaction(signature);

  if (!tx) {
    return { valid: false, error: 'Transaction not found. Wait for finalization and retry.' };
  }

  // Check for errors
  if (tx.meta?.err) {
    return { valid: false, error: 'Transaction failed on-chain' };
  }

  // Verify recipient received funds
  const accountKeys = tx.transaction.message.accountKeys;
  const walletIndex = accountKeys.findIndex(key => key === SOLANA_WALLET);

  if (walletIndex === -1) {
    return { valid: false, error: 'Payment not sent to correct wallet' };
  }

  // Calculate amount received
  const preBalance = tx.meta?.preBalances?.[walletIndex] || 0;
  const postBalance = tx.meta?.postBalances?.[walletIndex] || 0;
  const amountReceived = postBalance - preBalance;

  if (amountReceived < payment.amount_lamports) {
    return {
      valid: false,
      error: `Insufficient payment. Expected ${payment.amount_lamports} lamports, received ${amountReceived}`
    };
  }

  // Verify memo (optional but recommended)
  const memo = extractMemo(tx);
  if (memo && memo !== paymentId) {
    console.log(`[X402] Memo mismatch: expected ${paymentId}, got ${memo}`);
    // Don't fail on memo mismatch, just log it
  }

  // Payment verified - mark as paid
  markPaymentPaid(paymentId, signature);

  console.log(`[X402] Payment verified: ${paymentId} (${amountReceived} lamports)`);
  return { valid: true };
}

/**
 * Get current SOL price in USD (for dynamic pricing)
 */
export async function getSolPrice(): Promise<number | null> {
  try {
    // Use Jupiter price API
    const response = await fetch(
      'https://price.jup.ag/v4/price?ids=SOL'
    );
    const data = await response.json();
    return data.data?.SOL?.price || null;
  } catch (err) {
    console.error('[X402] Failed to fetch SOL price:', err);
    return null;
  }
}

/**
 * Generate payment instructions for a wallet
 */
export function getPaymentInstructions(paymentId: string, amountLamports: number): {
  wallet: string;
  amount_sol: string;
  amount_lamports: number;
  memo: string;
  instructions: string;
} {
  const amountSol = (amountLamports / 1_000_000_000).toFixed(9);

  return {
    wallet: SOLANA_WALLET,
    amount_sol: amountSol,
    amount_lamports: amountLamports,
    memo: paymentId,
    instructions: `Send ${amountSol} SOL to ${SOLANA_WALLET} with memo: ${paymentId}`
  };
}
