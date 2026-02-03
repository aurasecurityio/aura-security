/**
 * x402 Pricing Configuration
 *
 * Prices in USD and Solana lamports.
 * Update lamports based on current SOL price.
 */

// Assumes ~$200 SOL price. Update as needed.
// 1 SOL = 1,000,000,000 lamports
// $0.01 USD = 0.00005 SOL = 50,000 lamports (at $200/SOL)

export const PRICING: Record<string, { usd: number; lamports: number; description: string }> = {
  '/v1/rugcheck': {
    usd: 0.005,
    lamports: 25000,  // ~$0.005 at $200 SOL
    description: 'Quick trust score - repo age, commits, contributors'
  },
  '/v1/scamcheck': {
    usd: 0.01,
    lamports: 50000,  // ~$0.01 at $200 SOL
    description: 'Scam pattern detection - 20+ signatures'
  },
  '/v1/xcheck': {
    usd: 0.01,
    lamports: 50000,  // ~$0.01 at $200 SOL
    description: 'X/Twitter profile analysis - bot detection, legitimacy'
  }
};

/**
 * Get price for an endpoint
 */
export function getPrice(endpoint: string): { usd: number; lamports: number } | null {
  return PRICING[endpoint] || null;
}

/**
 * Update lamports prices based on current SOL price
 * Call this periodically to keep prices accurate
 */
export function updatePricesForSolRate(solPriceUsd: number): void {
  for (const endpoint of Object.keys(PRICING)) {
    const usdPrice = PRICING[endpoint].usd;
    const solAmount = usdPrice / solPriceUsd;
    PRICING[endpoint].lamports = Math.ceil(solAmount * 1_000_000_000);
  }
  console.log(`[X402] Updated prices for SOL @ $${solPriceUsd}`);
}

/**
 * Format price for display
 */
export function formatPrice(endpoint: string): string {
  const price = PRICING[endpoint];
  if (!price) return 'Unknown';
  return `$${price.usd} (${price.lamports} lamports)`;
}
