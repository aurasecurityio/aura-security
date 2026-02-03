# AuraSecurity x402 Payment Integration Spec

## Overview

Enable pay-per-scan API access using the x402 protocol. Exchanges and developers can call our security scanning endpoints without API keys — they pay per request using crypto micropayments.

---

## Endpoints

### Public x402 Endpoints

| Endpoint | Method | Price | Description |
|----------|--------|-------|-------------|
| `/v1/rugcheck` | POST | $0.005 | Quick trust score (5 sec) |
| `/v1/scamcheck` | POST | $0.01 | Scam pattern detection (15 sec) |
| `/v1/scan` | POST | $0.02 | Full security audit (30 sec) |

Base URL: `https://api.aurasecurity.io`

---

## How x402 Works

### Flow

```
1. Client sends request WITHOUT payment
   POST /v1/rugcheck
   {"repo": "https://github.com/owner/repo"}

2. Server returns 402 Payment Required
   {
     "status": 402,
     "message": "Payment required",
     "payment": {
       "amount": "0.005",
       "currency": "USD",
       "methods": [
         {
           "type": "solana",
           "address": "AuRa...xyz",
           "amount_lamports": 25000,
           "memo": "scan:abc123"
         },
         {
           "type": "lightning",
           "invoice": "lnbc50n1p...",
           "amount_sats": 25
         }
       ],
       "expires_at": "2026-02-03T12:00:00Z",
       "payment_id": "pay_abc123"
     }
   }

3. Client pays via preferred method

4. Client retries with payment proof
   POST /v1/rugcheck
   X-Payment-Id: pay_abc123
   X-Payment-Signature: <transaction_signature>
   {"repo": "https://github.com/owner/repo"}

5. Server verifies payment, returns scan result
   {
     "score": 75,
     "grade": "B",
     "verdict": "DYOR",
     ...
   }
```

---

## Request Format

### Without Payment (Initial Request)

```http
POST /v1/rugcheck HTTP/1.1
Host: api.aurasecurity.io
Content-Type: application/json

{
  "repo": "https://github.com/owner/repo"
}
```

### With Payment Proof (After Payment)

```http
POST /v1/rugcheck HTTP/1.1
Host: api.aurasecurity.io
Content-Type: application/json
X-Payment-Id: pay_abc123
X-Payment-Signature: 5tG7h...txSig

{
  "repo": "https://github.com/owner/repo"
}
```

---

## Response Format

### 402 Payment Required

```json
{
  "status": 402,
  "message": "Payment required",
  "payment": {
    "amount": "0.01",
    "currency": "USD",
    "payment_id": "pay_abc123",
    "expires_at": "2026-02-03T12:05:00Z",
    "methods": [
      {
        "type": "solana",
        "network": "mainnet-beta",
        "address": "AuRaSecurityPayments111111111111111111111",
        "amount_lamports": 50000,
        "amount_usdc": 10000,
        "token": "USDC",
        "memo": "pay_abc123"
      },
      {
        "type": "lightning",
        "invoice": "lnbc100n1pj...",
        "amount_sats": 50
      }
    ]
  }
}
```

### 200 Success (After Payment Verified)

```json
{
  "payment_id": "pay_abc123",
  "scan_id": "scan_xyz789",
  "repo": "https://github.com/owner/repo",
  "score": 75,
  "grade": "B",
  "verdict": "DYOR",
  "verdictEmoji": "🟡",
  "checks": [...],
  "redFlags": [...],
  "greenFlags": [...],
  "scannedAt": "2026-02-03T12:00:05Z"
}
```

### 400 Bad Request

```json
{
  "status": 400,
  "error": "Invalid GitHub URL",
  "message": "Please provide a valid GitHub repository URL"
}
```

### 402 Payment Failed/Expired

```json
{
  "status": 402,
  "error": "Payment not found or expired",
  "message": "Payment pay_abc123 has expired. Please request a new payment."
}
```

---

## Payment Methods

### 1. Solana (Primary)

Accept both SOL and USDC on Solana mainnet.

**Verification:**
- Check transaction exists on-chain
- Verify amount matches or exceeds required amount
- Verify recipient address matches our wallet
- Verify memo contains payment_id
- Confirm transaction is finalized (not just confirmed)

**Our Wallet:** `AuRaSecurityPayments111111111111111111111` (example)

### 2. Lightning Network (Secondary)

Accept Lightning payments via BOLT11 invoices.

**Verification:**
- Generate unique invoice per payment_id
- Use LND or similar to verify payment received
- Invoice expires after 5 minutes

---

## Implementation Plan

### Phase 1: Core Infrastructure

**File:** `src/x402/index.ts`

```typescript
// Payment middleware
export class X402Middleware {
  // Check if request has valid payment
  async verifyPayment(req: Request): Promise<PaymentStatus>

  // Generate payment request for 402 response
  async createPaymentRequest(endpoint: string, price: number): Promise<PaymentRequest>

  // Verify Solana transaction
  async verifySolanaPayment(signature: string, paymentId: string): Promise<boolean>

  // Verify Lightning payment
  async verifyLightningPayment(paymentId: string): Promise<boolean>
}
```

**File:** `src/x402/payments.ts`

```typescript
interface Payment {
  id: string;
  endpoint: string;
  amount_usd: number;
  amount_lamports: number;
  amount_sats: number;
  status: 'pending' | 'paid' | 'expired' | 'used';
  solana_address: string;
  lightning_invoice?: string;
  created_at: Date;
  expires_at: Date;
  paid_at?: Date;
  tx_signature?: string;
}
```

**File:** `src/x402/pricing.ts`

```typescript
export const PRICING = {
  '/v1/rugcheck': { usd: 0.005, lamports: 25000, sats: 25 },
  '/v1/scamcheck': { usd: 0.01, lamports: 50000, sats: 50 },
  '/v1/scan': { usd: 0.02, lamports: 100000, sats: 100 },
};
```

### Phase 2: Database Schema

Add `payments` table:

```sql
CREATE TABLE payments (
  id TEXT PRIMARY KEY,
  endpoint TEXT NOT NULL,
  amount_usd REAL NOT NULL,
  amount_lamports INTEGER NOT NULL,
  amount_sats INTEGER NOT NULL,
  status TEXT DEFAULT 'pending',
  solana_address TEXT NOT NULL,
  lightning_invoice TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  paid_at TEXT,
  tx_signature TEXT,
  used_at TEXT,
  client_ip TEXT,
  repo_url TEXT
);

CREATE INDEX idx_payments_status ON payments(status);
CREATE INDEX idx_payments_expires ON payments(expires_at);
```

### Phase 3: API Routes

**File:** `src/x402/routes.ts`

```typescript
// Wrap existing scan handlers with x402 middleware
app.post('/v1/rugcheck', x402Middleware, async (req, res) => {
  const result = await performTrustScan(req.body.repo);
  res.json(result);
});

app.post('/v1/scamcheck', x402Middleware, async (req, res) => {
  const result = await performScamScan(req.body.repo);
  res.json(result);
});

app.post('/v1/scan', x402Middleware, async (req, res) => {
  const result = await performFullScan(req.body.repo);
  res.json(result);
});
```

### Phase 4: Solana Integration

**Dependencies:**
```json
{
  "@solana/web3.js": "^1.87.0",
  "@solana/spl-token": "^0.3.8"
}
```

**Verification Logic:**

```typescript
import { Connection, PublicKey } from '@solana/web3.js';

async function verifySolanaPayment(
  signature: string,
  expectedAmount: number,
  expectedMemo: string
): Promise<boolean> {
  const connection = new Connection('https://api.mainnet-beta.solana.com');

  const tx = await connection.getTransaction(signature, {
    commitment: 'finalized',
    maxSupportedTransactionVersion: 0
  });

  if (!tx) return false;

  // Verify recipient
  const ourWallet = new PublicKey(process.env.SOLANA_WALLET!);
  const transferredToUs = tx.transaction.message.accountKeys.some(
    key => key.equals(ourWallet)
  );

  if (!transferredToUs) return false;

  // Verify amount (check postBalances - preBalances)
  // Verify memo matches payment_id

  return true;
}
```

### Phase 5: Lightning Integration (Optional)

Use LNbits, Alby, or self-hosted LND.

```typescript
// Using LNbits API
async function createLightningInvoice(amount_sats: number, memo: string): Promise<string> {
  const response = await fetch(`${LNBITS_URL}/api/v1/payments`, {
    method: 'POST',
    headers: {
      'X-Api-Key': process.env.LNBITS_API_KEY!,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      out: false,
      amount: amount_sats,
      memo: memo,
      expiry: 300 // 5 minutes
    })
  });

  const data = await response.json();
  return data.payment_request;
}
```

---

## Pricing Strategy

### Base Prices (USD)

| Endpoint | Price | Rationale |
|----------|-------|-----------|
| rugcheck | $0.005 | Quick metadata check, low compute |
| scamcheck | $0.01 | Pattern matching, medium compute |
| scan | $0.02 | Full analysis, high compute |

### Volume Projections

| Daily Scans | Revenue/Day | Revenue/Month |
|-------------|-------------|---------------|
| 1,000 | $10-20 | $300-600 |
| 10,000 | $100-200 | $3,000-6,000 |
| 100,000 | $1,000-2,000 | $30,000-60,000 |

### Price Conversion

Update prices based on SOL/USD rate. Fetch from Pyth or Jupiter price feeds.

```typescript
async function getLamportsPrice(usd: number): Promise<number> {
  const solPrice = await fetchSolPrice(); // e.g., $100
  const solAmount = usd / solPrice;
  return Math.ceil(solAmount * 1_000_000_000); // lamports
}
```

---

## Security Considerations

1. **Replay Protection** — Each payment_id can only be used once. Mark as 'used' after successful scan.

2. **Expiration** — Payments expire after 5 minutes. Prevents stale payment attacks.

3. **Amount Verification** — Always verify on-chain amount >= expected amount. Don't trust client-provided values.

4. **Rate Limiting** — Even with payments, rate limit by IP to prevent abuse (100 req/min).

5. **Refunds** — No automatic refunds. If scan fails after payment, credit the payment_id for retry.

---

## Client SDK (Optional)

Provide a simple SDK for exchanges:

```typescript
import { AuraSecurity } from '@aurasecurity/sdk';

const aura = new AuraSecurity({
  solanaWallet: wallet, // or
  lightningNode: lnd
});

// Handles payment automatically
const result = await aura.rugcheck('https://github.com/owner/repo');
console.log(result.score, result.verdict);
```

---

## Documentation Page

Create public docs at `https://api.aurasecurity.io/docs`:

1. **Getting Started** — How x402 works, payment flow
2. **Endpoints** — Request/response formats for each endpoint
3. **Payment Methods** — How to pay with Solana or Lightning
4. **Code Examples** — curl, JavaScript, Python
5. **Pricing** — Current prices and volume discounts
6. **SDKs** — Links to client libraries

---

## Files to Create

| File | Purpose |
|------|---------|
| `src/x402/index.ts` | Main exports |
| `src/x402/middleware.ts` | Express middleware for payment verification |
| `src/x402/payments.ts` | Payment creation and management |
| `src/x402/solana.ts` | Solana payment verification |
| `src/x402/lightning.ts` | Lightning payment verification |
| `src/x402/pricing.ts` | Price configuration |
| `src/x402/routes.ts` | API route handlers |
| `src/x402/types.ts` | TypeScript interfaces |

---

## Environment Variables

```bash
# Solana
SOLANA_WALLET=AuRaSecurityPayments111111111111111111111
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com

# Lightning (optional)
LNBITS_URL=https://legend.lnbits.com
LNBITS_API_KEY=your_api_key

# Pricing
X402_RUGCHECK_PRICE_USD=0.005
X402_SCAMCHECK_PRICE_USD=0.01
X402_SCAN_PRICE_USD=0.02
```

---

## Implementation Order

1. **Week 1:** Core infrastructure (payments table, middleware, pricing)
2. **Week 2:** Solana integration (wallet setup, verification logic)
3. **Week 3:** API routes, testing with testnet
4. **Week 4:** Documentation, mainnet deployment
5. **Week 5:** Lightning integration (optional), SDK

---

## Success Metrics

- Time to first paid scan
- Daily payment volume
- Unique paying clients
- Payment success rate (paid / requested)
- Average scans per client

---

## Example Integration for Axiom

```javascript
// Axiom's backend
async function checkRepoSecurity(repoUrl) {
  // 1. Request scan
  let response = await fetch('https://api.aurasecurity.io/v1/rugcheck', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ repo: repoUrl })
  });

  // 2. If 402, pay and retry
  if (response.status === 402) {
    const { payment } = await response.json();

    // Pay via Solana
    const txSig = await paySolana(
      payment.methods[0].address,
      payment.methods[0].amount_lamports,
      payment.methods[0].memo
    );

    // Retry with payment proof
    response = await fetch('https://api.aurasecurity.io/v1/rugcheck', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Payment-Id': payment.payment_id,
        'X-Payment-Signature': txSig
      },
      body: JSON.stringify({ repo: repoUrl })
    });
  }

  return response.json();
}
```

---

## Next Steps

1. Set up Solana wallet for receiving payments
2. Create payments table in database
3. Build middleware and verification logic
4. Test on devnet
5. Deploy to production
6. Announce to Axiom and other exchanges
