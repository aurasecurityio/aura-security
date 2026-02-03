/**
 * x402 Payment Management
 *
 * Creates, stores, and manages payment requests.
 * Uses SQLite for persistence.
 */

import { randomBytes } from 'crypto';
import type { Payment, PaymentRequest, PaymentMethod } from './types.js';
import { getPrice } from './pricing.js';

// In-memory store (replace with SQLite in production)
const payments = new Map<string, Payment>();

// Configuration
const PAYMENT_EXPIRY_SECONDS = 300; // 5 minutes
const SOLANA_WALLET = process.env.SOLANA_WALLET || 'AuRaSecurityPayments111111111111111111111';

/**
 * Generate a unique payment ID
 */
function generatePaymentId(): string {
  return `pay_${randomBytes(16).toString('hex')}`;
}

/**
 * Create a new payment request for an endpoint
 */
export function createPayment(endpoint: string, clientIp?: string, requestBody?: string): PaymentRequest | null {
  const price = getPrice(endpoint);
  if (!price) {
    return null;
  }

  const paymentId = generatePaymentId();
  const now = new Date();
  const expiresAt = new Date(now.getTime() + PAYMENT_EXPIRY_SECONDS * 1000);

  // Create payment record
  const payment: Payment = {
    id: paymentId,
    endpoint,
    amount_usd: price.usd,
    amount_lamports: price.lamports,
    status: 'pending',
    solana_address: SOLANA_WALLET,
    memo: paymentId,
    created_at: now.toISOString(),
    expires_at: expiresAt.toISOString(),
    client_ip: clientIp,
    request_body: requestBody
  };

  // Store payment
  payments.set(paymentId, payment);

  // Build payment methods
  const methods: PaymentMethod[] = [
    {
      type: 'solana',
      network: 'mainnet-beta',
      address: SOLANA_WALLET,
      amount_lamports: price.lamports,
      memo: paymentId
    }
  ];

  // Return 402 response
  return {
    status: 402,
    message: 'Payment required',
    payment: {
      amount: price.usd.toString(),
      currency: 'USD',
      payment_id: paymentId,
      expires_at: expiresAt.toISOString(),
      methods
    }
  };
}

/**
 * Get a payment by ID
 */
export function getPayment(paymentId: string): Payment | null {
  return payments.get(paymentId) || null;
}

/**
 * Mark payment as paid
 */
export function markPaymentPaid(paymentId: string, txSignature: string): boolean {
  const payment = payments.get(paymentId);
  if (!payment) return false;

  payment.status = 'paid';
  payment.paid_at = new Date().toISOString();
  payment.tx_signature = txSignature;
  payments.set(paymentId, payment);

  console.log(`[X402] Payment ${paymentId} marked as paid (tx: ${txSignature})`);
  return true;
}

/**
 * Mark payment as used (after successful scan)
 */
export function markPaymentUsed(paymentId: string): boolean {
  const payment = payments.get(paymentId);
  if (!payment) return false;

  payment.status = 'used';
  payment.used_at = new Date().toISOString();
  payments.set(paymentId, payment);

  console.log(`[X402] Payment ${paymentId} marked as used`);
  return true;
}

/**
 * Check if payment is valid for use
 */
export function isPaymentValid(paymentId: string): { valid: boolean; error?: string; payment?: Payment } {
  const payment = payments.get(paymentId);

  if (!payment) {
    return { valid: false, error: 'Payment not found' };
  }

  // Check expiry
  if (new Date(payment.expires_at) < new Date()) {
    payment.status = 'expired';
    payments.set(paymentId, payment);
    return { valid: false, error: 'Payment expired' };
  }

  // Check if already used
  if (payment.status === 'used') {
    return { valid: false, error: 'Payment already used' };
  }

  // Check if paid
  if (payment.status !== 'paid') {
    return { valid: false, error: 'Payment not yet confirmed' };
  }

  return { valid: true, payment };
}

/**
 * Clean up expired payments (run periodically)
 */
export function cleanupExpiredPayments(): number {
  const now = new Date();
  let cleaned = 0;

  for (const [id, payment] of payments) {
    if (payment.status === 'pending' && new Date(payment.expires_at) < now) {
      payment.status = 'expired';
      payments.set(id, payment);
      cleaned++;
    }
  }

  // Remove old expired/used payments (older than 1 hour)
  const oneHourAgo = new Date(now.getTime() - 60 * 60 * 1000);
  for (const [id, payment] of payments) {
    if ((payment.status === 'expired' || payment.status === 'used') &&
        new Date(payment.created_at) < oneHourAgo) {
      payments.delete(id);
      cleaned++;
    }
  }

  if (cleaned > 0) {
    console.log(`[X402] Cleaned up ${cleaned} expired/old payments`);
  }

  return cleaned;
}

/**
 * Get payment statistics
 */
export function getPaymentStats(): {
  total: number;
  pending: number;
  paid: number;
  used: number;
  expired: number;
  revenue_usd: number;
} {
  let pending = 0, paid = 0, used = 0, expired = 0;
  let revenue_usd = 0;

  for (const payment of payments.values()) {
    switch (payment.status) {
      case 'pending': pending++; break;
      case 'paid': paid++; break;
      case 'used':
        used++;
        revenue_usd += payment.amount_usd;
        break;
      case 'expired': expired++; break;
    }
  }

  return {
    total: payments.size,
    pending,
    paid,
    used,
    expired,
    revenue_usd
  };
}

// Start cleanup interval
setInterval(cleanupExpiredPayments, 60 * 1000); // Every minute
