/**
 * x402 Payment Management
 *
 * Creates, stores, and manages payment requests.
 * Uses SQLite for persistence to survive restarts.
 */

import { randomBytes } from 'crypto';
import type { Payment, PaymentRequest, PaymentMethod } from './types.js';
import { getPrice } from './pricing.js';
import Database from 'better-sqlite3';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { mkdirSync, existsSync } from 'fs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Configuration
const PAYMENT_EXPIRY_SECONDS = 300; // 5 minutes
const SOLANA_WALLET = process.env.SOLANA_WALLET || 'AuRaSecurityPayments111111111111111111111';
const MAX_PENDING_PER_IP = 10; // Rate limit: max pending payments per IP

// Database setup
const DB_DIR = join(__dirname, '..', '..', '.aura-security');
const DB_PATH = join(DB_DIR, 'x402-payments.db');

let db: Database.Database | null = null;

function getDb(): Database.Database {
  if (!db) {
    // Ensure directory exists
    if (!existsSync(DB_DIR)) {
      mkdirSync(DB_DIR, { recursive: true });
    }

    db = new Database(DB_PATH);

    // Create payments table
    db.exec(`
      CREATE TABLE IF NOT EXISTS payments (
        id TEXT PRIMARY KEY,
        endpoint TEXT NOT NULL,
        amount_usd REAL NOT NULL,
        amount_lamports INTEGER NOT NULL,
        status TEXT DEFAULT 'pending',
        solana_address TEXT NOT NULL,
        memo TEXT NOT NULL,
        created_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        paid_at TEXT,
        tx_signature TEXT,
        used_at TEXT,
        client_ip TEXT,
        request_body TEXT
      );

      CREATE INDEX IF NOT EXISTS idx_payments_status ON payments(status);
      CREATE INDEX IF NOT EXISTS idx_payments_expires ON payments(expires_at);
      CREATE INDEX IF NOT EXISTS idx_payments_ip ON payments(client_ip);
    `);

    console.log(`[X402] Payment database initialized at: ${DB_PATH}`);
  }

  return db;
}

/**
 * Generate a unique payment ID
 */
function generatePaymentId(): string {
  return `pay_${randomBytes(16).toString('hex')}`;
}

/**
 * Check rate limit for IP
 */
function checkRateLimit(clientIp: string): boolean {
  const database = getDb();
  const stmt = database.prepare(`
    SELECT COUNT(*) as count FROM payments
    WHERE client_ip = ? AND status = 'pending' AND expires_at > datetime('now')
  `);
  const result = stmt.get(clientIp) as { count: number };
  return result.count < MAX_PENDING_PER_IP;
}

/**
 * Create a new payment request for an endpoint
 */
export function createPayment(endpoint: string, clientIp?: string, requestBody?: string): PaymentRequest | null {
  const price = getPrice(endpoint);
  if (!price) {
    return null;
  }

  // Rate limit check
  if (clientIp && !checkRateLimit(clientIp)) {
    console.log(`[X402] Rate limited: ${clientIp} has too many pending payments`);
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

  // Store in database
  const database = getDb();
  const stmt = database.prepare(`
    INSERT INTO payments (id, endpoint, amount_usd, amount_lamports, status, solana_address, memo, created_at, expires_at, client_ip, request_body)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);
  stmt.run(
    payment.id,
    payment.endpoint,
    payment.amount_usd,
    payment.amount_lamports,
    payment.status,
    payment.solana_address,
    payment.memo,
    payment.created_at,
    payment.expires_at,
    payment.client_ip || null,
    payment.request_body || null
  );

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
  const database = getDb();
  const stmt = database.prepare('SELECT * FROM payments WHERE id = ?');
  const row = stmt.get(paymentId) as Payment | undefined;
  return row || null;
}

/**
 * Mark payment as paid
 */
export function markPaymentPaid(paymentId: string, txSignature: string): boolean {
  const database = getDb();
  const stmt = database.prepare(`
    UPDATE payments SET status = 'paid', paid_at = ?, tx_signature = ?
    WHERE id = ? AND status = 'pending'
  `);
  const result = stmt.run(new Date().toISOString(), txSignature, paymentId);

  if (result.changes > 0) {
    console.log(`[X402] Payment ${paymentId} marked as paid (tx: ${txSignature})`);
    return true;
  }
  return false;
}

/**
 * Mark payment as used (after successful scan)
 */
export function markPaymentUsed(paymentId: string): boolean {
  const database = getDb();
  const stmt = database.prepare(`
    UPDATE payments SET status = 'used', used_at = ?
    WHERE id = ? AND status = 'paid'
  `);
  const result = stmt.run(new Date().toISOString(), paymentId);

  if (result.changes > 0) {
    console.log(`[X402] Payment ${paymentId} marked as used`);
    return true;
  }
  return false;
}

/**
 * Check if payment is valid for use
 */
export function isPaymentValid(paymentId: string): { valid: boolean; error?: string; payment?: Payment } {
  const payment = getPayment(paymentId);

  if (!payment) {
    return { valid: false, error: 'Payment not found' };
  }

  // Check expiry
  if (new Date(payment.expires_at) < new Date()) {
    // Update status to expired
    const database = getDb();
    database.prepare("UPDATE payments SET status = 'expired' WHERE id = ?").run(paymentId);
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
  const database = getDb();

  // Mark expired pending payments
  const expireStmt = database.prepare(`
    UPDATE payments SET status = 'expired'
    WHERE status = 'pending' AND expires_at < datetime('now')
  `);
  const expireResult = expireStmt.run();

  // Delete old expired/used payments (older than 24 hours)
  const deleteStmt = database.prepare(`
    DELETE FROM payments
    WHERE (status = 'expired' OR status = 'used')
    AND created_at < datetime('now', '-24 hours')
  `);
  const deleteResult = deleteStmt.run();

  const cleaned = expireResult.changes + deleteResult.changes;
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
  const database = getDb();

  const countStmt = database.prepare(`
    SELECT status, COUNT(*) as count, SUM(amount_usd) as revenue
    FROM payments GROUP BY status
  `);
  const rows = countStmt.all() as Array<{ status: string; count: number; revenue: number }>;

  let pending = 0, paid = 0, used = 0, expired = 0, total = 0;
  let revenue_usd = 0;

  for (const row of rows) {
    total += row.count;
    switch (row.status) {
      case 'pending': pending = row.count; break;
      case 'paid': paid = row.count; break;
      case 'used':
        used = row.count;
        revenue_usd = row.revenue || 0;
        break;
      case 'expired': expired = row.count; break;
    }
  }

  return { total, pending, paid, used, expired, revenue_usd };
}

/**
 * Close database connection
 */
export function closePaymentDb(): void {
  if (db) {
    db.close();
    db = null;
  }
}

// Start cleanup interval
setInterval(cleanupExpiredPayments, 60 * 1000); // Every minute
