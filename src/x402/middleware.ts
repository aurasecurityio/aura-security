/**
 * x402 Payment Middleware
 *
 * Handles the payment flow for API requests:
 * 1. Check for payment headers
 * 2. If no payment, return 402 with payment instructions
 * 3. If payment provided, verify and allow request
 */

import { createPayment, isPaymentValid, markPaymentUsed, getPayment } from './payments.js';
import { verifySolanaPayment } from './solana.js';
import { getPrice } from './pricing.js';
import type { PaymentRequest } from './types.js';

export interface X402Request {
  method: string;
  url: string;
  path: string;
  headers: Record<string, string | undefined>;
  body: any;
  ip?: string;
}

export interface X402Response {
  status: number;
  body: any;
  headers?: Record<string, string>;
}

/**
 * Check if an endpoint requires payment
 */
export function requiresPayment(path: string): boolean {
  return getPrice(path) !== null;
}

/**
 * Process x402 payment for a request
 *
 * Returns null if payment is valid and request should proceed.
 * Returns PaymentRequest (402 response) if payment is needed.
 */
export async function processPayment(req: X402Request): Promise<X402Response | null> {
  const path = req.path;

  // Check if endpoint requires payment
  if (!requiresPayment(path)) {
    return null; // No payment needed, proceed
  }

  // Check for payment headers
  const paymentId = req.headers['x-payment-id'];
  const paymentSignature = req.headers['x-payment-signature'];

  // No payment provided - return 402
  if (!paymentId) {
    const paymentRequest = createPayment(
      path,
      req.ip,
      JSON.stringify(req.body)
    );

    if (!paymentRequest) {
      return {
        status: 500,
        body: { error: 'Failed to create payment request' }
      };
    }

    return {
      status: 402,
      body: paymentRequest,
      headers: {
        'X-Payment-Required': 'true',
        'X-Payment-Methods': 'solana'
      }
    };
  }

  // Payment ID provided - verify it
  const payment = getPayment(paymentId);

  if (!payment) {
    return {
      status: 402,
      body: {
        status: 402,
        error: 'Payment not found',
        message: 'Invalid payment ID. Please request a new payment.'
      }
    };
  }

  // Check if payment is for the right endpoint
  if (payment.endpoint !== path) {
    return {
      status: 402,
      body: {
        status: 402,
        error: 'Payment endpoint mismatch',
        message: `This payment is for ${payment.endpoint}, not ${path}`
      }
    };
  }

  // If payment signature provided, verify on-chain
  if (paymentSignature && payment.status === 'pending') {
    const verification = await verifySolanaPayment(paymentSignature, paymentId);

    if (!verification.valid) {
      return {
        status: 402,
        body: {
          status: 402,
          error: 'Payment verification failed',
          message: verification.error
        }
      };
    }
  }

  // Check if payment is valid for use
  const validCheck = isPaymentValid(paymentId);

  if (!validCheck.valid) {
    // If just pending (not yet verified), return instructions
    if (payment.status === 'pending') {
      return {
        status: 402,
        body: {
          status: 402,
          error: 'Payment pending',
          message: 'Payment not yet confirmed. Send SOL to the address and include tx signature in X-Payment-Signature header.',
          payment: {
            payment_id: paymentId,
            amount_lamports: payment.amount_lamports,
            address: payment.solana_address,
            memo: payment.memo,
            expires_at: payment.expires_at
          }
        }
      };
    }

    return {
      status: 402,
      body: {
        status: 402,
        error: validCheck.error,
        message: 'Payment invalid. Please request a new payment.'
      }
    };
  }

  // Payment is valid - mark as used and allow request to proceed
  markPaymentUsed(paymentId);

  console.log(`[X402] Payment ${paymentId} consumed for ${path}`);

  return null; // Proceed with request
}

/**
 * Create a handler wrapper for x402 endpoints
 */
export function withX402<T>(
  handler: (req: X402Request) => Promise<T>
): (req: X402Request) => Promise<X402Response> {
  return async (req: X402Request): Promise<X402Response> => {
    // Check payment
    const paymentResponse = await processPayment(req);

    if (paymentResponse) {
      return paymentResponse;
    }

    // Payment valid - execute handler
    try {
      const result = await handler(req);
      return {
        status: 200,
        body: result
      };
    } catch (err) {
      console.error(`[X402] Handler error for ${req.path}:`, err);
      return {
        status: 500,
        body: {
          error: 'Internal server error',
          message: err instanceof Error ? err.message : 'Unknown error'
        }
      };
    }
  };
}
