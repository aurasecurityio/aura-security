/**
 * x402 Payment Types
 */

export interface PaymentMethod {
  type: 'solana' | 'lightning';
  network?: string;
  address?: string;
  amount_lamports?: number;
  amount_usdc?: number;
  token?: string;
  memo?: string;
  invoice?: string;
  amount_sats?: number;
}

export interface PaymentRequest {
  status: 402;
  message: string;
  payment: {
    amount: string;
    currency: string;
    payment_id: string;
    expires_at: string;
    methods: PaymentMethod[];
  };
}

export interface Payment {
  id: string;
  endpoint: string;
  amount_usd: number;
  amount_lamports: number;
  status: 'pending' | 'paid' | 'expired' | 'used';
  solana_address: string;
  memo: string;
  created_at: string;
  expires_at: string;
  paid_at?: string;
  tx_signature?: string;
  used_at?: string;
  client_ip?: string;
  request_body?: string;
}

export interface PaymentVerification {
  valid: boolean;
  payment?: Payment;
  error?: string;
}

export interface X402Config {
  solanaWallet: string;
  solanaRpcUrl: string;
  paymentExpirySeconds: number;
  prices: {
    [endpoint: string]: {
      usd: number;
      lamports: number;
    };
  };
}
