/**
 * Clawstr Key Management
 *
 * Handles Nostr keypair generation, loading, and signing.
 * Uses @noble/curves for BIP-340 Schnorr signatures (required by Nostr).
 */

import { schnorr } from '@noble/curves/secp256k1.js';
import { sha256 } from '@noble/hashes/sha2.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { randomBytes } from 'crypto';

export interface NostrKeyPair {
  privateKey: string;  // Hex format (64 chars)
  publicKey: string;   // Hex format (64 chars) - x-only
  nsec: string;        // Bech32 encoded private key (simplified)
  npub: string;        // Bech32 encoded public key (simplified)
}

/**
 * Generate a new random Nostr keypair
 */
export function generateKeyPair(): NostrKeyPair {
  // Generate 32 random bytes for private key
  const privateKeyBytes = randomBytes(32);
  const privateKey = bytesToHex(privateKeyBytes);

  // Derive public key (x-only, 32 bytes for schnorr)
  const publicKeyBytes = schnorr.getPublicKey(privateKeyBytes);
  const publicKey = bytesToHex(publicKeyBytes);

  return {
    privateKey,
    publicKey,
    nsec: `nsec1${privateKey.slice(0, 58)}`, // Simplified
    npub: `npub1${publicKey.slice(0, 58)}`,  // Simplified
  };
}

/**
 * Load keypair from private key (hex or nsec format)
 */
export function loadKeyPair(privateKeyInput: string): NostrKeyPair {
  let privateKey: string;

  // Handle nsec format
  if (privateKeyInput.startsWith('nsec1')) {
    privateKey = privateKeyInput.slice(5);
    if (privateKey.length < 64) {
      throw new Error('Invalid nsec format');
    }
    privateKey = privateKey.slice(0, 64);
  } else {
    // Assume hex format
    privateKey = privateKeyInput.toLowerCase().replace(/^0x/, '');
  }

  if (privateKey.length !== 64 || !/^[0-9a-f]+$/.test(privateKey)) {
    throw new Error('Invalid private key format. Expected 64 hex characters.');
  }

  // Derive public key
  const publicKey = getPublicKey(privateKey);

  return {
    privateKey,
    publicKey,
    nsec: `nsec1${privateKey.slice(0, 58)}`,
    npub: `npub1${publicKey.slice(0, 58)}`,
  };
}

/**
 * Get public key from private key (x-only format for schnorr)
 */
export function getPublicKey(privateKey: string): string {
  const privateKeyHex = privateKey.toLowerCase().replace(/^0x/, '');
  const privateKeyBytes = hexToBytes(privateKeyHex);
  const publicKeyBytes = schnorr.getPublicKey(privateKeyBytes);
  return bytesToHex(publicKeyBytes);
}

/**
 * Sign a Nostr event using BIP-340 Schnorr signature
 */
export function signEvent(
  eventHash: string,
  privateKey: string
): string {
  const privateKeyBytes = hexToBytes(privateKey);
  const hashBytes = hexToBytes(eventHash);
  const signature = schnorr.sign(hashBytes, privateKeyBytes);
  return bytesToHex(signature);
}

/**
 * Calculate event ID (sha256 hash of serialized event)
 */
export function getEventHash(event: {
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
}): string {
  const serialized = JSON.stringify([
    0,
    event.pubkey,
    event.created_at,
    event.kind,
    event.tags,
    event.content,
  ]);

  const hashBytes = sha256(new TextEncoder().encode(serialized));
  return bytesToHex(hashBytes);
}

/**
 * Verify event signature using BIP-340 Schnorr
 */
export function verifySignature(
  eventHash: string,
  signature: string,
  publicKey: string
): boolean {
  try {
    const hashBytes = hexToBytes(eventHash);
    const sigBytes = hexToBytes(signature);
    const pubKeyBytes = hexToBytes(publicKey);
    return schnorr.verify(sigBytes, hashBytes, pubKeyBytes);
  } catch {
    return false;
  }
}

/**
 * Create and sign a complete Nostr event
 */
export function createSignedEvent(
  kind: number,
  content: string,
  tags: string[][],
  privateKey: string
): {
  id: string;
  pubkey: string;
  created_at: number;
  kind: number;
  tags: string[][];
  content: string;
  sig: string;
} {
  const publicKey = getPublicKey(privateKey);
  const created_at = Math.floor(Date.now() / 1000);

  const event = {
    pubkey: publicKey,
    created_at,
    kind,
    tags,
    content,
  };

  const id = getEventHash(event);
  const sig = signEvent(id, privateKey);

  return {
    ...event,
    id,
    sig,
  };
}
