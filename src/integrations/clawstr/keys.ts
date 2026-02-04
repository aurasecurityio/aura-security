/**
 * Clawstr Key Management
 *
 * Handles Nostr keypair generation, loading, and signing.
 * Uses Node.js built-in crypto for secp256k1 operations.
 */

import * as crypto from 'crypto';

export interface NostrKeyPair {
  privateKey: string;  // Hex format (64 chars)
  publicKey: string;   // Hex format (64 chars)
  nsec: string;        // Bech32 encoded private key (simplified)
  npub: string;        // Bech32 encoded public key (simplified)
}

/**
 * Generate a new random Nostr keypair
 */
export function generateKeyPair(): NostrKeyPair {
  // Generate a new keypair using secp256k1
  const keyPair = crypto.generateKeyPairSync('ec', {
    namedCurve: 'secp256k1',
  });

  // Export private key as raw bytes
  const privateKeyDer = keyPair.privateKey.export({ type: 'pkcs8', format: 'der' });
  // The raw 32-byte private key starts at offset 36 in PKCS8 DER format
  const privateKey = privateKeyDer.subarray(36, 68).toString('hex');

  // Get public key (x-only, 32 bytes for schnorr)
  const publicKey = getPublicKey(privateKey);

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
  const privateKeyBuffer = Buffer.from(privateKeyHex, 'hex');

  // Create key object from raw private key
  const keyObject = crypto.createPrivateKey({
    key: Buffer.concat([
      // PKCS8 header for secp256k1
      Buffer.from('303e020100301006072a8648ce3d020106052b8104000a042730250201010420', 'hex'),
      privateKeyBuffer,
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  // Get public key in uncompressed format
  const publicKeyDer = crypto.createPublicKey(keyObject).export({
    type: 'spki',
    format: 'der',
  });

  // Extract x-coordinate (32 bytes) from uncompressed public key
  // SPKI format: header (26 bytes) + 04 (1 byte) + x (32 bytes) + y (32 bytes)
  const xCoord = publicKeyDer.subarray(27, 59);
  return xCoord.toString('hex');
}

/**
 * Sign a Nostr event using schnorr signature
 */
export function signEvent(
  eventHash: string,
  privateKey: string
): string {
  const privateKeyBuffer = Buffer.from(privateKey, 'hex');
  const hashBuffer = Buffer.from(eventHash, 'hex');

  // Create key object
  const keyObject = crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('303e020100301006072a8648ce3d020106052b8104000a042730250201010420', 'hex'),
      privateKeyBuffer,
    ]),
    format: 'der',
    type: 'pkcs8',
  });

  // Sign using ECDSA (schnorr not yet widely supported in Node crypto)
  // Note: For production Nostr, use a proper schnorr library
  const signature = crypto.sign(null, hashBuffer, {
    key: keyObject,
    dsaEncoding: 'ieee-p1363', // Returns r || s format (64 bytes)
  });

  return signature.toString('hex');
}

/**
 * Calculate event ID (hash)
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

  const hash = crypto.createHash('sha256').update(serialized).digest();
  return hash.toString('hex');
}

/**
 * Verify event signature
 */
export function verifySignature(
  eventHash: string,
  signature: string,
  publicKey: string
): boolean {
  try {
    const hashBuffer = Buffer.from(eventHash, 'hex');
    const sigBuffer = Buffer.from(signature, 'hex');

    // Reconstruct public key in SPKI format
    // For x-only pubkey, we need to compute y and create uncompressed format
    // This is a simplified version - for production, use a proper library
    const xCoord = Buffer.from(publicKey, 'hex');

    // Create SPKI structure with uncompressed point (assuming even y)
    // Note: This is simplified and may not work for all keys
    const spkiPrefix = Buffer.from('3056301006072a8648ce3d020106052b8104000a03420004', 'hex');
    const yCoord = Buffer.alloc(32, 0); // Placeholder - proper implementation needed

    const publicKeyDer = Buffer.concat([spkiPrefix, xCoord, yCoord]);

    const keyObject = crypto.createPublicKey({
      key: publicKeyDer,
      format: 'der',
      type: 'spki',
    });

    return crypto.verify(null, hashBuffer, {
      key: keyObject,
      dsaEncoding: 'ieee-p1363',
    }, sigBuffer);
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
