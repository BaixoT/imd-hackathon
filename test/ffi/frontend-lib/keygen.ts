import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js'
import { bytesToHex, type Hex } from 'viem'
import { checkPublicKey, type KeyCheck } from './prepare.ts'

// Local ML-DSA-44 KeyGen (FIPS 204). The 32-byte seed IS the secret: it derives the signing key.
// scripts/check-keygen.mjs verifies this library against the RustCrypto KeyGen used by the project.
// The secret key is never kept: the seed alone regenerates it. Callers must wipe `seed`.
export function generateKey(): { seed: Uint8Array; publicKey: Hex; check: KeyCheck } {
  if (!globalThis.crypto?.getRandomValues) throw new Error('A secure random source is unavailable in this browser.')
  const seed = globalThis.crypto.getRandomValues(new Uint8Array(32))
  const { publicKey, secretKey } = ml_dsa44.keygen(seed)
  secretKey.fill(0)
  const hex = bytesToHex(publicKey)
  return { seed, publicKey: hex, check: checkPublicKey(hex) }
}

// Re-derives the public key from a seed (used to prove a key file restores the same identity).
export function publicKeyOf(seed: Uint8Array): Hex {
  const { publicKey, secretKey } = ml_dsa44.keygen(seed)
  secretKey.fill(0)
  return bytesToHex(publicKey)
}
