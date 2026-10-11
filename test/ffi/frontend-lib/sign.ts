import { ml_dsa44 } from '@noble/post-quantum/ml-dsa.js'
import { bytesToHex, hexToBytes, keccak256, type Hex } from 'viem'
import { withSeed } from './keyfile.ts'

// Signs the contract's canonical raw message with pure ML-DSA-44 (empty context, FIPS 204 hedged
// signing). The key file is decrypted only inside this call; seed and secret key are zeroed before
// returning, even on error. The message must be displayed to the user and come from the contract
// (registrationMessage / authorizationMessage). `expected` stops a wrong file from signing: either the
// full 1312-byte public key or its keccak256 hash (what the contract stores for an existing vault).
export function signMessage(fileText: string, password: string, message: Hex, expected: Hex): Promise<Hex> {
  return withSeed(fileText, password, seed => {
    const { publicKey, secretKey } = ml_dsa44.keygen(seed)
    try {
      const publicKeyHex = bytesToHex(publicKey)
      const actual = expected.length === 66 ? keccak256(publicKeyHex) : publicKeyHex
      if (actual !== expected.toLowerCase()) throw new Error('This key file does not belong to this vault.')
      return bytesToHex(ml_dsa44.sign(hexToBytes(message), secretKey))
    } finally { secretKey.fill(0) }
  })
}
