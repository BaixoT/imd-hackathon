import { shake128, shake256 } from '@noble/hashes/sha3.js'
import { bytesToHex, hexToBytes, keccak256, encodeAbiParameters, stringToHex, type Hex } from 'viem'

// PUBLIC-ONLY port of the pinned Fireblocks prepare() (see crypto/keygen/relation, which is
// golden-tested against the same vectors). It proves the blob matches the key; it cannot
// prove the key came from KeyGen. No secret ever enters this module.
export const PUBLIC_KEY_BYTES = 1312
export const BLOB_BYTES = 20545
const Q = 8_380_417

const powMod = (base: number, exp: number) => {
  let r = 1
  while (exp) { if (exp & 1) r = (r * base) % Q; base = (base * base) % Q; exp >>= 1 }
  return r
}
const rev8 = (n: number) => { let r = 0; for (let i = 0; i < 8; i++) r |= ((n >> i) & 1) << (7 - i); return r }
const ZETAS = Array.from({ length: 256 }, (_, i) => powMod(1753, rev8(i)))

function ntt(p: number[]) {
  let stage = 0
  for (let len = 128; len > 0; len >>= 1) {
    for (let start = 0; start < 256; start += 2 * len) {
      const zeta = ZETAS[++stage]
      for (let j = start; j < start + len; j++) {
        const t = (zeta * p[j + len]) % Q, a = p[j]
        p[j + len] = (a + Q - t) % Q
        p[j] = (a + t) % Q
      }
    }
  }
}

function compact(out: Uint8Array, offset: number, p: number[]) {
  // Big-endian EVM word; coefficient 0 sits in the least significant lane.
  for (let c = 0; c < 256; c += 8) for (let k = 7; k >= 0; k--) {
    const v = p[c + k]
    out[offset++] = v >>> 24; out[offset++] = (v >>> 16) & 255; out[offset++] = (v >>> 8) & 255; out[offset++] = v & 255
  }
  return offset
}

export function prepareBlob(pk: Uint8Array): Uint8Array {
  if (pk.length !== PUBLIC_KEY_BYTES) throw new Error('Public key must be exactly 1312 bytes.')
  const out = new Uint8Array(BLOB_BYTES) // out[0] = 0x00 prefix
  out.set(shake256(pk, { dkLen: 64 }), 1)
  let at = 65
  const packed = pk.subarray(32)
  for (let row = 0; row < 4; row++) {
    const poly: number[] = []
    for (let i = 0; i < 256; i++) {
      const bit = (row * 256 + i) * 10, off = bit >> 3
      const word = packed[off] | (packed[off + 1] << 8)
      poly.push((((word >> (bit % 8)) & 1023) * 8192) % Q)
    }
    ntt(poly)
    at = compact(out, at, poly)
  }
  for (let row = 0; row < 4; row++) for (let col = 0; col < 4; col++) {
    const xof = shake128.create({}).update(pk.subarray(0, 32)).update(Uint8Array.of(col, row))
    const poly: number[] = []
    while (poly.length < 256) {
      const b = xof.xof(3)
      const v = b[0] | (b[1] << 8) | ((b[2] & 127) << 16)
      if (v < Q) poly.push(v)
    }
    at = compact(out, at, poly)
  }
  if (at !== BLOB_BYTES) throw new Error('Internal length error.')
  return out
}

export const vaultIdFor = (publicKey: Hex): Hex => keccak256(encodeAbiParameters(
  [{ type: 'bytes32' }, { type: 'bytes32' }], [keccak256(stringToHex('BunkerVault.VaultIdentity.v1')), keccak256(publicKey)],
))

export type KeyCheck = {
  publicKeyHash: Hex; vaultId: Hex; expectedBlobCodeHash: Hex; blobCodeHash?: Hex; blobMatches?: boolean
}

// `blobCode` is the runtime code read from the registered blob address (optional).
export function checkPublicKey(publicKey: Hex, blobCode?: Hex): KeyCheck {
  const pk = hexToBytes(publicKey)
  const expectedBlobCodeHash = keccak256(bytesToHex(prepareBlob(pk)))
  const result: KeyCheck = { publicKeyHash: keccak256(publicKey), vaultId: vaultIdFor(publicKey), expectedBlobCodeHash }
  if (blobCode !== undefined) {
    result.blobCodeHash = keccak256(blobCode)
    result.blobMatches = result.blobCodeHash === expectedBlobCodeHash
  }
  return result
}
