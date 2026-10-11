import { xchacha20poly1305 } from '@noble/ciphers/chacha.js'
import { scryptAsync } from '@noble/hashes/scrypt.js'
import { bytesToHex, hexToBytes } from 'viem'

// BunkerVault key file (.key), PEM-armored like an SSH private key. Two forms, like ssh-keygen:
//  - protected: scrypt (N=2^17, r=8, p=1) -> XChaCha20-Poly1305, header authenticated as AAD;
//  - UNPROTECTED (empty password): the seed is stored in clear. Anyone who copies the file
//    controls the vault. The caller must obtain explicit user consent for this mode.
// KDF parameters are FIXED: a file cannot make the browser run an arbitrary-cost KDF.
const KDF = { name: 'scrypt', N: 2 ** 17, r: 8, p: 1 } as const
export const MIN_PASSWORD_LENGTH = 12
const MAX_FILE_CHARS = 8192
const BEGIN = '-----BEGIN BUNKERVAULT PRIVATE KEY-----'
const END = '-----END BUNKERVAULT PRIVATE KEY-----'

type Protected = {
  format: 'bunkervault.key.v1'; cipher: 'xchacha20poly1305'; kdf: typeof KDF & { salt: string }
  publicKeyHash: string; nonce: string; ciphertext: string
}
type Unprotected = { format: 'bunkervault.key.v1'; cipher: 'none'; publicKeyHash: string; seed: string }
type KeyFile = Protected | Unprotected

const aad = (h: Protected) => new TextEncoder().encode(JSON.stringify(
  [h.format, h.kdf.name, h.kdf.N, h.kdf.r, h.kdf.p, h.kdf.salt, h.cipher, h.publicKeyHash]))

const armor = (file: KeyFile) => `${BEGIN}\n${(btoa(JSON.stringify(file)).match(/.{1,64}/g) ?? []).join('\n')}\n${END}\n`
function unarmor(text: string): KeyFile {
  // Length first: the pattern below must never run over an arbitrarily large input.
  if (text.length > MAX_FILE_CHARS) throw new Error('This is not a BunkerVault key file.')
  const m = /^-----BEGIN BUNKERVAULT PRIVATE KEY-----\s+([A-Za-z0-9+/=\s]+?)\s+-----END BUNKERVAULT PRIVATE KEY-----\s*$/.exec(text.trim())
  if (!m) throw new Error('This is not a BunkerVault key file.')
  try { return JSON.parse(atob(m[1].replace(/\s+/g, ''))) } catch { throw new Error('This is not a BunkerVault key file.') }
}

async function deriveKey(password: string, salt: Uint8Array) {
  const pw = new TextEncoder().encode(password.normalize('NFKC'))
  try { return await scryptAsync(pw, salt, { N: KDF.N, r: KDF.r, p: KDF.p, dkLen: 32 }) } finally { pw.fill(0) }
}

// Empty `password` produces the UNPROTECTED form; otherwise it must meet the minimum length.
export async function encryptSeed(seed: Uint8Array, password: string, publicKeyHash: string): Promise<string> {
  if (seed.length !== 32) throw new Error('Seed must be 32 bytes.')
  if (password === '') return armor({ format: 'bunkervault.key.v1', cipher: 'none', publicKeyHash, seed: bytesToHex(seed) })
  if (password.length < MIN_PASSWORD_LENGTH) throw new Error(`Use a password of at least ${MIN_PASSWORD_LENGTH} characters, or none.`)
  const salt = crypto.getRandomValues(new Uint8Array(16))
  const nonce = crypto.getRandomValues(new Uint8Array(24))
  const header = { format: 'bunkervault.key.v1', cipher: 'xchacha20poly1305', kdf: { ...KDF, salt: bytesToHex(salt) }, publicKeyHash } as const
  const key = await deriveKey(password, salt)
  try {
    const ciphertext = bytesToHex(xchacha20poly1305(key, nonce, aad(header as Protected)).encrypt(seed))
    return armor({ ...header, nonce: bytesToHex(nonce), ciphertext })
  } finally { key.fill(0) }
}

export const isProtected = (fileText: string) => unarmor(fileText).cipher !== 'none'

// Hands the seed to `fn`, then ALWAYS zeroes it (and the derived key) before returning.
// `fn` must not retain the seed or any copy of it. Every new authorization asks for the file again.
export async function withSeed<T>(fileText: string, password: string, fn: (seed: Uint8Array) => T | Promise<T>): Promise<T> {
  const file = unarmor(fileText)
  let key: Uint8Array | undefined
  let seed: Uint8Array | undefined
  try {
    if (file.format !== 'bunkervault.key.v1') throw new Error('Unsupported key file.')
    if (file.cipher === 'none') {
      seed = hexToBytes(file.seed as `0x${string}`)
      if (seed.length !== 32) throw new Error('Damaged key file.')
    } else {
      const k = file.kdf
      if (file.cipher !== 'xchacha20poly1305' || k?.name !== KDF.name || k.N !== KDF.N || k.r !== KDF.r || k.p !== KDF.p) throw new Error('Unsupported key file.')
      key = await deriveKey(password, hexToBytes(k.salt as `0x${string}`))
      try { seed = xchacha20poly1305(key, hexToBytes(file.nonce as `0x${string}`), aad(file)).decrypt(hexToBytes(file.ciphertext as `0x${string}`)) }
      catch { throw new Error('Wrong password or damaged key file.') }
    }
    return await fn(seed)
  } finally { key?.fill(0); seed?.fill(0) }
}
