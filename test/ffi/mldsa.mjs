// FFI bridge for the Foundry tests in test/ffi/. It runs the client-side key/signing code (frontend-lib/) and the independent @noble/post-quantum ML-DSA-44 reference,
// and prints ABI-encoded results as 0x-hex on stdout. Keys are throwaway; nothing is written to disk.
// Requires `npm ci` in this directory and Node >= 22.18 (type stripping).
import { readFileSync } from 'node:fs'
import { encodeAbiParameters, bytesToHex, hexToBytes, stringToHex, hexToString } from 'viem'
import { ml_dsa44 as noble } from '@noble/post-quantum/ml-dsa.js'

const lib = name => import(new URL(`frontend-lib/${name}`, import.meta.url))

const out = (types, values) => process.stdout.write(encodeAbiParameters(types.map(type => ({ type })), values))
// Deterministic PRNG (LCG) so a failing case can be reproduced from its seed.
const rng = seed => { let s = seed >>> 0; return () => { s = (Math.imul(s, 1664525) + 1013904223) >>> 0; return s / 2 ** 32 } }
const bytes = (rand, n) => Uint8Array.from({ length: n }, () => Math.floor(rand() * 256))
const reference = (pk, msg, sig) => { try { return noble.verify(sig, msg, pk) } catch { return false } }

async function newKey(rand) {
  const { prepareBlob } = await lib('prepare.ts')
  const { blobInitCode } = await lib('blob-init.ts')
  const { publicKey, secretKey } = noble.keygen(bytes(rand, 32))
  return { pk: publicKey, sk: secretKey, init: blobInitCode(bytesToHex(prepareBlob(publicKey))) }
}

// Every suite returns (bytes[] blobInitCodes, uint256[] keyIndex, bytes[] messages, bytes[] signatures,
// bool[] referenceAccepts, string[] labels); the Solidity side asserts on-chain == reference for each case.
const suites = {
  async edges(rand) {
    const keys = [await newKey(rand), await newKey(rand)]; const cases = []
    for (const len of [0, 1, 2, 32, 69, 70, 71, 135, 136, 137, 271, 272, 273, 733, 734, 735, 800, 1024, 4096]) {
      const msg = bytes(rand, len); const sig = noble.sign(msg, keys[0].sk)
      if (!reference(keys[0].pk, msg, sig)) throw new Error(`reference rejects its own signature, len ${len}`)
      const edited = Uint8Array.from(len ? msg : [0]); if (len) edited[len >> 1] ^= 1; else edited[0] = 1
      cases.push([0, msg, sig, `valid, len ${len}`], [1, msg, sig, `ANOTHER key, len ${len}`], [0, edited, sig, `EDITED message, len ${len}`])
    }
    return [keys, cases]
  },
  async mutations(rand) {
    const keys = [await newKey(rand)]; const cases = []
    for (let i = 0; i < 1200; i++) {
      const msg = bytes(rand, 1 + Math.floor(rand() * 300)); const m = Uint8Array.from(noble.sign(msg, keys[0].sk))
      const kind = Math.floor(rand() * 8); let label
      if (kind === 0) { const p = Math.floor(rand() * 32); m[p] ^= 1 << Math.floor(rand() * 8); label = `c~[${p}] bitflip` }
      else if (kind === 1) { const p = 32 + Math.floor(rand() * 2304); m[p] ^= 1 << Math.floor(rand() * 8); label = `z[${p}] bitflip` }
      else if (kind === 2) { const p = 2336 + Math.floor(rand() * 84); m[p] ^= 1 << Math.floor(rand() * 8); label = `h[${p}] bitflip` }
      else if (kind === 3) { const p = 2336 + Math.floor(rand() * 80), q = 2336 + Math.floor(rand() * 80); [m[p], m[q]] = [m[q], m[p]]; label = `h swap ${p}/${q}` }
      else if (kind === 4) { const p = 2416 + Math.floor(rand() * 4); m[p] = Math.floor(rand() * 256); label = `h count byte [${p}] random` }
      else if (kind === 5) { const p = 2336 + Math.floor(rand() * 80); m[p] = 0; label = `h index [${p}] zeroed` }
      else if (kind === 6) { const p = 2336 + Math.floor(rand() * 80); m[p] = 255; label = `h index [${p}] 255` }
      else label = 'unmodified (positive control)'
      cases.push([0, msg, m, `${label}, msgLen ${msg.length}`])
    }
    return [keys, cases]
  },
  async valid(rand) {
    const keys = []; for (let i = 0; i < 6; i++) keys.push(await newKey(rand))
    const cases = []
    for (let i = 0; i < 400; i++) {
      const msg = bytes(rand, Math.floor(rand() * 600))
      cases.push([i % keys.length, msg, noble.sign(msg, keys[i % keys.length].sk), `valid signature (key ${i % keys.length}, len ${msg.length})`])
    }
    return [keys, cases]
  },
  async hints(rand) {
    const keys = [await newKey(rand)]; const cases = []
    for (let i = 0; i < 300; i++) {
      const msg = bytes(rand, 1 + Math.floor(rand() * 200)); const sig = Uint8Array.from(noble.sign(msg, keys[0].sk))
      const h = 2336, counts = [sig[2416], sig[2417], sig[2418], sig[2419]], total = counts[3]
      for (let poly = 0, start = 0; poly < 4; start = counts[poly], poly++) {
        if (counts[poly] - start >= 2) { const v = Uint8Array.from(sig); [v[h + start], v[h + start + 1]] = [v[h + start + 1], v[h + start]]; cases.push([0, msg, v, `swap indices in poly ${poly}`]); break }
      }
      if (total < 80) { const v = Uint8Array.from(sig); v[h + total] = 1; cases.push([0, msg, v, 'nonzero padding']) }
      { const v = Uint8Array.from(sig); v[2419] = 81; cases.push([0, msg, v, 'total count 81 > omega']) }
      if (counts[1] > 0) { const v = Uint8Array.from(sig); v[2417] = counts[0] - 1 < 0 ? 255 : counts[0] - 1; cases.push([0, msg, v, 'count decreases']) }
    }
    if (cases.length <= 300) throw new Error(`only ${cases.length} hint violations exercised`)
    for (const [, msg, v, label] of cases) if (reference(keys[0].pk, msg, v)) throw new Error(`reference accepts ${label}`)
    return [keys, cases]
  },
  async lengths(rand) {
    const keys = [await newKey(rand)]; const msg = bytes(rand, 40); const sig = noble.sign(msg, keys[0].sk)
    const bad = [new Uint8Array(0), sig.slice(0, 2419), new Uint8Array([...sig, 0]), new Uint8Array(2420), new Uint8Array(2420).fill(255)]
    return [keys, [[0, msg, sig, 'valid (control)'], ...bad.map(b => [0, msg, b, `length ${b.length}`])]]
  },
  async probe(rand) {
    const keys = [await newKey(rand)]; const msg = bytes(rand, 352)
    return [keys, [[0, msg, noble.sign(msg, keys[0].sk), 'typical 352-byte authorization message']]]
  },
}

const [command, ...args] = process.argv.slice(2)
if (command === 'suite') {
  const [keys, cases] = await suites[args[0]](rng(Number(args[1])))
  out(['bytes[]', 'uint256[]', 'bytes[]', 'bytes[]', 'bool[]', 'string[]'], [
    keys.map(k => k.init), cases.map(c => BigInt(c[0])), cases.map(c => bytesToHex(c[1])), cases.map(c => bytesToHex(c[2])),
    cases.map(c => reference(keys[c[0]].pk, c[1], c[2])), cases.map(c => c[3]),
  ])
} else if (command === 'keygen') {
  // The frontend's own KeyGen, preparation, publication initcode and key-file format.
  const { generateKey } = await lib('keygen.ts')
  const { prepareBlob } = await lib('prepare.ts')
  const { blobInitCode } = await lib('blob-init.ts')
  const { encryptSeed } = await lib('keyfile.ts')
  const key = generateKey()
  const keyFile = await encryptSeed(key.seed, '', key.check.publicKeyHash)
  key.seed.fill(0)
  out(['bytes', 'bytes', 'bytes32', 'bytes'],
    [key.publicKey, blobInitCode(bytesToHex(prepareBlob(hexToBytes(key.publicKey)))), key.check.vaultId, stringToHex(keyFile)])
} else if (command === 'sign') {
  const { signMessage } = await lib('sign.ts')
  out(['bytes'], [await signMessage(hexToString(args[0]), '', args[1], args[2])])
} else if (command === 'blobinit') {
  const { blobInitCode } = await lib('blob-init.ts')
  // `@path` reads the argument from a file: a 20,545-byte blob exceeds the Windows command-line limit.
  const input = args[0].startsWith('@') ? readFileSync(args[0].slice(1), 'utf8') : args[0]
  try { out(['bool', 'bytes'], [true, blobInitCode(input)]) } catch { out(['bool', 'bytes'], [false, '0x']) }
} else {
  throw new Error(`unknown command ${command}`)
}
