// Read-only upstream import. Never clone upstream private signing fixtures.
// Run from blockchain/: node script/import-public-crypto.mjs (paths below are relative to blockchain/).
import { mkdir, readFile, writeFile } from 'node:fs/promises'
import { createHash } from 'node:crypto'
import { spawnSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'

const revision = 'cca262b537a5ac2ee55efb427e5c61de0308e566'
const base = `https://raw.githubusercontent.com/fireblocks-labs/evm-ml-dsa-verifier/${revision}/`
const sha256 = bytes => createHash('sha256').update(bytes).digest('hex')
const files = ['LICENSE', 'src/IMLDSAVerifier.sol', 'src/MLDSA44Verifier.sol', 'src/Decode.sol',
  'src/FastKeccak170.sol', 'src/Ntt.sol', 'src/InvNtt.sol', 'prepare/prepare.py',
  'prepare/mldsa_min.py', 'helpers/f1600_170.hex']
const manifest = { revision, source: base, files: {} }
for (const file of files) {
  const response = await fetch(base + file)
  if (!response.ok) throw new Error(`Cannot fetch ${file}: ${response.status}`)
  const bytes = Buffer.from(await response.arrayBuffer())
  const target = file.startsWith('src/')
    ? `test/vendor/fireblocks/${file.slice(4)}`
    : `test/fixtures/fireblocks/${file}`
  await mkdir(dirname(target), { recursive: true })
  await writeFile(target, bytes)
  manifest.files[target] = sha256(bytes)
}

// This upstream corpus includes private material in some records. Keep it ONLY
// in memory, never serialize/spread a record, and persist an explicit public whitelist.
const corpusResponse = await fetch(base + 'tools/fixtures/acvp_data/mldsa44.json')
if (!corpusResponse.ok) throw new Error('Cannot fetch public-vector source')
const corpusBytes = Buffer.from(await corpusResponse.arrayBuffer())
const corpus = JSON.parse(corpusBytes.toString('utf8'))
const publicCases = [
  ...corpus.sigGen.pure.filter(v => v.context === '').map(v => ({ source: 'sigGen', v })),
  ...corpus.tr1.pure.filter(v => v.context === '').map(v => ({ source: 'tr1', v })),
  ...corpus.sigVer.pure.filter(v => v.testPassed === false).slice(0, 3).map(v => ({ source: 'sigVer', v })),
]
if (publicCases.length !== 11) throw new Error(`Unexpected vector census: ${publicCases.length}`)
const cases = publicCases.map(({ source, v }) => {
  const prepared = spawnSync('python', [resolve('test/fixtures/fireblocks/prepare/prepare.py')],
    { input: v.pk, encoding: 'utf8', maxBuffer: 100_000 })
  if (prepared.status !== 0) throw new Error(`Public-key preparation failed for ${source}/${v.tcId}`)
  if (prepared.stdout.trim().length !== 41090) throw new Error('Wrong prepared public-blob size')
  return { label: `${source}/${v.tcId}`, publicKey: `0x${v.pk}`, message: `0x${v.message}`,
    signature: `0x${v.signature}`, context: `0x${v.context}`, expected: source !== 'sigVer',
    blobCode: `0x${prepared.stdout.trim()}` }
})
const fixture = { revision, upstreamCorpusSha256: sha256(corpusBytes),
  nistProvenance: corpus._provenance, cases }
const fixturePath = 'test/fixtures/fireblocks/public-vectors.json'
await writeFile(fixturePath, JSON.stringify(fixture, null, 2) + '\n')
manifest.files[fixturePath] = sha256(await readFile(fixturePath))
await writeFile('test/fixtures/fireblocks/manifest.json', JSON.stringify(manifest, null, 2) + '\n')
console.log(`Imported pinned public verifier dependencies and ${cases.length} public-only vectors.`)
