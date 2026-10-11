# BunkerVault

Shared vault contract for public ERC-20 and ETH balances. Every operation needs an ML-DSA-44 signature from the
vault's key **and** a transaction from its permanent controller wallet. Unaudited research code.

Specification, trust assumptions and known limitations: [docs/CONTRACT.md](docs/CONTRACT.md).

## Layout

- `src/BunkerVault.sol`: the contract. `src/AuthorizationMessage.sol`: canonical encoding of what the key signs.
  `src/interfaces/`: verifier and WETH interfaces.
- `test/*.t.sol`: tests with a programmable **mock** verifier (checks application policy, not ML-DSA), plus
  `RealVerifier.t.sol` (public NIST vectors on the real verifier). `test/utils/VaultFixture.sol` builds a vault and
  arms the mock for a given message.
- `test/ffi/`: end-to-end, red-team and differential tests with real ML-DSA keys and signatures.
- `test/mocks/`: hostile ERC-20s, WETH9 mock, forced-ETH and reverting/reentrant recipients. Test-only.
- `test/vendor/fireblocks/`: the research ML-DSA-44 verifier (upstream revision and SHA-256 digests in
  `test/fixtures/fireblocks/manifest.json`). Separate from the vault, trusted by it through a code-hash pin.
- `test/fixtures/`: public data only (NIST vectors, Keccak helper runtime, mainnet WETH9 runtime).
- `lib/`: vendored forge-std v1.10.0 and OpenZeppelin Contracts v5.6.1 (`lib/VERSIONS.md`).
- `script/import-public-crypto.mjs`: reproducible import of the vendored verifier and public vectors.

## Build and test

Requires [Foundry](https://book.getfoundry.sh/) (forge 1.3.5). Solc 0.8.30, Cancun, optimizer 200 runs,
`bytecode_hash = "none"`; the verifier is compiled via-IR with 10,000 runs.

```sh
forge build
forge test                      # 103 tests, no network, no external tools
(cd test/ffi && npm ci)         # Node >= 22.18
forge test --ffi                # 122 tests, adds real ML-DSA keys and signatures
```
