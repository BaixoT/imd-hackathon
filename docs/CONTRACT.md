# BunkerVault: contract specification

Scope of this document: the logic of `src/BunkerVault.sol` and `src/AuthorizationMessage.sol`, what they promise,
what they trust and what they knowingly do not do. Unaudited research code.

## 1. What it is

One shared contract holding many independent vaults. A vault holds **public** balances of ERC-20 tokens and of ETH
(held as one pinned WETH). Control of a vault needs two factors at once:

1. an **ML-DSA-44** signature (FIPS 204, pure, empty context) from the vault's current public key, verified on-chain
   by an external verifier contract, and
2. a transaction sent by the vault's **controller** wallet, which is the fee payer at registration and can never change.

There is no owner, admin, upgrade path, delegatecall, rescue function, token approval to third parties or ECDSA /
ERC-1271 fallback. Everything is fixed in the constructor.

## 2. Constructor (7 static arguments, all immutable)

`feeToken, feeTokenCodeHash, developerWallet, verifier, verifierCodeHash, weth, wethCodeHash`

Reverts `InvalidConfiguration` unless: every address has code, every code hash matches `extcodehash`, developer is
not zero or the vault, `weth != feeToken`, `weth != this`, `weth.decimals() == 18`; on chain id 1 the fee token and
WETH must be the hard-coded mainnet addresses. Fee token decimals must be 1..18 (`UnsupportedDecimals`).
`registrationFee = 10**decimals`, `developerFee = fee / 10`, `lockedFee = fee - developerFee`.
WETH is pre-admitted as a custody asset. Code hashes are re-checked at use time (`CodeChanged`).

## 3. State

| Item | Meaning |
| --- | --- |
| `_accounts[vaultId]` | `pkBlob` (address holding the prepared key), `publicKeyHash`, `keyCodeHash`, `nonce`, `keyEpoch` |
| `controllerOf[vaultId]` | the only wallet that may send that vault's operations; set once |
| `registeredVault[payer]` | one vault per fee-paying address |
| `usedPublicKeys[keyHash]` | global; retired keys stay used forever |
| `publicBalanceOf[vaultId][token]`, `totalPublicLiability[token]` | per-vault ledger and its sum |
| `assetConfig[token]` | `{kind, codeHash}` pinned at the first deposit (WETH at construction) |
| `_heldTokens[vaultId]` | append-only list of tokens ever deposited |
| `totalLockedFees` | registration liabilities (monotonic) |

`vaultId = keccak256(abi.encode(keccak256("BunkerVault.VaultIdentity.v1"), keccak256(publicKey)))` for the initial
1,312-byte public key; it stays stable across key rotations.

## 4. Public key blob

The verifier does not take the 1,312-byte key; it reads a *prepared* blob stored as the runtime code of a contract
(`pkBlob`): exactly 20,545 bytes, first byte `0x00`, `extcodehash == keyCodeHash`. The vault checks size, prefix and
code hash (`_checkKeyBlob`) at registration, rotation and **every** authorization. It cannot check that the blob equals
`prepare(publicKey)` or that the key came from an honest KeyGen. See limitation L1.

## 5. Authorization

`_consumeAuthorization(id, operation, paramsHash, authorization)` is the single gate of every vault operation:

1. vault exists (`UnknownVault`), `msg.sender == controllerOf[id]` (`NotController`);
2. `authorization.nonce == account.nonce` (`InvalidNonce`) and `authorization.keyEpoch == account.keyEpoch` (`InvalidEpoch`);
3. `0 < expiresAt - block.timestamp <= 1 hour` (`InvalidExpiry`);
4. blob checks (section 4);
5. the verifier accepts the signature over the message below; the signature must be exactly 2,420 bytes and the
   verifier code hash must equal the pinned one; a revert or `false` is a rejection;
6. `++nonce`.

Message (`AuthorizationMessage.encodeAccount`, canonical `abi.encode`, no packing):

```
(ACCOUNT_DOMAIN = keccak256("BunkerVault.AccountAuthorization.v2"), block.chainid, address(this), vaultId,
 publicKeyHash, keyCodeHash, operation, paramsHash, nonce, expiresAt, keyEpoch)
```

`paramsHash` per operation (`msg.sender` is always the controller):

| Operation constant | `paramsHash = keccak256(abi.encode(...))` |
| --- | --- |
| `DEPOSIT_ERC20` | `token, amount, expectedAssetHash, msg.sender` |
| `WITHDRAW_ERC20` | `token, recipient, amount, expectedAssetHash, msg.sender` |
| `DEPOSIT_ETH` | `msg.value, msg.sender` |
| `WITHDRAW_ETH` | `recipient, amount, msg.sender` |
| `ROTATE_KEY` | `keccak256(newPublicKey), newPkBlob, newKeyCodeHash, executor, verifierCodeHash` |

Every external function that uses the gate is `nonReentrant`. The nonce is incremented before any token or ETH
interaction; a revert anywhere undoes the increment.

## 6. Functions

**`createVault(Registration)`** (nonReentrant). The caller must be both `executor` and `feePayer` (no relayers), must
not already own a vault, the public key must be unused, expiry valid, blob valid. The registration message
(`CREATE_VAULT`, nonce 0, epoch 0, binding blob, payer, executor, fee token and its code hash and decimals, all fee
amounts, developer, verifier code hash) must verify against the **new** key (proof of possession) **before** any fee
token call. Then `_collectRegistrationFee`: `safeTransferFrom(payer, vault, fee)` with exact payer debit, exact vault
credit, unchanged total supply; then `safeTransfer(developer, fee/10)` with exact deltas and exact retained reserve;
fee token code hash and decimals re-checked. Only after all that: `totalLockedFees += lockedFee`, payer slot,
controller, key marked used, account stored. The locked 90% can never leave.

**`depositERC20 / withdrawERC20`.** The token may not be the fee token, zero, the vault or codeless. Amount must be
nonzero. After the gate, `_validateAsset` pins the token's runtime code hash at first use and requires
`expectedAssetHash == keccak256(abi.encode(AssetConfig(ERC20, token.codehash)))`, and the code hash must be unchanged
before and after the transfer. Exact-delta checks: vault balance (+amount / -amount), payer or recipient balance,
total supply unchanged, reserve `>= totalPublicLiability` before the call. Withdrawals debit the ledger and the
liability before transferring.

**`depositETH / withdrawETH`.** Deposit wraps `msg.value` through `weth.deposit()` and credits the WETH ledger with
exact balance and supply delta checks. Withdrawal debits first, sets `unwrapping = true`, calls `weth.withdraw`, resets
the flag, checks exact ETH and WETH deltas using `address(this).balance` **deltas** (forced ETH is never credited), then
sends ETH to the recipient fixed in the signature (`ETHTransferFailed` on failure). The recipient may not be zero, the
vault or the WETH contract. `receive()` accepts ETH only from WETH while `unwrapping`; `fallback()` always reverts.

**`rotateKey(id, KeyRotation, Authorization)`** (nonReentrant). The caller must be `rotation.executor` and the
controller. The new key must be unused; the new blob valid. Two signatures are required: the **current** key over the
rotation message (`ROTATE_KEY`, through the gate), and the **new** key over a possession message (`ROTATION_POP`,
`paramsHash = keccak256(rotationMessage)`, same nonce/expiry/epoch, bound to the new key hash and code hash). Effect:
blob, key hash and code hash replaced, `keyEpoch++`, the nonce stays monotonic, the new key marked used, the old key
stays used. No fee.

**Views.** `vaultIdFor`, `registrationMessage`, `authorizationMessage`, `rotationMessage`,
`rotationPossessionMessage`, `assetConfigurationHash`, `account`, `heldTokenCount`, `heldTokens(id, start, count)`.

## 7. Invariants the design intends

1. No change to a vault's state without a valid signature from its current key and a transaction from its controller.
2. A signature authorizes one operation with exactly its signed parameters, once: bound to chain, contract, vault,
   key, operation, every parameter, nonce, expiry and epoch.
3. For each token, the sum of `publicBalanceOf` over vaults equals `totalPublicLiability`, which is at most the
   vault's token balance. Unassigned tokens (donations) belong to nobody.
4. `totalLockedFees` only grows; the fee token is never a custody asset and only the developer share of a newly
   collected fee ever leaves.
5. The contract holds no ETH between calls except forced ETH, which is never credited.
6. A failed operation leaves no trace (nonce, asset admission, fee settlement all revert).
7. Registration and rotation validate key size, blob size, prefix and code hash, key uniqueness, and verify possession
   before any external fee call.

## 8. External dependencies and trust

| Dependency | Assumption |
| --- | --- |
| ML-DSA-44 verifier (`IMLDSAVerifier.verify(pkBlob, message, signature)`) | Returns `true` only for a valid signature of the key stored in `pkBlob`. Pinned by code hash. The reference implementation in `test/vendor/fireblocks/` is research code (about 1.35M gas per verification). |
| Fee token | A plain fixed-supply ERC-20 without fee, rebase or seizure; checked only by balance deltas and code hash. Trusted, reviewed outside this repository. |
| WETH | Canonical WETH9 (sends ETH back with `transfer`, 2,300 gas). Pinned by code hash. |
| Custody tokens | Untrusted. Admission is by exact observed behavior only; a token can lie about itself, harm must stay confined to that token. Not supported: fee-on-transfer, rebasing, tokens with hooks that depend on external state. |

## 9. Known limitations and accepted risks

- **L1 Open admission.** Anyone can register any public key with a blob of their choosing, so a mempool observer can
  register a victim's public key first with a mismatched blob, denying that key. The victim must use a new key.
  Clients must check `prepare(pk)` against the on-chain blob before depositing.
  **Rotation is a second, fee-free squatting path.** `rotateKey` takes the new public key as free input and its
  possession proof is checked against the caller-chosen `rotation.pkBlob`, so a registered attacker can mark any
  key hash as used for gas only (about 2.8M gas per key, no registration fee). This can front-run a victim's
  `createVault` or `rotateKey`, which then reverts with `PublicKeyAlreadyRegistered`. Custody and nonce of the
  victim are unaffected; the victim must use a new key. Accepted as part of L1.
- **L2 Controller is permanent.** Losing or compromising the controller wallet cannot be repaired. The wallet is an ECDSA
  key: against a quantum attacker only the ML-DSA key remains.
- **L3 Public data.** Balances and amounts are public.
- **L4 Fee token trust.** A misbehaving fee token can block registrations, not custody.
- **L5 Griefing is not prevented**: a payer who registers with a bad blob burns their own fee and slot.
- **L6 Authorization lifetime** is at most one hour; a signed authorization that is not submitted simply expires.
- **L7 Verifier gas.** Each operation costs roughly 1.4M to 2.8M gas, dominated by signature verification.

## 10. Tests

`forge test` (103 tests, a mock verifier checks application policy only) and `forge test --ffi` (122 tests, adds real
ML-DSA keys and signatures, a red-team suite and a differential test of the on-chain verifier against an independent
implementation). See `README.md`.
