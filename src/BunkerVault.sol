// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC20Metadata} from "@openzeppelin/contracts/token/ERC20/extensions/IERC20Metadata.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {IWETH} from "./interfaces/IWETH.sol";
import {IMLDSAVerifier} from "./interfaces/IMLDSAVerifier.sol";
import {AuthorizationMessage} from "./AuthorizationMessage.sol";

/// @notice Shared PQ-authorized accounts holding public ERC-20 balances and ETH (held as WETH).
/// @dev Research implementation, NOT deployment-ready. Admission is open: the contract
/// checks key size/prefix/code hash/uniqueness and ML-DSA PoP, but cannot prove KeyGen
/// provenance or that the blob equals prepare(pk); clients must verify this off-chain before depositing.
/// Fee token must be independently reviewed as a fixed-balance ERC20, without
/// rebase, arbitrary seizure or upgrade paths. Balance checks cannot detect lying.
contract BunkerVault is ReentrancyGuard {
    using SafeERC20 for IERC20;

    address public constant MAINNET_FEE_TOKEN = 0xD34a99Bc0f67aE1bbd63C660e6d0b0dd03E263B7;
    address public constant MAINNET_WETH = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
    bytes32 public constant VAULT_ID_DOMAIN = keccak256("BunkerVault.VaultIdentity.v1");
    bytes32 public constant CREATE_VAULT = keccak256("BunkerVault.CreateVault.v2");
    bytes32 public constant ROTATE_KEY = keccak256("BunkerVault.RotateKey.v1");
    bytes32 public constant ROTATION_POP = keccak256("BunkerVault.RotationPossession.v1");
    bytes32 public constant DEPOSIT_ERC20 = keccak256("BunkerVault.DepositERC20.v1");
    bytes32 public constant WITHDRAW_ERC20 = keccak256("BunkerVault.WithdrawERC20.v1");
    bytes32 public constant DEPOSIT_ETH = keccak256("BunkerVault.DepositETH.v1");
    bytes32 public constant WITHDRAW_ETH = keccak256("BunkerVault.WithdrawETH.v1");
    uint256 public constant MAX_AUTHORIZATION_LIFETIME = 1 hours;

    IERC20 public immutable feeToken;
    bytes32 public immutable feeTokenCodeHash;
    uint8 public immutable feeTokenDecimals;
    uint256 public immutable registrationFee;
    uint256 public immutable developerFee;
    uint256 public immutable lockedFee;
    address public immutable developerWallet;
    IMLDSAVerifier public immutable verifier;
    bytes32 public immutable verifierCodeHash;
    /// @notice ETH deposits are wrapped into this WETH and credited as a normal public balance.
    IWETH public immutable weth;
    bytes32 public immutable wethCodeHash;

    /// @notice Registration liabilities only; unsolicited tokens are also locked.
    uint256 public totalLockedFees;
    mapping(address payer => bytes32 vaultId) public registeredVault;
    mapping(bytes32 publicKeyHash => bool used) public usedPublicKeys;
    // Two factors per vault: every operation needs the ML-DSA authorization AND a transaction
    // sent by this wallet. It is the fee payer at registration and can NEVER
    // change (revision 6). No relayers.
    mapping(bytes32 vaultId => address controller) public controllerOf;

    struct Account {
        address pkBlob;
        bytes32 publicKeyHash;
        bytes32 keyCodeHash;
        uint256 nonce;
        uint256 keyEpoch;
    }

    struct Registration {
        bytes publicKey;
        address pkBlob;
        bytes32 keyCodeHash;
        address feePayer;
        address executor;
        uint256 expiresAt;
        bytes proofOfPossession;
    }

    struct Authorization {
        uint256 nonce;
        uint256 expiresAt;
        uint256 keyEpoch;
        bytes signature;
    }

    struct KeyRotation {
        bytes publicKey;
        address pkBlob;
        bytes32 keyCodeHash;
        address executor;
        bytes proofOfPossession;
    }

    mapping(bytes32 vaultId => Account account) private _accounts;
    // Never attribute donations/aggregate custody to an individual account.
    mapping(bytes32 vaultId => mapping(address token => uint256 balance)) public publicBalanceOf;
    mapping(address token => uint256 liability) public totalPublicLiability;
    // Append-only list of tokens a vault has ever deposited, so a client can enumerate
    // them without scanning logs. Only the vault's own PQ-authorized deposits add to it, so nobody can
    // grow another vault's list. Zero balances stay listed; clients filter them.
    mapping(bytes32 vaultId => address[] tokens) private _heldTokens;
    mapping(bytes32 vaultId => mapping(address token => bool listed)) private _isHeld;

    enum AssetKind { Unknown, ERC20 }
    struct AssetConfig {
        AssetKind kind;
        bytes32 codeHash;
    }
    // First PQ-authorized deposit pins the token's runtime code; no owner/configuration override.
    // WETH is pinned at construction.
    mapping(address token => AssetConfig config) public assetConfig;

    error InvalidConfiguration();
    error UnsupportedDecimals();
    error TokenConfigurationChanged();
    error AlreadyRegistered();
    error PublicKeyAlreadyRegistered();
    error InvalidPublicKey();
    error InvalidExecutor();
    error NotController();
    error InvalidExpiry();
    error InvalidSignature();
    error CodeChanged();
    error UnexpectedFeeBalance();
    error UnsupportedTokenBehavior();
    error LockedFeeToken();
    error UnknownVault();
    error InvalidNonce();
    error InvalidEpoch();
    error InvalidAsset();
    error AssetConfigurationChanged();
    error InvalidAmount();
    error InvalidRecipient();
    error InsufficientPublicBalance();
    error UnexpectedAssetBalance();
    error DirectETHRejected();
    error ETHTransferFailed();

    event AssetAccepted(address indexed token, AssetKind kind, bytes32 codeHash);
    event ERC20Deposited(bytes32 indexed vaultId, address indexed token, address indexed sender, uint256 amount);
    event ERC20Withdrawn(bytes32 indexed vaultId, address indexed token, address indexed recipient, uint256 amount);
    event ETHDeposited(bytes32 indexed vaultId, address indexed sender, uint256 amount);
    event ETHWithdrawn(bytes32 indexed vaultId, address indexed recipient, uint256 amount);

    event VaultCreated(
        bytes32 indexed vaultId,
        bytes32 indexed publicKeyHash,
        address indexed feePayer,
        address pkBlob,
        uint256 lockedAmount,
        uint256 developerAmount
    );

    event KeyRotated(
        bytes32 indexed vaultId, bytes32 indexed previousPublicKeyHash,
        bytes32 indexed publicKeyHash, address pkBlob, bytes32 keyCodeHash,
        uint256 keyEpoch, uint256 nextNonce
    );

    /// @dev All args are static types (address / bytes32). Approved code hashes must
    /// come from independently reviewed deployment artifacts, not on-chain probes.
    constructor(
        address feeToken_, bytes32 approvedFeeTokenCodeHash_, address developerWallet_,
        address verifier_, bytes32 approvedVerifierCodeHash_, address weth_, bytes32 approvedWethCodeHash_
    ) {
        if (
            feeToken_.code.length == 0 || approvedFeeTokenCodeHash_ == bytes32(0)
                || feeToken_.codehash != approvedFeeTokenCodeHash_
                || developerWallet_ == address(0) || developerWallet_ == address(this)
                || verifier_.code.length == 0 || approvedVerifierCodeHash_ == bytes32(0)
                || verifier_.codehash != approvedVerifierCodeHash_
                || (block.chainid == 1 && feeToken_ != MAINNET_FEE_TOKEN)
                || weth_.code.length == 0 || approvedWethCodeHash_ == bytes32(0) || weth_.codehash != approvedWethCodeHash_
                || weth_ == feeToken_ || weth_ == address(this) || (block.chainid == 1 && weth_ != MAINNET_WETH)
                || IERC20Metadata(weth_).decimals() != 18
        ) revert InvalidConfiguration();

        uint8 decimals_ = IERC20Metadata(feeToken_).decimals();
        // At least one decimal is necessary for an EXACT 0.1-token developer cut.
        // Limit to the reviewed 1..18 range; no implicit metadata defaults.
        if (decimals_ < 1 || decimals_ > 18) revert UnsupportedDecimals();
        uint256 fee = 10 ** uint256(decimals_);
        feeToken = IERC20(feeToken_);
        feeTokenCodeHash = approvedFeeTokenCodeHash_;
        feeTokenDecimals = decimals_;
        registrationFee = fee;
        developerFee = fee / 10;
        lockedFee = fee - fee / 10;
        developerWallet = developerWallet_;
        verifier = IMLDSAVerifier(verifier_);
        verifierCodeHash = approvedVerifierCodeHash_;
        weth = IWETH(weth_);
        wethCodeHash = approvedWethCodeHash_;
        // WETH is admitted at construction so ETH credits can also leave through withdrawERC20.
        assetConfig[weth_] = AssetConfig(AssetKind.ERC20, approvedWethCodeHash_);
    }

    function vaultIdFor(bytes calldata publicKey) public pure returns (bytes32) {
        if (publicKey.length != 1312) revert InvalidPublicKey();
        return keccak256(abi.encode(VAULT_ID_DOMAIN, keccak256(publicKey)));
    }

    function registrationMessage(Registration calldata registration) public view returns (bytes memory) {
        bytes32 id = vaultIdFor(registration.publicKey);
        bytes32 paramsHash = keccak256(abi.encode(
            registration.pkBlob, registration.feePayer, registration.executor,
            address(feeToken), feeTokenCodeHash, feeTokenDecimals, registrationFee,
            developerWallet, developerFee, lockedFee, verifierCodeHash
        ));
        return AuthorizationMessage.encodeAccount(
            block.chainid, address(this), id, keccak256(registration.publicKey), registration.keyCodeHash,
            AuthorizationMessage.Request(CREATE_VAULT, paramsHash, 0, registration.expiresAt, 0)
        );
    }

    function createVault(Registration calldata registration) external nonReentrant returns (bytes32 id) {
        if (registration.executor != msg.sender || registration.feePayer == address(0)
            || registration.feePayer == address(this)) revert InvalidExecutor();
        // Open admission does not bind a key to a payer's prior consent. Require
        // self-submission so another PQ key cannot consume a victim's existing fee
        // allowance/one-time slot. This is payment consent, not asset authority.
        if (registration.feePayer != msg.sender) revert InvalidExecutor();
        if (registeredVault[registration.feePayer] != bytes32(0)) revert AlreadyRegistered();
        id = vaultIdFor(registration.publicKey);
        bytes32 keyHash = keccak256(registration.publicKey);
        if (usedPublicKeys[keyHash] || _accounts[id].pkBlob != address(0)) revert PublicKeyAlreadyRegistered();
        _checkExpiry(registration.expiresAt);
        _checkKeyBlob(registration.pkBlob, registration.keyCodeHash);

        // PoP MUST succeed before any fee-token calls, transfers or activation.
        _verify(registration.pkBlob, registrationMessage(registration), registration.proofOfPossession);
        _collectRegistrationFee(registration.feePayer);

        // Credentials/one-time markers become active only after exact settlement.
        totalLockedFees += lockedFee;
        registeredVault[registration.feePayer] = id;
        controllerOf[id] = registration.feePayer;
        usedPublicKeys[keyHash] = true;
        _accounts[id] = Account(registration.pkBlob, keyHash, registration.keyCodeHash, 0, 0);
        emit VaultCreated(id, keyHash, registration.feePayer, registration.pkBlob, lockedFee, developerFee);
    }

    function account(bytes32 id) external view returns (Account memory) { return _accounts[id]; }

    function _rotationParams(KeyRotation calldata rotation) private view returns (bytes32) {
        return keccak256(abi.encode(
            keccak256(rotation.publicKey), rotation.pkBlob, rotation.keyCodeHash,
            rotation.executor, verifierCodeHash
        ));
    }

    function rotationMessage(bytes32 id, KeyRotation calldata rotation, Authorization calldata authorization)
        public view returns (bytes memory)
    {
        return authorizationMessage(id, ROTATE_KEY, _rotationParams(rotation),
            authorization.nonce, authorization.expiresAt, authorization.keyEpoch);
    }

    /// @notice New-key consent binds the old credentials and exact old-key intent.
    function rotationPossessionMessage(
        bytes32 id, KeyRotation calldata rotation, Authorization calldata authorization
    ) public view returns (bytes memory) {
        return AuthorizationMessage.encodeAccount(
            block.chainid, address(this), id, keccak256(rotation.publicKey), rotation.keyCodeHash,
            AuthorizationMessage.Request(ROTATION_POP,
                keccak256(rotationMessage(id, rotation, authorization)),
                authorization.nonce, authorization.expiresAt, authorization.keyEpoch)
        );
    }

    /// @notice Requires the current PQ key AND possession of a validated new key.
    /// Keeps identity, balances, payer slot and monotonic nonce. No registration fee.
    function rotateKey(bytes32 id, KeyRotation calldata rotation, Authorization calldata authorization)
        external nonReentrant
    {
        if (rotation.executor != msg.sender) revert InvalidExecutor();
        if (rotation.publicKey.length != 1312) revert InvalidPublicKey();
        bytes32 newKeyHash = keccak256(rotation.publicKey);
        if (usedPublicKeys[newKeyHash]) revert PublicKeyAlreadyRegistered();
        _checkKeyBlob(rotation.pkBlob, rotation.keyCodeHash);

        // Capture both intents before mutating nonce/credentials. Failure of either
        // verification reverts the entire rotation, including nonce consumption.
        bytes memory possessionMessage = rotationPossessionMessage(id, rotation, authorization);
        _consumeAuthorization(id, ROTATE_KEY, _rotationParams(rotation), authorization);
        _verify(rotation.pkBlob, possessionMessage, rotation.proofOfPossession);
        Account storage principal = _accounts[id];
        bytes32 previousKeyHash = principal.publicKeyHash;
        principal.pkBlob = rotation.pkBlob;
        principal.publicKeyHash = newKeyHash;
        principal.keyCodeHash = rotation.keyCodeHash;
        ++principal.keyEpoch;
        usedPublicKeys[newKeyHash] = true; // Retired keys stay burned globally.
        emit KeyRotated(id, previousKeyHash, newKeyHash, rotation.pkBlob, rotation.keyCodeHash,
            principal.keyEpoch, principal.nonce);
    }

    function heldTokenCount(bytes32 id) external view returns (uint256) { return _heldTokens[id].length; }

    /// @notice Page through the tokens a vault has deposited, oldest first. Out-of-range pages are empty.
    function heldTokens(bytes32 id, uint256 start, uint256 count) external view returns (address[] memory page) {
        address[] storage all = _heldTokens[id];
        if (start >= all.length) return page;
        uint256 end = start + count > all.length ? all.length : start + count;
        page = new address[](end - start);
        for (uint256 i = start; i < end; ++i) page[i - start] = all[i];
    }

    function _trackHeld(bytes32 id, address token) private {
        if (_isHeld[id][token]) return;
        _isHeld[id][token] = true;
        _heldTokens[id].push(token);
    }

    /// @notice Commitment the PQ signer must review and bind before asset use: the token's runtime code hash.
    function assetConfigurationHash(address token) external view returns (bytes32) {
        _requireVaultAsset(token);
        return keccak256(abi.encode(_describeAsset(token)));
    }

    /// @notice Public ERC20 custody. Amounts and balances are NOT confidential.
    /// @dev PQ consent binds asset admission as well as payer, amount and code.
    /// No decimals/name/symbol requirement: those are optional ERC20 metadata.
    function depositERC20(
        bytes32 id, address token, uint256 amount, bytes32 expectedAssetHash, Authorization calldata authorization
    ) external nonReentrant {
        _requireVaultAsset(token);
        if (amount == 0) revert InvalidAmount();
        _consumeAuthorization(id, DEPOSIT_ERC20,
            keccak256(abi.encode(token, amount, expectedAssetHash, msg.sender)), authorization);
        _validateAsset(token, expectedAssetHash);
        IERC20 asset = IERC20(token);
        uint256 reserveBefore = asset.balanceOf(address(this));
        if (reserveBefore < totalPublicLiability[token]) revert UnexpectedAssetBalance();
        uint256 payerBefore = asset.balanceOf(msg.sender);
        uint256 supplyBefore = asset.totalSupply();
        asset.safeTransferFrom(msg.sender, address(this), amount);
        uint256 payerAfter = asset.balanceOf(msg.sender);
        if (asset.balanceOf(address(this)) != reserveBefore + amount
            || payerAfter > payerBefore || payerBefore - payerAfter != amount) revert UnexpectedAssetBalance();
        if (asset.totalSupply() != supplyBefore) revert UnsupportedTokenBehavior();
        _validateAsset(token, expectedAssetHash);
        publicBalanceOf[id][token] += amount;
        totalPublicLiability[token] += amount;
        _trackHeld(id, token);
        emit ERC20Deposited(id, token, msg.sender, amount);
    }

    /// @notice Transfer public ERC20 out of this account with independent PQ consent.
    function withdrawERC20(
        bytes32 id, address token, address recipient, uint256 amount,
        bytes32 expectedAssetHash, Authorization calldata authorization
    ) external nonReentrant {
        _requireVaultAsset(token);
        _checkRecipient(recipient);
        if (amount == 0) revert InvalidAmount();
        _consumeAuthorization(id, WITHDRAW_ERC20,
            keccak256(abi.encode(token, recipient, amount, expectedAssetHash, msg.sender)), authorization);
        if (assetConfig[token].kind == AssetKind.Unknown) revert InvalidAsset();
        _validateAsset(token, expectedAssetHash);
        if (publicBalanceOf[id][token] < amount) revert InsufficientPublicBalance();
        IERC20 asset = IERC20(token);
        uint256 reserveBefore = asset.balanceOf(address(this));
        if (reserveBefore < totalPublicLiability[token]) revert UnexpectedAssetBalance();
        uint256 receiverBefore = asset.balanceOf(recipient);
        uint256 supplyBefore = asset.totalSupply();
        publicBalanceOf[id][token] -= amount;
        totalPublicLiability[token] -= amount;
        asset.safeTransfer(recipient, amount);
        uint256 reserveAfter = asset.balanceOf(address(this));
        if (reserveAfter > reserveBefore || reserveBefore - reserveAfter != amount
            || asset.balanceOf(recipient) != receiverBefore + amount) revert UnexpectedAssetBalance();
        if (asset.totalSupply() != supplyBefore) revert UnsupportedTokenBehavior();
        _validateAsset(token, expectedAssetHash);
        emit ERC20Withdrawn(id, token, recipient, amount);
    }

    /// @notice Deposit ETH: it is wrapped into WETH and credited as a normal public WETH balance.
    /// @dev Amounts are PUBLIC. The only ETH this contract ever holds is in transit inside this call.
    function depositETH(bytes32 id, Authorization calldata authorization) external payable nonReentrant {
        if (msg.value == 0) revert InvalidAmount();
        _consumeAuthorization(id, DEPOSIT_ETH, keccak256(abi.encode(msg.value, msg.sender)), authorization);
        _checkWeth();
        uint256 reserveBefore = weth.balanceOf(address(this));
        if (reserveBefore < totalPublicLiability[address(weth)]) revert UnexpectedAssetBalance();
        uint256 supplyBefore = weth.totalSupply();
        weth.deposit{value: msg.value}();
        if (weth.balanceOf(address(this)) != reserveBefore + msg.value
            || weth.totalSupply() != supplyBefore + msg.value) revert UnexpectedAssetBalance();
        publicBalanceOf[id][address(weth)] += msg.value;
        totalPublicLiability[address(weth)] += msg.value;
        _trackHeld(id, address(weth));
        emit ETHDeposited(id, msg.sender, msg.value);
    }

    /// @notice Withdraw ETH from this account's WETH balance with independent PQ consent.
    /// @dev WETH is unwrapped and the exact amount is sent to the recipient fixed in the signature.
    /// Use withdrawERC20 to take WETH out as WETH instead.
    function withdrawETH(bytes32 id, address recipient, uint256 amount, Authorization calldata authorization)
        external nonReentrant
    {
        _checkRecipient(recipient);
        // Sending ETH to WETH would re-wrap it into an unassigned WETH surplus owned by nobody.
        if (recipient == address(weth)) revert InvalidRecipient();
        if (amount == 0) revert InvalidAmount();
        _consumeAuthorization(id, WITHDRAW_ETH, keccak256(abi.encode(recipient, amount, msg.sender)), authorization);
        _checkWeth();
        if (publicBalanceOf[id][address(weth)] < amount) revert InsufficientPublicBalance();
        uint256 reserveBefore = weth.balanceOf(address(this));
        if (reserveBefore < totalPublicLiability[address(weth)]) revert UnexpectedAssetBalance();
        uint256 ethBefore = address(this).balance; // deltas only: forced ETH can never be credited or taken
        uint256 supplyBefore = weth.totalSupply();
        publicBalanceOf[id][address(weth)] -= amount;
        totalPublicLiability[address(weth)] -= amount;
        unwrapping = true; // the only moment receive() accepts ETH, and only from WETH
        weth.withdraw(amount);
        unwrapping = false;
        if (address(this).balance != ethBefore + amount || weth.balanceOf(address(this)) != reserveBefore - amount
            || weth.totalSupply() != supplyBefore - amount) revert UnexpectedAssetBalance();
        (bool sent, ) = recipient.call{value: amount}("");
        if (!sent) revert ETHTransferFailed();
        emit ETHWithdrawn(id, recipient, amount);
    }

    /// @dev Set only while withdrawETH is unwrapping.
    bool private unwrapping;

    /// @notice Plain ETH transfers are rejected: everything must come through depositETH/depositERC20.
    /// The one exception is WETH returning the ETH of an in-progress withdrawETH.
    receive() external payable {
        if (msg.sender != address(weth) || !unwrapping) revert DirectETHRejected();
    }

    /// @notice Unknown calls, with or without ETH, are rejected with a named error.
    fallback() external payable { revert DirectETHRejected(); }

    function _checkWeth() private view {
        if (address(weth).codehash != wethCodeHash) revert CodeChanged();
        if (IERC20Metadata(address(weth)).decimals() != 18) revert TokenConfigurationChanged();
    }

    function _checkRecipient(address recipient) private view {
        if (recipient == address(0) || recipient == address(this)) revert InvalidRecipient();
    }

    function _validateAsset(address token, bytes32 expectedAssetHash) private {
        _requireVaultAsset(token);
        AssetConfig storage stored = assetConfig[token];
        if (stored.kind != AssetKind.Unknown && token.codehash != stored.codeHash) revert CodeChanged();
        AssetConfig memory found = _describeAsset(token);
        if (expectedAssetHash == bytes32(0) || keccak256(abi.encode(found)) != expectedAssetHash) {
            revert AssetConfigurationChanged();
        }
        if (stored.kind == AssetKind.Unknown) {
            assetConfig[token] = found;
            emit AssetAccepted(token, found.kind, found.codeHash);
        } else if (keccak256(abi.encode(stored)) != keccak256(abi.encode(found))) {
            revert AssetConfigurationChanged();
        }
    }

    /// @dev No interface probe: calling optional functions on an ordinary ERC20 would revert internally.
    function _describeAsset(address token) private view returns (AssetConfig memory) {
        return AssetConfig(AssetKind.ERC20, token.codehash);
    }

    function authorizationMessage(
        bytes32 id, bytes32 operation, bytes32 paramsHash, uint256 nonce_, uint256 expiresAt_, uint256 keyEpoch_
    ) public view returns (bytes memory) {
        Account storage principal = _accounts[id];
        if (principal.pkBlob == address(0)) revert UnknownVault();
        return AuthorizationMessage.encodeAccount(
            block.chainid, address(this), id, principal.publicKeyHash, principal.keyCodeHash,
            AuthorizationMessage.Request(operation, paramsHash, nonce_, expiresAt_, keyEpoch_)
        );
    }

    /// @dev Future typed privileged entry points must use this helper under
    /// nonReentrant and recompute paramsHash from all actual operation arguments.
    function _consumeAuthorization(
        bytes32 id, bytes32 operation, bytes32 paramsHash, Authorization calldata authorization
    ) internal {
        Account storage principal = _accounts[id];
        if (principal.pkBlob == address(0)) revert UnknownVault();
        if (msg.sender != controllerOf[id]) revert NotController();
        if (authorization.nonce != principal.nonce) revert InvalidNonce();
        if (authorization.keyEpoch != principal.keyEpoch) revert InvalidEpoch();
        _checkExpiry(authorization.expiresAt);
        _checkKeyBlob(principal.pkBlob, principal.keyCodeHash);
        _verify(principal.pkBlob, authorizationMessage(
            id, operation, paramsHash, authorization.nonce, authorization.expiresAt, authorization.keyEpoch
        ), authorization.signature);
        ++principal.nonce;
    }

    /// @dev No rescue/approval/arbitrary-call API. The fee token can never be a custody asset.
    function _requireVaultAsset(address token) internal view {
        if (token == address(feeToken)) revert LockedFeeToken();
        if (token == address(0) || token == address(this) || token.code.length == 0) revert InvalidAsset();
    }

    function _checkExpiry(uint256 expiresAt) private view {
        if (expiresAt <= block.timestamp || expiresAt - block.timestamp > MAX_AUTHORIZATION_LIFETIME)
            revert InvalidExpiry();
    }

    function _checkKeyBlob(address pkBlob, bytes32 keyCodeHash) private view {
        if (pkBlob.code.length != 20545 || keyCodeHash == bytes32(0) || pkBlob.codehash != keyCodeHash)
            revert InvalidPublicKey();
        bytes memory prefix = new bytes(1);
        assembly ("memory-safe") { extcodecopy(pkBlob, add(prefix, 32), 0, 1) }
        if (prefix[0] != 0) revert InvalidPublicKey();
    }

    function _verify(address pkBlob, bytes memory message, bytes calldata signature) private view {
        if (address(verifier).codehash != verifierCodeHash) revert CodeChanged();
        if (signature.length != 2420 || !verifier.verify(pkBlob, message, signature)) revert InvalidSignature();
    }

    function _checkFeeToken() private view {
        if (address(feeToken).codehash != feeTokenCodeHash) revert CodeChanged();
        if (IERC20Metadata(address(feeToken)).decimals() != feeTokenDecimals) revert TokenConfigurationChanged();
    }

    function _collectRegistrationFee(address payer) private {
        _checkFeeToken();
        uint256 reserveBefore = feeToken.balanceOf(address(this));
        if (reserveBefore < totalLockedFees) revert UnexpectedFeeBalance();
        uint256 payerBefore = feeToken.balanceOf(payer);
        uint256 supplyBefore = feeToken.totalSupply();

        feeToken.safeTransferFrom(payer, address(this), registrationFee);
        uint256 afterCollection = feeToken.balanceOf(address(this));
        uint256 payerAfter = feeToken.balanceOf(payer);
        if (afterCollection < reserveBefore || afterCollection - reserveBefore != registrationFee
            || payerBefore < payerAfter || payerBefore - payerAfter != registrationFee)
            revert UnexpectedFeeBalance();
        if (feeToken.totalSupply() != supplyBefore) revert UnsupportedTokenBehavior();

        // Snapshot after collection also supports developer == fee payer.
        uint256 developerBefore = feeToken.balanceOf(developerWallet);
        feeToken.safeTransfer(developerWallet, developerFee);
        uint256 reserveAfter = feeToken.balanceOf(address(this));
        uint256 developerAfter = feeToken.balanceOf(developerWallet);
        if (reserveAfter != reserveBefore + lockedFee || developerAfter < developerBefore
            || developerAfter - developerBefore != developerFee) revert UnexpectedFeeBalance();
        if (feeToken.totalSupply() != supplyBefore) revert UnsupportedTokenBehavior();
        _checkFeeToken();
    }
}
