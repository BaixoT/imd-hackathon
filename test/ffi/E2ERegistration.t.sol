// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {BunkerVault} from "../../src/BunkerVault.sol";
import {IMLDSAVerifier} from "../../src/interfaces/IMLDSAVerifier.sol";
import {RegistrationFeeTokenMock} from "../mocks/RegistrationFixtures.sol";
import {UnderlyingMock} from "../mocks/AssetFixtures.sol";
import {WETH9Mock} from "../mocks/EthFixtures.sol";
import {FfiBase} from "./FfiBase.sol";

/// @notice END-TO-END with the REAL research ML-DSA verifier: the client-side crypto (test/ffi/frontend-lib) generates the key, prepares
/// and publishes the blob, signs the contract's canonical messages, and the contract verifies them on the EVM.
/// Keys are throwaway random seeds; nothing is stored. Alice (this contract) is the controller wallet.
abstract contract E2EBase is FfiBase {
    address alice = address(this);
    address relayer = makeAddr("relayer");
    address developer = makeAddr("developer");
    BunkerVault vault;
    RegistrationFeeTokenMock token;
    WETH9Mock weth;
    uint256 fee;
    Key key;
    BunkerVault.Registration registration;

    receive() external payable {}

    function setUp() public virtual {
        IMLDSAVerifier verifier = deployRealVerifier(makeAddr("helper"));
        token = new RegistrationFeeTokenMock(6);
        weth = new WETH9Mock();
        vault = new BunkerVault(address(token), address(token).codehash, developer, address(verifier),
            address(verifier).codehash, address(weth), address(weth).codehash);
        fee = vault.registrationFee();
        token.mint(alice, fee * 2);
        token.approve(address(vault), fee * 2);
        vm.deal(alice, 10 ether);
    }

    /// @dev Called from tests (after requiresFfi) because it needs the bridge.
    function setUpKey() internal {
        key = makeKey();
        registration = BunkerVault.Registration(key.publicKey, key.pkBlob, key.keyCodeHash, alice, alice,
            block.timestamp + 1800, "");
    }

    function register() internal returns (uint256 gasUsed) {
        BunkerVault.Registration memory reg = registration;
        reg.proofOfPossession = sign(key, vault.registrationMessage(reg));
        uint256 before = gasleft();
        vault.createVault(reg);
        gasUsed = before - gasleft();
    }

    function authorization(Key memory signer, bytes32 operation, bytes32 paramsHash, uint256 expiresAt)
        internal returns (BunkerVault.Authorization memory auth)
    {
        BunkerVault.Account memory a = vault.account(key.vaultId);
        auth = BunkerVault.Authorization(a.nonce, expiresAt, a.keyEpoch, "");
        auth.signature = sign(signer, vault.authorizationMessage(key.vaultId, operation, paramsHash, auth.nonce,
            auth.expiresAt, auth.keyEpoch));
    }

    function authorization(Key memory signer, bytes32 operation, bytes32 paramsHash)
        internal returns (BunkerVault.Authorization memory)
    {
        return authorization(signer, operation, paramsHash, registration.expiresAt);
    }

    function newAsset(uint256 amount) internal returns (address asset, bytes32 assetHash) {
        UnderlyingMock m = new UnderlyingMock(6);
        asset = address(m);
        assetHash = vault.assetConfigurationHash(asset);
        m.mint(alice, amount);
        m.approve(address(vault), amount);
    }

    function depositHash(address asset, uint256 amount, bytes32 assetHash) internal view returns (bytes32) {
        return keccak256(abi.encode(asset, amount, assetHash, alice));
    }

    function rotationTo(Key memory next, Key memory oldSigner, Key memory newSigner)
        internal returns (BunkerVault.KeyRotation memory rotation, BunkerVault.Authorization memory auth)
    {
        BunkerVault.Account memory a = vault.account(key.vaultId);
        rotation = BunkerVault.KeyRotation(next.publicKey, next.pkBlob, next.keyCodeHash, alice, "");
        auth = BunkerVault.Authorization(a.nonce, registration.expiresAt, a.keyEpoch, "");
        auth.signature = sign(oldSigner, vault.rotationMessage(key.vaultId, rotation, auth));
        rotation.proofOfPossession = sign(newSigner, vault.rotationPossessionMessage(key.vaultId, rotation, auth));
    }
}

contract E2ERegistrationTest is E2EBase {
    function test_RegistersALocallyGeneratedKeyWithExactFeeAndPayerAsController() public requiresFfi {
        setUpKey();
        BunkerVault.Registration memory reg = registration;
        reg.proofOfPossession = sign(key, vault.registrationMessage(reg));
        vm.expectEmit(address(vault));
        emit BunkerVault.VaultCreated(key.vaultId, keccak256(key.publicKey), alice, key.pkBlob, fee * 9 / 10, fee / 10);
        vault.createVault(reg);
        assertEq(vault.registeredVault(alice), key.vaultId);
        assertEq(vault.controllerOf(key.vaultId), alice);
        assertEq(token.balanceOf(address(vault)), fee * 9 / 10);
        assertEq(token.balanceOf(developer), fee / 10);
    }

    function test_RejectsACorruptedProofOfPossessionAndASignatureForAnotherMessage() public requiresFfi {
        setUpKey();
        BunkerVault.Registration memory reg = registration;
        reg.proofOfPossession = sign(key, vault.registrationMessage(reg));
        reg.proofOfPossession[100] ^= 0x01;
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(reg);
        reg.proofOfPossession = sign(key, abi.encodePacked(keccak256("another message"), new bytes(268)));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(reg);
        assertEq(vault.registeredVault(alice), bytes32(0));
    }

    function test_AcceptsARealSignatureForAPrivilegedOperationOnlyFromTheController() public requiresFfi {
        setUpKey();
        register();
        (address asset, bytes32 assetHash) = newAsset(100);
        BunkerVault.Authorization memory auth =
            authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 10, assetHash));
        // The file alone is not enough: a different wallet is refused even with a valid signature.
        vm.prank(relayer);
        vm.expectRevert(BunkerVault.NotController.selector);
        vault.depositERC20(key.vaultId, asset, 10, assetHash, auth);
        vault.depositERC20(key.vaultId, asset, 10, assetHash, auth);
        assertEq(vault.publicBalanceOf(key.vaultId, asset), 10);
        assertEq(vault.controllerOf(key.vaultId), alice);
    }

    function test_ReplacesTheKeyWithOldConsentAndNewPossessionKeepingIdentity() public requiresFfi {
        setUpKey();
        register();
        Key memory next = makeKey();
        (BunkerVault.KeyRotation memory rotation, BunkerVault.Authorization memory auth) = rotationTo(next, key, next);
        // Both keys are required: using the old-key consent in both roles must fail.
        BunkerVault.KeyRotation memory swapped = BunkerVault.KeyRotation(rotation.publicKey, rotation.pkBlob,
            rotation.keyCodeHash, rotation.executor, auth.signature);
        vm.expectRevert();
        vault.rotateKey(key.vaultId, swapped, auth);
        uint256 before = gasleft();
        vault.rotateKey(key.vaultId, rotation, auth);
        emit log_named_uint("rotateKey gas (real verifier, two verifications)", before - gasleft());
        BunkerVault.Account memory after_ = vault.account(key.vaultId);
        assertEq(after_.pkBlob, next.pkBlob);
        assertEq(after_.keyEpoch, 1);
        assertEq(vault.registeredVault(alice), key.vaultId);
    }

    function test_MeasuresOperationGasWithTheRealVerifier() public requiresFfi {
        setUpKey();
        uint256 registerGas = register();
        (address asset, bytes32 assetHash) = newAsset(1_000_000);
        BunkerVault.Authorization memory d = authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 500, assetHash));
        uint256 before = gasleft();
        vault.depositERC20(key.vaultId, asset, 500, assetHash, d);
        uint256 depositGas = before - gasleft();
        BunkerVault.Authorization memory w = authorization(key, vault.WITHDRAW_ERC20(),
            keccak256(abi.encode(asset, alice, uint256(200), assetHash, alice)));
        before = gasleft();
        vault.withdrawERC20(key.vaultId, asset, alice, 200, assetHash, w);
        uint256 withdrawGas = before - gasleft();
        assertEq(vault.publicBalanceOf(key.vaultId, asset), 300);
        emit log_named_uint("createVault (excluding blob publication)", registerGas);
        emit log_named_uint("blob publication (CREATE execution gas, local)", key.publishGas);
        emit log_named_uint("first depositERC20 (includes first-use asset admission)", depositGas);
        emit log_named_uint("withdrawERC20", withdrawGas);
    }
}

/// @notice RED TEAM with the REAL verifier: the attacker holds the controller wallet (as after an ECDSA break) but
/// not the victim's key file. Every attempt must be rejected without moving funds or consuming the nonce.
contract AdversarialAuthorizationTest is E2EBase {
    address asset;
    bytes32 assetHash;

    function victim() internal {
        setUpKey();
        register();
        (asset, assetHash) = newAsset(10_000);
    }

    function deposit(uint256 amount, BunkerVault.Authorization memory auth) internal {
        vault.depositERC20(key.vaultId, asset, amount, assetHash, auth);
    }

    function deposit(uint256 amount) internal {
        deposit(amount, authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, amount, assetHash)));
    }

    function test_RejectsASignatureByAnyOtherKeyEvenAValidOne() public requiresFfi {
        victim();
        deposit(500);
        Key memory attackerKey = makeKey(); // the attacker's own genuine key and blob
        uint256 nonce = vault.account(key.vaultId).nonce;
        BunkerVault.Authorization memory forged = authorization(attackerKey, vault.WITHDRAW_ERC20(),
            keccak256(abi.encode(asset, alice, uint256(500), assetHash, alice)));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(key.vaultId, asset, alice, 500, assetHash, forged);
        assertEq(vault.account(key.vaultId).nonce, nonce);
        assertEq(vault.publicBalanceOf(key.vaultId, asset), 500);
    }

    function test_DoesNotLetOneOperationOrParameterSetAuthorizeAnother() public requiresFfi {
        victim();
        deposit(500);
        BunkerVault.Authorization memory dep =
            authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 100, assetHash));
        // same nonce/epoch/expiry, different operation, amount or asset kind
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(key.vaultId, asset, alice, 100, assetHash, dep);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositERC20(key.vaultId, asset, 101, assetHash, dep);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositETH{value: 100}(key.vaultId, dep);
        assertEq(vault.publicBalanceOf(key.vaultId, asset), 500);
    }

    function test_AcceptsASignatureOnceRejectsReplayAndStaleExpiry() public requiresFfi {
        victim();
        BunkerVault.Authorization memory auth =
            authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 50, assetHash));
        deposit(50, auth);
        vm.expectRevert(BunkerVault.InvalidNonce.selector);
        deposit(50, auth);
        vm.warp(block.timestamp + 100);
        uint256[3] memory expiries = [block.timestamp - 1, block.timestamp, block.timestamp + 7200];
        for (uint256 i; i < expiries.length; ++i) {
            BunkerVault.Authorization memory a =
                authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 1, assetHash), expiries[i]);
            vm.expectRevert(BunkerVault.InvalidExpiry.selector);
            deposit(1, a);
        }
    }

    function test_DoesNotLetTheControllerRotateWithItsOwnKeyAsOldConsent() public requiresFfi {
        victim();
        Key memory evil = makeKey();
        // The attacker signs BOTH roles with their own key: old-key consent must come from the vault's current key.
        (BunkerVault.KeyRotation memory rotation, BunkerVault.Authorization memory auth) = rotationTo(evil, evil, evil);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.rotateKey(key.vaultId, rotation, auth);
        assertEq(vault.account(key.vaultId).publicKeyHash, keccak256(key.publicKey));
    }

    function test_InvalidatesSignaturesMadeBeforeAKeyReplacementAndRetiresTheOldKey() public requiresFfi {
        victim();
        BunkerVault.Authorization memory stale =
            authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 5, assetHash));
        Key memory next = makeKey();
        (BunkerVault.KeyRotation memory rotation, BunkerVault.Authorization memory auth) = rotationTo(next, key, next);
        vault.rotateKey(key.vaultId, rotation, auth);
        vm.expectRevert(); // old epoch/nonce AND old key
        deposit(5, stale);
        // The retired key can no longer sign for the vault, even for the CURRENT nonce and epoch.
        BunkerVault.Authorization memory old =
            authorization(key, vault.DEPOSIT_ERC20(), depositHash(asset, 5, assetHash));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        deposit(5, old);
        deposit(5, authorization(next, vault.DEPOSIT_ERC20(), depositHash(asset, 5, assetHash)));
        assertEq(vault.publicBalanceOf(key.vaultId, asset), 5);
    }

    function test_BindsRealETHDepositsAndWithdrawalsToAmountAndRecipient() public requiresFfi {
        victim();
        BunkerVault.Authorization memory auth =
            authorization(key, vault.DEPOSIT_ETH(), keccak256(abi.encode(uint256(0.1 ether), alice)));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositETH{value: 0.1 ether + 1}(key.vaultId, auth);
        vault.depositETH{value: 0.1 ether}(key.vaultId, auth);
        assertEq(vault.publicBalanceOf(key.vaultId, address(weth)), 0.1 ether);
        BunkerVault.Authorization memory w =
            authorization(key, vault.WITHDRAW_ETH(), keccak256(abi.encode(relayer, uint256(0.1 ether), alice)));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawETH(key.vaultId, alice, 0.1 ether, w);
        uint256 before = relayer.balance;
        vault.withdrawETH(key.vaultId, relayer, 0.1 ether, w);
        assertEq(relayer.balance - before, 0.1 ether);
    }
}
