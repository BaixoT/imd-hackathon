// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {BunkerVault} from "../src/BunkerVault.sol";
import {RegistrationFeeTokenMock} from "./mocks/RegistrationFixtures.sol";
import {UnderlyingMock} from "./mocks/AssetFixtures.sol";
import {VaultFixture} from "./utils/VaultFixture.sol";

/// @notice BunkerVault key rotation (mock crypto, open admission).
contract RotationTest is VaultFixture {
    address internal blobC = makeAddr("blobC");
    bytes32 internal id;
    BunkerVault.KeyRotation internal rotation;
    BunkerVault.Authorization internal auth;

    /// @dev Synthetic public fixture, NOT a real KeyGen result.
    function publicKeyC() internal pure returns (bytes memory) { return rep(0x33, 1312); }
    function newSignature() internal pure returns (bytes memory) { return rep(0x43, 2420); }

    function setUp() public {
        fixture();
        vm.etch(blobC, blobA.code);
        id = idFor(publicKeyA());
        vault.createVault(registration);
        rotation = BunkerVault.KeyRotation(publicKeyC(), blobC, codeHash, alice, newSignature());
        auth = BunkerVault.Authorization(0, registration.expiresAt, 0, signature());
        arm(rotation, auth);
    }

    function arm(BunkerVault.KeyRotation memory r, BunkerVault.Authorization memory a) internal {
        verifier.configure(blobA, vault.rotationMessage(id, r, a), a.signature, false);
        verifier.configureAdditional(r.pkBlob, vault.rotationPossessionMessage(id, r, a), r.proofOfPossession);
    }

    function rotate(BunkerVault.KeyRotation memory r, BunkerVault.Authorization memory a) internal {
        vault.rotateKey(id, r, a);
    }

    function rotationSnapshot() internal view returns (bytes32) {
        return keccak256(abi.encode(vault.account(id), vault.totalLockedFees(), token.balanceOf(address(vault)),
            token.balanceOf(alice), token.balanceOf(developer), vault.registeredVault(alice),
            vault.usedPublicKeys(keccak256(publicKeyC()))));
    }

    function test_RequiresTwoKeysKeepsIdentityAndFeesAndBumpsNonceAndEpoch() public {
        bytes32 feesBefore = keccak256(abi.encode(vault.totalLockedFees(), token.balanceOf(address(vault)),
            token.balanceOf(alice), token.balanceOf(developer), vault.registeredVault(alice)));
        vm.expectEmit(address(vault));
        emit BunkerVault.KeyRotated(id, keccak256(publicKeyA()), keccak256(publicKeyC()), blobC, codeHash, 1, 1);
        rotate(rotation, auth);
        BunkerVault.Account memory account = vault.account(id);
        assertEq(account.pkBlob, blobC);
        assertEq(account.publicKeyHash, keccak256(publicKeyC()));
        assertEq(account.keyCodeHash, codeHash);
        assertEq(account.nonce, 1);
        assertEq(account.keyEpoch, 1);
        assertEq(keccak256(abi.encode(vault.totalLockedFees(), token.balanceOf(address(vault)),
            token.balanceOf(alice), token.balanceOf(developer), vault.registeredVault(alice))), feesBefore);
        assertTrue(vault.usedPublicKeys(keccak256(publicKeyA())));
        assertTrue(vault.usedPublicKeys(keccak256(publicKeyC())));
        assertEq(vault.account(idFor(publicKeyC())).pkBlob, address(0));
        assertEq(vault.account(idFor(publicKeyC())).publicKeyHash, bytes32(0));
        assertEq(vaultCreatedCount(), 1);
    }

    function test_BindsBothSignaturesToAllRotationParametersAndContext() public {
        bytes32 before = rotationSnapshot();
        for (uint256 i; i < 5; ++i) {
            BunkerVault.KeyRotation memory r = rotation;
            if (i == 0) r.pkBlob = second.pkBlob;
            if (i == 1) r.executor = bob;
            if (i == 2) r.publicKey = publicKeyB();
            if (i == 3) r.keyCodeHash = bytes32(0);
            if (i == 4) r.proofOfPossession = signature();
            vm.expectRevert();
            rotate(r, auth);
        }
        for (uint256 i; i < 5; ++i) {
            BunkerVault.Authorization memory a = auth;
            if (i == 0) a.nonce = 1;
            if (i == 1) a.keyEpoch = 1;
            if (i == 2) a.expiresAt += 1;
            if (i == 3) a.signature = newSignature();
            if (i == 4) a.expiresAt = 0;
            vm.expectRevert();
            rotate(rotation, a);
        }
        vm.prank(relayer);
        vm.expectRevert(BunkerVault.InvalidExecutor.selector);
        vault.rotateKey(id, rotation, auth);
        vm.prank(relayer);
        vm.expectRevert();
        vault.rotateKey(idFor(publicKeyB()), rotation, auth);
        assertEq(rotationSnapshot(), before);
    }

    function test_RollsBackNonceAndCredentialsIfOnlyTheOldKeyConsents() public {
        bytes32 before = rotationSnapshot();
        verifier.configure(blobA, vault.rotationMessage(id, rotation, auth), signature(), false);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        rotate(rotation, auth);
        assertEq(rotationSnapshot(), before);
    }

    function test_RejectsNewKeyOnlyConsentAndUnavailableVerifiers() public {
        bytes32 before = rotationSnapshot();
        verifier.configure(blobC, vault.rotationPossessionMessage(id, rotation, auth), newSignature(), false);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        rotate(rotation, auth);
        verifier.configure(blobA, vault.rotationMessage(id, rotation, auth), signature(), true);
        vm.expectRevert();
        rotate(rotation, auth);
        assertEq(rotationSnapshot(), before);
    }

    function test_RejectsMalformedSignaturesAndChangedKeyCode() public {
        bytes32 before = rotationSnapshot();
        uint256[3] memory lengths = [uint256(0), 2419, 2421];
        for (uint256 i; i < lengths.length; ++i) {
            BunkerVault.KeyRotation memory r = rotation;
            r.proofOfPossession = rep(0x43, lengths[i]);
            arm(r, auth);
            vm.expectRevert(BunkerVault.InvalidSignature.selector);
            rotate(r, auth);
        }
        arm(rotation, auth);
        vm.etch(blobC, bytes.concat(hex"00", rep(0x02, 20544)));
        vm.expectRevert(BunkerVault.InvalidPublicKey.selector);
        rotate(rotation, auth);
        assertEq(rotationSnapshot(), before);
    }

    function test_RejectsSignatureReuseOnAnotherDeployment() public {
        BunkerVault other = deployVault(ctorArgs);
        token.approve(address(other), fee);
        verifier.configure(blobA, other.registrationMessage(registration), signature(), false);
        other.createVault(registration);
        arm(rotation, auth);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        other.rotateKey(id, rotation, auth);
    }

    function test_PreservesNonzeroNonceAndLedgerAndRetiresOldAuthority() public {
        UnderlyingMock asset = new UnderlyingMock(6);
        address tokenAddress = address(asset);
        bytes32 config = vault.assetConfigurationHash(tokenAddress);
        asset.mint(alice, 100);
        asset.approve(address(vault), 100);
        bytes32 hash = keccak256(abi.encode(tokenAddress, uint256(100), config, alice));
        verifier.configure(blobA, vault.authorizationMessage(id, vault.DEPOSIT_ERC20(), hash, 0, auth.expiresAt, 0),
            signature(), false);
        vault.depositERC20(id, tokenAddress, 100, config, auth);
        BunkerVault.Authorization memory rotationAuth = auth;
        rotationAuth.nonce = 1;
        arm(rotation, rotationAuth);
        rotate(rotation, rotationAuth);
        assertEq(vault.account(id).nonce, 2);
        assertEq(vault.publicBalanceOf(id, tokenAddress), 100);
        BunkerVault.Authorization memory next = auth;
        next.nonce = 2;
        next.keyEpoch = 1;
        bytes32 withdrawHash = keccak256(abi.encode(tokenAddress, bob, uint256(60), config, alice));
        bytes memory message = vault.authorizationMessage(id, vault.WITHDRAW_ERC20(), withdrawHash, 2, next.expiresAt, 1);
        verifier.configure(blobA, message, signature(), false);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(id, tokenAddress, bob, 60, config, next);
        BunkerVault.Authorization memory stale = BunkerVault.Authorization(2, next.expiresAt, 0, signature());
        vm.expectRevert(BunkerVault.InvalidEpoch.selector);
        vault.withdrawERC20(id, tokenAddress, bob, 60, config, stale);
        verifier.configure(blobC, message, signature(), false);
        vault.withdrawERC20(id, tokenAddress, bob, 60, config, next);
        assertEq(vault.publicBalanceOf(id, tokenAddress), 40);
        vm.expectRevert(BunkerVault.PublicKeyAlreadyRegistered.selector);
        rotate(rotation, auth);
    }

    function test_RejectsExpiryEqualityExcessiveLifetimeAndMalformedOldKeySignature() public {
        bytes32 before = rotationSnapshot();
        for (uint256 i; i < 3; ++i) {
            BunkerVault.Authorization memory a = auth;
            if (i == 0) a.expiresAt = block.timestamp;
            if (i == 1) a.expiresAt = block.timestamp + 7200;
            if (i == 2) a.signature = "";
            arm(rotation, a);
            vm.expectRevert();
            rotate(rotation, a);
        }
        assertEq(rotationSnapshot(), before);
    }

    function test_RejectsCodeSubstitutionOfCurrentKeyOrVerifier() public {
        bytes32 before = rotationSnapshot();
        bytes memory oldCode = blobA.code;
        vm.etch(blobA, bytes.concat(hex"00", rep(0x02, 20544)));
        vm.expectRevert(BunkerVault.InvalidPublicKey.selector);
        rotate(rotation, auth);
        vm.etch(blobA, oldCode);
        vm.etch(address(verifier), hex"600160005260206000f3");
        vm.expectRevert(BunkerVault.CodeChanged.selector);
        rotate(rotation, auth);
        assertEq(rotationSnapshot(), before);
    }

    function test_BlocksTokenCallbackReentryIntoRotation() public {
        RegistrationFeeTokenMock asset = new RegistrationFeeTokenMock(6);
        address tokenAddress = address(asset);
        bytes32 config = vault.assetConfigurationHash(tokenAddress);
        asset.mint(alice, 20);
        asset.approve(address(vault), 20);
        BunkerVault.KeyRotation memory r = rotation;
        BunkerVault.Authorization memory a = auth;
        asset.setReentry(address(vault), abi.encodeCall(BunkerVault.rotateKey, (id, r, a)));
        bytes32 hash = keccak256(abi.encode(tokenAddress, uint256(20), config, alice));
        verifier.configure(blobA, vault.authorizationMessage(id, vault.DEPOSIT_ERC20(), hash, 0, auth.expiresAt, 0),
            signature(), false);
        vault.depositERC20(id, tokenAddress, 20, config, auth);
        assertFalse(asset.reentrySucceeded());
        assertEq(asset.reentryResult(), abi.encodePacked(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
        BunkerVault.Account memory account = vault.account(id);
        assertEq(account.publicKeyHash, keccak256(publicKeyA()));
        assertEq(account.keyEpoch, 0);
        assertEq(account.nonce, 1);
    }
}
