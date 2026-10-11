// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {BunkerVault} from "../src/BunkerVault.sol";
import {RegistrationFeeTokenMock, MissingFeeMetadataMock, RegistrationHarness} from "./mocks/RegistrationFixtures.sol";
import {UnderlyingMock} from "./mocks/AssetFixtures.sol";
import {VaultFixture} from "./utils/VaultFixture.sol";

/// @notice Shared BunkerVault registration (on-chain policy with mock ML-DSA verifier).
contract RegistrationTest is VaultFixture {
    function test_RejectsOldShadowVaultDomainAfterRename() public {
        fixture();
        bytes memory message = vault.registrationMessage(registration);
        bytes memory former = bytes.concat(keccak256("ShadowVault.AccountAuthorization.v2"), _from(message, 32));
        verifier.configure(blobA, former, signature(), false);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(registration);
        assertEq(vault.registeredVault(alice), bytes32(0));
        assertEq(vault.VAULT_ID_DOMAIN(), keccak256("BunkerVault.VaultIdentity.v1"));
    }

    function test_CreatesDeterministicVaultAndSplitsExactly90_10() public {
        fixture();
        bytes32 id = idFor(publicKeyA());
        vm.expectEmit(address(vault));
        emit BunkerVault.VaultCreated(id, keccak256(publicKeyA()), alice, blobA, fee * 9 / 10, fee / 10);
        vault.createVault(registration);
        assertEq(vault.vaultIdFor(publicKeyA()), id);
        assertEq(vault.registeredVault(alice), id);
        assertTrue(vault.usedPublicKeys(keccak256(publicKeyA())));
        BunkerVault.Account memory account = vault.account(id);
        assertEq(account.pkBlob, blobA);
        assertEq(account.publicKeyHash, keccak256(publicKeyA()));
        assertEq(account.keyCodeHash, codeHash);
        assertEq(account.nonce, 0);
        assertEq(account.keyEpoch, 0);
        assertEq(token.balanceOf(alice), fee * 9);
        assertEq(token.balanceOf(developer), fee / 10);
        assertEq(token.balanceOf(address(vault)), fee * 9 / 10);
        assertEq(vault.totalLockedFees(), fee * 9 / 10);
        assertEq(token.allowance(address(vault), developer), 0);
    }

    function test_ChargesExactlyOneTokenWith1Decimal() public { _chargesOneToken(1); }
    function test_ChargesExactlyOneTokenWith6Decimals() public { _chargesOneToken(6); }
    function test_ChargesExactlyOneTokenWith18Decimals() public { _chargesOneToken(18); }

    function _chargesOneToken(uint8 decimals) private {
        Options memory o = defaults();
        o.decimals = decimals;
        fixture(o);
        uint256 unit = 10 ** decimals;
        assertEq(fee, unit);
        assertEq(vault.developerFee(), unit / 10);
        assertEq(vault.lockedFee(), 9 * unit / 10);
        vault.createVault(registration);
        assertEq(token.balanceOf(developer), unit / 10);
        assertEq(token.balanceOf(address(vault)), 9 * unit / 10);
    }

    function test_RejectsDuplicatePayerWithoutAnotherFee() public {
        fixture();
        vault.createVault(registration);
        bytes32 before = snapshot();
        vm.expectRevert(BunkerVault.AlreadyRegistered.selector);
        vault.createVault(registration);
        assertEq(snapshot(), before);
        assertEq(vaultCreatedCount(), 1);
    }

    function test_SettlesExactlyWhenDeveloperIsAlsoPayer() public {
        Options memory o = defaults();
        o.developerIsPayer = true;
        fixture(o);
        vault.createVault(registration);
        assertEq(token.balanceOf(alice), fee * 9 + fee / 10);
        assertEq(token.balanceOf(address(vault)), fee * 9 / 10);
        assertEq(vault.totalLockedFees(), fee * 9 / 10);
    }

    function test_RejectsDuplicatePublicKeyFromAnotherPayerSlot() public {
        Options memory o = defaults();
        o.sameKey = true;
        fixture(o);
        vault.createVault(registration);
        arm(second);
        bytes32 before = snapshot();
        uint256 bobBefore = token.balanceOf(bob);
        vm.prank(bob);
        vm.expectRevert(BunkerVault.PublicKeyAlreadyRegistered.selector);
        vault.createVault(second);
        assertEq(snapshot(), before);
        assertEq(token.balanceOf(bob), bobBefore);
        assertEq(vault.registeredVault(bob), bytes32(0));
    }

    function test_RejectsRelayerSpendingAnotherPayersAllowance() public {
        fixture();
        bytes32 before = snapshot();
        BunkerVault.Registration memory reg = registration;
        reg.executor = relayer;
        arm(reg);
        vm.prank(relayer);
        vm.expectRevert(BunkerVault.InvalidExecutor.selector);
        vault.createVault(reg);
        assertEq(snapshot(), before);
    }

    function test_AtomicallyRejectsInsufficientBalance() public { _insufficient(true); }
    function test_AtomicallyRejectsInsufficientAllowance() public { _insufficient(false); }

    function _insufficient(bool balance) private {
        Options memory o = defaults();
        o.funded = false;
        fixture(o);
        token.mint(alice, balance ? fee - 1 : fee);
        token.approve(address(vault), balance ? fee : fee - 1);
        bytes32 before = snapshot();
        vm.expectRevert();
        vault.createVault(registration);
        assertEq(snapshot(), before);
        assertEq(vaultCreatedCount(), 0);
    }

    /// @dev Modes 1..6: false / revert / no-op / tax / rebase / surcharge.
    function test_RollsBackEveryBadPullTransferMode() public {
        for (uint8 mode = 1; mode <= 6; ++mode) _rollsBack(mode, 0);
    }

    function test_RollsBackEveryBadDeveloperTransferMode() public {
        for (uint8 mode = 1; mode <= 6; ++mode) _rollsBack(0, mode);
    }

    function _rollsBack(uint8 pull, uint8 send) private {
        fixture();
        token.setModes(pull, send);
        bytes32 before = snapshot();
        vm.expectRevert();
        vault.createVault(registration);
        assertEq(snapshot(), before);
        assertEq(vaultCreatedCount(), 0);
    }

    function test_AcceptsExactSettlementTokensWithoutBooleanReturn() public {
        Options memory o = defaults();
        o.noReturn = true;
        fixture(o);
        vault.createVault(registration);
        assertEq(token.balanceOf(address(vault)), fee * 9 / 10);
        assertEq(token.balanceOf(developer), fee / 10);
    }

    function test_RejectsUnsupportedDecimalsAtConstruction() public {
        fixture();
        uint8[3] memory bad = [0, 19, 255];
        for (uint256 i; i < bad.length; ++i) {
            CtorArgs memory a = ctorArgs;
            a.feeToken = address(new RegistrationFeeTokenMock(bad[i]));
            a.feeTokenCodeHash = a.feeToken.codehash;
            vm.expectRevert(BunkerVault.UnsupportedDecimals.selector);
            deployVault(a);
        }
    }

    function test_RejectsMissingMetadataAndChangedDecimalsWithoutDefaulting() public {
        fixture();
        CtorArgs memory a = ctorArgs;
        a.feeToken = address(new MissingFeeMetadataMock());
        a.feeTokenCodeHash = a.feeToken.codehash;
        vm.expectRevert();
        deployVault(a);
        token.setDecimals(6);
        bytes32 before = snapshot();
        vm.expectRevert(BunkerVault.TokenConfigurationChanged.selector);
        vault.createVault(registration);
        assertEq(snapshot(), before);
    }

    function test_RejectsUnsafeConstructorConfiguration() public {
        fixture();
        for (uint256 i; i < 7; ++i) {
            CtorArgs memory a = ctorArgs;
            if (i == 0) a.feeToken = address(0);
            if (i == 1) a.feeTokenCodeHash = keccak256("wrong token code");
            if (i == 2) a.developer = address(0);
            if (i == 3) a.verifier = address(0);
            if (i == 4) a.verifierCodeHash = keccak256("wrong verifier code");
            if (i == 5) a.weth = address(0);
            if (i == 6) a.wethCodeHash = keccak256("wrong weth code");
            vm.expectRevert(BunkerVault.InvalidConfiguration.selector);
            deployVault(a);
        }
    }

    function test_ValidatesPoPBeforeTouchingARevertingFeeToken() public {
        fixture();
        token.setModes(2, 2);
        bytes32 before = snapshot();
        BunkerVault.Registration memory reg = registration;
        reg.proofOfPossession = rep(0x43, 2420);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(reg);
        assertEq(snapshot(), before);
        assertEq(token.pullCalls(), 0);
    }

    function test_RejectsWrongSizePublicKeysWithNoState() public {
        fixture();
        uint256[3] memory lengths = [uint256(0), 1311, 1313];
        bytes32 before = snapshot();
        for (uint256 i; i < lengths.length; ++i) {
            BunkerVault.Registration memory reg = registration;
            reg.publicKey = rep(0x11, lengths[i]);
            vm.expectRevert(BunkerVault.InvalidPublicKey.selector);
            vault.createVault(reg);
        }
        assertEq(snapshot(), before);
    }

    function test_RejectsAbsentTruncatedSubstitutedAndWrongPrefixKeyCode() public {
        bytes[4] memory codes =
            [bytes(""), hex"00", bytes.concat(hex"01", rep(0x01, 20544)), bytes.concat(hex"00", rep(0x02, 20544))];
        for (uint256 i; i < codes.length; ++i) {
            fixture();
            bytes32 before = snapshot();
            vm.etch(blobA, codes[i]);
            BunkerVault.Registration memory reg = registration;
            // Matching a wrong-prefix hash still cannot bypass the prefix check.
            if (i == 2) reg.keyCodeHash = keccak256(codes[i]);
            vm.expectRevert(BunkerVault.InvalidPublicKey.selector);
            vault.createVault(reg);
            assertEq(snapshot(), before);
        }
    }

    function test_FailsClosedOnVerifierRevertMalformedOutputOrSubstitution() public {
        fixture();
        bytes32 before = snapshot();
        arm(registration, true);
        vm.expectRevert(bytes("mock verifier unavailable"));
        vault.createVault(registration);
        assertEq(snapshot(), before);
        vm.etch(address(verifier), hex"00");
        vm.expectRevert(BunkerVault.CodeChanged.selector);
        vault.createVault(registration);
        assertEq(snapshot(), before);
        // A pinned malformed-return verifier must fail ABI decoding, not become success.
        bytes memory malformedCode = hex"600160005360016000f3";
        vm.etch(attacker, malformedCode);
        CtorArgs memory a = ctorArgs;
        a.verifier = attacker;
        a.verifierCodeHash = keccak256(malformedCode);
        BunkerVault other = deployVault(a);
        vm.expectRevert();
        other.createVault(registration);
        assertEq(other.registeredVault(alice), bytes32(0));
        vm.etch(attacker, "");
    }

    function test_RejectsMalformedSignatureSizes() public {
        fixture();
        bytes32 before = snapshot();
        uint256[3] memory lengths = [uint256(0), 2419, 2421];
        for (uint256 i; i < lengths.length; ++i) {
            BunkerVault.Registration memory reg = registration;
            reg.proofOfPossession = rep(0x42, lengths[i]);
            vm.expectRevert(BunkerVault.InvalidSignature.selector);
            vault.createVault(reg);
        }
        assertEq(snapshot(), before);
    }

    function test_RejectsExpiredAndUnboundedRegistrationProofs() public {
        fixture();
        bytes32 before = snapshot();
        uint256[3] memory expiries = [0, block.timestamp, block.timestamp + 7200];
        for (uint256 i; i < expiries.length; ++i) {
            BunkerVault.Registration memory reg = registration;
            reg.expiresAt = expiries[i];
            vm.expectRevert(BunkerVault.InvalidExpiry.selector);
            vault.createVault(reg);
        }
        assertEq(snapshot(), before);
    }

    function test_RejectsCopiedPoPFromAnotherExecutor() public {
        fixture();
        bytes32 before = snapshot();
        vm.prank(attacker);
        vm.expectRevert(BunkerVault.InvalidExecutor.selector);
        vault.createVault(registration);
        BunkerVault.Registration memory modified = registration;
        modified.executor = attacker;
        // Open admission: payment consent requires the payer to submit, so this stops earlier.
        vm.prank(attacker);
        vm.expectRevert(BunkerVault.InvalidExecutor.selector);
        vault.createVault(modified);
        assertEq(snapshot(), before);
        vault.createVault(registration);
    }

    function test_BindsPoPToPublicKeyBlobPayerExecutorAndExpiry() public {
        Options memory o = defaults();
        o.sameKey = true;
        fixture(o);
        bytes32 before = snapshot();
        for (uint256 i; i < 3; ++i) {
            BunkerVault.Registration memory reg = registration;
            if (i == 0) reg.pkBlob = second.pkBlob;
            if (i == 1) reg.expiresAt += 1;
            if (i == 2) reg.publicKey = publicKeyB();
            vm.expectRevert(BunkerVault.InvalidSignature.selector);
            vault.createVault(reg);
        }
        assertEq(snapshot(), before);
    }

    function test_EncodesContractChainVaultIdKeyAndFeeIntentCanonically() public {
        fixture();
        BunkerVault.Registration memory reg = registration;
        bytes32 paramsHash = keccak256(abi.encode(
            reg.pkBlob, reg.feePayer, reg.executor, address(token), vault.feeTokenCodeHash(),
            vault.feeTokenDecimals(), fee, developer, fee / 10, fee * 9 / 10, vault.verifierCodeHash()
        ));
        bytes memory encoded = abi.encode(
            keccak256("BunkerVault.AccountAuthorization.v2"), uint256(31337), address(vault), idFor(publicKeyA()),
            keccak256(publicKeyA()), reg.keyCodeHash, keccak256("BunkerVault.CreateVault.v2"), paramsHash,
            uint256(0), reg.expiresAt, uint256(0)
        );
        assertEq(vault.registrationMessage(reg), encoded);
        bytes memory foreign = bytes.concat(_word(encoded, 0), bytes32(uint256(11155111)), _from(encoded, 64));
        verifier.configure(reg.pkBlob, foreign, signature(), false);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(reg);
    }

    function test_RejectsPoPReplayOnAnotherDeployment() public {
        fixture();
        BunkerVault other = deployVault(ctorArgs);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        other.createVault(registration);
        assertEq(other.registeredVault(alice), bytes32(0));
    }

    function test_BlocksRegistrationReentryDuringFeeCollection() public {
        fixture();
        BunkerVault.Registration memory reg = registration;
        token.setReentry(address(vault), abi.encodeCall(BunkerVault.createVault, (reg)));
        vault.createVault(reg);
        assertFalse(token.reentrySucceeded());
        assertEq(token.reentryResult(), abi.encodePacked(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
        assertEq(vaultCreatedCount(), 1);
        assertEq(vault.totalLockedFees(), fee * 9 / 10);
    }

    function test_KeepsUnsolicitedFeeTokensLockedAndOutOfCustody() public {
        fixture();
        uint256 donation = 13;
        token.transfer(address(vault), donation);
        vault.createVault(registration);
        assertEq(token.balanceOf(address(vault)), donation + fee * 9 / 10);
        assertEq(vault.totalLockedFees(), fee * 9 / 10);
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        vault.assetConfigurationHash(address(token));
    }

    function test_AccumulatesReservesWithoutMixingCredentials() public {
        fixture();
        vault.createVault(registration);
        bytes32 first = keccak256(abi.encode(vault.account(idFor(publicKeyA()))));
        arm(second);
        createAs(bob, second);
        assertEq(token.balanceOf(address(vault)), 2 * fee * 9 / 10);
        assertEq(token.balanceOf(developer), 2 * fee / 10);
        assertEq(vault.totalLockedFees(), 2 * fee * 9 / 10);
        assertEq(keccak256(abi.encode(vault.account(idFor(publicKeyA())))), first);
        assertEq(vault.account(idFor(publicKeyB())).publicKeyHash, keccak256(publicKeyB()));
    }

    function test_FailedLaterRegistrationCannotSpendEarlierReserves() public {
        fixture();
        vault.createVault(registration);
        bytes32 before = snapshot();
        arm(second);
        token.setModes(0, 6);
        vm.prank(bob);
        vm.expectRevert();
        vault.createVault(second);
        assertEq(snapshot(), before);
        assertEq(vault.registeredVault(bob), bytes32(0));
    }

    function test_HasNoAdminRescueReplacementUpgradeDelegatecallOrFeeApproval() public {
        fixture();
        vault.createVault(registration);
        bytes32 before = snapshot();
        address[3] memory callers = [alice, developer, attacker];
        string[8] memory signatures = ["withdraw(address,uint256)", "rescueTokens(address,address,uint256)",
            "upgradeTo(address)", "execute(address,bytes)", "setDeveloperWallet(address)",
            "setPublicKey(bytes32,bytes)", "rotateKey(bytes32,bytes)", "recoverVault(bytes32,address)"];
        for (uint256 c; c < callers.length; ++c) {
            for (uint256 s; s < signatures.length; ++s) {
                vm.prank(callers[c]);
                (bool ok,) = address(vault).call(abi.encodePacked(bytes4(keccak256(bytes(signatures[s])))));
                assertFalse(ok, signatures[s]);
            }
        }
        assertEq(snapshot(), before);
        assertEq(vault.developerWallet(), developer);
        assertEq(token.allowance(address(vault), developer), 0);
    }

    function test_ContainsNoExecutableDelegatecallCallcodeOrSelfdestruct() public view {
        bytes memory code = vm.getDeployedCode("BunkerVault.sol:BunkerVault");
        // Solidity's final two bytes encode the CBOR metadata length, which is data.
        uint256 metadataLength = uint8(code[code.length - 2]) * 256 + uint8(code[code.length - 1]);
        uint256 executableEnd = code.length - metadataLength - 2;
        assertGt(executableEnd, 0);
        for (uint256 pc; pc < executableEnd; ++pc) {
            uint8 opcode = uint8(code[pc]);
            assertTrue(opcode != 0xf2 && opcode != 0xf4 && opcode != 0xff, string.concat("forbidden opcode at ",
                vm.toString(pc)));
            if (opcode >= 0x60 && opcode <= 0x7f) pc += opcode - 0x5f;
        }
    }

    // ---- open admission: no root, no KeyGen proof ----

    function test_OpenAdmissionRegistersSelfSubmittingPayer() public {
        fixture();
        createAs(alice, registration);
        assertEq(vault.registeredVault(alice), idFor(publicKeyA()));
        assertEq(vault.totalLockedFees(), fee * 9 / 10);
    }

    /// @dev The constructor arity (7 static arguments) is enforced at compile time by deployVault.
    function test_OpenAdmissionExposesNoAdmissionPolicySurface() public view {
        assertFalse(abiHasFunction("enrollmentRoot"));
        assertFalse(abiHasFunction("keyValidationVerifier"));
        assertFalse(abiHasFunction("keyValidationPolicyId"));
        assertTrue(abiHasFunction("createVault")); // the ABI lookup itself works
    }

    function test_OpenAdmissionRejectsArbitraryKeyWhosePoPDoesNotVerify() public {
        fixture();
        bytes32 before = snapshot();
        BunkerVault.Registration memory reg = registration;
        reg.proofOfPossession = rep(0x43, 2420);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.createVault(reg);
        assertEq(snapshot(), before);
    }

    // ---- shared authorization and asset lock boundary (test-only public asset harness) ----

    function _harness() private returns (RegistrationHarness h) {
        Options memory o = defaults();
        o.harness = true;
        fixture(o);
        h = RegistrationHarness(payable(address(vault)));
        vault.createVault(registration);
    }

    function test_HarnessRejectsFeeTokenDepositWithdrawalAndRescue() public {
        RegistrationHarness h = _harness();
        bytes32 id = idFor(publicKeyA());
        BunkerVault.Authorization memory auth = BunkerVault.Authorization(0, registration.expiresAt, 0, signature());
        bytes32 before = snapshot();
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        h.depositForTest(id, address(token), 1);
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        h.withdrawForTest(id, address(token), alice, 1, auth);
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        h.rescueForTest(address(token));
        assertEq(snapshot(), before);
    }

    function test_HarnessCompromisedEOACannotSpendOrAuthorizeWithoutPQ() public {
        RegistrationHarness h = _harness();
        bytes32 id = idFor(publicKeyA());
        UnderlyingMock asset = new UnderlyingMock(6);
        asset.mint(alice, 100);
        asset.approve(address(vault), 100);
        h.depositForTest(id, address(asset), 100);
        bytes[3] memory badSignatures = [bytes(""), signature(), rep(0x43, 2420)];
        string[3] memory operations = ["ROTATE_KEY", "RECOVERY", "UPDATE_POLICY"];
        for (uint256 i; i < badSignatures.length; ++i) {
            BunkerVault.Authorization memory auth =
                BunkerVault.Authorization(0, registration.expiresAt, 0, badSignatures[i]);
            vm.expectRevert(BunkerVault.InvalidSignature.selector);
            h.withdrawForTest(id, address(asset), attacker, 100, auth);
            for (uint256 j; j < operations.length; ++j) {
                vm.expectRevert(BunkerVault.InvalidSignature.selector);
                h.authorizeForTest(id, keccak256(bytes(operations[j])), keccak256("attacker parameters"), auth);
            }
        }
        assertEq(h.testBalances(id, address(asset)), 100);
        assertEq(asset.balanceOf(attacker), 0);
        assertEq(vault.account(id).pkBlob, blobA);
        assertEq(vault.account(id).nonce, 0);
    }

    function test_HarnessAcceptsOnlyOwnControllerKeepsLedgersAndNeverRecharges() public {
        RegistrationHarness h = _harness();
        arm(second);
        createAs(bob, second);
        Snapshot memory feeBefore = snapshotOf();
        bytes32 idA = idFor(publicKeyA());
        bytes32 idB = idFor(publicKeyB());
        UnderlyingMock asset = new UnderlyingMock(6);
        asset.mint(alice, 100);
        asset.approve(address(vault), 100);
        h.depositForTest(idA, address(asset), 100);
        asset.mint(bob, 200);
        vm.startPrank(bob);
        asset.approve(address(vault), 200);
        h.depositForTest(idB, address(asset), 200);
        vm.stopPrank();
        bytes32 params = keccak256(abi.encode(address(asset), relayer, uint256(30)));
        BunkerVault.Authorization memory auth = BunkerVault.Authorization(0, registration.expiresAt, 0, signature());
        verifier.configure(blobA, vault.authorizationMessage(idA, h.TEST_WITHDRAW(), params, 0, auth.expiresAt, 0),
            signature(), false);
        vm.expectRevert(BunkerVault.NotController.selector);
        h.withdrawForTest(idB, address(asset), relayer, 30, auth);
        h.withdrawForTest(idA, address(asset), relayer, 30, auth);
        assertEq(h.testBalances(idA, address(asset)), 70);
        assertEq(h.testBalances(idB, address(asset)), 200);
        assertEq(vault.account(idA).nonce, 1);
        assertEq(vault.account(idB).nonce, 0);
        assertEq(asset.balanceOf(relayer), 30);
        Snapshot memory feeAfter = snapshotOf();
        feeAfter.account = feeBefore.account;
        assertEq(keccak256(abi.encode(feeAfter)), keccak256(abi.encode(feeBefore)));
        vm.expectRevert(BunkerVault.InvalidNonce.selector);
        h.withdrawForTest(idA, address(asset), relayer, 30, auth);
    }

    // ---- byte helpers ----

    function _from(bytes memory data, uint256 start) private pure returns (bytes memory out) {
        out = new bytes(data.length - start);
        for (uint256 i; i < out.length; ++i) out[i] = data[start + i];
    }

    function _word(bytes memory data, uint256 offset) private pure returns (bytes32 word) {
        assembly ("memory-safe") { word := mload(add(add(data, 32), offset)) }
    }
}
