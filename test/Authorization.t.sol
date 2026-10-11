// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {AuthorizationMessage} from "../src/AuthorizationMessage.sol";
import {AuthorizationHarness, MessageVerifierMock} from "./mocks/AuthorizationHarness.sol";

/// @notice Authorization policy scaffold (mock verifier, no cryptographic claim). Synthetic signature marker only.
contract AuthorizationTest is Test {
    MessageVerifierMock verifier;
    AuthorizationHarness harness;
    address key;
    address relayer = makeAddr("relayer");
    AuthorizationMessage.Request request;

    function signature() internal pure returns (bytes memory s) {
        s = new bytes(2420);
        for (uint256 i; i < s.length; ++i) s[i] = 0x42;
    }

    function setUp() public {
        verifier = new MessageVerifierMock();
        // Test key is just a contract with code; deliberately no enrollment claim.
        key = address(verifier);
        harness = new AuthorizationHarness(address(verifier), key);
        request = AuthorizationMessage.Request(keccak256("CONFIDENTIAL_TRANSFER"),
            keccak256("opaque encrypted operation parameters"), 0, block.timestamp + 3600, 0);
        verifier.configure(key, harness.message(request), signature(), false);
    }

    function test_MatchesCanonicalAbiEncodingWithChainAndContractDomain() public view {
        bytes memory encoded = abi.encode(keccak256("BunkerVault.Authorization.v1"), uint256(31337), address(harness),
            harness.keyCodeHash(), request.operation, request.paramsHash, request.nonce, request.expiresAt,
            request.keyEpoch);
        assertEq(harness.message(request), encoded);
    }

    function test_AllowsAnIndependentRelayerAndConsumesExactlyOneNonce() public {
        vm.prank(relayer);
        harness.consume(request, signature());
        assertEq(harness.nonce(), 1);
        vm.expectRevert(AuthorizationHarness.InvalidNonce.selector);
        harness.consume(request, signature());
    }

    function test_RejectsSkippedNoncesAndStaleKeyEpochs() public {
        AuthorizationMessage.Request memory r = request;
        r.nonce = 1;
        vm.expectRevert(AuthorizationHarness.InvalidNonce.selector);
        harness.consume(r, signature());
        r = request;
        r.keyEpoch = 1;
        vm.expectRevert(AuthorizationHarness.InvalidEpoch.selector);
        harness.consume(r, signature());
        assertEq(harness.nonce(), 0);
    }

    function test_RejectsTamperingWithOperationParamsAndExpiry() public {
        for (uint256 i; i < 3; ++i) {
            AuthorizationMessage.Request memory r = request;
            if (i == 0) r.operation = keccak256("changed");
            if (i == 1) r.paramsHash = keccak256("changed");
            if (i == 2) r.expiresAt += 1;
            vm.expectRevert(AuthorizationHarness.InvalidSignature.selector);
            harness.consume(r, signature());
        }
        assertEq(harness.nonce(), 0);
    }

    function test_RejectsAnAuthorizationAtTheExactExpiryBoundary() public {
        vm.warp(request.expiresAt);
        vm.expectRevert(AuthorizationHarness.Expired.selector);
        harness.consume(request, signature());
        assertEq(harness.nonce(), 0);
    }

    function test_RejectsZeroExpiryAndMalformedOrAlteredSignatures() public {
        AuthorizationMessage.Request memory r = request;
        r.expiresAt = 0;
        vm.expectRevert(AuthorizationHarness.Expired.selector);
        harness.consume(r, signature());
        bytes memory altered = signature();
        altered[0] = 0x43;
        bytes[4] memory bad = [bytes(""), _resize(2419), altered, _resize(2421)];
        for (uint256 i; i < bad.length; ++i) {
            vm.expectRevert(AuthorizationHarness.InvalidSignature.selector);
            harness.consume(request, bad[i]);
        }
        assertEq(harness.nonce(), 0);
    }

    function test_FailsClosedWhenTheVerifierRevertsEvenForTheDeployer() public {
        verifier.configure(key, harness.message(request), signature(), true);
        vm.expectRevert(bytes("mock verifier unavailable"));
        harness.consume(request, signature());
        assertEq(harness.nonce(), 0);
    }

    function test_RejectsAuthorizationForAnotherChainVaultOrKeyCode() public {
        for (uint256 i; i < 3; ++i) {
            bytes memory foreign = harness.encodeForDomain(
                i == 0 ? 11155111 : 31337, i == 1 ? relayer : address(harness),
                i == 2 ? keccak256("different code") : harness.keyCodeHash(), request);
            verifier.configure(key, foreign, signature(), false);
            vm.expectRevert(AuthorizationHarness.InvalidSignature.selector);
            harness.consume(request, signature());
        }
        assertEq(harness.nonce(), 0);
    }

    function test_RejectsKeyCodeSubstitutionAfterRegistration() public {
        vm.etch(key, hex"00");
        vm.expectRevert(AuthorizationHarness.KeyCodeChanged.selector);
        harness.consume(request, signature());
        assertEq(harness.nonce(), 0);
    }

    function _resize(uint256 length) private pure returns (bytes memory s) {
        s = new bytes(length);
        for (uint256 i; i < length; ++i) s[i] = 0x42;
    }
}
