// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IMLDSAVerifier} from "../../src/interfaces/IMLDSAVerifier.sol";
import {GasProbe} from "../mocks/AssetFixtures.sol";
import {FfiBase} from "./FfiBase.sol";

/// @notice DIFFERENTIAL AUDIT TEST: the on-chain research verifier (trusted for every authorization) against the
/// independent noble-post-quantum ML-DSA-44 implementation used for client-side signing. Any accept/reject disagreement
/// is a bug in one of them. Mutations target c~ (0..31), z (32..2335) and the hint block (2336..2419), plus message
/// lengths around the SHAKE rate and the 734-byte case. Seeds are fixed so a failing case can be replayed.
contract VerifierDifferentialTest is FfiBase {
    IMLDSAVerifier verifier;

    function setUp() public {
        verifier = deployRealVerifier(makeAddr("helper"));
    }

    function _agree(Suite memory s) internal view returns (uint256 accepted) {
        for (uint256 i; i < s.messages.length; ++i) {
            bool a = onChain(verifier, s.blobs[s.keyIndex[i]], s.messages[i], s.signatures[i]);
            assertEq(a, s.referenceAccepts[i], string.concat(s.labels[i], ": on-chain disagrees with the reference"));
            if (a) ++accepted;
        }
    }

    function test_AgreesOnEdgeLengthMessagesWrongKeysAndEditedMessages() public requiresFfi {
        Suite memory s = suite("edges", 0xed6e5);
        _agree(s);
        for (uint256 i; i < s.messages.length; i += 3) assertTrue(s.referenceAccepts[i], s.labels[i]); // valid accepted
    }

    function test_AgreesOnEveryMutationOfAValidSignature() public requiresFfi {
        Suite memory s = suite("mutations", 0xb0c4e7);
        uint256 accepted = _agree(s);
        emit log_named_string("differential mutations", string.concat(vm.toString(s.messages.length), " cases, ",
            vm.toString(accepted), " accepted (positive controls), 0 mismatches"));
        assertGt(accepted, 0);
    }

    function test_AcceptsHundredsOfValidSignaturesUnderSeveralKeys() public requiresFfi {
        Suite memory s = suite("valid", 0x51a7);
        assertEq(_agree(s), s.messages.length);
        assertEq(s.messages.length, 400);
    }

    function test_RejectsEveryFIPS204HintEncodingViolation() public requiresFfi {
        Suite memory s = suite("hints", 0x4a11);
        assertEq(_agree(s), 0);
        assertGt(s.messages.length, 300);
    }

    function test_RejectsWrongSignatureLengthsAndAbsentOrWrongSizeKeyBlobs() public requiresFfi {
        Suite memory s = suite("lengths", 0x1e9);
        assertEq(_agree(s), 1); // only the control
        bytes memory message = s.messages[0];
        bytes memory valid = s.signatures[0];
        assertFalse(onChain(verifier, address(0), message, valid));
        assertFalse(onChain(verifier, makeAddr("eoa"), message, valid));
        assertFalse(onChain(verifier, address(verifier), message, valid)); // a contract of the wrong size
    }

    /// @dev Used gas (gasleft delta) for a typical 352-byte authorization message. eth_estimateGas reports a larger
    /// limit because of the 63/64 rule across the verifier's inner calls.
    function test_MeasuresGasUsedByOneVerification() public requiresFfi {
        Suite memory s = suite("probe", 0x352);
        GasProbe probe = new GasProbe();
        for (uint256 i; i < 3; ++i) {
            (bool ok, uint256 used) = probe.measure(address(verifier), s.blobs[0], s.messages[0], s.signatures[0]);
            assertTrue(ok);
            emit log_named_uint("verification gas used", used);
        }
    }
}
