// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IMLDSAVerifier} from "../src/interfaces/IMLDSAVerifier.sol";
import {RealVerifierBase} from "./utils/RealVerifierBase.sol";

/// @notice Pinned research ML-DSA verifier: real EVM verification against public-only NIST vectors.
contract RealVerifierTest is RealVerifierBase {
    string constant MANIFEST = "test/fixtures/fireblocks/manifest.json";
    string constant VECTORS = "test/fixtures/fireblocks/public-vectors.json";
    address helper = makeAddr("helper");
    address blob = makeAddr("blob");
    IMLDSAVerifier verifier;
    string vectors;

    function setUp() public {
        verifier = deployRealVerifier(helper);
        vectors = vm.readFile(VECTORS);
    }

    function _case(uint256 i, string memory field) internal pure returns (string memory) {
        return string.concat(".cases[", vm.toString(i), "].", field);
    }

    function test_ChecksVendoredDigestsHelperIdentityAndPublicOnlyFixtureSchema() public view {
        string memory manifest = vm.readFile(MANIFEST);
        assertEq(vm.parseJsonString(manifest, ".revision"), "cca262b537a5ac2ee55efb427e5c61de0308e566");
        string[] memory files = vm.parseJsonKeys(manifest, ".files");
        assertEq(files.length, 11);
        for (uint256 i; i < files.length; ++i) {
            bytes32 expected = vm.parseBytes32(string.concat("0x",
                vm.parseJsonString(manifest, string.concat(".files['", files[i], "']"))));
            assertEq(sha256(vm.readFileBinary(files[i])), expected, files[i]);
        }
        assertEq(keccak256(helperCode()), HELPER_HASH);
        assertEq(helperCode().length, 21622);
        string[7] memory schema = ["blobCode", "context", "expected", "label", "message", "publicKey", "signature"];
        uint256 accepted;
        uint256 n;
        for (; vm.keyExistsJson(vectors, string.concat(".cases[", vm.toString(n), "]")); ++n) {
            assertEq(vm.parseJsonKeys(vectors, string.concat(".cases[", vm.toString(n), "]")).length, schema.length);
            for (uint256 k; k < schema.length; ++k) assertTrue(vm.keyExistsJson(vectors, _case(n, schema[k])));
            if (vm.parseJsonBool(vectors, _case(n, "expected"))) ++accepted;
            assertEq(vm.parseJsonBytes(vectors, _case(n, "publicKey")).length, 1312);
            assertEq(vm.parseJsonBytes(vectors, _case(n, "blobCode")).length, 20545);
        }
        assertEq(n, 11);
        assertEq(accepted, 8);
    }

    function test_AcceptsAndRejectsEveryOfficialPublicVector() public {
        for (uint256 i; i < 11; ++i) {
            vm.etch(blob, vm.parseJsonBytes(vectors, _case(i, "blobCode")));
            bool result = verifier.verify{gas: 16_000_000}(blob, vm.parseJsonBytes(vectors, _case(i, "message")),
                vm.parseJsonBytes(vectors, _case(i, "signature")));
            assertEq(result, vm.parseJsonBool(vectors, _case(i, "expected")), vm.parseJsonString(vectors, _case(i, "label")));
        }
    }

    function test_RejectsChangedMessageChangedSignatureAndAbsentOrTruncatedKeyCode() public {
        vm.etch(blob, vm.parseJsonBytes(vectors, _case(0, "blobCode")));
        bytes memory message = vm.parseJsonBytes(vectors, _case(0, "message"));
        bytes memory sig = vm.parseJsonBytes(vectors, _case(0, "signature"));
        assertTrue(verifier.verify{gas: 16_000_000}(blob, message, sig)); // positive control
        assertFalse(verifier.verify{gas: 16_000_000}(blob, bytes.concat(message, hex"00"), sig));
        bytes memory changed = bytes.concat(sig);
        changed[100] ^= 0x01;
        assertFalse(verifier.verify{gas: 16_000_000}(blob, message, changed));
        bytes[2] memory codes = [bytes(""), hex"0001"];
        for (uint256 i; i < codes.length; ++i) {
            vm.etch(blob, codes[i]);
            assertFalse(verifier.verify(blob, message, sig));
        }
    }

    function test_FailsClosedIfTheKeccakHelperCodeIsSubstituted() public {
        vm.etch(blob, vm.parseJsonBytes(vectors, _case(0, "blobCode")));
        bytes memory message = vm.parseJsonBytes(vectors, _case(0, "message"));
        bytes memory sig = vm.parseJsonBytes(vectors, _case(0, "signature"));
        vm.etch(helper, hex"00");
        vm.expectRevert();
        verifier.verify(blob, message, sig);
        vm.expectRevert();
        deployCode(VERIFIER_ARTIFACT, abi.encode(helper));
    }

    /// @dev Gas is a local estimate for one public vector only.
    function test_KeepsVerifierRuntimeBelowEIP170() public {
        uint256 size = vm.getDeployedCode(VERIFIER_ARTIFACT).length;
        assertLe(size, 24576);
        vm.etch(blob, vm.parseJsonBytes(vectors, _case(0, "blobCode")));
        bytes memory message = vm.parseJsonBytes(vectors, _case(0, "message"));
        bytes memory sig = vm.parseJsonBytes(vectors, _case(0, "signature"));
        uint256 before = gasleft();
        assertTrue(verifier.verify(blob, message, sig));
        uint256 used = before - gasleft();
        assertLt(used, 16_000_000);
        emit log_named_uint("research verifier runtime bytes", size);
        emit log_named_uint(string.concat("verify gas for ", vm.parseJsonString(vectors, _case(0, "label"))), used);
    }
}
