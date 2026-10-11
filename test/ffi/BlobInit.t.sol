// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {FfiBase} from "./FfiBase.sol";

/// @notice The initcode used to publish a prepared key blob as a contract's runtime code (test/ffi/frontend-lib/blob-init.ts).
contract BlobInitTest is FfiBase {
    function _initCode(string memory runtimeHex) internal returns (bool ok, bytes memory initCode) {
        return abi.decode(bridge("blobinit", runtimeHex, ""), (bool, bytes));
    }

    function test_DeploysThePreparedBlobByteForByteWithPinnedSizeAndPrefix() public requiresFfi {
        bytes memory blob = bytes.concat(hex"00", new bytes(20544));
        for (uint256 i = 1; i < blob.length; ++i) blob[i] = 0xab;
        string memory path = string.concat("cache/ffi/", vm.toString(keccak256(blob)), ".hex");
        vm.createDir("cache/ffi", true);
        vm.writeFile(path, vm.toString(blob));
        (bool ok, bytes memory initCode) = _initCode(string.concat("@", path));
        vm.removeFile(path);
        assertTrue(ok);
        address deployed = create(initCode);
        assertEq(deployed.code, blob);
        assertEq(deployed.code.length, 20545);
        assertEq(deployed.codehash, keccak256(blob));
    }

    function test_WorksForSmallAndOddPayloadsAndRejectsMalformedInput() public requiresFfi {
        bytes memory large = new bytes(301);
        for (uint256 i = 1; i < large.length; ++i) large[i] = 0xff;
        bytes[3] memory blobs = [bytes(hex"00"), hex"0001", large];
        for (uint256 i; i < blobs.length; ++i) {
            (bool ok, bytes memory initCode) = _initCode(vm.toString(blobs[i]));
            assertTrue(ok);
            assertEq(create(initCode).code, blobs[i]);
        }
        string[3] memory bad = ["0x", "0x0", "0xzz"];
        for (uint256 i; i < bad.length; ++i) {
            (bool ok,) = _initCode(bad[i]);
            assertFalse(ok, bad[i]);
        }
    }
}
