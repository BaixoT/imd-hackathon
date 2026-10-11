// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Vm} from "forge-std/Vm.sol";
import {RealVerifierBase} from "../utils/RealVerifierBase.sol";

/// @notice Tests that drive the client-side key/signing crypto (test/ffi/frontend-lib) through test/ffi/mldsa.mjs.
/// They are skipped unless forge runs with --ffi (and need `npm ci` in test/ffi plus Node >= 22.18).
abstract contract FfiBase is RealVerifierBase {
    string internal constant BRIDGE = "test/ffi/mldsa.mjs";

    struct Key {
        bytes publicKey;
        address pkBlob;
        bytes32 keyCodeHash;
        bytes32 vaultId;
        bytes keyFile;
        uint256 publishGas;
    }

    struct Suite {
        address[] blobs;
        uint256[] keyIndex;
        bytes[] messages;
        bytes[] signatures;
        bool[] referenceAccepts;
        string[] labels;
    }

    modifier requiresFfi() {
        string[] memory probe = new string[](2);
        probe[0] = "node";
        probe[1] = "--version";
        bool enabled;
        try vm.tryFfi(probe) returns (Vm.FfiResult memory result) { enabled = result.exitCode == 0; } catch {}
        if (!enabled) vm.skip(true);
        _;
    }

    function bridge(string memory a) internal returns (bytes memory) {
        string[] memory cmd = new string[](3);
        (cmd[0], cmd[1], cmd[2]) = ("node", BRIDGE, a);
        return vm.ffi(cmd);
    }

    function bridge(string memory a, string memory b, string memory c, string memory d) internal returns (bytes memory) {
        string[] memory cmd = new string[](6);
        (cmd[0], cmd[1], cmd[2], cmd[3], cmd[4], cmd[5]) = ("node", BRIDGE, a, b, c, d);
        return vm.ffi(cmd);
    }

    function bridge(string memory a, string memory b, string memory c) internal returns (bytes memory) {
        string[] memory cmd = new string[](5);
        (cmd[0], cmd[1], cmd[2], cmd[3], cmd[4]) = ("node", BRIDGE, a, b, c);
        return vm.ffi(cmd);
    }

    /// @dev Frontend KeyGen -> prepare -> publication initcode -> key file (empty password); blob published here.
    function makeKey() internal returns (Key memory k) {
        bytes memory initCode;
        (k.publicKey, initCode, k.vaultId, k.keyFile) = abi.decode(bridge("keygen"), (bytes, bytes, bytes32, bytes));
        uint256 before = gasleft();
        k.pkBlob = create(initCode);
        k.publishGas = before - gasleft();
        k.keyCodeHash = k.pkBlob.codehash;
    }

    /// @dev Signs `message` with signMessage (decrypts the key file, checks it matches `publicKey`).
    function sign(Key memory k, bytes memory message) internal returns (bytes memory) {
        return abi.decode(bridge("sign", vm.toString(k.keyFile), vm.toString(message), vm.toString(k.publicKey)), (bytes));
    }

    function suite(string memory name, uint256 seed) internal returns (Suite memory s) {
        bytes[] memory initCodes;
        (initCodes, s.keyIndex, s.messages, s.signatures, s.referenceAccepts, s.labels) = abi.decode(
            bridge("suite", name, vm.toString(seed)), (bytes[], uint256[], bytes[], bytes[], bool[], string[]));
        s.blobs = new address[](initCodes.length);
        for (uint256 i; i < initCodes.length; ++i) s.blobs[i] = create(initCodes[i]);
    }
}
