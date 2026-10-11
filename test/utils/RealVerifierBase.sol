// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test} from "forge-std/Test.sol";
import {IMLDSAVerifier} from "../../src/interfaces/IMLDSAVerifier.sol";

/// @notice Deploys the vendored research ML-DSA-44 verifier (compiled via-IR, so deployed from its artifact) with
/// its byte-pinned Keccak-f[1600] helper. Public data only.
abstract contract RealVerifierBase is Test {
    bytes32 internal constant HELPER_HASH = 0x4afb4435879cdf8e50474c7aab2bc3a679caed432550ad6dba64f509309a817b;
    string internal constant VERIFIER_ARTIFACT = "out/MLDSA44Verifier.sol/MLDSA44Verifier.json";

    function helperCode() internal view returns (bytes memory) {
        return vm.parseBytes(string.concat("0x", vm.trim(vm.readFile("test/fixtures/fireblocks/helpers/f1600_170.hex"))));
    }

    function deployRealVerifier(address helper) internal returns (IMLDSAVerifier) {
        vm.etch(helper, helperCode());
        return IMLDSAVerifier(deployCode(VERIFIER_ARTIFACT, abi.encode(helper)));
    }

    /// @dev Publishes a contract whose runtime is exactly the bytes `initCode` returns (e.g. a prepared key blob).
    function create(bytes memory initCode) internal returns (address deployed) {
        assembly ("memory-safe") { deployed := create(0, add(initCode, 32), mload(initCode)) }
        require(deployed != address(0), "create failed");
    }

    /// @dev A revert, short return or unavailable verifier is a rejection.
    function onChain(IMLDSAVerifier verifier, address blob, bytes memory message, bytes memory sig)
        internal view returns (bool)
    {
        try verifier.verify{gas: 30_000_000}(blob, message, sig) returns (bool accepted) { return accepted; }
        catch { return false; }
    }
}
