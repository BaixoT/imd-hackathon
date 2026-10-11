// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Fireblocks' verified upstream ABI (not a verifier implementation).
/// @dev Source: fireblocks-labs/evm-ml-dsa-verifier at
/// cca262b537a5ac2ee55efb427e5c61de0308e566, src/IMLDSAVerifier.sol.
/// Pure ML-DSA-44, empty context, 2420-byte signatures, prepared public-key code.
interface IMLDSAVerifier {
    function verify(address pkBlob, bytes calldata message, bytes calldata signature)
        external view returns (bool accepted);
}
