// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice Proposed BunkerVault message encoding, not a signature verifier or vault.
/// @dev Sign the returned bytes with pure ML-DSA-44 and empty FIPS 204 context.
library AuthorizationMessage {
    bytes32 internal constant DOMAIN = keccak256("BunkerVault.Authorization.v1");
    bytes32 internal constant ACCOUNT_DOMAIN = keccak256("BunkerVault.AccountAuthorization.v2");

    struct Request {
        bytes32 operation;
        bytes32 paramsHash;
        uint256 nonce;
        uint256 expiresAt;
        uint256 keyEpoch;
    }

    function encode(
        uint256 chainId,
        address vault,
        bytes32 keyCodeHash,
        Request memory request
    ) internal pure returns (bytes memory) {
        return abi.encode(
            DOMAIN, chainId, vault, keyCodeHash, request.operation,
            request.paramsHash, request.nonce, request.expiresAt, request.keyEpoch
        );
    }

    /// @dev Shared-vault authorizations bind the logical vault and current key.
    /// The v1 encoding above remains only for the original standalone test fixture.
    function encodeAccount(
        uint256 chainId,
        address bunkerVault,
        bytes32 vaultId,
        bytes32 publicKeyHash,
        bytes32 keyCodeHash,
        Request memory request
    ) internal pure returns (bytes memory) {
        return abi.encode(
            ACCOUNT_DOMAIN, chainId, bunkerVault, vaultId, publicKeyHash,
            keyCodeHash, request.operation, request.paramsHash,
            request.nonce, request.expiresAt, request.keyEpoch
        );
    }
}
