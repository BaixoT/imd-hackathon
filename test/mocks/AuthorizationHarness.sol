// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {AuthorizationMessage} from "../../src/AuthorizationMessage.sol";
import {IMLDSAVerifier} from "../../src/interfaces/IMLDSAVerifier.sol";

/// @notice TEST ONLY: no assets, no enrollment validator, no production authorization.
contract AuthorizationHarness {
    IMLDSAVerifier public immutable verifier;
    address public immutable pkBlob;
    bytes32 public immutable keyCodeHash;
    uint256 public nonce;
    uint256 public keyEpoch;

    error InvalidNonce();
    error Expired();
    error InvalidEpoch();
    error InvalidSignature();
    error KeyCodeChanged();

    constructor(address verifier_, address pkBlob_) {
        verifier = IMLDSAVerifier(verifier_);
        pkBlob = pkBlob_;
        keyCodeHash = pkBlob_.codehash;
    }

    function encodeForDomain(
        uint256 chainId, address vault, bytes32 codeHash,
        AuthorizationMessage.Request calldata request
    ) external pure returns (bytes memory) {
        return AuthorizationMessage.encode(chainId, vault, codeHash, request);
    }

    function message(AuthorizationMessage.Request calldata request) public view returns (bytes memory) {
        return AuthorizationMessage.encode(block.chainid, address(this), keyCodeHash, request);
    }

    function consume(AuthorizationMessage.Request calldata request, bytes calldata signature) external {
        if (request.nonce != nonce) revert InvalidNonce();
        if (request.expiresAt <= block.timestamp) revert Expired();
        if (request.keyEpoch != keyEpoch) revert InvalidEpoch();
        if (pkBlob.codehash != keyCodeHash) revert KeyCodeChanged();
        if (signature.length != 2420) revert InvalidSignature();
        if (!verifier.verify(pkBlob, message(request), signature)) revert InvalidSignature();
        ++nonce;
    }
}

/// @notice TEST ONLY: programmable test double; does not implement ML-DSA.
contract MessageVerifierMock is IMLDSAVerifier {
    address private expectedKey;
    bytes32 private expectedMessage;
    bytes32 private expectedSignature;
    bool private shouldRevert;
    address private additionalKey;
    bytes32 private additionalMessage;
    bytes32 private additionalSignature;

    function configure(address key, bytes calldata message_, bytes calldata signature_, bool revert_) external {
        expectedKey = key;
        expectedMessage = keccak256(message_);
        expectedSignature = keccak256(signature_);
        shouldRevert = revert_;
        additionalKey = address(0);
    }

    function configureAdditional(address key, bytes calldata message_, bytes calldata signature_) external {
        additionalKey = key;
        additionalMessage = keccak256(message_);
        additionalSignature = keccak256(signature_);
    }

    function verify(address key, bytes calldata message_, bytes calldata signature_) external view returns (bool) {
        require(!shouldRevert, "mock verifier unavailable");
        return (key == expectedKey && keccak256(message_) == expectedMessage
            && keccak256(signature_) == expectedSignature)
            || (key == additionalKey && keccak256(message_) == additionalMessage
                && keccak256(signature_) == additionalSignature);
    }
}
