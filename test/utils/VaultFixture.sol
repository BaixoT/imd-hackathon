// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {Test, Vm} from "forge-std/Test.sol";
import {BunkerVault} from "../../src/BunkerVault.sol";
import {
    RegistrationFeeTokenMock, NoReturnFeeTokenMock, RegistrationHarness
} from "../mocks/RegistrationFixtures.sol";
import {MessageVerifierMock} from "../mocks/AuthorizationHarness.sol";
import {WETH9Mock} from "../mocks/EthFixtures.sol";

/// @notice Shared fixture: BunkerVault with a programmable mock verifier. These tests do NOT claim ML-DSA or
/// KeyGen/prepare validity; the mock only accepts the exact (key, message, signature) it was armed with.
/// Alice is this test contract, so un-pranked calls come from her.
abstract contract VaultFixture is Test {
    struct Options {
        uint8 decimals;
        bool funded;
        bool sameKey;
        bool noReturn;
        bool harness;
        bool developerIsPayer;
        bool realWeth;
    }

    struct CtorArgs {
        address feeToken;
        bytes32 feeTokenCodeHash;
        address developer;
        address verifier;
        bytes32 verifierCodeHash;
        address weth;
        bytes32 wethCodeHash;
    }

    struct Snapshot {
        uint256 payer;
        uint256 developer;
        uint256 reserve;
        uint256 allowance;
        uint256 supply;
        uint256 locked;
        bytes32 slot;
        bool used;
        bytes32 account;
    }

    address internal alice = address(this);
    address internal bob = makeAddr("bob");
    address internal defaultDeveloper = makeAddr("developer");
    address internal relayer = makeAddr("relayer");
    address internal attacker = makeAddr("attacker");
    address internal blobA = makeAddr("blobA");
    address internal blobB = makeAddr("blobB");
    address internal developer;

    RegistrationFeeTokenMock internal token;
    MessageVerifierMock internal verifier;
    WETH9Mock internal weth;
    BunkerVault internal vault;
    uint256 internal fee;
    bytes32 internal codeHash;
    CtorArgs internal ctorArgs;
    BunkerVault.Registration internal registration;
    BunkerVault.Registration internal second;
    uint256 private _vaultCreatedSeen;

    receive() external payable {}

    // ---- synthetic public data (markers, not real keys or signatures) ----

    function rep(uint8 value, uint256 length) internal pure returns (bytes memory out) {
        out = new bytes(length);
        for (uint256 i; i < length; ++i) out[i] = bytes1(value);
    }

    function signature() internal pure returns (bytes memory) { return rep(0x42, 2420); }
    function publicKeyA() internal pure returns (bytes memory) { return rep(0x11, 1312); }
    function publicKeyB() internal pure returns (bytes memory) { return rep(0x22, 1312); }
    function blobCode() internal pure returns (bytes memory) { return bytes.concat(hex"00", rep(0x01, 20544)); }

    function idFor(bytes memory key) internal pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("BunkerVault.VaultIdentity.v1"), keccak256(key)));
    }

    function defaults() internal pure returns (Options memory) {
        return Options({decimals: 18, funded: true, sameKey: false, noReturn: false, harness: false,
            developerIsPayer: false, realWeth: false});
    }

    function hexFile(string memory path) internal view returns (bytes memory) {
        return vm.parseBytes(string.concat("0x", vm.trim(vm.readFile(path))));
    }

    // ---- fixture ----

    function fixture() internal { fixture(defaults()); }

    function fixture(Options memory o) internal {
        developer = o.developerIsPayer ? alice : defaultDeveloper;
        vm.etch(blobA, blobCode());
        vm.etch(blobB, blobCode());
        codeHash = keccak256(blobCode());
        token = o.noReturn
            ? RegistrationFeeTokenMock(address(new NoReturnFeeTokenMock()))
            : new RegistrationFeeTokenMock(o.decimals);
        verifier = new MessageVerifierMock();
        weth = new WETH9Mock();
        // Real WETH9 runtime (canonical mainnet WETH9, public bytecode) instead of the mock, so the vault runs against the
        // exact 2300-gas `transfer` path of the contract it will really use. Storage layout matches the mock.
        if (o.realWeth) vm.etch(address(weth), hexFile("test/fixtures/weth9-runtime.hex"));
        ctorArgs = CtorArgs(address(token), address(token).codehash, developer, address(verifier),
            address(verifier).codehash, address(weth), address(weth).codehash);
        vault = o.harness ? _deployHarness(ctorArgs) : deployVault(ctorArgs);
        fee = vault.registrationFee();
        if (o.funded) {
            fundFee(alice, fee * 10);
            fundFee(bob, fee * 10);
        }
        vm.deal(alice, 1_000 ether);
        vm.deal(bob, 1_000 ether);
        registration = BunkerVault.Registration(publicKeyA(), blobA, codeHash, alice, alice,
            block.timestamp + 1800, signature());
        second = BunkerVault.Registration(o.sameKey ? publicKeyA() : publicKeyB(), blobB, codeHash, bob, bob,
            block.timestamp + 1800, signature());
        vm.recordLogs();
        _vaultCreatedSeen = 0;
        arm(registration, false);
    }

    function deployVault(CtorArgs memory a) internal returns (BunkerVault) {
        return new BunkerVault(a.feeToken, a.feeTokenCodeHash, a.developer, a.verifier, a.verifierCodeHash,
            a.weth, a.wethCodeHash);
    }

    function _deployHarness(CtorArgs memory a) private returns (BunkerVault) {
        return new RegistrationHarness(a.feeToken, a.feeTokenCodeHash, a.developer, a.verifier,
            a.verifierCodeHash, a.weth, a.wethCodeHash);
    }

    /// @dev Low-level approve so tokens without a boolean return are funded the same way.
    function fundFee(address payer, uint256 amount) internal {
        token.mint(payer, amount);
        approveFrom(address(token), payer, address(vault), amount);
    }

    function approveFrom(address asset, address owner, address spender, uint256 amount) internal {
        vm.prank(owner);
        (bool ok,) = asset.call(abi.encodeWithSignature("approve(address,uint256)", spender, amount));
        require(ok, "approve failed");
    }

    function arm(BunkerVault.Registration memory reg, bool shouldRevert) internal {
        verifier.configure(reg.pkBlob, vault.registrationMessage(reg), reg.proofOfPossession, shouldRevert);
    }

    function arm(BunkerVault.Registration memory reg) internal { arm(reg, false); }

    function createAs(address sender, BunkerVault.Registration memory reg) internal returns (bytes32) {
        vm.prank(sender);
        return vault.createVault(reg);
    }

    function snapshotOf() internal view returns (Snapshot memory) {
        return Snapshot({
            payer: token.balanceOf(alice), developer: token.balanceOf(developer),
            reserve: token.balanceOf(address(vault)), allowance: token.allowance(alice, address(vault)),
            supply: token.totalSupply(), locked: vault.totalLockedFees(), slot: vault.registeredVault(alice),
            used: vault.usedPublicKeys(keccak256(publicKeyA())),
            account: keccak256(abi.encode(vault.account(idFor(publicKeyA()))))
        });
    }

    function snapshot() internal view returns (bytes32) { return keccak256(abi.encode(snapshotOf())); }

    /// @dev Counts VaultCreated events emitted by the vault since the fixture was built.
    function vaultCreatedCount() internal returns (uint256) {
        Vm.Log[] memory logs = vm.getRecordedLogs();
        for (uint256 i; i < logs.length; ++i) {
            if (logs[i].emitter == address(vault) && logs[i].topics[0] == BunkerVault.VaultCreated.selector) {
                ++_vaultCreatedSeen;
            }
        }
        return _vaultCreatedSeen;
    }

    function accountOf(bytes32 id) internal view returns (BunkerVault.Account memory) { return vault.account(id); }

    /// @dev Arms the mock for the vault's canonical message and returns the matching authorization.
    function authorize(bytes32 id, bytes32 operation, bytes32 paramsHash)
        internal returns (BunkerVault.Authorization memory auth)
    {
        BunkerVault.Account memory a = vault.account(id);
        auth = BunkerVault.Authorization(a.nonce, registration.expiresAt, a.keyEpoch, signature());
        verifier.configure(a.pkBlob,
            vault.authorizationMessage(id, operation, paramsHash, auth.nonce, auth.expiresAt, auth.keyEpoch),
            signature(), false);
    }

    /// @dev Does the compiled vault ABI expose a function with this name (any parameters)?
    function abiHasFunction(string memory name) internal view returns (bool) {
        string[] memory signatures =
            vm.parseJsonKeys(vm.readFile("out/BunkerVault.sol/BunkerVault.json"), ".methodIdentifiers");
        bytes memory prefix = bytes(string.concat(name, "("));
        for (uint256 i; i < signatures.length; ++i) {
            bytes memory s = bytes(signatures[i]);
            if (s.length < prefix.length) continue;
            bool same = true;
            for (uint256 j; j < prefix.length && same; ++j) same = s[j] == prefix[j];
            if (same) return true;
        }
        return false;
    }

    function selector(string memory errorSignature) internal pure returns (bytes memory) {
        return abi.encodePacked(bytes4(keccak256(bytes(errorSignature))));
    }
}
