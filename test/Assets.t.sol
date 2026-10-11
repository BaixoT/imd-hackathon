// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {BunkerVault} from "../src/BunkerVault.sol";
import {RegistrationFeeTokenMock, NoReturnFeeTokenMock} from "./mocks/RegistrationFixtures.sol";
import {UnderlyingMock, MetadataFreeERC20Mock} from "./mocks/AssetFixtures.sol";
import {ForceEth, ReentrantEthRecipient, RejectingEthRecipient} from "./mocks/EthFixtures.sol";
import {VaultFixture} from "./utils/VaultFixture.sol";

/// @notice Two registered vaults (A: alice, B: bob) plus helpers for public ERC-20 and ETH operations.
abstract contract AssetBase is VaultFixture {
    enum Kind { Underlying, NoReturn, MetadataFree, Adversarial }

    bytes32 internal idA;
    bytes32 internal idB;

    function assetFixture(bool realWeth) internal {
        Options memory o = defaults();
        o.realWeth = realWeth;
        fixture(o);
        vault.createVault(registration);
        arm(second);
        createAs(bob, second);
        idA = idFor(publicKeyA());
        idB = idFor(publicKeyB());
    }

    function controllerOf(bytes32 id) internal view returns (address) { return id == idB ? bob : alice; }

    function publicAsset(Kind kind, uint8 decimals) internal returns (address asset, bytes32 assetHash) {
        if (kind == Kind.Underlying) asset = address(new UnderlyingMock(decimals));
        else if (kind == Kind.NoReturn) asset = address(new NoReturnFeeTokenMock());
        else if (kind == Kind.MetadataFree) asset = address(new MetadataFreeERC20Mock());
        else asset = address(new RegistrationFeeTokenMock(decimals));
        assetHash = vault.assetConfigurationHash(asset);
        _mintAndApprove(asset, alice, 1000);
    }

    function publicAsset() internal returns (address, bytes32) { return publicAsset(Kind.Underlying, 6); }

    function _mintAndApprove(address asset, address owner, uint256 amount) internal {
        UnderlyingMock(asset).mint(owner, amount); // every mock exposes mint(address,uint256)
        approveFrom(asset, owner, address(vault), amount);
    }

    function depositAuth(bytes32 id, address asset, uint256 amount, bytes32 assetHash)
        internal returns (BunkerVault.Authorization memory)
    {
        return authorize(id, vault.DEPOSIT_ERC20(),
            keccak256(abi.encode(asset, amount, assetHash, controllerOf(id))));
    }

    /// @dev Only a vault's own controller wallet may send its operations, so B's deposits come from bob.
    function deposit(address asset, bytes32 assetHash, uint256 amount, bytes32 id) internal {
        if (id == idB) _mintAndApprove(asset, bob, 1000);
        BunkerVault.Authorization memory a = depositAuth(id, asset, amount, assetHash);
        vm.prank(controllerOf(id));
        vault.depositERC20(id, asset, amount, assetHash, a);
    }

    function deposit(address asset, bytes32 assetHash, uint256 amount) internal { deposit(asset, assetHash, amount, idA); }

    function withdrawAuth(bytes32 id, address asset, address recipient, uint256 amount, bytes32 assetHash)
        internal returns (BunkerVault.Authorization memory)
    {
        return authorize(id, vault.WITHDRAW_ERC20(),
            keccak256(abi.encode(asset, recipient, amount, assetHash, controllerOf(id))));
    }

    function ethDepositAuth(bytes32 id, uint256 value, address sender)
        internal returns (BunkerVault.Authorization memory)
    {
        return authorize(id, vault.DEPOSIT_ETH(), keccak256(abi.encode(value, sender)));
    }

    function ethWithdrawAuth(bytes32 id, address recipient, uint256 amount, address sender)
        internal returns (BunkerVault.Authorization memory)
    {
        return authorize(id, vault.WITHDRAW_ETH(), keccak256(abi.encode(recipient, amount, sender)));
    }

    function depositEth(bytes32 id, uint256 value) internal {
        BunkerVault.Authorization memory a = ethDepositAuth(id, value, controllerOf(id));
        vm.prank(controllerOf(id));
        vault.depositETH{value: value}(id, a);
    }

    function withdrawEth(bytes32 id, address recipient, uint256 amount) internal {
        BunkerVault.Authorization memory a = ethWithdrawAuth(id, recipient, amount, controllerOf(id));
        vm.prank(controllerOf(id));
        vault.withdrawETH(id, recipient, amount, a);
    }
}

/// @notice BunkerVault generic ERC20 custody (public amounts, mocked PQ policy).
contract ERC20CustodyTest is AssetBase {
    function setUp() public { assetFixture(false); }

    function test_AcceptsUnlistedStandardERC20AtAnyDecimalsWithoutWrapping() public {
        uint8[4] memory precisions = [0, 6, 18, 24];
        for (uint256 i; i < precisions.length; ++i) {
            (address asset, bytes32 assetHash) = publicAsset(Kind.Underlying, precisions[i]);
            uint256 locked = vault.totalLockedFees();
            BunkerVault.Authorization memory a = depositAuth(idA, asset, 100, assetHash);
            vm.expectEmit(address(vault));
            emit BunkerVault.ERC20Deposited(idA, asset, alice, 100);
            vault.depositERC20(idA, asset, 100, assetHash, a);
            assertEq(vault.publicBalanceOf(idA, asset), 100);
            assertEq(vault.totalPublicLiability(asset), 100);
            (BunkerVault.AssetKind kind,) = vault.assetConfig(asset);
            assertEq(uint8(kind), uint8(BunkerVault.AssetKind.ERC20));
            assertEq(vault.totalLockedFees(), locked);
        }
    }

    function test_AcceptsOptionalReturnERC20WithoutNameSymbolDecimals() public {
        (address asset, bytes32 assetHash) = publicAsset(Kind.NoReturn, 0);
        deposit(asset, assetHash, 100);
        assertEq(vault.publicBalanceOf(idA, asset), 100);
    }

    function test_AcceptsBaseERC20InterfaceWithAllOptionalMetadataAbsent() public {
        (address asset, bytes32 assetHash) = publicAsset(Kind.MetadataFree, 0);
        deposit(asset, assetHash, 100);
        assertEq(vault.publicBalanceOf(idA, asset), 100);
    }

    function test_KeepsDonationsUnassignedAndLiabilitiesIndependent() public {
        (address asset, bytes32 assetHash) = publicAsset();
        IERC20(asset).transfer(address(vault), 15);
        deposit(asset, assetHash, 100);
        deposit(asset, assetHash, 80, idB);
        assertEq(IERC20(asset).balanceOf(address(vault)), 195);
        assertEq(vault.totalPublicLiability(asset), 180);
        assertEq(vault.publicBalanceOf(idA, asset), 100);
        assertEq(vault.publicBalanceOf(idB, asset), 80);
    }

    function test_PermitsControllerWithdrawalAndRejectsReplayAndAccountSubstitution() public {
        (address asset, bytes32 assetHash) = publicAsset();
        deposit(asset, assetHash, 100);
        BunkerVault.Authorization memory a = withdrawAuth(idA, asset, bob, 40, assetHash);
        vm.expectRevert();
        vault.withdrawERC20(idB, asset, bob, 40, assetHash, a);
        vault.withdrawERC20(idA, asset, bob, 40, assetHash, a);
        assertEq(IERC20(asset).balanceOf(bob), 40);
        assertEq(vault.publicBalanceOf(idA, asset), 60);
        vm.expectRevert(BunkerVault.InvalidNonce.selector);
        vault.withdrawERC20(idA, asset, bob, 40, assetHash, a);
    }

    function test_BindsRecipientAmountTokenCodeExecutorAndOperation() public {
        (address asset, bytes32 assetHash) = publicAsset();
        deposit(asset, assetHash, 100);
        BunkerVault.Authorization memory a = withdrawAuth(idA, asset, bob, 40, assetHash);
        address different = address(new UnderlyingMock(6));
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(idA, different, bob, 40, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(idA, asset, attacker, 40, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(idA, asset, bob, 41, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawERC20(idA, asset, bob, 40, bytes32(0), a);
        vm.prank(relayer);
        vm.expectRevert(BunkerVault.NotController.selector);
        vault.withdrawERC20(idA, asset, bob, 40, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositERC20(idA, asset, 40, assetHash, a);
        assertEq(vault.account(idA).nonce, 1);
    }

    /// @dev Modes 1..6: false / revert / no-op / tax / rebase / surcharge.
    function test_RollsBackEveryRejectedDepositBehaviorIncludingAdmissionAndNonce() public {
        for (uint8 mode = 1; mode <= 6; ++mode) {
            setUp();
            (address asset, bytes32 assetHash) = publicAsset(Kind.Adversarial, 6);
            RegistrationFeeTokenMock(asset).setModes(mode, 0);
            uint256 before = IERC20(asset).balanceOf(alice);
            BunkerVault.Authorization memory a = depositAuth(idA, asset, 100, assetHash);
            vm.expectRevert();
            vault.depositERC20(idA, asset, 100, assetHash, a);
            assertEq(IERC20(asset).balanceOf(alice), before);
            assertEq(IERC20(asset).balanceOf(address(vault)), 0);
            (BunkerVault.AssetKind kind,) = vault.assetConfig(asset);
            assertEq(uint8(kind), uint8(BunkerVault.AssetKind.Unknown));
            assertEq(vault.account(idA).nonce, 0);
            assertEq(vault.totalPublicLiability(asset), 0);
        }
    }

    function test_RollsBackEveryRejectedWithdrawalBehavior() public {
        for (uint8 mode = 1; mode <= 6; ++mode) {
            setUp();
            (address asset, bytes32 assetHash) = publicAsset(Kind.Adversarial, 6);
            deposit(asset, assetHash, 100);
            BunkerVault.Authorization memory a = withdrawAuth(idA, asset, bob, 40, assetHash);
            RegistrationFeeTokenMock(asset).setModes(0, mode);
            vm.expectRevert();
            vault.withdrawERC20(idA, asset, bob, 40, assetHash, a);
            assertEq(vault.publicBalanceOf(idA, asset), 100);
            assertEq(IERC20(asset).balanceOf(address(vault)), 100);
            assertEq(IERC20(asset).balanceOf(bob), 0);
            assertEq(vault.account(idA).nonce, 1);
        }
    }

    function test_BlocksTokenReentryIntoDepositWhileOuterDepositCompletes() public {
        (address asset, bytes32 assetHash) = publicAsset(Kind.Adversarial, 6);
        BunkerVault.Authorization memory inner = BunkerVault.Authorization(0, registration.expiresAt, 0, signature());
        RegistrationFeeTokenMock(asset).setReentry(address(vault),
            abi.encodeCall(BunkerVault.depositERC20, (idA, asset, 1, assetHash, inner)));
        deposit(asset, assetHash, 100);
        assertFalse(RegistrationFeeTokenMock(asset).reentrySucceeded());
        assertEq(RegistrationFeeTokenMock(asset).reentryResult(),
            abi.encodePacked(ReentrancyGuard.ReentrancyGuardReentrantCall.selector));
    }

    function test_ExcludesTheFeeTokenFromCustody() public {
        BunkerVault.Authorization memory a = authorize(idA, vault.DEPOSIT_ERC20(),
            keccak256(abi.encode(address(token), uint256(10), codeHash, alice)));
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        vault.depositERC20(idA, address(token), 10, codeHash, a);
        vm.expectRevert(BunkerVault.LockedFeeToken.selector);
        vault.assetConfigurationHash(address(token));
        assertEq(vault.account(idA).nonce, 0);
    }

    function test_RejectsChangedCodeZeroAddressesZeroAmountsAndInsufficientCredit() public {
        (address asset, bytes32 assetHash) = publicAsset();
        deposit(asset, assetHash, 100);
        BunkerVault.Authorization memory a = withdrawAuth(idA, asset, bob, 101, assetHash);
        vm.expectRevert(BunkerVault.InsufficientPublicBalance.selector);
        vault.withdrawERC20(idA, asset, bob, 101, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidRecipient.selector);
        vault.withdrawERC20(idA, asset, address(0), 1, assetHash, a);
        vm.expectRevert(BunkerVault.InvalidAmount.selector);
        vault.depositERC20(idA, asset, 0, assetHash, a);
        vm.etch(asset, hex"60006000fd");
        vm.expectRevert(BunkerVault.CodeChanged.selector);
        vault.withdrawERC20(idA, asset, bob, 101, assetHash, a);
    }

    // ---- held-token list (on-chain enumeration, no log scanning) ----

    function test_ListsEachTokenOncePerVaultAndKeepsItAtZeroBalance() public {
        (address a, bytes32 aHash) = publicAsset();
        (address b, bytes32 bHash) = publicAsset();
        assertEq(vault.heldTokenCount(idA), 0);
        deposit(a, aHash, 100);
        deposit(a, aHash, 50);
        deposit(b, bHash, 10);
        assertEq(vault.heldTokenCount(idA), 2);
        address[] memory page = vault.heldTokens(idA, 0, 10);
        assertEq(page.length, 2);
        assertEq(page[0], a);
        assertEq(page[1], b);
        page = vault.heldTokens(idA, 1, 1);
        assertEq(page.length, 1);
        assertEq(page[0], b);
        assertEq(vault.heldTokens(idA, 2, 5).length, 0);
        assertEq(vault.heldTokens(idA, 99, 5).length, 0);
        assertEq(vault.heldTokenCount(idB), 0);
        // Another vault depositing the same token is tracked separately.
        deposit(a, aHash, 5, idB);
        page = vault.heldTokens(idB, 0, 10);
        assertEq(page.length, 1);
        assertEq(page[0], a);
        // Withdrawing everything does not delist; the balance is the source of truth.
        BunkerVault.Authorization memory w = withdrawAuth(idA, b, alice, 10, bHash);
        vault.withdrawERC20(idA, b, alice, 10, bHash, w);
        assertEq(vault.publicBalanceOf(idA, b), 0);
        assertEq(vault.heldTokenCount(idA), 2);
    }

    function test_NeverListsARejectedDeposit() public {
        (address p, bytes32 pHash) = publicAsset();
        deposit(p, pHash, 10);
        (address other, bytes32 otherHash) = publicAsset();
        BunkerVault.Authorization memory a = depositAuth(idA, other, 7, otherHash);
        vm.expectRevert();
        vault.depositERC20(idA, other, 7, bytes32(0), a);
        address[] memory page = vault.heldTokens(idA, 0, 10);
        assertEq(page.length, 1);
        assertEq(page[0], p);
        assertEq(vault.heldTokenCount(idA), 1);
    }

    // ---- controller wallet (two factors, fixed at registration) ----

    function test_MakesFeePayerTheControllerWithNoWayToChangeIt() public view {
        assertEq(vault.controllerOf(idA), alice);
        assertEq(vault.controllerOf(idB), bob);
        assertFalse(abiHasFunction("proposeController"));
        assertFalse(abiHasFunction("acceptController"));
        assertFalse(abiHasFunction("pendingControllerOf"));
        assertFalse(abiHasFunction("setController"));
    }

    function test_RejectsValidPQAuthorizationSentByAnyOtherWallet() public {
        (address asset, bytes32 assetHash) = publicAsset();
        BunkerVault.Authorization memory a = authorize(idA, vault.DEPOSIT_ERC20(),
            keccak256(abi.encode(asset, uint256(5), assetHash, relayer)));
        address[3] memory wallets = [relayer, attacker, bob];
        for (uint256 i; i < wallets.length; ++i) {
            vm.prank(wallets[i]);
            vm.expectRevert(BunkerVault.NotController.selector);
            vault.depositERC20(idA, asset, 5, assetHash, a);
        }
        assertEq(vault.account(idA).nonce, 0);
    }

    function test_RejectsTheControllerWithoutAValidPQAuthorization() public {
        (address asset, bytes32 assetHash) = publicAsset();
        BunkerVault.Authorization memory a = depositAuth(idA, asset, 5, assetHash);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositERC20(idA, asset, 6, assetHash, a);
    }
}

/// @notice ETH custody: wrapped into WETH, public amounts, mocked PQ policy. Runs against the WETH9 mock and the
/// real mainnet WETH9 runtime bytecode.
abstract contract EthCustodyTests is AssetBase {
    function realWeth() internal pure virtual returns (bool);

    function setUp() public { assetFixture(realWeth()); }

    function test_WrapsETHCreditsPublicWETHAndKeepsNoETH() public {
        BunkerVault.Authorization memory a = ethDepositAuth(idA, 1 ether, alice);
        vm.expectEmit(address(vault));
        emit BunkerVault.ETHDeposited(idA, alice, 1 ether);
        vault.depositETH{value: 1 ether}(idA, a);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 1 ether);
        assertEq(vault.totalPublicLiability(address(weth)), 1 ether);
        assertEq(weth.balanceOf(address(vault)), 1 ether);
        assertEq(address(vault).balance, 0);
        address[] memory page = vault.heldTokens(idA, 0, 10);
        assertEq(page.length, 1);
        assertEq(page[0], address(weth));
        assertEq(vault.account(idA).nonce, 1);
    }

    function test_WithdrawsExactlyTheSignedAmountToTheSignedRecipient() public {
        depositEth(idA, 5 ether);
        uint256 before = bob.balance;
        BunkerVault.Authorization memory a = ethWithdrawAuth(idA, bob, 2 ether, alice);
        vm.expectEmit(address(vault));
        emit BunkerVault.ETHWithdrawn(idA, bob, 2 ether);
        vault.withdrawETH(idA, bob, 2 ether, a);
        assertEq(bob.balance - before, 2 ether);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 3 ether);
        assertEq(weth.balanceOf(address(vault)), 3 ether);
        assertEq(address(vault).balance, 0);
    }

    function test_LetsETHCreditedWETHLeaveAsWETHThroughERC20Path() public {
        depositEth(idA, 1 ether);
        bytes32 hash = vault.assetConfigurationHash(address(weth));
        BunkerVault.Authorization memory a = withdrawAuth(idA, address(weth), bob, 0.4 ether, hash);
        vault.withdrawERC20(idA, address(weth), bob, 0.4 ether, hash, a);
        assertEq(weth.balanceOf(bob), 0.4 ether);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 0.6 ether);
    }

    function test_RejectsPlainETHETHWithCalldataAndETHFromAnyoneButWETH() public {
        _expectDirectRejection(address(this), 1, "");
        _expectDirectRejection(address(this), 1, hex"12345678");
        _expectDirectRejection(address(this), 0, hex"12345678");
        // The WETH contract itself may only send while withdrawETH is unwrapping.
        vm.deal(address(weth), 100 ether);
        _expectDirectRejection(address(weth), 1, "");
        assertEq(address(vault).balance, 0);
        assertEq(vault.account(idA).nonce, 0);
    }

    function _expectDirectRejection(address from, uint256 value, bytes memory data) private {
        vm.prank(from);
        (bool ok, bytes memory result) = address(vault).call{value: value}(data);
        assertFalse(ok);
        assertEq(result, abi.encodePacked(BunkerVault.DirectETHRejected.selector));
    }

    function test_NeverCreditsForcedETHAndKeepsWithdrawalsExactBesideIt() public {
        ForceEth force = new ForceEth{value: 7}();
        force.destroy(payable(address(vault)));
        assertEq(address(vault).balance, 7);
        assertEq(vault.totalPublicLiability(address(weth)), 0);
        depositEth(idA, 1 ether);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 1 ether);
        uint256 before = bob.balance;
        withdrawEth(idA, bob, 1 ether);
        assertEq(bob.balance - before, 1 ether);
        assertEq(address(vault).balance, 7); // the unassigned ETH is still not anyone's
    }

    function test_BindsAmountRecipientAndSenderToThePQAuthorization() public {
        BunkerVault.Authorization memory d = ethDepositAuth(idA, 100, alice);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.depositETH{value: 101}(idA, d);
        vm.prank(bob);
        vm.expectRevert(BunkerVault.NotController.selector);
        vault.depositETH{value: 100}(idA, d);
        vault.depositETH{value: 100}(idA, d);
        BunkerVault.Authorization memory w = ethWithdrawAuth(idA, bob, 50, alice);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawETH(idA, alice, 50, w);
        vm.expectRevert(BunkerVault.InvalidSignature.selector);
        vault.withdrawETH(idA, bob, 51, w);
        vm.prank(bob);
        vm.expectRevert(BunkerVault.NotController.selector);
        vault.withdrawETH(idA, bob, 50, w);
        vault.withdrawETH(idA, bob, 50, w);
        vm.expectRevert(BunkerVault.InvalidNonce.selector); // replay
        vault.withdrawETH(idA, bob, 50, w);
    }

    function test_RejectsZeroOverBalanceAndBadRecipientsWithoutConsumingNonce() public {
        depositEth(idA, 100);
        uint256 nonce = vault.account(idA).nonce;
        BunkerVault.Authorization memory a = ethDepositAuth(idA, 0, alice);
        vm.expectRevert(BunkerVault.InvalidAmount.selector);
        vault.depositETH{value: 0}(idA, a);
        a = ethWithdrawAuth(idA, bob, 101, alice);
        vm.expectRevert(BunkerVault.InsufficientPublicBalance.selector);
        vault.withdrawETH(idA, bob, 101, a);
        a = ethWithdrawAuth(idA, bob, 0, alice);
        vm.expectRevert(BunkerVault.InvalidAmount.selector);
        vault.withdrawETH(idA, bob, 0, a);
        address[3] memory bad = [address(0), address(vault), address(weth)];
        for (uint256 i; i < bad.length; ++i) {
            a = ethWithdrawAuth(idA, bad[i], 1, alice);
            vm.expectRevert(BunkerVault.InvalidRecipient.selector);
            vault.withdrawETH(idA, bad[i], 1, a);
        }
        assertEq(vault.account(idA).nonce, nonce);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 100);
    }

    function test_RollsEverythingBackWhenTheRecipientRefusesETH() public {
        depositEth(idA, 100);
        uint256 nonce = vault.account(idA).nonce;
        address bad = address(new RejectingEthRecipient());
        BunkerVault.Authorization memory a = ethWithdrawAuth(idA, bad, 40, alice);
        vm.expectRevert(BunkerVault.ETHTransferFailed.selector);
        vault.withdrawETH(idA, bad, 40, a);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 100);
        assertEq(vault.totalPublicLiability(address(weth)), 100);
        assertEq(weth.balanceOf(address(vault)), 100);
        assertEq(vault.account(idA).nonce, nonce);
    }

    function test_BlocksReentryFromTheETHRecipientAndPaysOnce() public {
        depositEth(idA, 100);
        ReentrantEthRecipient evil = new ReentrantEthRecipient();
        BunkerVault.Authorization memory inner = BunkerVault.Authorization(1, registration.expiresAt, 0, signature());
        evil.arm(address(vault), abi.encodeCall(BunkerVault.withdrawETH, (idA, address(evil), 1, inner)));
        withdrawEth(idA, address(evil), 40);
        assertFalse(evil.reentered());
        assertEq(address(evil).balance, 40);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 60);
    }

    function test_KeepsIndependentVaultsWETHLedgersSeparate() public {
        depositEth(idA, 100);
        depositEth(idB, 30);
        withdrawEth(idA, bob, 100);
        assertEq(vault.publicBalanceOf(idA, address(weth)), 0);
        assertEq(vault.publicBalanceOf(idB, address(weth)), 30);
        BunkerVault.Authorization memory a = ethWithdrawAuth(idA, alice, 1, alice);
        vm.expectRevert(BunkerVault.InsufficientPublicBalance.selector);
        vault.withdrawETH(idA, alice, 1, a);
        assertEq(weth.balanceOf(address(vault)), 30);
    }

    function test_DetectsChangedWETHCodeBeforeMovingETH() public {
        vm.etch(address(weth), hex"60006000fd");
        BunkerVault.Authorization memory a = ethDepositAuth(idA, 1, alice);
        vm.expectRevert(BunkerVault.CodeChanged.selector);
        vault.depositETH{value: 1}(idA, a);
    }

    struct Random {
        uint32 seed;
        address[2] tokens;
        bytes32[2] hashes;
        bytes32 wethHash;
        uint256 ok;
        uint256 rejected;
    }

    /// @notice AUDIT: random sequences of valid and invalid operations across two vaults, two ERC-20s and ETH.
    /// After EVERY step: per-token ledger sums equal the liability counter, the vault holds exactly what it owes
    /// (no token donations in this run) and only the forced ETH, which is never credited.
    function test_KeepsLedgerSumsReservesAndETHExactAcross300RandomSteps() public {
        Random memory r;
        r.seed = realWeth() ? 0xbeef1 : 0xa0d17;
        (r.tokens[0], r.hashes[0]) = publicAsset();
        (r.tokens[1], r.hashes[1]) = publicAsset();
        r.wethHash = vault.assetConfigurationHash(address(weth));
        for (uint256 k; k < 2; ++k) {
            _mintAndApprove(r.tokens[k], alice, 10_000);
            _mintAndApprove(r.tokens[k], bob, 10_000);
        }
        ForceEth force = new ForceEth{value: 3}();
        force.destroy(payable(address(vault)));
        for (uint256 i; i < 300; ++i) {
            _randomStep(r, i);
            _checkCustody(r, i);
        }
        emit log_named_string("random steps", string.concat(vm.toString(r.ok), " succeeded, ",
            vm.toString(r.rejected), " rejected; invariants held after every step"));
        assertGt(r.ok, 50);
        assertGt(r.rejected, 20);
    }

    function _randomStep(Random memory r, uint256 i) private {
        bytes32 id = _draw(r, 2) == 0 ? idA : idB;
        uint256 op = _draw(r, 6);
        uint256 amount = 1 + _draw(r, 400);
        uint256 k = _draw(r, 2);
        uint256 nonceBefore = vault.account(id).nonce;
        bool success = _step(op, id, r.tokens[k], r.hashes[k], r.wethHash, amount);
        if (op == 5) assertFalse(success, "plain ETH was accepted");
        if (success) {
            assertEq(vault.account(id).nonce, nonceBefore + 1);
            ++r.ok;
        } else {
            assertEq(vault.account(id).nonce, nonceBefore,
                string.concat("step ", vm.toString(i), ": a failed call consumed the nonce"));
            ++r.rejected;
        }
    }

    function _checkCustody(Random memory r, uint256 i) private view {
        address[3] memory everTokens = [r.tokens[0], r.tokens[1], address(weth)];
        for (uint256 t; t < everTokens.length; ++t) {
            uint256 liability = vault.totalPublicLiability(everTokens[t]);
            assertEq(vault.publicBalanceOf(idA, everTokens[t]) + vault.publicBalanceOf(idB, everTokens[t]), liability,
                string.concat("ledger sum, step ", vm.toString(i)));
            assertEq(IERC20(everTokens[t]).balanceOf(address(vault)), liability,
                string.concat("reserve, step ", vm.toString(i)));
        }
        assertEq(address(vault).balance, 3, string.concat("ETH held, step ", vm.toString(i)));
    }

    function _step(uint256 op, bytes32 id, address asset, bytes32 assetHash, bytes32 wethHash, uint256 amount)
        private returns (bool)
    {
        address wallet = controllerOf(id);
        address other = id == idA ? bob : alice;
        BunkerVault.Authorization memory a;
        if (op == 0) a = depositAuth(id, asset, amount, assetHash);
        else if (op == 1) a = withdrawAuth(id, asset, other, amount, assetHash);
        else if (op == 2) a = ethDepositAuth(id, amount, wallet);
        else if (op == 3) a = ethWithdrawAuth(id, other, amount, wallet);
        else if (op == 4) a = withdrawAuth(id, address(weth), other, amount, wethHash);
        vm.prank(wallet);
        if (op == 0) try vault.depositERC20(id, asset, amount, assetHash, a) { return true; } catch { return false; }
        if (op == 1) try vault.withdrawERC20(id, asset, other, amount, assetHash, a) { return true; } catch { return false; }
        if (op == 2) try vault.depositETH{value: amount}(id, a) { return true; } catch { return false; }
        if (op == 3) try vault.withdrawETH(id, other, amount, a) { return true; } catch { return false; }
        if (op == 4) {
            try vault.withdrawERC20(id, address(weth), other, amount, wethHash, a) { return true; } catch { return false; }
        }
        (bool sent,) = address(vault).call{value: amount}(""); // plain ETH must always be refused
        return sent;
    }

    /// @dev LCG: s' = s * 1664525 + 1013904223 mod 2^32, value = floor(s' / 2^32 * k).
    function _draw(Random memory r, uint256 k) private pure returns (uint256) {
        unchecked { r.seed = r.seed * 1664525 + 1013904223; }
        return (uint256(r.seed) * k) >> 32;
    }
}

contract EthCustodyMockWethTest is EthCustodyTests {
    function realWeth() internal pure override returns (bool) { return false; }
}

contract EthCustodyRealWeth9Test is EthCustodyTests {
    function realWeth() internal pure override returns (bool) { return true; }
}
