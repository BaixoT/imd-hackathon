// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {BunkerVault} from "../../src/BunkerVault.sol";

/// @notice Test-only adversarial ERC20. Mutable behavior is deliberately unsafe.
contract RegistrationFeeTokenMock is ERC20 {
    uint8 private _precision;
    uint8 public pullMode;
    uint8 public sendMode;
    uint256 public pullCalls;
    address private _reentryTarget;
    bytes private _reentryData;
    bool public reentrySucceeded;
    bytes public reentryResult;

    error ForcedTransferFailure();

    constructor(uint8 precision_) ERC20("Local registration fee", "FEE") { _precision = precision_; }
    function decimals() public view override returns (uint8) { return _precision; }
    function setDecimals(uint8 precision_) external { _precision = precision_; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
    function setModes(uint8 pull, uint8 send) external { pullMode = pull; sendMode = send; }
    function setReentry(address target, bytes calldata data) external { _reentryTarget = target; _reentryData = data; }

    function transferFrom(address from, address to, uint256 value) public override returns (bool) {
        ++pullCalls;
        if (pullMode == 1) return false;
        if (pullMode == 2) revert ForcedTransferFailure();
        if (pullMode == 3) return true; // Claims success without moving tokens.
        _spendAllowance(from, msg.sender, value);
        _move(from, to, value, pullMode);
        if (_reentryTarget != address(0)) {
            (reentrySucceeded, reentryResult) = _reentryTarget.call(_reentryData);
        }
        return true;
    }

    function transfer(address to, uint256 value) public override returns (bool) {
        if (sendMode == 1) return false;
        if (sendMode == 2) revert ForcedTransferFailure();
        if (sendMode == 3) return true;
        _move(msg.sender, to, value, sendMode);
        return true;
    }

    function _move(address from, address to, uint256 value, uint8 mode) private {
        if (mode == 4) {
            _transfer(from, to, value - 1);
            _burn(from, 1); // Tax deducted from amount.
        } else {
            _transfer(from, to, value);
            if (mode == 5) _mint(address(this), 1); // Supply/rebase side effect.
            if (mode == 6) _burn(from, 1); // Surcharge attempts to use old reserves.
        }
    }
}

/// @notice Test-only nonstandard optional-return token used to exercise SafeERC20.
contract NoReturnFeeTokenMock {
    uint8 public constant decimals = 6;
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    function mint(address to, uint256 value) external { balanceOf[to] += value; totalSupply += value; }
    function approve(address spender, uint256 value) external { allowance[msg.sender][spender] = value; }
    function transferFrom(address from, address to, uint256 value) external {
        allowance[from][msg.sender] -= value;
        balanceOf[from] -= value;
        balanceOf[to] += value;
    }
    function transfer(address to, uint256 value) external {
        balanceOf[msg.sender] -= value;
        balanceOf[to] += value;
    }
}

contract MissingFeeMetadataMock {}

/// @notice TEST ONLY: demonstrates common PQ gate and lock exclusion for future
/// asset paths. The public ERC20 ledger here is NOT a confidential implementation.
contract RegistrationHarness is BunkerVault {
    using SafeERC20 for IERC20;
    bytes32 public constant TEST_WITHDRAW = keccak256("TEST_ONLY_WITHDRAW");
    mapping(bytes32 => mapping(address => uint256)) public testBalances;

    constructor(
        address feeToken_, bytes32 feeCodeHash_, address developer_,
        address verifier_, bytes32 verifierCodeHash_, address weth_, bytes32 wethCodeHash_
    ) BunkerVault(feeToken_, feeCodeHash_, developer_, verifier_, verifierCodeHash_, weth_, wethCodeHash_) {}

    function authorizeForTest(
        bytes32 id, bytes32 operation, bytes32 paramsHash, Authorization calldata authorization
    ) external nonReentrant { _consumeAuthorization(id, operation, paramsHash, authorization); }

    function depositForTest(bytes32 id, address token, uint256 amount) external nonReentrant {
        _requireVaultAsset(token);
        if (this.account(id).pkBlob == address(0)) revert UnknownVault();
        uint256 beforeBalance = IERC20(token).balanceOf(address(this));
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        require(IERC20(token).balanceOf(address(this)) == beforeBalance + amount);
        testBalances[id][token] += amount;
    }

    function withdrawForTest(
        bytes32 id, address token, address recipient, uint256 amount, Authorization calldata authorization
    ) external nonReentrant {
        _requireVaultAsset(token);
        _consumeAuthorization(id, TEST_WITHDRAW, keccak256(abi.encode(token, recipient, amount)), authorization);
        testBalances[id][token] -= amount;
        IERC20(token).safeTransfer(recipient, amount);
    }

    function rescueForTest(address token) external view { _requireVaultAsset(token); }
}
