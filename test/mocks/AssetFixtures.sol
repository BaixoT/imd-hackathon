// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import {ERC20} from "@openzeppelin/contracts/token/ERC20/ERC20.sol";

/// @notice TEST ONLY: ordinary mintable ERC20 with configurable decimals.
contract UnderlyingMock is ERC20 {
    uint8 private immutable precision;
    constructor(uint8 decimals_) ERC20("Local token", "LOCAL") { precision = decimals_; }
    function decimals() public view override returns (uint8) { return precision; }
    function mint(address to, uint256 amount) external { _mint(to, amount); }
}

/// @notice TEST ONLY: ERC20 base interface without optional name/symbol/decimals.
contract MetadataFreeERC20Mock {
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    event Transfer(address indexed from, address indexed to, uint256 value);
    event Approval(address indexed owner, address indexed spender, uint256 value);
    function mint(address to, uint256 value) external {
        balanceOf[to] += value; totalSupply += value; emit Transfer(address(0), to, value);
    }
    function approve(address spender, uint256 value) external returns (bool) {
        allowance[msg.sender][spender] = value; emit Approval(msg.sender, spender, value); return true;
    }
    function transfer(address to, uint256 value) external returns (bool) {
        balanceOf[msg.sender] -= value; balanceOf[to] += value; emit Transfer(msg.sender, to, value); return true;
    }
    function transferFrom(address from, address to, uint256 value) external returns (bool) {
        allowance[from][msg.sender] -= value; balanceOf[from] -= value; balanceOf[to] += value;
        emit Transfer(from, to, value); return true;
    }
}

interface IVerifyProbe { function verify(address pkBlob, bytes calldata message, bytes calldata signature) external view returns (bool); }

/// @notice TEST ONLY: reports the gas one verifier call actually consumes (gasleft delta), as opposed to the
/// larger limit eth_estimateGas finds because of the 63/64 rule across the verifier's many inner calls.
contract GasProbe {
    function measure(address verifier, address blob, bytes calldata message, bytes calldata signature)
        external view returns (bool ok, uint256 used)
    {
        uint256 before = gasleft();
        ok = IVerifyProbe(verifier).verify(blob, message, signature);
        used = before - gasleft();
    }
}
