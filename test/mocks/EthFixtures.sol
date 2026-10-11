// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

/// @notice TEST ONLY: WETH9 behavior, including the 2300-gas `transfer` the real WETH9 uses to send ETH
/// back. Real WETH9 is the canonical contract; this mirrors its observable behavior for local tests.
contract WETH9Mock {
    string public name = "Wrapped Ether";
    string public symbol = "WETH";
    uint8 public decimals = 18;
    event Approval(address indexed src, address indexed guy, uint256 wad);
    event Transfer(address indexed src, address indexed dst, uint256 wad);
    event Deposit(address indexed dst, uint256 wad);
    event Withdrawal(address indexed src, uint256 wad);
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    receive() external payable { deposit(); }
    function deposit() public payable { balanceOf[msg.sender] += msg.value; emit Deposit(msg.sender, msg.value); }
    function withdraw(uint256 wad) public {
        require(balanceOf[msg.sender] >= wad);
        balanceOf[msg.sender] -= wad;
        payable(msg.sender).transfer(wad);
        emit Withdrawal(msg.sender, wad);
    }
    function totalSupply() public view returns (uint256) { return address(this).balance; }
    function approve(address guy, uint256 wad) public returns (bool) { allowance[msg.sender][guy] = wad; emit Approval(msg.sender, guy, wad); return true; }
    function transfer(address dst, uint256 wad) public returns (bool) { return transferFrom(msg.sender, dst, wad); }
    function transferFrom(address src, address dst, uint256 wad) public returns (bool) {
        require(balanceOf[src] >= wad);
        if (src != msg.sender && allowance[src][msg.sender] != type(uint256).max) {
            require(allowance[src][msg.sender] >= wad);
            allowance[src][msg.sender] -= wad;
        }
        balanceOf[src] -= wad; balanceOf[dst] += wad;
        emit Transfer(src, dst, wad);
        return true;
    }
}

/// @notice TEST ONLY: pushes ETH into any address, bypassing receive(): the way unsolicited ETH can still arrive.
contract ForceEth {
    constructor() payable {}
    function destroy(address payable target) external { selfdestruct(target); }
}

/// @notice TEST ONLY: recipient that tries to re-enter the vault when it receives ETH.
contract ReentrantEthRecipient {
    address public target;
    bytes public payload;
    bool public reentered;
    function arm(address to, bytes calldata data) external { target = to; payload = data; }
    receive() external payable {
        if (target != address(0)) { (bool ok, ) = target.call(payload); reentered = ok; }
    }
}

/// @notice TEST ONLY: recipient that refuses ETH.
contract RejectingEthRecipient { receive() external payable { revert(); } }
