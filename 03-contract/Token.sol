// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Token {
    event Withdraw(address indexed fromL3Address, address indexed toL1Address, uint256 amount, string  context);
    event Deposit(address indexed fromL1L2Address, address indexed toL3Address, uint256 amount, string context);

    constructor(){
    }

    function withdraw(address fromL3Address, address payable toL1Address, uint256 amount, uint256 ticketNonce,bytes32 r, bytes32 s, uint8 v, string calldata context, uint256 chainId) public nonReentrant {
        uint256 balance_ = address(this).balance;
        require(balance_ >= amount, "Insufficient balance");

        toL1Address.transfer(amount);
        
        emit Withdraw(fromL3Address, toL1Address, amount, context);
    }

    function deposit(address payable fromL1L2Address, address toL3Address, uint256 amount,string calldata context) public override payable  {
        require(address(fromL1L2Address).balance >= amount, "Insufficient payment");
        require(msg.value == amount,"send fund and amount are inconsistent");
        emit Deposit(fromL1L2Address, toL3Address,amount, context);
    }
}
