// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleDelegate {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    // Simple function to demonstrate the contract is working
    function getOwner() public view returns (address) {
        return owner;
    }

    // Function to receive Ether
    receive() external payable {}
}