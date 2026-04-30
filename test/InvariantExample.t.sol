// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "../src/MyToken.sol";

/// @notice Example invariant test demonstrating how to assert that
/// the total supply equals the sum of all balances.  Replace MyToken
/// with the contract under test and customise the setUp logic.
contract InvariantExample is Test {
    MyToken token;
    address[] users;

    function setUp() public {
        // Deploy the contract and set up sample users.  In a real test,
        // deploy your own contract and assign initial balances.
        token = new MyToken();
        users.push(address(0x1));
        users.push(address(0x2));
        token.mint(users[0], 100 ether);
        token.mint(users[1], 50 ether);
    }

    /// Invariant: totalSupply must equal the sum of all balances.
    function invariant_totalSupplyMatchesBalances() public {
        uint256 total = token.totalSupply();
        uint256 sum = 0;
        for (uint i = 0; i < users.length; i++) {
            sum += token.balanceOf(users[i]);
        }
        assertEq(total, sum, "Invariant broken: totalSupply != sum of balances");
    }
}
