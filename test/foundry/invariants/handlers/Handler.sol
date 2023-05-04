// SPDX-License-Identifier: GPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../../../contracts/ETH_Keycrypt.sol";


uint256 constant ETH_BALANCE = 1_000_000 ether;
uint256 constant USDC_BALANCE = 1_000_000_000 * 1e6;

contract Handler is Test {

    ETH_Keycrypt public keycrypt;

    constructor(ETH_Keycrypt _keycrypt) {
        keycrypt = _keycrypt;
    }

    receive() external payable {}
}