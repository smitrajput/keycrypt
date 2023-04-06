// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/Keycrypt.sol";

// interface INonceHolder {
//     /// @dev Returns the deployment nonce for the accounts used for CREATE opcode.
//     function getDeploymentNonce(address _address) external view returns (uint256);
// }

interface AnyswapV6Router {
    /// @dev Returns the deployment nonce for the accounts used for CREATE opcode.
    function mpc() external view returns (address);
}

contract KeycryptTest is Test {
    uint256 zkSyncFork;
    Keycrypt public keycrypt;
    address public owner;
    address public guardian1;
    address public guardian2;

    function setUp() public {
        // create zksync testnet fork and deploy Keycrypt.sol to it
        zkSyncFork = vm.createFork('https://eth-goerli.g.alchemy.com/v2/o0zPBQM7rdfOMk8or8Dmlq60oHZqtnqU');
        vm.selectFork(zkSyncFork);
        owner = address(0x123);
        guardian1 = address(0x456);
        guardian2 = address(0x789);
        keycrypt = new Keycrypt(owner, guardian1, guardian2);
    }

    function testAddToWhitelist() public {
        // counter.increment();
        // assertEq(counter.number(), 1);
        INonceHolder nonceHolder = INonceHolder(0x0000000000000000000000000000000000008003);
        uint256 nonce = nonceHolder.getDeploymentNonce(0x7Bae133d541Ac388BCdF17C72436ebbb625F94bF);
        console.log('Nonce: ', nonce);
        // AnyswapV6Router nonceHolder = AnyswapV6Router(0xB44a9B6905aF7c801311e8F4E76932ee959c663C);
        // address nonce = nonceHolder.mpc();
        // console.log('Nonce: ', nonce);
    }

    function testSetNumber(uint256 x) public {
        // counter.setNumber(x);
        // assertEq(counter.number(), x);
    }
}

// write solidity code to initialise test setup for Keycrypt.sol by creating a new instance of Keycrypt and calling its constructor




