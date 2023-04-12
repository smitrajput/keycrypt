// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/ETH_Factory.sol";
import "../../contracts/ETH_Keycrypt.sol";

// interface INonceHolder {
//     /// @dev Returns the deployment nonce for the accounts used for CREATE opcode.
//     function getDeploymentNonce(address _address) external view returns (uint256);
// }

interface AnyswapV6Router {
    /// @dev Returns the deployment nonce for the accounts used for CREATE opcode.
    function mpc() external view returns (address);
}

contract KeycryptTest is Test {
    uint256 mainnetFork;
    ETH_Factory public factory;
    ETH_Keycrypt public keycrypt;
    address public owner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/SJVS2ntWXSBZLjio560R-qMw-s3XaN14');
        vm.selectFork(mainnetFork);
        owner = address(0x123);
        guardian1 = address(0x456);
        guardian2 = address(0x789);
        factory = new ETH_Factory(entryPoint);
    }

    function test_FactoryDotCreateAccount() public {
        // counter.increment();
        // assertEq(counter.number(), 1);
        // INonceHolder nonceHolder = INonceHolder(0x0000000000000000000000000000000000008003);
        // uint256 nonce = nonceHolder.getDeploymentNonce(0x7Bae133d541Ac388BCdF17C72436ebbb625F94bF);
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
        console.log('keycrypt address:', address(keycrypt));
        assertEq(keycrypt.owner(), owner);
        //send 1 ETH to keycrypt
        // vm.deal(address(keycrypt), 1 ether);
    }

    function test_ETH_KeycryptDotAddToWhitelist() public {
        console.log('keycrypt balance:', address(keycrypt).balance);
        console.log('keycrypt owner:', keycrypt.owner());
        // entryPoint.
    }
}

// write solidity code to initialise test setup for Keycrypt.sol by creating a new instance of Keycrypt and calling its constructor




