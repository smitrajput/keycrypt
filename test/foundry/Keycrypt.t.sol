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
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
    }

    function test_ETH_KeycryptDotAddToWhitelist() public {
        vm.deal(address(keycrypt), 1 ether);
        console.log('keycrypt balance:', address(keycrypt).balance / 1e18);
        console.log('keycrypt owner:', keycrypt.owner());
        // create UserOperation struct
        UserOperation[] memory userOp;
        userOp[0] = UserOperation({
            sender: address(0x123),
            nonce: 0,
            initCode: bytes(""),
            callData: bytes(""),
            callGasLimit: 0,
            verificationGasLimit: 0,
            preVerificationGas: 0,
            maxFeePerGas: 0,
            maxPriorityFeePerGas: 0,
            paymasterAndData: bytes(""),
            signature: bytes("")
        });
        entryPoint.handleOps(userOp, payable(msg.sender));
        address[] memory addresses;
        addresses[0] = address(0x123);
        keycrypt.addToWhitelist(addresses);
    }
}

// write solidity code to initialise test setup for Keycrypt.sol by creating a new instance of Keycrypt and calling its constructor




