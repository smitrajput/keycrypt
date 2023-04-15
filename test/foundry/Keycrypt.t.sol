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
    address[] addresses;

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = address(0x123);
        guardian1 = address(0x456);
        guardian2 = address(0x789);
        factory = new ETH_Factory(entryPoint);
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
        console.log("WHAT_UPDOG");
    }

    function test_ETH_KeycryptDotAddToWhitelist() public {
        vm.deal(address(keycrypt), 1 ether);
        console.log('keycrypt balance:', address(keycrypt).balance / 1e18);
        console.log('keycrypt owner:', keycrypt.owner());
        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        addresses.push(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        addresses.push(0x6B175474E89094C44Da98b954EedeAC495271d0F);
        //create calldata for addToWhitelist function
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        // create UserOperation struct
        UserOperation[] memory userOp;
        userOp[0] = UserOperation({
            sender: address(keycrypt),
            nonce: 1,
            initCode: bytes(""),
            callData: callData_,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 43683902336,
            maxPriorityFeePerGas: 60865874,
            paymasterAndData: bytes(""),
            // create signature signed by owner and guardian1, with signing data being userOp[0]


        });
        entryPoint.handleOps(userOp, payable(msg.sender));
        addresses[0] = address(0x123);
        keycrypt.addToWhitelist(addresses);
    }

    function test_addToWhitelistGas() public {
        addresses.push(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        addresses.push(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        addresses.push(0x6B175474E89094C44Da98b954EedeAC495271d0F);
        uint256 gas = gasleft();
        vm.prank(address(entryPoint));
        console.log("1");
        keycrypt.addToWhitelist(addresses);
        console.log("2");
        gas = gas - gasleft();
        console.log('gas used:', gas);
    }
}

// write solidity code to initialise test setup for Keycrypt.sol by creating a new instance of Keycrypt and calling its constructor




