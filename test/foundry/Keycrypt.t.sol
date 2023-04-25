// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "../../contracts/ETH_Factory.sol";
import "../../contracts/ETH_Keycrypt.sol";
import "forge-std/Test.sol";
import "../../contracts/interfaces/UserOperation.sol";


contract KeycryptTest is Test {
    using UserOperationLib for UserOperation;

    UserOperation userOpData;
    uint256 mainnetFork;
    ETH_Factory public factory;
    ETH_Keycrypt public keycrypt;
    address public owner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    address[] addresses;
    UserOperation[] userOp;
    bytes sign;

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = 0x640E35B6AfC3F6AD37bC14792536dA06e1C8cc19;
        guardian1 = 0xb2234c988cC1C4BE0b31fEbd2bA54BE61735f315;
        guardian2 = 0x213ce1554f6F96dB5CdAEa7D750F89Ab2Ae43294;
        factory = new ETH_Factory(entryPoint);
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
        sign = hex"b7b6288db992122d6fc03a7c5d9f4710544ced4b6154a8ffa13d38023a73cb2a60f08e85477db10633334801fa888abaad873cc31991d03edb7c9c9e619d8a111c576b0a497cb56630d7346ad0d04d6832b9ae9a7a4dc3538136525a40003085200b8ae9e92dfad27229452f572a0fbbca11cec280529a49d0fc83bb120381ffbf1c";
    }

    function test_ETH_KeycryptDotAddToWhitelist() public {
        vm.deal(address(keycrypt), 1 ether);
        console.log('keycrypt balance:', address(keycrypt).balance / 1e18);
        console.log('keycrypt owner:', keycrypt.owner());
        console.log('keycrypt address:', address(keycrypt));
        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        addresses.push(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        addresses.push(0x6B175474E89094C44Da98b954EedeAC495271d0F);
        // create calldata for addToWhitelist function
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        // console.log('callData:', callData_);
        userOpData = UserOperation({
            sender: address(keycrypt),
            nonce: 0,
            initCode: "",
            callData: callData_,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 43683902336,
            maxPriorityFeePerGas: 60865874,
            paymasterAndData: "",
            signature: ""
        });
        bytes32 userOpHash = keccak256(abi.encode(userOpData.hash(), address(this), block.chainid));
        console.log('userOpHash:', userOpHash);
        // create UserOperation struct
        userOp.push(UserOperation({
            sender: address(keycrypt),
            nonce: 0,
            initCode: "",
            callData: callData_,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 43683902336,
            maxPriorityFeePerGas: 60865874,
            paymasterAndData: "",
            // create signature signed by owner and guardian1, with signing data being userOp[0]
            signature: sign
        }));
        entryPoint.handleOps(userOp, payable(msg.sender));
        // keycrypt.addToWhitelist(addresses);
    }

    // receive() external payable {}
}





