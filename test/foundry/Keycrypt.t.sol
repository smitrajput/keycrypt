// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/ETH_Factory.sol";
import "../../contracts/ETH_Keycrypt.sol";


contract KeycryptTest is Test {
    using UserOperationLib for UserOperation;

    uint256 mainnetFork;
    ETH_Factory public factory;
    ETH_Keycrypt public keycrypt;
    address public owner;
    address public newOwner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    address[] addresses;
    UserOperation[] userOp;
    bytes sign;
    Hasher hasher;

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = vm.addr(19);
        guardian1 = vm.addr(20);
        guardian2 = vm.addr(21);
        factory = new ETH_Factory(entryPoint);
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
        // sign = hex"edd79d1d9520e698e726b63b5a8959162da3a899727ae68d012bdb60000093b17348db30ff8fae84ed1418b657f1e1b15ee299e725f0b497a2addffcf7ea705f1c7e5d7426781b7c4792ce12b5b1d19d0809a29e9e66a92493dbc41120df47d14204aa73c3abba722cd6b3fa367889881ca0303d6562e1b55930547eb950bc62db1c";
        hasher = new Hasher();
    }

    function test_addToWhitelist() public {
        vm.deal(address(keycrypt), 1 ether);
        console.log('keycrypt balance:', address(keycrypt).balance / 1e18);
        console.log('keycrypt owner:', keycrypt.owner());
        console.log('keycrypt address:', address(keycrypt));

        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
        addresses.push(0xdAC17F958D2ee523a2206206994597C13D831ec7);
        addresses.push(0x6B175474E89094C44Da98b954EedeAC495271d0F);

        // check that none of the addresses are whitelisted
        assertFalse(keycrypt.isWhitelisted(addresses[0]));
        assertFalse(keycrypt.isWhitelisted(addresses[1]));
        assertFalse(keycrypt.isWhitelisted(addresses[2]));

        // create calldata for addToWhitelist function
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        // call createUserOpHash(callData_); and sign the output with owner and guardian1 off-chain
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", createUserOpHash(callData_)));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
        bytes memory sign1 = abi.encodePacked(r, s, v);
        (v, r, s) = vm.sign(20, userOpHash);
        bytes memory sign2 = abi.encodePacked(r, s, v);

        sign = abi.encodePacked(sign1, sign2);
        // create UserOperation struct with signature created above and set to 'sign' variable
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
            signature: sign
        }));

        // simulate the bundler calling handleOps on entryPoint
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.isWhitelisted(addresses[0]), true);
        assertEq(keycrypt.isWhitelisted(addresses[1]), true);
        assertEq(keycrypt.isWhitelisted(addresses[2]), true);
    }

    // function test_changeOwner() public {
    //     assertEq(keycrypt.owner(), owner);

    //     address mockOwner = vm.addr(22);
    //     bytes memory callData_ = abi.encodeWithSignature("changeOwner(address)", mockOwner);
    //     bytes32 userOpHash = createUserOpHash(callData_);

    //     (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
    //     bytes memory sign1 = abi.encodePacked(v, r, s);
    //     (v, r, s) = vm.sign(20, userOpHash);
    //     bytes memory sign2 = abi.encodePacked(v, r, s);
    //     sign = abi.encodePacked(sign1, sign2);
    //     console.log('changeOwner sign');
    //     console.logBytes(sign);

    //     userOp[0] = UserOperation({
    //         sender: address(keycrypt),
    //         nonce: 0,
    //         initCode: "",
    //         callData: callData_,
    //         callGasLimit: 1000000,
    //         verificationGasLimit: 1000000,
    //         preVerificationGas: 1000000,
    //         maxFeePerGas: 43683902336,
    //         maxPriorityFeePerGas: 60865874,
    //         paymasterAndData: "",
    //         signature: sign
    //     });

    //     // simulate the bundler calling handleOps on entryPoint
    //     entryPoint.handleOps(userOp, payable(msg.sender));

    //     assertEq(keycrypt.owner(), mockOwner);
    // }

    // to generate the userOpHash along the lines of EntryPoint.getUserOpHash(), 
    // as expected by ETH_Keycrypt.isValidSignature(), which is signed by owner and 1 guardian
    function createUserOpHash(bytes memory _callData) public view returns(bytes32 userOpHash){
        UserOperation memory userOpData = UserOperation({
            sender: address(keycrypt),
            nonce: 0,
            initCode: "",
            callData: _callData,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 43683902336,
            maxPriorityFeePerGas: 60865874,
            paymasterAndData: "",
            signature: ""
        });
        userOpHash = keccak256(abi.encode(hasher.hash(userOpData), address(entryPoint), block.chainid));
        // console.logBytes32(userOpHash);
    }

    // receive() external payable {}
}

contract Hasher {
    function pack(UserOperation calldata _userOp) internal pure returns (bytes memory ret) {
        //lighter signature scheme. must match UserOp.ts#packUserOp
        bytes calldata sig = _userOp.signature;
        // copy directly the userOp from calldata up to (but not including) the signature.
        // this encoding depends on the ABI encoding of calldata, but is much lighter to copy
        // than referencing each field separately.
        assembly {
            let ofs := _userOp
            let len := sub(sub(sig.offset, ofs), 32)
            ret := mload(0x40)
            mstore(0x40, add(ret, add(len, 32)))
            mstore(ret, len)
            calldatacopy(add(ret, 32), ofs, len)
        }
    }

    function hash(UserOperation calldata _userOp) public pure returns (bytes32) {
        return keccak256(pack(_userOp));
    }
}





