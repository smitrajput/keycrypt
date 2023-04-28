// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/ETH_Factory.sol";
import "../../contracts/ETH_Keycrypt.sol";

// import openzeppelin's ERC20 interface
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

contract KeycryptTest is Test {
    using UserOperationLib for UserOperation;

    address constant public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant public USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 mainnetFork;
    ETH_Factory public factory;
    ETH_Keycrypt public keycrypt;
    address public owner;
    address public newOwner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    address[] addresses;
    bytes[] funcSigs;
    UserOperation[] userOp;
    bytes sign;
    Util util;

    function setUp() public {
        // create eth mainnet fork and deploy ETH_Factory.sol to it
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = vm.addr(19);
        guardian1 = vm.addr(20);
        guardian2 = vm.addr(21);
        factory = new ETH_Factory(entryPoint);
        keycrypt = factory.createAccount(owner, guardian1, guardian2, 0);
        vm.deal(address(keycrypt), 1 ether);
        // sign = hex"edd79d1d9520e698e726b63b5a8959162da3a899727ae68d012bdb60000093b17348db30ff8fae84ed1418b657f1e1b15ee299e725f0b497a2addffcf7ea705f1c7e5d7426781b7c4792ce12b5b1d19d0809a29e9e66a92493dbc41120df47d14204aa73c3abba722cd6b3fa367889881ca0303d6562e1b55930547eb950bc62db1c";
        util = new Util();
    }

    function test_addToWhitelist() public {
        console.log('keycrypt balance:', address(keycrypt).balance / 1e18);
        console.log('keycrypt owner:', keycrypt.owner());
        console.log('keycrypt address:', address(keycrypt));

        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(USDC);
        addresses.push(USDT);
        addresses.push(DAI);

        // check that none of the addresses are whitelisted
        assertFalse(keycrypt.isWhitelisted(addresses[0]));
        assertFalse(keycrypt.isWhitelisted(addresses[1]));
        assertFalse(keycrypt.isWhitelisted(addresses[2]));

        // create calldata for addToWhitelist function
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        // call _createUserOpHash(callData_); and sign the output with owner and guardian1 off-chain
        sign = _twoOfThreeSign(0, callData_);

        _addUserOp(0, callData_, sign);
        // simulate the bundler calling handleOps on entryPoint
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.isWhitelisted(addresses[0]), true);
        assertEq(keycrypt.isWhitelisted(addresses[1]), true);
        assertEq(keycrypt.isWhitelisted(addresses[2]), true);
    }

    function test_removeFromWhitelist() public {
        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(USDC);
        addresses.push(USDT);
        addresses.push(DAI);

        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertTrue(keycrypt.isWhitelisted(addresses[0]));
        assertTrue(keycrypt.isWhitelisted(addresses[1]));
        assertTrue(keycrypt.isWhitelisted(addresses[2]));

        // create calldata for removeFromWhitelist function
        callData_ = abi.encodeWithSignature("removeFromWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(1, callData_);
        userOp.pop();
        _addUserOp(1, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.isWhitelisted(addresses[0]), false);
        assertEq(keycrypt.isWhitelisted(addresses[1]), false);
        assertEq(keycrypt.isWhitelisted(addresses[2]), false);
    }

    function test_changeOwner() public {
        assertEq(keycrypt.owner(), owner);

        newOwner = vm.addr(22);
        bytes memory callData_ = abi.encodeWithSignature("changeOwner(address)", newOwner);
        sign = _twoOfThreeSign(0, callData_);

        _addUserOp(0, callData_, sign);
        // simulate the bundler calling handleOps on entryPoint
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.owner(), newOwner);
    }

    function test_addDeposit() public {
        bytes memory callData_ = abi.encodeWithSignature("addDeposit(uint256)", 0.2 ether);
        sign = _oneOfOneSign(0, callData_);

        _addUserOp(0, callData_, sign);
        
        uint keycryptEthBefore = address(keycrypt).balance;
        entryPoint.handleOps(userOp, payable(msg.sender));
        uint keycryptEthAfter = address(keycrypt).balance;

        assertGe(keycryptEthBefore - keycryptEthAfter, 0.2 ether);
        // deposits in entryPoint must be at least 0.2 ether
        assertGe(entryPoint.getDepositInfo(address(keycrypt)).deposit, 0.2 ether);
    }

    function test_withdrawDepositTo() public {
        // add deposit first
        bytes memory callData_ = abi.encodeWithSignature("addDeposit(uint256)", 0.2 ether);
        sign = _oneOfOneSign(0, callData_);
        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        // withdraw deposit
        callData_ = abi.encodeWithSignature("withdrawDepositTo(address,uint256)", guardian2, 0.1 ether);
        sign = _twoOfThreeSign(1, callData_);
        userOp.pop();
        _addUserOp(1, callData_, sign);
        
        uint depositBefore = entryPoint.getDepositInfo(address(keycrypt)).deposit;
        uint guardian2EthBefore = guardian2.balance;
        entryPoint.handleOps(userOp, payable(msg.sender));
        uint guardian2EthAfter = guardian2.balance;
        uint depositAfter = entryPoint.getDepositInfo(address(keycrypt)).deposit;

        assertEq(guardian2EthAfter - guardian2EthBefore, 0.1 ether);
        assertGe(depositBefore - depositAfter, 0.1 ether);
    }


    function test_execute() public {
        // WHITELISTING
        addresses.push(DAI);
        addresses.push(guardian1);
        console.log('GUARDIAN1', guardian1);
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        //execute whitelisting
        entryPoint.handleOps(userOp, payable(msg.sender));

        // EXECUTE
        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", DAI, 0, abi.encodeWithSignature("approve(address,uint256)", guardian1, 1e18));
        sign = _oneOfOneSign(1, callData_);
        userOp.pop(); // remove previous op
        _addUserOp(1, callData_, sign); // note the updated nonce
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(IERC20(DAI).allowance(address(keycrypt), guardian1), 1e18);
    }

    function test_executeBatch() public {
        // WHITELISTING
        addresses.push(DAI);
        addresses.push(USDC);
        addresses.push(USDT);
        // add owner, guardian1, guardian2 to addresses
        addresses.push(owner);
        addresses.push(guardian1);
        addresses.push(guardian2);

        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        //execute whitelisting
        entryPoint.handleOps(userOp, payable(msg.sender));

        // EXECUTE_BATCH
        // remove owner, guardian1, guardian2 from addresses to send execute() calls to
        addresses.pop(); addresses.pop(); addresses.pop();
        funcSigs.push(abi.encodeWithSignature("approve(address,uint256)", owner, 1e18));
        funcSigs.push(abi.encodeWithSignature("approve(address,uint256)", guardian1, 1e18));
        funcSigs.push(abi.encodeWithSignature("approve(address,uint256)", guardian2, 1e18));

        console.log('OWNER', owner);
        callData_ = abi.encodeWithSignature("executeBatch(address[],bytes[])", addresses, funcSigs);
        sign = _oneOfOneSign(1, callData_);
        userOp.pop(); // remove previous op // EASILY FORGETTABLE
        _addUserOp(1, callData_, sign);
        // simulate the bundler calling handleOps on entryPoint
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(IERC20(DAI).allowance(address(keycrypt), owner), 1e18);
        assertEq(IERC20(USDC).allowance(address(keycrypt), guardian1), 1e18);
        assertEq(IERC20(USDT).allowance(address(keycrypt), guardian2), 1e18);
    }

    function _oneOfOneSign(uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
        _sign = abi.encodePacked(r, s, v);
    }

    function _twoOfThreeSign(uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
        bytes memory sign1 = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(20, userOpHash);
        bytes memory sign2 = abi.encodePacked(r, s, v);
        _sign = abi.encodePacked(sign1, sign2);
    }

    function _addUserOp(uint256 _nonce, bytes memory _callData, bytes memory _sign) internal {
        userOp.push(UserOperation({
            sender: address(keycrypt),
            nonce: _nonce,
            initCode: "",
            callData: _callData,
            callGasLimit: 1000000,
            verificationGasLimit: 1000000,
            preVerificationGas: 1000000,
            maxFeePerGas: 43683902336,
            maxPriorityFeePerGas: 60865874,
            paymasterAndData: "",
            signature: _sign
        }));
    }

    // to generate the userOpHash along the lines of EntryPoint.getUserOpHash(), 
    // as expected by ETH_Keycrypt.isValidSignature(), which is signed by owner and 1 guardian
    function _createUserOpHash(uint256 _nonce, bytes memory _callData) internal view returns(bytes32 userOpHash){
        UserOperation memory userOpData = UserOperation({
            sender: address(keycrypt),
            nonce: _nonce,
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
        userOpHash = keccak256(abi.encode(util.hash(userOpData), address(entryPoint), block.chainid));
    }

    // receive() external payable {}
}

contract Util {
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





