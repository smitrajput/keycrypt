// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../contracts/ETH_Keycrypt.sol";

// import openzeppelin's ERC20 interface
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@solady/src/utils/ERC1967Factory.sol";

interface IUSDC {
    function configureMinter(address minter, uint256 minterAllowedAmount) external;
    function mint(address _to, uint256 _amount) external;
}

contract KeycryptTest is Test {
    using UserOperationLib for UserOperation;

    address constant public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant public USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 mainnetFork;
    ERC1967Factory public soladyFactory;
    ETH_Keycrypt public keycrypt;
    ETH_Keycrypt public keycryptImpl;
    address public owner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    address[] addresses;
    bytes[] funcSigs;
    UserOperation[] userOp;
    bytes sign;
    Util util;

    function setUp() public {
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = vm.addr(19);
        guardian1 = vm.addr(20);
        guardian2 = vm.addr(21);
        // solady's ERC1967Factory is already deployed at this address
        soladyFactory = ERC1967Factory(0x0000000000006396FF2a80c067f99B3d2Ab4Df24);
        bytes memory data = abi.encodeWithSelector(ETH_Keycrypt.initialize.selector, owner, guardian1, guardian2);
        keycryptImpl = new ETH_Keycrypt(entryPoint);
        address keycryptAddr = soladyFactory.deployDeterministicAndCall(address(keycryptImpl), owner, 0, data);
        keycrypt = ETH_Keycrypt(payable(keycryptAddr));
        vm.deal(address(keycrypt), 100 ether);
        // sign = hex"edd79d1d9520e698e726b63b5a8959162da3a899727ae68d012bdb60000093b17348db30ff8fae84ed1418b657f1e1b15ee299e725f0b497a2addffcf7ea705f1c7e5d7426781b7c4792ce12b5b1d19d0809a29e9e66a92493dbc41120df47d14204aa73c3abba722cd6b3fa367889881ca0303d6562e1b55930547eb950bc62db1c";
        util = new Util();
    }

    function test_addToWhitelist(address _addyA, address _addyB, address _addyC) public {
        console.log('keycrypt balance: %s, owner: %s, address: %s', 
        address(keycrypt).balance / 1e18, keycrypt.owner(), address(keycrypt));

        // set _addyA, _addyB, _addyC as whitelisted tokens
        addresses.push(_addyA);
        addresses.push(_addyB);
        addresses.push(_addyC);

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

    function test_removeFromWhitelist(address _addyA, address _addyB, address _addyC) public {
        // set USDC, USDT, DAI as whitelisted tokens
        addresses.push(_addyA);
        addresses.push(_addyB);
        addresses.push(_addyC);

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

    // "Call did not revert as expected" smh smh smh
    // function test_RevertOn_upgradingToNonUUPSImpl(address _newKeycryptImpl) public {
    //     assertEq(keycrypt.currentImplementation(), address(keycryptImpl));

    //     // ETH_Keycrypt keycryptNewImpl = new ETH_Keycrypt(entryPoint);
    //     // bytes memory data = abi.encodeWithSelector(ETH_Keycrypt.initialize.selector, guardian2, owner, guardian1);
    //     bytes memory callData_ = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", _newKeycryptImpl, hex"");
    //     sign = _twoOfThreeSign(0, callData_);
    //     _addUserOp(0, callData_, sign);

    //     vm.expectRevert("ERC1967Upgrade: new implementation is not UUPS");
    //     entryPoint.handleOps(userOp, payable(msg.sender));
    // }

    // "Call did not revert as expected" smh smh smh
    // function test_RevertOn_upgradingToProxy() public {
    //     assertEq(keycrypt.currentImplementation(), address(keycryptImpl));

    //     // ETH_Keycrypt keycryptNewImpl = new ETH_Keycrypt(entryPoint);
    //     // address(keycrypt) is a proxy
    //     bytes memory callData_ = abi.encodeWithSignature("upgradeTo(address)", address(keycrypt));
    //     sign = _twoOfThreeSign(0, callData_);
    //     _addUserOp(0, callData_, sign);

    //     vm.expectRevert(bytes(""));
    //     entryPoint.handleOps(userOp, payable(msg.sender));
    // }

    function test_upgradeToUUPSImpl() public {
        assertEq(keycrypt.currentImplementation(), address(keycryptImpl));

        ETH_Keycrypt keycryptNewImpl = new ETH_Keycrypt(entryPoint);
        // bytes memory data = abi.encodeWithSelector(ETH_Keycrypt.initialize.selector, guardian2, owner, guardian1);
        bytes memory callData_ = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(keycryptNewImpl), hex"");
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.currentImplementation(), address(keycryptNewImpl));
    }

    function test_changeOwner(address _newOwner) public {
        vm.assume(_newOwner != address(0));
        assertEq(keycrypt.owner(), owner);

        bytes memory callData_ = abi.encodeWithSignature("changeOwner(address)", _newOwner);
        sign = _twoOfThreeSign(0, callData_);

        _addUserOp(0, callData_, sign);
        // simulate the bundler calling handleOps on entryPoint
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.owner(), _newOwner);
    }

    function test_changeGuardianOne(address _newGuardian1) public {
        vm.assume(_newGuardian1 != address(0));
        assertEq(keycrypt.guardian1(), guardian1);

        bytes memory callData_ = abi.encodeWithSignature("changeGuardianOne(address)", _newGuardian1);
        sign = _twoOfThreeSign(0, callData_);

        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.guardian1(), _newGuardian1);
    }

    function test_changeGuardianTwo(address _newGuardian2) public {
        vm.assume(_newGuardian2 != address(0));
        assertEq(keycrypt.guardian2(), guardian2);

        bytes memory callData_ = abi.encodeWithSignature("changeGuardianTwo(address)", _newGuardian2);
        sign = _twoOfThreeSign(0, callData_);

        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        assertEq(keycrypt.guardian2(), _newGuardian2);
    }

    function test_addDeposit(uint256 _amount) public {
        vm.assume(_amount < 100 ether);
        bytes memory callData_ = abi.encodeWithSignature("addDeposit(uint256)", _amount);
        sign = _oneOfOneSign(0, callData_);

        _addUserOp(0, callData_, sign);
        
        uint keycryptEthBefore = address(keycrypt).balance;
        entryPoint.handleOps(userOp, payable(msg.sender));
        uint keycryptEthAfter = address(keycrypt).balance;

        assertGe(keycryptEthBefore - keycryptEthAfter, _amount);
        // deposits in entryPoint must be at least _amount
        assertGe(entryPoint.getDepositInfo(address(keycrypt)).deposit, _amount);
    }

    function test_withdrawDepositTo(uint256 _depositAmt, uint256 _withdrawalAmt) public {
        // 0.3 ETH is gas cost for executing UserOperation
        vm.assume(_depositAmt >= 0.3 ether && _depositAmt < 100 ether && _withdrawalAmt < _depositAmt - 0.3 ether);
        // add deposit first
        bytes memory callData_ = abi.encodeWithSignature("addDeposit(uint256)", _depositAmt);
        sign = _oneOfOneSign(0, callData_);
        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        // withdraw deposit
        callData_ = abi.encodeWithSignature("withdrawDepositTo(address,uint256)", guardian2, _withdrawalAmt);
        sign = _twoOfThreeSign(1, callData_);
        userOp.pop();
        _addUserOp(1, callData_, sign);
        
        uint depositBefore = entryPoint.getDepositInfo(address(keycrypt)).deposit;
        uint guardian2EthBefore = guardian2.balance;
        entryPoint.handleOps(userOp, payable(msg.sender));
        uint guardian2EthAfter = guardian2.balance;
        uint depositAfter = entryPoint.getDepositInfo(address(keycrypt)).deposit;

        assertEq(guardian2EthAfter - guardian2EthBefore, _withdrawalAmt);
        assertGe(depositBefore - depositAfter, _withdrawalAmt);
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

    function test_RevertOn_CallingNonWhitelistedToken() public {
        // WHITELISTING
        addresses.push(DAI);
        addresses.push(guardian1);
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        //execute whitelisting
        entryPoint.handleOps(userOp, payable(msg.sender));

        // EXECUTE
        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", USDC, 0, abi.encodeWithSignature("approve(address,uint256)", guardian1, 1e18));
        sign = _oneOfOneSign(1, callData_);
        userOp.pop(); // remove previous op
        _addUserOp(1, callData_, sign); // note the updated nonce
        (bool success, ) = address(entryPoint).call(abi.encodeWithSignature("handleOps(bytes[],address)", userOp, payable(msg.sender)));
        assertEq(success, false);
    }

    function test_RevertOn_ApprovingNonWhitelistedAddressOnWhitelistedToken() public {
        // WHITELISTING
        addresses.push(DAI);
        addresses.push(guardian1);
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        // execute whitelisting
        entryPoint.handleOps(userOp, payable(msg.sender));

        // EXECUTE
        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", DAI, 0, abi.encodeWithSignature("approve(address,uint256)", guardian2, 1e18));
        sign = _oneOfOneSign(1, callData_);
        userOp.pop(); // remove previous op
        _addUserOp(1, callData_, sign); // note the updated nonce
        (bool success, ) = address(entryPoint).call(abi.encodeWithSignature("handleOps(bytes[],address)", userOp, payable(msg.sender)));
        assertEq(success, false);
    }

    function test_RevertOn_TransferringWhitelistedTokenToNonWhitelistedAddress() public {
        // WHITELISTING
        addresses.push(USDC);
        addresses.push(guardian1);
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeSign(0, callData_);
        _addUserOp(0, callData_, sign);
        //execute whitelisting
        entryPoint.handleOps(userOp, payable(msg.sender));

        // minting 1000 USDC to keycrypt
        vm.startPrank(0xE982615d461DD5cD06575BbeA87624fda4e3de17);
        IUSDC(USDC).configureMinter(0xE982615d461DD5cD06575BbeA87624fda4e3de17, 1000 * 1e6);
        IUSDC(USDC).mint(address(keycrypt), 1000 * 1e6);
        vm.stopPrank();
        console.log('USDC balance', IERC20(USDC).balanceOf(address(keycrypt)));

        // EXECUTE
        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", USDC, 0, abi.encodeWithSignature("transfer(address,uint256)", guardian2, 100 * 1e6));
        sign = _oneOfOneSign(1, callData_);
        userOp.pop(); // remove previous op
        _addUserOp(1, callData_, sign); // note the updated nonce
        (bool success, ) = address(entryPoint).call(abi.encodeWithSignature("handleOps(bytes[],address)", userOp, payable(msg.sender)));
        assertEq(success, false);
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


    // failed selective fuzzing
    // function test_execute(address _token, uint256 _amount, bytes calldata _data, address _to) public {
    //     // vm.assume _token is DAI or USDC or USDT, and _data is abi encoded approve, safeApprove, transfer, safeTransfer, 
    //     // increaseAllowance, safeIncreaseAllowance, decreaseAllowance, safeDecreaseAllowance
    //     vm.assume((_token == DAI || _token == USDC || _token == USDT) && 
    //               (keccak256(_data) == keccak256(abi.encodeWithSignature("approve(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("safeApprove(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("transfer(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("safeTransfer(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("increaseAllowance(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("safeIncreaseAllowance(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("decreaseAllowance(address,uint256)", _to, _amount))
    //               || keccak256(_data) == keccak256(abi.encodeWithSignature("safeDecreaseAllowance(address,uint256)", _to, _amount))));
        
    //     // WHITELISTING
    //     addresses.push(_token);
    //     addresses.push(_to);
    //     console.log('GUARDIAN1', _to);
    //     bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
    //     sign = _twoOfThreeSign(0, callData_);
    //     _addUserOp(0, callData_, sign);
    //     //execute whitelisting
    //     entryPoint.handleOps(userOp, payable(msg.sender));

    //     // EXECUTE
    //     callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", _token, 0, _data);
    //     sign = _oneOfOneSign(1, callData_);
    //     userOp.pop(); // remove previous op
    //     _addUserOp(1, callData_, sign); // note the updated nonce
    //     entryPoint.handleOps(userOp, payable(msg.sender));

    //     // assertEq(IERC20(DAI).allowance(address(keycrypt), _to), 1e18);
    // }


