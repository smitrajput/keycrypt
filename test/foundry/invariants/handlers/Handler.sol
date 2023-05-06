// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../../../contracts/ETH_Keycrypt.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";

/// @dev different values of '_pk' signing txns below, simulate different actors calling keycrypt via entryPoint and not the handler
/// this is why we don't need to vm.prank(msg.sender) before making a call to keycrypt
contract Handler is Test {

    address constant public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant public USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 constant ETH_BALANCE = 1_000_000 ether;
    uint256 constant USDC_BALANCE = 1_000_000_000 * 1e6;

    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    ETH_Keycrypt public keycrypt;
    UserOperation[] userOp;
    address[] addresses;
    bytes sign;
    Util util;

    /// @dev ghost variable that updates by 1 for every successful call to keycrypt
    uint256 public ghost_Nonce;
    mapping(bytes32 => uint256) public calls;

    modifier countCall(bytes32 key) {
        calls[key]++;
        _;
    }

    constructor(ETH_Keycrypt _keycrypt) {
        keycrypt = _keycrypt;
        util = new Util();
    }

    /// @dev to summarise the number of calls made to each of the functions below
    function callSummary() public view {
        console.log("Call summary:");
        console.log("-------------------");
        console.log("oneOfOneNonOwnerExecute", calls["oneOfOneNonOwnerExecute"]);
        console.log("oneOfOneOwnerExecute", calls["oneOfOneOwnerExecute"]);
        console.log("twoOfThreeNonAuthChangeOG1G2", calls["twoOfThreeNonAuthChangeOG1G2"]);
        console.log("twoOfThreeNonAuthUpgrade", calls["twoOfThreeNonAuthUpgrade"]);
    }

    /// @dev function exposed: execute(), with all target functions in _targetTokenFunc()
    /// _pk simulates attacker's private key
    /// actual test here is non-owner trying to execute()
    function oneOfOneNonOwnerExecute(uint256 _pk, uint256 _funcSeed) public countCall("oneOfOneNonOwnerExecute") {
        addresses.push(USDC);
        // even if attacker's address is whitelisted smh
        addresses.push(vm.addr(_pk));
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeAuthSign(keycrypt.nonce(), callData_);
        _addUserOp(keycrypt.nonce(), callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        ++ghost_Nonce;

        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", USDC, 0, _targetTokenFunc(_funcSeed, _pk));
        sign = _oneOfOneNonOwnerSign(_pk, keycrypt.nonce(), callData_);
        userOp.pop(); // remove previous op
        _addUserOp(keycrypt.nonce(), callData_, sign); // note the updated nonce
        entryPoint.handleOps(userOp, payable(msg.sender));
        
        if(_funcSeed == 2) {
            IERC20(USDC).transferFrom(address(keycrypt), vm.addr(_pk), 1e15);
        } 
        // else if(_funcSeed == 3) {
        //     SafeERC20(USDC).safeTransferFrom(address(keycrypt), vm.addr(_pk), 1e15);
        // }

        // execution reaching here means the calls to keycrypt were successful
        ++ghost_Nonce;
    }

    /// @dev function exposed: execute(), with all target functions in _targetTokenFunc()
    /// simulating the scenario when _pk gains access to the owner's private key (by compromising the owner's machine)
    /// actual test here is of vm.addr(_pk) not being whitelisted
    function oneOfOneOwnerExecute(uint256 _pk, uint256 _funcSeed) public countCall("oneOfOneOwnerExecute") {
        addresses.push(USDC);
        // attacker's address is not whitelisted
        // addresses.push(vm.addr(_pk));
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeAuthSign(keycrypt.nonce(), callData_);
        _addUserOp(keycrypt.nonce(), callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        ++ghost_Nonce;

        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", USDC, 0, _targetTokenFunc(_funcSeed, _pk));
        sign = _oneOfOneOwnerSign(keycrypt.nonce(), callData_);
        userOp.pop(); // remove previous op
        _addUserOp(keycrypt.nonce(), callData_, sign); // note the updated nonce
        entryPoint.handleOps(userOp, payable(msg.sender));

        if(_funcSeed == 2) {
            IERC20(USDC).transferFrom(address(keycrypt), vm.addr(_pk), 1e15);
        }

        ++ghost_Nonce;
    }

    /// @dev function exposed: all target functions in _targetChangeFunc()
    /// simulating non-auth 160-sized signs changing owner/guardian
    function twoOfThreeNonAuthChangeOG1G2(uint256 _pk1, uint256 _pk2, uint256 _funcSeed) public countCall("twoOfThreeNonAuthChangeOG1G2") {
        // (_pk1 + _pk2) % 2 == 0 is just to introduce randomness to the new owner being set
        bytes memory callData_ = abi.encodeWithSignature(_targetChangeFunc(_funcSeed), (_pk1 + _pk2) % 2 == 0 ? vm.addr(_pk1) : vm.addr(_pk2));
        sign = _twoOfThreeNonAuthSign(_pk1, _pk2, keycrypt.nonce(), callData_);
        _addUserOp(keycrypt.nonce(), callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        ++ghost_Nonce;
    }

    /// @dev functions exposed: initialize(), upgradeTo(), upgradeToAndCall()
    /// simulating non-auth 160-sized signs trying to make the calls above
    function twoOfThreeNonAuthUpgrade(uint256 _pk1, uint256 _pk2, uint256 _funcSeed) public countCall("twoOfThreeNonAuthUpgrade") {
        bytes memory callData_;
        ETH_Keycrypt maliciousKeycrypt = new ETH_Keycrypt(entryPoint);
        uint256 seed = _funcSeed % 3;
        if(seed == 0) {
            callData_ = abi.encodeWithSignature("initialize(address,address,address)", vm.addr(_pk1), vm.addr(_pk2), vm.addr(_pk1));
        } else if(seed == 1) {
            callData_ = abi.encodeWithSignature("upgradeTo(address)", address(maliciousKeycrypt));
        } else {
            callData_ = abi.encodeWithSignature("upgradeToAndCall(address,bytes)", address(maliciousKeycrypt), abi.encodeWithSignature("initialize(address,address,address)", vm.addr(_pk1), vm.addr(_pk2), vm.addr(_pk1)));
        }
        sign = _twoOfThreeNonAuthSign(_pk1, _pk2, keycrypt.nonce(), callData_);
        _addUserOp(keycrypt.nonce(), callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        ++ghost_Nonce;
    }

    /// TODO: expose executeBatch(), add/withdrawDeposit(), addTo/removeFromWhitelist(). These were postponed due to lack of relevancy
    /// TODO: check why callSummary() is not printing logs

    function _targetTokenFunc(uint256 _funcSeed, uint256 _pk) internal pure returns (bytes memory) {
        string[] memory funcSig = new string[](8);
        funcSig[0] = "transfer(address,uint256)";
        funcSig[1] = "safeTransfer(address,uint256)";
        funcSig[2] = "approve(address,uint256)";
        funcSig[3] = "safeApprove(address,uint256)";
        funcSig[4] = "increaseAllowance(address,uint256)";
        funcSig[5] = "safeIncreaseAllowance(address,uint256)";
        funcSig[6] = "decreaseAllowance(address,uint256)";
        funcSig[7] = "safeDecreaseAllowance(address,uint256)";

        return abi.encodeWithSignature(funcSig[_funcSeed % 8], vm.addr(_pk), 1e15);
    }

    function _targetChangeFunc(uint256 _funcSeed) internal pure returns (string memory) {
        string[] memory funcSig = new string[](3);
        funcSig[0] = "changeOwner(address)";
        funcSig[1] = "changeGuardianOne(address)";
        funcSig[2] = "changeGuardianTwo(address)";

        return funcSig[_funcSeed % 3];
    }

    function _targetUpgradeFunc(uint256 _funcSeed) internal pure returns (string memory) {
        string[] memory funcSig = new string[](3);
        funcSig[0] = "initialize(address,address,address)";
        funcSig[1] = "upgradeTo(address)";
        funcSig[2] = "upgradeToAndCall(address,bytes)";

        return funcSig[_funcSeed % 3];
    }

    function _oneOfOneOwnerSign(uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
        _sign = abi.encodePacked(r, s, v);
    }

    function _oneOfOneNonOwnerSign(uint256 _pk, uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        // owner's private key is 19
        vm.assume(_pk != 19);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk, userOpHash);
        _sign = abi.encodePacked(r, s, v);
    }

    function _twoOfThreeAuthSign(uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(19, userOpHash);
        bytes memory sign1 = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(20, userOpHash);
        bytes memory sign2 = abi.encodePacked(r, s, v);
        _sign = abi.encodePacked(sign1, sign2);
    }

    function _twoOfThreeNonAuthSign(uint256 _pk1, uint256 _pk2, uint256 _nonce, bytes memory _callData) internal view returns (bytes memory _sign){
        bytes32 userOpHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", _createUserOpHash(_nonce, _callData)));

        // owner's private key is 19
        // we can be more pecky by allowing one of _pk1 or _pk2 to be 19, and assume the other is none of guardians' private key, if time allows
        vm.assume(_pk1 != 19 && _pk2 != 19);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(_pk1, userOpHash);
        bytes memory sign1 = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(_pk2, userOpHash);
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

    receive() external payable {}
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