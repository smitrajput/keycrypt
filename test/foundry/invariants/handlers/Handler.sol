// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../../../../contracts/ETH_Keycrypt.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";

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

    constructor(ETH_Keycrypt _keycrypt) {
        keycrypt = _keycrypt;
        util = new Util();
    }

    function oneOfOneNonOwnerExecute(uint256 _pk) public {
        addresses.push(USDC);
        addresses.push(keycrypt.guardian1());
        bytes memory callData_ = abi.encodeWithSignature("addToWhitelist(address[])", addresses);
        sign = _twoOfThreeAuthSign(0, callData_);
        _addUserOp(0, callData_, sign);
        entryPoint.handleOps(userOp, payable(msg.sender));

        callData_ = abi.encodeWithSignature("execute(address,uint256,bytes)", USDC, 0, abi.encodeWithSignature("transfer(address,uint256)", address(this), 1e15));
        sign = _oneOfOneNonOwnerSign(_pk, 1, callData_);
        userOp.pop(); // remove previous op
        _addUserOp(1, callData_, sign); // note the updated nonce
        entryPoint.handleOps(userOp, payable(msg.sender));
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