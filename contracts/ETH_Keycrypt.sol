// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts/interfaces/IERC1271.sol";

import "./ETH_BaseAccount.sol";
import "forge-std/Test.sol";


/**
  *  this account has execute, eth handling methods
  *  has a single signer that can send requests through the entryPoint.
  */
contract ETH_Keycrypt is IERC1271, ETH_BaseAccount, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       CUSTOM ERRORS                        */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    error InvalidNewOwner(address currentOwner, address newOwner);
    error InvalidNewGuardianOne(address currentGuardian1, address newGuardian1);
    error InvalidNewGuardianTwo(address currentGuardian2, address newGuardian2);
    error InvalidNonce(uint256 accountNonce, uint256 userOpNonce);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                           EVENTS                           */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    event ETH_KeycryptInitialized(IEntryPoint indexed entryPoint, address indexed owner, address guardian1, address guardian2);
    event ChangeOwner(address indexed prevOwner, address indexed newOwner);
    event ChangeGuardianOne(address indexed prevGuardian1, address indexed newGuardian1);
    event ChangeGuardianTwo(address indexed prevGuardian2, address indexed newGuardian2);
    event AddToWhitelist(address[] indexed addresses);
    event RemoveFromWhitelist(address[] indexed addresses);
    event Execute(address indexed target, uint256 indexed value, bytes indexed data);

    /*´:°•.°+.*•´.*:˚.°*.˚•´.°:°•.°•.*•´.*:˚.°*.˚•´.°:°•.°+.*•´.*:*/
    /*                       STORAGE                              */
    /*.•°:°.´+˚.*°.˚:*.´•*.+°.•°:´*.´•*.•°.•°:°.´:•˚°.*°.˚:*.´+°.•*/

    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;

    // filler member, to push the nonce and owner to the same slot
    // the "Initializeble" class takes 2 bytes in the first slot
    bytes28 private _filler;

    // explicit sizes of nonce, to fit a single storage cell with "owner"
    uint96 private _nonce;
    address public owner;
    address public guardian1;
    address public guardian2;
    mapping(address => bool) public isWhitelisted;
    IEntryPoint private immutable _entryPoint;


    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of ETH_Keycrypt must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address _owner, address _guardian1, address _guardian2) public onlyProxy virtual initializer {
        owner = _owner;
        guardian1 = _guardian1;
        guardian2 = _guardian2;
        emit ETH_KeycryptInitialized(_entryPoint, owner, guardian1, guardian2);
    }

    // 2/3 multisig
    function changeOwner(address _newOwner) external onlyProxy onlyEntryPoint {
        // require that new owner is not a guardian, current owner, address(0)
        if(_newOwner == address(0) || _newOwner == guardian1 || _newOwner == guardian2 || _newOwner == owner) {
            revert InvalidNewOwner(owner, _newOwner);
        }
        emit ChangeOwner(owner, _newOwner);
        owner = _newOwner;
    }

    // 2/3 multisig
    function changeGuardianOne(address _newGuardian1) external onlyProxy onlyEntryPoint {
        // require that new guardian1 is not a guardian, current owner, address(0)
        if(_newGuardian1 == address(0) || _newGuardian1 == guardian1 || _newGuardian1 == guardian2 || _newGuardian1 == owner) {
            revert InvalidNewGuardianOne(guardian1, _newGuardian1);
        }
        emit ChangeGuardianOne(guardian1, _newGuardian1);
        guardian1 = _newGuardian1;
    }

    // 2/3 multisig
    function changeGuardianTwo(address _newGuardian2) external onlyProxy onlyEntryPoint {
        // require that new guardian2 is not a guardian, current owner, address(0)
        if(_newGuardian2 == address(0) || _newGuardian2 == guardian1 || _newGuardian2 == guardian2 || _newGuardian2 == owner) {
            revert InvalidNewGuardianTwo(guardian2, _newGuardian2);
        }
        emit ChangeGuardianTwo(guardian2, _newGuardian2);
        guardian2 = _newGuardian2;
    }

    // 2/3 multisig
    // NOTE: don't whitelist THIS contract, or it will be able to call itself
    function addToWhitelist(address[] calldata _addresses) external onlyProxy onlyEntryPoint {
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = true;
        }
        emit AddToWhitelist(_addresses);
    }

    // 2/3 multisig
    function removeFromWhitelist(address[] calldata _addresses) external onlyProxy onlyEntryPoint {
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = false;
        }
        emit RemoveFromWhitelist(_addresses);
    }

    /** 1/1 multisig
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit(uint256 _amount) external onlyProxy payable {
        entryPoint().depositTo{value : _amount}(address(this));
    }

    /** 2/3 multisig
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) external onlyProxy onlyEntryPoint {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /** 1/1 multisig for whitelisted txns and 2/3 for non-whitelisted ones
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata data) external onlyProxy onlyEntryPoint {
        _call(dest, value, data);
    }

    /** 1/1 multisig for whitelisted txns and 2/3 for non-whitelisted ones
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata data) external onlyProxy onlyEntryPoint {
        require(dest.length == data.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, data[i]);
        }
    }

    /// adding access checks in upgradeTo() and upgradeToAndCall() of UUPSUpgradeable
    function _authorizeUpgrade(address _newImplementation) internal view override onlyEntryPoint {}

    /// implement template method of ETH_BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata _userOp) internal override {
        if(_nonce != _userOp.nonce) {
            revert InvalidNonce(_nonce, _userOp.nonce);
        }
        ++_nonce;
    }

    /// implement template method of ETH_BaseAccount
    function _validateSignature(
        UserOperation calldata _userOp,
        bytes32 _userOpHash
    ) internal override virtual returns (uint256 validationData) {
        bytes32 hash = _userOpHash.toEthSignedMessageHash();
        if(isValidSignature(hash, _userOp.signature) == EIP1271_SUCCESS_RETURN_VALUE &&
            _validatePermissions(_userOp)) {
            return 0;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _validatePermissions(UserOperation calldata userOp) internal view returns (bool) {
        /* 1/1 multisig
        * Allowed interations:
        *  1. addDeposit()
        *  2. execute() for whitelisted 'dest' (hence also NOT this contract unless whitelisted)
        *      a. if 'func' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
        *         then func.to must be whitelisted
        *  3. executeBatch() for whitelisted 'dest' (hence also NOT this contract unless whitelisted)
        *      a. if 'func' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
        *         then CORRESPONDING func.to must be whitelisted
         */
        if(userOp.signature.length == 65) {
            // to disallow the owner from calling this contract (esp. changeOwner()) WITHOUT guardians
            bytes4 funcSig = bytes4(userOp.callData[:4]);
            if(funcSig == bytes4(keccak256("addDeposit(uint256)"))) {
                return true;
            }
            if(funcSig == bytes4(keccak256("execute(address,uint256,bytes)"))) {
                address dest; uint256 value; bytes memory data;
                (dest, value, data) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
                // extract first 4 bytes from 'data' without using index range access
                bytes4 internalFuncSig; address to;
                assembly {
                    internalFuncSig := mload(add(data, 32))
                    to := mload(add(data, 36))
                }
                if(isWhitelisted[dest]) {
                    return _checkWhitelistedTokenInteractions(internalFuncSig, to);
                }
            }
            if(funcSig == bytes4(keccak256("executeBatch(address[],bytes[])"))) {
                address[] memory dest;
                bytes[] memory data;
                (dest, data) = abi.decode(userOp.callData[4:], (address[], bytes[]));
                bytes4 internalFuncSig; address to;
                bytes memory dataMem;
                for(uint256 i = 0; i < dest.length; i++) {
                    if(!isWhitelisted[dest[i]]) {
                        return false;
                    }
                    dataMem = data[i];
                    assembly {
                        internalFuncSig := mload(add(dataMem, 32))
                        to := mload(add(dataMem, 36))
                    }
                    if(!_checkWhitelistedTokenInteractions(internalFuncSig, to)) return false;
                }
                return true;
            }
        }
        /* 2/3 multisig
         * Allowed interations (basically everything):
        *  1. addDeposit()
        *  2. execute() for ALL 'dest' (even this contract)
        *  3. executeBatch() for ALL 'dest' (even this contract)
        *  4. changeOwner()
        *  5. addToWhitelist()
        *  6. removeFromWhitelist()
        *  7. withdrawDepositTo()
        *  8. changeGuardianOne()
        *  9. changeGuardianTwo()
         */
        else if(userOp.signature.length == 130) {
            return true;
        }
        // for signature length != 65, 130, and garbage ones
        return false;
    }

    function _checkWhitelistedTokenInteractions(bytes4 _internalFuncSig, address _to) internal view returns (bool) {
        if(
            ((_internalFuncSig == bytes4(keccak256("transfer(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("safeTransfer(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("approve(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("safeApprove(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("increaseAllowance(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("safeIncreaseAllowance(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("decreaseAllowance(address,uint256)")) || 
            _internalFuncSig == bytes4(keccak256("safeDecreaseAllowance(address,uint256)"))
            ) && (!isWhitelisted[_to]))
        ) {
            return false;
        }
        return true;
    }

    function _call(address _target, uint256 _value, bytes memory _data) internal {
        (bool success, bytes memory result) = _target.call{value : _value}(_data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
        emit Execute(_target, _value, _data);
    }

    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public view override returns (bytes4 magic) {
        magic = EIP1271_SUCCESS_RETURN_VALUE;

        if(_signature.length == 65) {
            if(!_checkValidECDSASignatureFormat(_signature)) {
                magic = bytes4(0);
            }
            address recoveredAddr = _hash.recover(_signature);
            // NOTE: abstain from using the require here in order to allow for fee estimation to work
            if(recoveredAddr != owner) {
                magic = bytes4(0);
            }
        } else if(_signature.length == 130) {
            (bytes memory signature1, bytes memory signature2) = _extractECDSASignature(_signature);
            if(!_checkValidECDSASignatureFormat(signature1) || !_checkValidECDSASignatureFormat(signature2)) {
                magic = bytes4(0);
            }
            address recoveredAddr1 = _hash.recover(signature1);
            address recoveredAddr2 = _hash.recover(signature2);

            // NOTE: abstain from using the require here in order to allow for fee estimation to work
            // Either of the recovered addresses should be owner and the other address should be either guardian1 or guardian2
            if(recoveredAddr1 == owner) {
                if(recoveredAddr2 != guardian1 && recoveredAddr2 != guardian2) {
                    magic = bytes4(0);
                }
            } else if(recoveredAddr2 == owner) {
                if(recoveredAddr1 != guardian1 && recoveredAddr1 != guardian2) {
                    magic = bytes4(0);
                }
            } else {
                magic = bytes4(0);
            }

        } else {
            magic = bytes4(0);
        }
    }

    function currentImplementation() public view returns (address) {
        return _getImplementation();
    }

    /**
     * check current account deposit in the entryPoint
     */
    function getDeposit() public view returns (uint256) {
        return entryPoint().balanceOf(address(this));
    }

    /// @inheritdoc ETH_BaseAccount
    function nonce() public view virtual override returns (uint256) {
        return _nonce;
    }

    /// @inheritdoc ETH_BaseAccount
    function entryPoint() public view virtual override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _extractECDSASignature(
        bytes memory _fullSignature
    ) internal pure returns (bytes memory signature1, bytes memory signature2) {
        require(_fullSignature.length == 130, "Invalid length");

        signature1 = new bytes(65);
        signature2 = new bytes(65);

        // Copying the first signature. Note, that we need an offset of 0x20
        // since it is where the length of the `_fullSignature` is stored
        assembly {
            let r := mload(add(_fullSignature, 0x20))
            let s := mload(add(_fullSignature, 0x40))
            let v := and(mload(add(_fullSignature, 0x41)), 0xff)

            mstore(add(signature1, 0x20), r)
            mstore(add(signature1, 0x40), s)
            mstore8(add(signature1, 0x60), v)
        }

        // Copying the second signature.
        assembly {
            let r := mload(add(_fullSignature, 0x61))
            let s := mload(add(_fullSignature, 0x81))
            let v := and(mload(add(_fullSignature, 0x82)), 0xff)

            mstore(add(signature2, 0x20), r)
            mstore(add(signature2, 0x40), s)
            mstore8(add(signature2, 0x60), v)
        }
    }

    // This function verifies that the ECDSA signature is both in correct format and non-malleable
    function _checkValidECDSASignatureFormat(
        bytes memory _signature
    ) internal pure returns (bool) {
        if (_signature.length != 65) {
            return false;
        }

        uint8 v;
        bytes32 r;
        bytes32 s;
        // Signature loading code
        // we jump 32 (0x20) as the first slot of bytes contains the length
        // we jump 65 (0x41) per signature
        // for v we load 32 bytes ending with v (the first 31 come from s) then apply a mask
        assembly {
            r := mload(add(_signature, 0x20))
            s := mload(add(_signature, 0x40))
            v := and(mload(add(_signature, 0x41)), 0xff)
        }
        if (v != 27 && v != 28) {
            return false;
        }

        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (301): 0 < s < secp256k1n ÷ 2 + 1, and for v in (302): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        if (
            uint256(s) >
            0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0
        ) {
            return false;
        }

        return true;
    }

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}
}
