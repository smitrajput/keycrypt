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
    // constant's storage slot will be ignored iirc
    bytes4 constant EIP1271_SUCCESS_RETURN_VALUE = 0x1626ba7e;

    //filler member, to push the nonce and owner to the same slot
    // the "Initializeble" class takes 2 bytes in the first slot
    bytes28 private _filler;

    //explicit sizes of nonce, to fit a single storage cell with "owner"
    uint96 private _nonce;
    address public owner;
    address public guardian1;
    address public guardian2;
    mapping(address => bool) public isWhitelisted;
    IEntryPoint private immutable _entryPoint;

    event ETH_KeycryptInitialized(IEntryPoint indexed entryPoint, address indexed owner, address guardian1, address guardian2);
    event LogSignatures(bytes indexed signature1, bytes indexed signature2);

    modifier onlyOwner() {
        _onlyOwner();
        _;
    }

    constructor(IEntryPoint anEntryPoint) {
        _entryPoint = anEntryPoint;
        _disableInitializers();
    }

    /**
     * @dev The _entryPoint member is immutable, to reduce gas consumption.  To upgrade EntryPoint,
     * a new implementation of ETH_Keycrypt must be deployed with the new EntryPoint address, then upgrading
      * the implementation by calling `upgradeTo()`
     */
    function initialize(address _owner, address _guardian1, address _guardian2) public virtual initializer {
        owner = _owner;
        guardian1 = _guardian1;
        guardian2 = _guardian2;
        emit ETH_KeycryptInitialized(_entryPoint, owner, guardian1, guardian2);
    }

    // 2/3 multisig
    function changeOwner(address _newOwner) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        owner = _newOwner;
    }

    // 2/3 multisig
    // NOTE: don't whitelist THIS contract, or it will be able to call itself
    function addToWhitelist(address[] calldata _addresses) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = true;
        }
    }

    // 2/3 multisig
    function removeFromWhitelist(address[] calldata _addresses) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = false;
        }
    }

    /** 1/1 multisig
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /** 2/3 multisig
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /** 1/1 multisig for whitelisted txns and 2/3 for non-whitelisted ones
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /** 1/1 multisig for whitelisted txns and 2/3 for non-whitelisted ones
     * execute a sequence of transactions
     */
    function executeBatch(address[] calldata dest, bytes[] calldata func) external {
        _requireFromEntryPointOrOwner();
        require(dest.length == func.length, "wrong array lengths");
        for (uint256 i = 0; i < dest.length; i++) {
            _call(dest[i], 0, func[i]);
        }
    }

    /// implement template method of ETH_BaseAccount
    function _validateAndUpdateNonce(UserOperation calldata userOp) internal override {
        require(_nonce++ == userOp.nonce, "account: invalid nonce");
    }

    /// implement template method of ETH_BaseAccount
    function _validateSignature(
        UserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        // if (owner != hash.recover(userOp.signature))
        //     return SIG_VALIDATION_FAILED;
        if(isValidSignature(hash, userOp.signature) == EIP1271_SUCCESS_RETURN_VALUE) {
            _validatePermissions(userOp, hash);
            return 0;
        } else {
            return SIG_VALIDATION_FAILED;
        }
    }

    function _validatePermissions(UserOperation calldata userOp, bytes32 _hash) internal returns (bool) {
        // 1/1 multisig
        /** Allowed interations:
         *  1. addDeposit()
         *  2. execute() for whitelisted 'dest' (hence also NOT this contract)
         *      a. for 'dest' = token contracts, and 'func' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
         *         func.to must be whitelisted
         *  3. executeBatch() for whitelisted 'dest' (hence also NOT this contract)
         *      b. for ALL 'dest' = token contracts, and CORRESPONDING 'func' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
         *         ALL CORRESPONDING func.to must be whitelisted
         */
        if(userOp.signature.length == 65) {
            address recoveredAddr = _hash.recover(userOp.signature);
            // to disallow the owner from calling this contract (esp. changeOwner()) WITHOUT guardians
            // UserOperation memory userOp = abi.decode(abi.encodePacked(_hash), (UserOperation));
            bytes4 funcSig = bytes4(userOp.callData[:4]);
            console.log('funcSig, addDeposit');
            console.logBytes4(funcSig);
            console.logBytes4(bytes4(keccak256("addDeposit()")));
            if(funcSig == bytes4(keccak256("addDeposit()"))) {
                return true;
            }
            if(funcSig == bytes4(keccak256("execute(address,uint256,bytes)"))) {
                address dest;
                uint256 value;
                bytes memory func;
                (dest, value, func) = abi.decode(userOp.callData[4:], (address, uint256, bytes));
                if(isWhitelisted[dest]) {
                    return true;
                }
            }
            // if(funcSig == bytes4(keccak256("executeBatch(address[],bytes[])"))) {
            //     address[] memory dest;
            //     bytes[] memory func;
            //     (dest, func) = abi.decode(userOp.callData[4:], (address[], bytes[]));
            //     bool allWhitelisted = true;
            //     for(uint256 i = 0; i < dest.length; i++) {
            //         if(!isWhitelisted[dest[i]]) {
            //             allWhitelisted = false;
            //             break;
            //         }
            //     }
            //     if(allWhitelisted) {
            //         return true;
            //     }
            // }
            // return false;
       
            // console.log('userOp.sender');
            // console.log(userOp.sender);
            // console.log('userOp.callData');
            // console.logBytes(userOp.callData);
            // if(userOp.to == uint160(address(this)) || !isWhitelisted[address(uint160(txn.to))]) {
            //     magic = bytes4(0);
            // }
            // if(magic != bytes4(0)) {
            //     // extract the first 4 bytes from txn.data and check if its decoded version is 'transfer()', 'safeTransfer()', 'approve()' or 'safeApprove()' and if yes, set magic = bytes4(0)
            //     // extract address from the next 32 bytes of txn.data and check if it is whitelited or not. If not, set magic = bytes4(0)
            //     bytes4 functionSelector;
            //     address to;
            //     assembly {
            //         functionSelector := mload(add(txn.data, 0x20))
            //         to := mload(add(txn.data, 0x40))
            //     }
            //     if((functionSelector == bytes4(keccak256("transfer(address,uint256)")) || 
            //         functionSelector == bytes4(keccak256("safeTransfer(address,uint256)")) || 
            //         functionSelector == bytes4(keccak256("approve(address,uint256)")) || 
            //         functionSelector == bytes4(keccak256("safeApprove(address,uint256)"))
            //         ) && (!isWhitelisted[to])
            //     ) {
            //         magic = bytes4(0);
            //     }
            // }
            }
        // 2/3 multisig
        /** Allowed interations:
         *  1. addDepositTo()
         *  2. execute() for ALL 'dest' (even this contract)
         *  3. executeBatch() for ALL 'dest' (even this contract)
         *  4. changeOwner()
         *  5. addToWhitelist()
         *  6. removeFromWhitelist()
         *  7. withdrawDepositTo()
         */
        else if(userOp.signature.length == 130) {

            (bytes memory signature1, bytes memory signature2) = _extractECDSASignature(userOp.signature);
            address recoveredAddr1 = _hash.recover(signature1);
            address recoveredAddr2 = _hash.recover(signature2);

        }
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
        }
    }

    function isValidSignature(
        bytes32 _hash,
        bytes memory _signature
    ) public view override returns (bytes4 magic) {
        magic = EIP1271_SUCCESS_RETURN_VALUE;

        // verify if fee estimation on eth is same as on zkSync
        // if (_signature.length != 130) {
        //     // Signature is invalid, but we need to proceed with the signature verification as usual
        //     // in order for the fee estimation to work correctly
        //     _signature = new bytes(130);
            
        //     // Making sure that the signatures look like a valid ECDSA signature and are not rejected rightaway
        //     // while skipping the main verification process.
        //     _signature[64] = bytes1(uint8(27));
        //     _signature[129] = bytes1(uint8(27));
        // }

        if(_signature.length == 65) {
            if(!_checkValidECDSASignatureFormat(_signature)) {
                magic = bytes4(0);
            }
            address recoveredAddr = _hash.recover(_signature);
            // Note, that we should abstain from using the require here in order to allow for fee estimation to work
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

            // Note, that we should abstain from using the require here in order to allow for fee estimation to work
            // recoveredAddr1 and recoveredAddr2 both need to be either owner or guardian1 or guardian2,
            // to ensure 2/3 multisig
            if(recoveredAddr1 != owner && recoveredAddr1 != guardian1 && recoveredAddr1 != guardian2) {
                magic = bytes4(0);
            } else if(recoveredAddr2 != owner && recoveredAddr2 != guardian1 && recoveredAddr2 != guardian2) {
                magic = bytes4(0);
            } else if(recoveredAddr1 == recoveredAddr2) {
                magic = bytes4(0);
            } 
        } else {
            magic = bytes4(0);
        }
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

    // Require the function call went through EntryPoint or owner
    function _requireFromEntryPointOrOwner() internal view {
        require(msg.sender == address(entryPoint()) || msg.sender == owner, "account: not Owner or EntryPoint");
    }

    function _onlyOwner() internal view {
        //directly from EOA owner, or through the account itself (which gets redirected through execute())
        require(msg.sender == owner || msg.sender == address(this), "only owner");
    }

    function _authorizeUpgrade(address newImplementation) internal view override {
        (newImplementation);
        _onlyOwner();
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
