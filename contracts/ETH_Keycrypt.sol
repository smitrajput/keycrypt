// SPDX-License-Identifier: MIT
pragma solidity 0.8.19;

/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */
/* solhint-disable reason-string */

import "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import "@openzeppelin/contracts/proxy/utils/Initializable.sol";
import "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol";

import "./ETH_BaseAccount.sol";

/**
  *  this account has execute, eth handling methods
  *  has a single signer that can send requests through the entryPoint.
  */
contract ETH_Keycrypt is ETH_BaseAccount, UUPSUpgradeable, Initializable {
    using ECDSA for bytes32;

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

    function changeOwner(address _newOwner) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        owner = _newOwner;
    }

    function addToWhitelist(address[] calldata _addresses) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = true;
        }
    }

    function removeFromWhitelist(address[] calldata _addresses) external {
        require(msg.sender == address(entryPoint()), "!authorised");
        for (uint256 i = 0; i < _addresses.length; i++) {
            isWhitelisted[_addresses[i]] = false;
        }
    }

    /**
     * deposit more funds for this account in the entryPoint
     */
    function addDeposit() public payable {
        entryPoint().depositTo{value : msg.value}(address(this));
    }

    /**
     * withdraw value from the account's deposit
     * @param withdrawAddress target to send to
     * @param amount to withdraw
     */
    function withdrawDepositTo(address payable withdrawAddress, uint256 amount) public onlyOwner {
        entryPoint().withdrawTo(withdrawAddress, amount);
    }

    /**
     * execute a transaction (called directly from owner, or by entryPoint)
     */
    function execute(address dest, uint256 value, bytes calldata func) external {
        _requireFromEntryPointOrOwner();
        _call(dest, value, func);
    }

    /**
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
    function _validateSignature(UserOperation calldata userOp, bytes32 userOpHash)
    internal override virtual returns (uint256 validationData) {
        bytes32 hash = userOpHash.toEthSignedMessageHash();
        if (owner != hash.recover(userOp.signature))
            return SIG_VALIDATION_FAILED;
        return 0;
    }

    function _call(address target, uint256 value, bytes memory data) internal {
        (bool success, bytes memory result) = target.call{value : value}(data);
        if (!success) {
            assembly {
                revert(add(result, 32), mload(result))
            }
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

    // solhint-disable-next-line no-empty-blocks
    receive() external payable {}
}
