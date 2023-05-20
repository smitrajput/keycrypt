// SPDX-License-Identifier: MIT
/* Assumptions:
 * 1. All proxies are created from Solady's ERC1967ProxyFactory (which is out of scope for this test suite)
 * 2. All wallet proxies are ERC1967Proxy and implementations are UUPS compatible
 * 3. Anybody can deploy a wallet proxy of their own and use it
 * 
 * Constraints/Properties:
 * 1. All funcitons are intended to be called via ERC1967Proxy (delegatecall)
 * 2. Except for addDeposit(), all functions need to be called from EntryPoint, to enable signature validation
 * 3. _nonce cannot be reused
 * 4. Acceptable signature lengths are 65 and 130 bytes
 * 5. For signs sized 65, signer needs to be owner
 * 6. For signs sized 130, one signer needs to be owner and the other needs to be guardian1 or guardian2
 * 7. For 65-sized signs, allowed interations are:
 *    1. addDeposit()
 *    2. execute(address dest, uint256 value, bytes calldata data) for whitelisted 'dest'
 *        a. if 'data' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
 *           then data.to must be whitelisted
 *    3. executeBatch() for whitelisted 'dest'
 *        a. if 'data' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
 *           then CORRESPONDING data.to must be whitelisted
 * 8. For 130-sized signs, allowed interations are (basically everything):
 *    1. addDeposit()
 *    2. execute() for ALL 'dest' (even this contract)
 *    3. executeBatch() for ALL 'dest' (even this contract)
 *    4. changeOwner()
 *    5. addToWhitelist()
 *    6. removeFromWhitelist()
 *    7. withdrawDepositTo()
 *    8. changeGuardianOne()
 *    9. changeGuardianTwo()
 * 
 * Invariants:
 * 1. Signs that are not owner-signed or (owner + guardian1/2)-signed, cannot alter system state
 * 2. Sum of all deposits via addDeposit() minus all withdrawals via withdrawDepositTo(), equals entryPoint().balanceOf(keycrypt)
 * 3. // (not really an invariant) isValidSignature(_hash, signature) returns EIP1271_SUCCESS_RETURN_VALUE for ALL 65-sized signs signed by owner
 * 4. // (not really an invariant) isValidSignature(_hash, signature) returns EIP1271_SUCCESS_RETURN_VALUE for ALL 130-sized signs signed by owner and guardian1/2
 * 5. For ALL 65-sized owner-signed signs, if userOp.callData[:4] is, addDeposit(), execute() with 5.2.a above, executeBatch() with 5.3.a above, validateUserOp() returns 0
 * 6. For ALL 130-sized (owner + guardian1/2)-signed signs, if userOp.callData[:4] is, addDeposit(), execute(), executeBatch(), changeOwner(), addToWhitelist(), removeFromWhitelist(), withdrawDepositTo(),
 *    changeGuardianOne(), changeGuardianTwo(), validateUserOp() returns 0
 * 7. For the wallet owning 1m ETH and 1B USDC, if (5) and (6) are false (at any of the 3 layers of permissions), then wallet balance stays the same.
 * 8. Number of successful txns = _nonce
 * 9. getImplementation() = address(keycryptImpl)
 * 10. owner = 19, guardian1 = 20, guardian2 = 21
*/

// Holy Grail reference: https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw

pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@solady/src/utils/ERC1967Factory.sol";
import "../../../contracts/ETH_Keycrypt.sol";
import "./handlers/Handler.sol";

interface IUSDC {
    function configureMinter(address minter, uint256 minterAllowedAmount) external;
    function mint(address _to, uint256 _amount) external;
}

contract KeycryptInvariants is Test {
    using UserOperationLib for UserOperation;

    address constant public DAI = 0x6B175474E89094C44Da98b954EedeAC495271d0F;
    address constant public USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    address constant public USDT = 0xdAC17F958D2ee523a2206206994597C13D831ec7;

    uint256 mainnetFork;
    ERC1967Factory public soladyFactory;
    ETH_Keycrypt public keycrypt;
    ETH_Keycrypt public keycryptImpl;
    Handler public handler;
    address public owner;
    address public guardian1;
    address public guardian2;
    IEntryPoint public entryPoint = IEntryPoint(0x0576a174D229E3cFA37253523E645A78A0C91B57);
    address[] addresses;
    bytes[] funcSigs;
    UserOperation[] userOp;
    bytes sign;

    function setUp() public {
        mainnetFork = vm.createFork('https://eth-mainnet.g.alchemy.com/v2/BKt4FdcCBCJR7b5-KAdqNfoovPA7rFcx');
        vm.selectFork(mainnetFork);
        owner = vm.addr(19);
        guardian1 = vm.addr(20);
        guardian2 = vm.addr(21);
        soladyFactory = ERC1967Factory(0x0000000000006396FF2a80c067f99B3d2Ab4Df24);
        bytes memory data = abi.encodeWithSelector(ETH_Keycrypt.initialize.selector, owner, guardian1, guardian2);
        keycryptImpl = new ETH_Keycrypt(entryPoint);
        address keycryptAddr = soladyFactory.deployDeterministicAndCall(address(keycryptImpl), owner, 0, data);
        keycrypt = ETH_Keycrypt(payable(keycryptAddr));
        handler = new Handler(keycrypt);

        // minting 1m ETH and 1B USDC to create a system state
        vm.deal(address(keycrypt), 1_000_000 ether);
        vm.startPrank(0xE982615d461DD5cD06575BbeA87624fda4e3de17);
        IUSDC(USDC).configureMinter(0xE982615d461DD5cD06575BbeA87624fda4e3de17, 1_000_000_000 * 1e6);
        IUSDC(USDC).mint(address(keycrypt), 1_000_000_000 * 1e6);
        vm.stopPrank();

        bytes4[] memory selectors = new bytes4[](4);
        selectors[0] = Handler.oneOfOneNonOwnerExecute.selector;
        selectors[1] = Handler.oneOfOneOwnerExecute.selector;
        selectors[2] = Handler.twoOfThreeNonAuthChangeOG1G2.selector;
        selectors[3] = Handler.twoOfThreeNonAuthUpgrade.selector;

        targetSelector(FuzzSelector({addr: address(handler), selectors: selectors}));
        targetContract(address(handler));
    }

    function invariant_unchangedETHBalance() public {
        assertEq(address(keycrypt).balance, 1_000_000 ether);
    }

    function invariant_unchangedUSDCBalance() public view {
        assert(IERC20(USDC).balanceOf(address(keycrypt)) == 1_000_000_000 * 1e6);
    }

    function invariant_unchangedOwnerAndGuardians() public {
        assertEq(keycrypt.owner(), owner);
        assertEq(keycrypt.guardian1(), guardian1);
        assertEq(keycrypt.guardian2(), guardian2);
    }

    function invariant_unchangedImplementation() public {
        assertEq(keycrypt.currentImplementation(), address(keycryptImpl));
    }

    function invariant_correctNonceIncrement() public {
        assertEq(handler.ghost_Nonce(), keycrypt.nonce());
    }

    /// @dev gives the number of calls made to each target selector, in the last run
    function invariant_callSummary() public view {
        handler.callSummary();
    }
}
