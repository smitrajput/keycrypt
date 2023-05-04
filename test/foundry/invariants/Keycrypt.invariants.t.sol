// SPDX-License-Identifier: UNLICENSED
/* Assumptions:
 * 1. All proxies are created from Solady's ERC1967ProxyFactory (which is out of scope for this test suite)
 * 2. All wallet proxies are ERC1967Proxy and implementations are UUPS compatible
 * 3. Anybody can deploy a wallet proxy of their own and use it
 * 
 * Constraints:
 * 1. All funcitons are intended to be called via ERC1967Proxy (delegatecall)
 * 2. Except for addDeposit(), all functions need to be called from EntryPoint, to enable signature validation
 * 
 * Properties:
 * 1. _nonce cannot be reused
 * 2. Acceptable signature lengths are 65 and 130 bytes
 * 3. For signs sized 65, signer needs to be owner
 * 4. For signs sized 130, one signer needs to be owner and the other needs to be guardian1 or guardian2
 * 5. For 65-sized signs, allowed interations are:
 *    1. addDeposit()
 *    2. execute(address dest, uint256 value, bytes calldata data) for whitelisted 'dest'
 *        a. if 'data' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
 *           then data.to must be whitelisted
 *    3. executeBatch() for whitelisted 'dest'
 *        a. if 'data' = transfer(), safeTransfer(), approve(), safeApprove(), increaseAllowance(), decreaseAllowance(),
 *           then CORRESPONDING data.to must be whitelisted
 * 6. For 130-sized signs, allowed interations are (basically everything):
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
*/