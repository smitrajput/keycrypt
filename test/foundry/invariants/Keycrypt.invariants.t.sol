// SPDX-License-Identifier: UNLICENSED
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
 * 3. isValidSignature(_hash, signature) returns EIP1271_SUCCESS_RETURN_VALUE for ALL 65-sized signs signed by owner
 * 4. isValidSignature(_hash, signature) returns EIP1271_SUCCESS_RETURN_VALUE for ALL 130-sized signs signed by owner and guardian1/2
 * 5. For ALL 65-sized owner-signed signs, if userOp.callData[:4] is, addDeposit(), execute() with 5.2.a above, executeBatch() with 5.3.a above, validateUserOp() returns 0
 * 6. For ALL 130-sized (owner + guardian1/2)-signed signs, if userOp.callData[:4] is, addDeposit(), execute(), executeBatch(), changeOwner(), addToWhitelist(), removeFromWhitelist(), withdrawDepositTo(),
 *    changeGuardianOne(), changeGuardianTwo(), validateUserOp() returns 0
 * 7. For the wallet owning 1m ETH and 1B USDC, if (5) and (6) are false (at any of the 3 layers of permissions), then wallet balance stays the same.
*/