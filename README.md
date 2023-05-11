# keycrypt
#### A hackproof crypto smart wallet on Ethereum, built assuming compromised private keys from the very start. The last pill whales would need for a peaceful sleep.<br/>

## Feature Set
1. Based on ERC4337 (account-abstraction), hence allows easy gas fee sponsoring for users.<br/>
2. Social recovery: owner private keys once compromised, can be replaced afresh, with the help of 2 other 'guardian' keys. <br/>
3. 3 layers of permissions for owner-signed risky transactions (ones that might empty the wallet). <br/>
4. Allows arbitrary interaction with any contract, for doubly-signed (owner + guardian) transactions. <br/>

## Tech
1. Smart contracts in Solidity, tested with foundry.
2. EIPs/ERCs involved: 
    - ERC4337 (account-abstraction)
    - ERC1271 (signing standard)
    - EIP712 (typed data signing)
    - ERC1967 (wallet-proxy-implementation)
3. Wallet proxies deployed using [Solady's hyper-optimised ERC1967Factory](https://github.com/Vectorized/solady/blob/main/src/utils/ERC1967Factory.sol).
4. [Invariant test suite](https://github.com/smitrajput/keycrypt/blob/main/test/foundry/invariants/Keycrypt.invariants.t.sol), inspired from [horsefacts' article](https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw)

