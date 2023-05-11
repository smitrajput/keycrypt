# keycrypt
<img width="1189" alt="Screenshot 2023-05-11 at 10 17 45 PM" src="https://github.com/smitrajput/keycrypt/assets/22425782/7e9034c6-904d-43cd-bb45-87ba69e0a57a">

A multisig-convertible crypto smart wallet on Ethereum, <br/> 
* with multi-layered fail-safe system
* built assuming compromised private keys from the very start 
* reducing chances of stolen funds by 99.9%, as compared to pure multisigs and EOAs <br/>

The last pill that 🐋, 🐳 need for a peaceful sleep.<br/>

## Feature Set
1. Based on ERC4337 (account-abstraction), decoupling signature creation from submission, allowing owners to sign off-chain and anyone to sponsor their gas fees and submit the signatures on their behalf.<br/>
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
3. Wallet implements UUPS upgradable pattern (the fixed one 😄). Proxies are deployed cheaply using [Solady's ERC1967Factory](https://github.com/Vectorized/solady/blob/main/src/utils/ERC1967Factory.sol).
4. [Invariant test suite](https://github.com/smitrajput/keycrypt/blob/main/test/foundry/invariants/Keycrypt.invariants.t.sol), inspired from [horsefacts' article](https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw). <br/>

