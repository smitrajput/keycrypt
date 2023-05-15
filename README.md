# keycrypt
<img width="1189" alt="Screenshot 2023-05-11 at 10 17 45 PM" src="https://github.com/smitrajput/keycrypt/assets/22425782/7e9034c6-904d-43cd-bb45-87ba69e0a57a">

A quasi-multisig, smart contract wallet on Ethereum, <br/> 
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
    - ERC1271 (contract-signature validation)
    - EIP712 (standard signed data format)
    - ERC1967 (wallet-proxy-implementation)
3. Wallet implements UUPS upgradable pattern (the fixed one 😄). Proxies are deployed cheaply using [Solady's ERC1967Factory](https://github.com/Vectorized/solady/blob/main/src/utils/ERC1967Factory.sol).
4. [Invariant test suite](https://github.com/smitrajput/keycrypt/blob/main/test/foundry/invariants/Keycrypt.invariants.t.sol), inspired from [horsefacts' article](https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw). <br/>

## Signature Formats Accepted
1. Ensure the data being signed in the signatures, conforms to the EIP712 standard (see [here](https://eips.ethereum.org/EIPS/eip-712)). 
2. For verifying the signatures originating from this wallet, call `isValidSignature(bytes32 _hash, bytes memory _signature)` on the wallet contract with the appropriate `_hash` i.e. the hash of the data, and the `signature` itself.
3. Signature sizes: 
    - 65 bytes (1/1 from now): singly signed (owner)
    - 130 bytes (2/3 from now): doubly signed (owner + one of the guardians)
Rest of the signatures are considered garbage.

## Whitelisting Wall
The following addresses need to be whitelisted with a combined signature of owner + one of the guardians:
1. every address that the wallet wishes to interact with directly
2. every address the wallet wishes to send tokens/ETH to.
This is to disallow the owner from interacting with addresses (all by him/herself) that might drain its funds. After whitelisting, the owner can interact with the whitelisted addresses, with 1/1 signatures. Otherwise, the owner needs 2/3 signatures to interact with any address.

## Value Prop
Wallet consists of 3 primary entities: owner and 2 guardians. It is assumed that the owner's private keys are compromised, hence:
1. owner is not allowed to change the current owner or any of the guardians, all by him/herself. It needs one more signature from any of the guardians to do so. So in case the owner's private keys are actually compromised, the real owner can create a signature with one of the guardians and replace the owner's address with a new one, while the malicious actor won't be able to do so as the guardians won't sign off on the transaction.
2. owner can also not send any tokens or ETH to any address that hasn't been whitelisted previously by a combined signature of owner + guardian, all by him/herself. This is to prevent the malicious actor from sending funds to his/her own address after compromising the owner.