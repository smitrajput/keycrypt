# keycrypt
<img width="1189" alt="Screenshot 2023-05-11 at 10 17 45 PM" src="https://github.com/smitrajput/keycrypt/assets/22425782/7e9034c6-904d-43cd-bb45-87ba69e0a57a"> <br/>

The endgame for secure smart contract wallets on Ethereum, <br/> 
* with safe tokens and ownership, __post-compromise__
* account-abstracted wallets
* social recovery
* 4 layers of permissions for your sweet millies and billies
* fuzzed, invariant tested  <br/>

The last pill that 🐋, 🐳 need for a peaceful sleep.<br/>

## Table of Contents
1. [Feature Set](#feature-set)
2. [Tech](#tech)
3. [Layers of Swiss Cheese 🧀 / Security](#layers-of-swiss-cheese---security)
4. [Quad-cheese Burger in Action](#quad-cheese-burger-in-action)
5. [Signature Formats Accepted](#signature-formats-accepted)
6. [Usage](#usage)
7. [References](#references)


## Feature Set
1. Based on ERC4337 (account-abstraction), decoupling signature creation from submission, allowing owners to sign off-chain and anyone to sponsor their gas fees and submit the signatures on their behalf.<br/>
2. Social recovery: owner private keys once compromised, can be replaced afresh, with the help of 2 other 'guardian' keys. <br/>
3. 4 layers of permissions for owner-signed risky transactions (ones that might empty the wallet). <br/>
4. Allows arbitrary interaction with any contract, for doubly-signed (owner + guardian) transactions. <br/>

## Tech
1. Smart contracts in Solidity, tested with foundry. Some hardhat config exists to create a protocol-native account-abstraction variant for zkSync in the future.
2. [Fuzz tests](https://github.com/smitrajput/keycrypt/blob/main/test/foundry/Keycrypt.t.sol#L54) wherever possible, and an [invariant test suite](https://github.com/smitrajput/keycrypt/blob/main/test/foundry/invariants/Keycrypt.invariants.t.sol).
3. EIPs/ERCs involved: 
    - ERC4337 (account-abstraction)
    - ERC1271 (contract-signature validation)
    - EIP712 (standard signed data format)
    - ERC1967 (wallet-proxy-implementation)
4. Wallet implements UUPS upgradable pattern (the fixed one 😄). Proxies are deployed cheaply using [Solady's ERC1967Factory](https://github.com/Vectorized/solady/blob/main/src/utils/ERC1967Factory.sol). <br/>


## Layers of Swiss Cheese 🧀 / Security
1. **Layer 1**: only signatures of a standard structure are accepted, which have been signed by either the owner (1/1 signature), or owner + one of the guardians (2/3 signature). [More Details](https://github.com/smitrajput/keycrypt#signature-formats-accepted).
2. **Layer 2**: 2/3 signatures can call any function on any contract without prior whitelisting, but 1/1 signatures can only call certain functions on certain contracts. On the wallet contract, they can only call `addDeposit()`, `execute()` and `executeBatch()` (with further restrictions on the latter two as seen below).
3. **Layer 3**: 1/1 signatures can only interact with addresses that have been whitelisted previously with a 2/3 signature calling `addToWhitelist()` on the wallet contract.
4. **Layer 4**: for 1/1 signatures interacting with whitelisted addresses, if the whitelisted address happens to be a token, then the `to` address i.e. the address receiving the tokens or being approved for transferring the tokens, must be whitelisted previously with a 2/3 signature calling `addToWhitelist()` on the wallet contract. <br/>

## Quad-cheese 🍔 in Action
Chad owns $1.1B USDC in his keycrypt wallet and is currently vacationing in Japan, spending his bull run gains, and has set Aron and Bella as his guardians. But due to his [recent mistaken upgrade in Ledger](https://twitter.com/Mudit__Gupta/status/1658368265687556097?s=20), his private keys were acquired by Kim Pong-Un, who is now trying to empty his wallet.
1. Kim with invalid signatures (of sizes other than 65, 130 bytes) or ones with the correct size but not signed by Chad or his guardians, can't interact with the wallet (Layer 1).
2. Kim can't change the owner or guardians to gain complete control of the wallet, as he can't call `changeOwner()` or `changeGuardianOne/Two()` all by himself (Layer 2).
3. Kim manages to call `transfer()` on the USDC contract via `execute()` on the wallet contract, but can't send the tokens to his address as it hasn't been whitelisted previously (Layer 4). He can't even whitelist it now, as he can't call `addToWhitelist()` all by himself (Layer 2).
4. Kim acts smart and writes a malicious contract that can pull funds out of the wallet, and calls `execute()` on the wallet contract. But it doesn't work too as the malicious contract hasn't been whitelisted previously (Layer 3), moreover he can't whitelist it now as he can't call `addToWhitelist()` all by himself (Layer 2).

Chad checks etherscan and sees some 'failed' transactions on his wallet and goes, "Ah! Not again, this is the 5th time!". Frustrated, not out of fear, but out of boredom to change the owner once again. Calls Bella, and sends a 2/3 signature to change the current owner. Kim in dismay, returns to his [pleasure squad](https://youtu.be/EL4nlb_yuYE) after realising this transaction. <br/>



## Signature Formats Accepted
1. Ensure the data being signed in the signatures, conforms to the EIP712 standard (see [here](https://eips.ethereum.org/EIPS/eip-712)). 
2. For verifying the signatures originating from this wallet, call `isValidSignature(bytes32 _hash, bytes memory _signature)` on the wallet contract with the appropriate `_hash` i.e. the hash of the data, and the `signature` itself.
3. Signature sizes: 
    - 65 bytes: singly signed (owner)
    - 130 bytes: doubly signed (owner + one of the guardians)
     
Rest of the signatures are considered garbage.

## Usage
1. Running the project locally:
    - `git clone git@github.com:smitrajput/keycrypt.git && cd keycrypt`
    - install foundry (follow [this section](https://book.getfoundry.sh/getting-started/installation#using-foundryup))
    - `npm i --force` (to circumvent zkSync deps)
    - `forge install`
    - `forge test --via-ir` <br/> should look something like this: <img width="750" alt="Screenshot 2023-05-16 at 1 12 22 PM" src="https://github.com/smitrajput/keycrypt/assets/22425782/a7833bb3-f817-44c8-ae54-2cd66e2ea1a1">
2. Users need to sign transactions off-chain, and submit them to the [alt mempool](https://eips.ethereum.org/EIPS/eip-4337#abstract) dedicated for ERC4337-specific transactions, as the wallet contract only accepts transactions initiated from the [EntryPoint contract](https://eips.ethereum.org/EIPS/eip-4337#definitions) (for security reasons).
3. For gas fees, 
    - users willing to pay for it themselves, can directy send ETH to the wallet contract
    - users willing to get it sponsored, can ask their sponsors to send ETH directly to wallet contract, or call `addDeposit()` on the wallet contract, sending the required ETH along with it (this function deposits ETH directly in the EntryPoint contract). <br/>

## References
1. [Reference implementation](https://github.com/eth-infinitism/account-abstraction/tree/main) of ERC4337.
2. [Invariant Testing WETH with Foundry](https://mirror.xyz/horsefacts.eth/Jex2YVaO65dda6zEyfM_-DXlXhOWCAoSpOx5PLocYgw).