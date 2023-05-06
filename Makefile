check:
	git apply "bugs/$(bug).patch" && forge test --via-ir --match-contract KeycryptInvariants

clean:
	git checkout contracts/ETH_Keycrypt.sol