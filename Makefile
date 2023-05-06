check:
	git apply "bugs/$(bug).patch" && forge test

clean:
	git checkout contracts/ETH_Keycrypt.sol