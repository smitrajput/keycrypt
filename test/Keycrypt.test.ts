import { expect } from "chai";
import { Wallet, Provider, Contract } from "zksync-web3";
import * as hre from "hardhat";
import { Deployer } from "@matterlabs/hardhat-zksync-deploy";

const RICH_WALLET_PK = "0x3eb15da85647edd9a1159a4a13b9e7c56877c4eb33f614546d4db06a51868b1c";

async function deployKeycrypt(deployer: Deployer): Promise<Contract> {
  const artifact = await deployer.loadArtifact("Keycrypt");
  return await deployer.deploy(artifact, ["0x640E35B6AfC3F6AD37bC14792536dA06e1C8cc19", "0xb2234c988cC1C4BE0b31fEbd2bA54BE61735f315", "0x213ce1554f6F96dB5CdAEa7D750F89Ab2Ae43294"]);
}

describe("Keycrypt", function () {
  it("should whitelist a list of addresses", async function () {
    const provider = Provider.getDefaultProvider();

    const wallet = new Wallet(RICH_WALLET_PK, provider);
    const deployer = new Deployer(hre, wallet);

    //check ETH balance of RIch Wallet
    const ethBalance = await wallet.getBalance();
    console.log("ETH Balance: ", ethBalance.toString());

    // const keycrypt = await deployKeycrypt(deployer);

    // expect(await keycrypt.owner()).to.eq("0x640E35B6AfC3F6AD37bC14792536dA06e1C8cc19");
    // whitelist USDC, USDT, and WETH
    // const addToWhitelistTx = await keycrypt.addToWhitelist(["0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48", "0xdAC17F958D2ee523a2206206994597C13D831ec7", "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"]);
    // // wait until the transaction is mined
    // await addToWhitelistTx.wait();

    // expect(await keycrypt.isWhitelisted("0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48")).to.equal(true);
  });
});
