import {utils, Wallet} from 'zksync-web3';
import * as ethers from 'ethers';
import {HardhatRuntimeEnvironment} from 'hardhat/types';
import {Deployer} from '@matterlabs/hardhat-zksync-deploy';

export default async function (hre: HardhatRuntimeEnvironment) {
	const PRIVATE_KEY: string = process.env.ZKS_PRIVATE_KEY || '';
	const wallet = new Wallet(PRIVATE_KEY);
	const deployer = new Deployer(hre, wallet);
	const factoryArtifact = await deployer.loadArtifact('Factory');
	const aaArtifact = await deployer.loadArtifact('Keycrypt');

	// Getting the bytecodeHash of the account
	const bytecodeHash = utils.hashBytecode(aaArtifact.bytecode);
	console.log('bytecodeHash: ', bytecodeHash);

	// Estimate contract deployment fee
	const deploymentFee = await deployer.estimateDeployFee(factoryArtifact, [
		bytecodeHash,
	]);
	console.log('Deployment fee: ', deploymentFee.toString());

	const factory = await deployer.deploy(
		factoryArtifact,
		[bytecodeHash],
		undefined,
		[
			// Since the factory requires the code of the multisig to be available,
			// we should pass it here as well.
			aaArtifact.bytecode,
		]
	);

	console.log(`AA factory address: ${factory.address}`);
	// AA factory address: 0x7Bae133d541Ac388BCdF17C72436ebbb625F94bF
	console.log(
		'constructor args:' + factory.interface.encodeDeploy([bytecodeHash])
	);
	// AA factory address: 0x771F394e184525dF90376C34922399Db2c4b504E, 0x7724153EF95B1dA3F2c770dC6BfE56626fe7d339, 0xA015E20967741f10D6aAfE71C85cf638430d20aB,
	// 0xEc6658b9b1bB97D19216311CCB58E1F69396f1D3
	// constructor args:0x010004092e0545c6ebc485fb7a00d7f753347b34a91edb1c79ccccc12075ba3c
}
