import {utils, Wallet, Provider, EIP712Signer, types} from 'zksync-web3';
import * as ethers from 'ethers';
import {HardhatRuntimeEnvironment} from 'hardhat/types';

// Put the address of your factory
const FACTORY_ADDRESS = '0x7Bae133d541Ac388BCdF17C72436ebbb625F94bF';

export default async function (hre: HardhatRuntimeEnvironment) {
	const provider = new Provider('https://zksync2-testnet.zksync.dev');

	const PRIVATE_KEY: string = process.env.ZKS_PRIVATE_KEY || '';
	const PRIVATE_KEY_2: string = process.env.ZKS_PRIVATE_KEY_2 || '';
	const PRIVATE_KEY_3: string = process.env.ZKS_PRIVATE_KEY_3 || '';
	const PRIVATE_KEY_4: string = process.env.ZKS_PRIVATE_KEY_4 || '';

	const wallet = new Wallet(PRIVATE_KEY).connect(provider);
	const factoryArtifact = await hre.artifacts.readArtifact('Factory');

	const aaFactory = new ethers.Contract(
		FACTORY_ADDRESS,
		factoryArtifact.abi,
		wallet
	);

	// The two owners of the multisig
	const owner1 = new Wallet(PRIVATE_KEY).connect(provider); //Wallet.createRandom();
	const owner2 = new Wallet(PRIVATE_KEY_2).connect(provider); //Wallet.createRandom();

	// For the simplicity of the tutorial, we will use zero hash as salt
	const salt = ethers.constants.HashZero;

	// const tx = await aaFactory.deployAccount(
	// 	salt,
	// 	owner1.address,
	// 	owner2.address
	// );
	// await tx.wait();

	// Getting the address of the deployed contract
	const abiCoder = new ethers.utils.AbiCoder();
	const multisigAddress = utils.create2Address(
		FACTORY_ADDRESS,
		await aaFactory.aaBytecodeHash(),
		salt,
		abiCoder.encode(['address', 'address'], [owner1.address, owner2.address])
	);
	console.log(`Multisig deployed on address ${multisigAddress}`);
	// Multisig deployed on address 0xaB3766EB2Bd4d5856C79ab3C50BCbF6FC9B92C29

	// Sending some ETH to the multisig
	// await (
	// 	await wallet.sendTransaction({
	// 		to: multisigAddress,
	// 		// You can increase the amount of ETH sent to the multisig
	// 		value: ethers.utils.parseEther('0.2'),
	// 	})
	// ).wait();

	let aaTx = await aaFactory.populateTransaction.deployAccount(
		salt,
		new Wallet(PRIVATE_KEY_3).connect(provider).address,
		new Wallet(PRIVATE_KEY_4).connect(provider).address
	);

	const gasLimit = await provider.estimateGas(aaTx);
	const gasPrice = await provider.getGasPrice();

	aaTx = {
		...aaTx,
		from: multisigAddress,
		gasLimit: gasLimit,
		gasPrice: gasPrice,
		chainId: (await provider.getNetwork()).chainId,
		nonce: await provider.getTransactionCount(multisigAddress),
		type: 113,
		customData: {
			gasPerPubdata: utils.DEFAULT_GAS_PER_PUBDATA_LIMIT,
		} as types.Eip712Meta,
		value: ethers.BigNumber.from(0),
	};
	const signedTxHash = EIP712Signer.getSignedDigest(aaTx);

	const signature = ethers.utils.concat([
		// Note, that `signMessage` wouldn't work here, since we don't want
		// the signed hash to be prefixed with `\x19Ethereum Signed Message:\n`
		ethers.utils.joinSignature(owner1._signingKey().signDigest(signedTxHash)),
		ethers.utils.joinSignature(owner2._signingKey().signDigest(signedTxHash)),
	]);

	aaTx.customData = {
		...aaTx.customData,
		customSignature: signature,
	};

	console.log(
		`The multisig's nonce before the first tx is ${await provider.getTransactionCount(
			multisigAddress
		)}`
	);
	const sentTx = await provider.sendTransaction(utils.serialize(aaTx));
	await sentTx.wait();

	// Checking that the nonce for the account has increased
	console.log(
		`The multisig's nonce after the first tx is ${await provider.getTransactionCount(
			multisigAddress
		)}`
	);
}
