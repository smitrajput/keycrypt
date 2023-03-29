import '@matterlabs/hardhat-zksync-deploy';
import '@matterlabs/hardhat-zksync-solc';

module.exports = {
	zksolc: {
		version: '1.3.1',
		compilerSource: 'binary',
		settings: {
			isSystem: true,
		},
	},
	defaultNetwork: 'zkSyncTestnet',

	networks: {
		zkSyncTestnet: {
			url: 'https://zksync2-testnet.zksync.dev',
			ethNetwork:
				'https://eth-goerli.g.alchemy.com/v2/o0zPBQM7rdfOMk8or8Dmlq60oHZqtnqU', //'goerli', // Can also be the RPC URL of the network (e.g. `https://goerli.infura.io/v3/<API_KEY>`)
			zksync: true,
		},
	},
	solidity: {
		version: '0.8.17',
	},
};
