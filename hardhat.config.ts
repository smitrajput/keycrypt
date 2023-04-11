import '@matterlabs/hardhat-zksync-deploy';
import '@matterlabs/hardhat-zksync-solc';
import '@matterlabs/hardhat-zksync-verify';
import * as dotenv from 'dotenv';
dotenv.config();

// dynamically changes endpoints for local tests
const zkSyncTestnet =
  process.env.NODE_ENV == "test"
    ? {
        url: "http://localhost:3050",
        ethNetwork: "http://localhost:8545",
        zksync: true,
      }
    : {
				url: 'https://zksync2-testnet.zksync.dev',
				ethNetwork:
					'https://eth-goerli.g.alchemy.com/v2/o0zPBQM7rdfOMk8or8Dmlq60oHZqtnqU', //'goerli', // Can also be the RPC URL of the network (e.g. `https://goerli.infura.io/v3/<API_KEY>`)
				zksync: true,
				verifyURL:
					'https://zksync2-testnet-explorer.zksync.dev/contract_verification',
      };

module.exports = {
	zksolc: {
		version: '1.3.8',
		compilerSource: 'binary',
		settings: {
			isSystem: true,
		},
	},

	defaultNetwork: 'zkSyncTestnet',

	networks: {
		hardhat: {
      zksync: true,
    },
    // load test network details
		zkSyncTestnet,
	},
	
	solidity: {
		compilers: [
			{
				version: '0.8.17',
			},
			// {
			// 	version: '0.8.18',
			// },
			{
				version: '0.8.19',
			}
		]
	},
};
