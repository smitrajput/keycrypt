const fs = require('fs');
const path = require('path');

async function main() {
	const contractName = 'AAFactory';
	const artifactsPath = path.join(__dirname, './artifacts-zk/contracts');
	const artifactFilename = `${contractName}.sol/${contractName}.json`;

	const artifact = JSON.parse(
		fs.readFileSync(path.join(artifactsPath, artifactFilename), 'utf8')
	);
	console.log(`Bytecode for contract ${contractName}:`);
	console.log(artifact.deployedBytecode);
}

main()
	.then(() => process.exit(0))
	.catch((error) => {
		console.error(error);
		process.exit(1);
	});
