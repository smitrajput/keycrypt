const dotenv = require('dotenv');
dotenv.config();
const { ethers } = require('ethers');

const privateKey1 = process.env.ZKS_PRIVATE_KEY;
const privateKey2 = process.env.ZKS_PRIVATE_KEY_2;

const userOp = {
  sender: '0xaa49524B61e4AfC10c2202cB25040Da25401ae4E',
  nonce: 0,
  initCode: '0x',
  callData: '0x0a4a015c7000000000000000000000000a0b86991c6218b36c1d19d4a2e9eb0ce3606eb4000000000000000000000000dac17f958d2ee523a2206206994597c13d831ec70000000000000000000000006b175474e89094c44da98b954eedeac495271d0f',
  callGasLimit: 1000000,
  verificationGasLimit: 1000000,
  preVerificationGas: 1000000,
  maxFeePerGas: 43683902336,
  maxPriorityFeePerGas: 60865874,
  paymasterAndData: '0x',
  // signature: '0x',
};

function createSignature(userOp, privateKey) {
  const wallet = new ethers.Wallet(privateKey);
  const dataToSign = ethers.utils.solidityKeccak256(
    [
      'address',
      'uint256',
      'bytes',
      'bytes',
      'uint256',
      'uint256',
      'uint256',
      'uint256',
      'uint256',
      'bytes',
    ],
    [
      userOp.sender,
      userOp.nonce,
      userOp.initCode,
      userOp.callData,
      userOp.callGasLimit,
      userOp.verificationGasLimit,
      userOp.preVerificationGas,
      userOp.maxFeePerGas,
      userOp.maxPriorityFeePerGas,
      userOp.paymasterAndData,
    ]
  );

  return wallet.signMessage(ethers.utils.arrayify(dataToSign));
}

(async () => {
  const signature1 = await createSignature(userOp, privateKey1);
  const signature2 = await createSignature(userOp, privateKey2);

  console.log('Signature1:', signature1);
  console.log('Signature2:', signature2);

  const concatenatedSignatures = signature1 + signature2.slice(2); // Remove the '0x' from signature2 before concatenating
  console.log('Concatenated Signatures:', concatenatedSignatures);
})();
