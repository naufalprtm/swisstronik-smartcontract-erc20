import { ethers, network } from 'hardhat';
import { encryptDataField } from '@swisstronik/utils';
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/src/signers';
import { HttpNetworkConfig } from 'hardhat/types';
import deployedAddress from '../utils/deployed-address';

const sendShieldedTransaction = async (
  signer: HardhatEthersSigner,
  destination: string,
  data: string,
  value: number
) => {
  const rpclink = (network.config as HttpNetworkConfig).url;

  const [encryptedData] = await encryptDataField(rpclink, data);

  return await signer.sendTransaction({
    from: signer.address,
    to: destination,
    data: encryptedData,
    value,
  });
};

async function main() {
  const contractAddress = deployedAddress;

  const [signer] = await ethers.getSigners();

  const contractFactory = await ethers.getContractFactory('Zix');
  const contract = contractFactory.attach(contractAddress);

  const functionName = 'mint';
  const mintAmount = ethers.parseUnits('1000000', 18); // Mint 1.000.000 tokens
  const functionArgs = [signer.address, mintAmount.toString()];
  const setMessageTx = await sendShieldedTransaction(
    //@ts-ignore
    signer,
    contractAddress,
    contract.interface.encodeFunctionData(functionName, functionArgs),
    0
  );
  await setMessageTx.wait();

  console.log('Transaction Receipt: ', setMessageTx);
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
