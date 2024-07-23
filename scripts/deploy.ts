import { ethers } from 'hardhat';
import fs from 'fs';
import path from 'path';

async function main() {
  const Contract = await ethers.getContractFactory('Zix');
  
  console.log('Deploying token...');
  
  // Mendapatkan alamat deployer sebagai initialOwner
  const [deployer] = await ethers.getSigners();
  const initialOwner = deployer.address;
  
  // Mengirimkan initialOwner ke konstruktor kontrak
  const contract = await Contract.deploy(initialOwner);
  
  // Menunggu kontrak terdeploy
  await contract.deploymentTransaction().wait();
  
  // Mengambil alamat kontrak yang terdeploy
  const contractAddress = await contract.getAddress();
  console.log('Token deployed to:', contractAddress);
  
  const deployedAddressPath = path.join(__dirname, '..', 'utils', 'deployed-address.ts');
  
  const fileContent = `const deployedAddress = '${contractAddress}'\n\nexport default deployedAddress\n`;
  
  fs.writeFileSync(deployedAddressPath, fileContent, { encoding: 'utf8' });
  console.log('Address written to deployedAddress.ts');
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
