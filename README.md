# Swisstronik ERC20 Smart Contract

Zix is an ERC20 Solidity contract with enhanced security features. It includes mechanisms to prevent reentrancy attacks, signature replay attacks, and more. This contract is designed to be highly secure and robust.

## Features

- **Reentrancy Protection**: Protects against reentrancy attacks using OpenZeppelin's `ReentrancyGuard`.
- **Safe Math Operations**: Uses SafeMath to prevent arithmetic overflow and underflow.
- **Signature Replay Protection**: Implements nonce-based signature verification to prevent replay attacks.
- **Access Control**: Only the owner can mint new tokens.
- **Secure Transfer**: Safe transfer functions to ensure validity and security of transactions.
- **Nonce Management**: Ensures unique nonces for preventing replay attacks.

## Installation

Clone the repository and install the dependencies:

   ```
git clone https://github.com/naufalprtm/swisstronik-smartcontract-erc20.git
cd swisstronik-smartcontract-erc20
npm install
   ```

## Token Contract


   ```
   // SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import { ERC20 } from "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import { Ownable } from "@openzeppelin/contracts/access/Ownable.sol";
import { ReentrancyGuard } from "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import { Math } from "@openzeppelin/contracts/utils/math/Math.sol";
import { Address } from "@openzeppelin/contracts/utils/Address.sol";
import { ECDSA } from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

/**
 * @title Zix Token Contract
 * @notice ERC20 Token with advanced security features and access control.
 */
contract Zix is ERC20, Ownable, ReentrancyGuard {
    using Math for uint256;
    using Address for address;
    using ECDSA for bytes32;

    // Mapping for storing nonces to prevent replay attacks
    mapping(address => uint256) private nonces;

    // Event for minting
    event TokensMinted(address indexed to, uint256 amount);

    constructor(address initialOwner) ERC20("Zix Token", "ZX") Ownable(initialOwner) {
        require(initialOwner != address(0), "Owner address cannot be zero");
        _mint(initialOwner, 10000000000 * 10 ** decimals());
    }

    /**
     * @dev Mint new tokens. Only the owner can call this function.
     * @param to The address to receive the new tokens.
     * @param amount The number of tokens to be minted.
     */
    function mint(address to, uint256 amount) public onlyOwner nonReentrant {
        require(to != address(0), "Recipient address cannot be zero");
        require(amount > 0, "Mint amount must be greater than zero");
        _mint(to, amount);
        emit TokensMinted(to, amount);
    }

    /**
     * @dev Prevent denial of service (DoS) by ensuring contract functionality is resilient to various conditions.
     */
    function safeTransfer(address recipient, uint256 amount) external nonReentrant {
        require(recipient != address(0), "Recipient address cannot be zero");
        require(balanceOf(msg.sender) >= amount, "Insufficient balance");
        _transfer(msg.sender, recipient, amount);
    }

    /**
     * @dev Prevent signature replay attacks by using nonces.
     * @param from Address that signed the transaction.
     * @param to Address receiving the tokens.
     * @param amount Amount of tokens to transfer.
     * @param nonce Unique identifier for the transaction.
     * @param signature Signed hash of the transaction.
     */
    function transferWithSignature(
        address from,
        address to,
        uint256 amount,
        uint256 nonce,
        bytes calldata signature
    ) external nonReentrant {
        require(nonce == nonces[from], "Invalid nonce");
        bytes32 hash = keccak256(abi.encodePacked(from, to, amount, nonce));
        bytes32 ethSignedMessageHash = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        require(ECDSA.recover(ethSignedMessageHash, signature) == from, "Invalid signature");
        nonces[from] += 1;
        _transfer(from, to, amount);
    }

    /**
     * @dev Get the current nonce for the address.
     * @param account Address to retrieve the nonce for.
     * @return Current nonce for the address.
     */
    function getNonce(address account) external view returns (uint256) {
        return nonces[account];
    }
}
   ```


## Deployment Script
To deploy the contract, create a file scripts/deploy.ts with the following content:

```

import { ethers } from 'hardhat'
import fs from 'fs'
import path from 'path'

async function main() {
  const Contract = await ethers.getContractFactory('Zix')

  console.log('Deploying token...')
  const contract = await Contract.deploy("0xYourInitialOwnerAddress")

  await contract.deployed()
  const contractAddress = contract.address
  console.log('Token deployed to:', contractAddress)

  const deployedAddressPath = path.join(__dirname, '..', 'utils', 'deployed-address.ts')

  const fileContent = `const deployedAddress = '${contractAddress}'\n\nexport default deployedAddress\n`

  fs.writeFileSync(deployedAddressPath, fileContent, { encoding: 'utf8' })
  console.log('Address written to deployedAddress.ts')
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error)
    process.exit(1)
  })

  ```

Run the deployment script with:


```

npx hardhat run scripts/deploy.ts --network yourNetwork

```
## Mint Script
To mint tokens, create a file scripts/mint.ts with the following content:

```
import { ethers, network } from 'hardhat'
import { encryptDataField } from '@swisstronik/utils'
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/src/signers'
import { HttpNetworkConfig } from 'hardhat/types'
import deployedAddress from '../utils/deployed-address'

const sendShieldedTransaction = async (
  signer: HardhatEthersSigner,
  destination: string,
  data: string,
  value: number
) => {
  const rpclink = (network.config as HttpNetworkConfig).url

  const [encryptedData] = await encryptDataField(rpclink, data)

  return await signer.sendTransaction({
    from: signer.address,
    to: destination,
    data: encryptedData,
    value,
  })
}

async function main() {
  const contractAddress = deployedAddress

  const [signer] = await ethers.getSigners()

  const contractFactory = await ethers.getContractFactory('Zix')
  const contract = contractFactory.attach(contractAddress)

  const functionName = 'mint'
  const recipient = '0xRecipientAddress'
  const amount = ethers.utils.parseUnits('1000', 18)
  const functionArgs = [recipient, amount]
  const setMessageTx = await sendShieldedTransaction(
    signer,
    contractAddress,
    contract.interface.encodeFunctionData(functionName, functionArgs),
    0
  )
  await setMessageTx.wait()

  console.log('Transaction Receipt: ', setMessageTx)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})

```

Run the mint script with:


```
npx hardhat run scripts/mint.ts --network yourNetwork

```


## Transfer Script

To transfer tokens, create a file scripts/transfer.ts with the following content:

```
import { ethers, network } from 'hardhat'
import { encryptDataField } from '@swisstronik/utils'
import { HardhatEthersSigner } from '@nomicfoundation/hardhat-ethers/src/signers'
import { HttpNetworkConfig } from 'hardhat/types'
import deployedAddress from '../utils/deployed-address'

const sendShieldedTransaction = async (
  signer: HardhatEthersSigner,
  destination: string,
  data: string,
  value: number
) => {
  const rpclink = (network.config as HttpNetworkConfig).url

  const [encryptedData] = await encryptDataField(rpclink, data)

  return await signer.sendTransaction({
    from: signer.address,
    to: destination,
    data: encryptedData,
    value,
  })
}

async function main() {
  const contractAddress = deployedAddress

  const [signer] = await ethers.getSigners()

  const contractFactory = await ethers.getContractFactory('Zix')
  const contract = contractFactory.attach(contractAddress)

  const functionName = 'transfer'
  const recipient = '0xRecipientAddress'
  const amount = ethers.utils.parseUnits('1', 18)
  const functionArgs = [recipient, amount]
  const setMessageTx = await sendShieldedTransaction(
    signer,
    contractAddress,
    contract.interface.encodeFunctionData(functionName, functionArgs),
    0
  )
  await setMessageTx.wait()

  console.log('Transaction Receipt: ', setMessageTx)
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})
```
Run the transfer script with:

```
npx hardhat run scripts/transfer.ts --network yourNetwork
```

## Check Supply Script
To check the total supply, create a file scripts/checkSupply.ts with the following content:

```
import { ethers, network } from 'hardhat';
import { encryptDataField, decryptNodeResponse } from '@swisstronik/utils';
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider';
import { JsonRpcProvider } from 'ethers';
import { HttpNetworkConfig } from 'hardhat/types';
import deployedAddress from '../utils/deployed-address';

const sendShieldedQuery = async (
  provider: HardhatEthersProvider | JsonRpcProvider,
  destination: string,
  data: string
) => {
  const rpclink = (network.config as HttpNetworkConfig).url;

  const [encryptedData, usedEncryptedKey] = await encryptDataField(rpclink, data);

  const response = await provider.call({
    to: destination,
    data: encryptedData,
  });

  return await decryptNodeResponse(rpclink, response, usedEncryptedKey);
};

async function main() {
  const contractAddress = deployedAddress;
  const [signer] = await ethers.getSigners();

  const contractFactory = await ethers.getContractFactory('Zix');
  const contract = contractFactory.attach(contractAddress);

  const functionName = 'totalSupply';
  const responseMessage = await sendShieldedQuery(
    signer.provider,
    contractAddress,
    contract.interface.encodeFunctionData(functionName)
  );

  const totalSupply = contract.interface.decodeFunctionResult(functionName, responseMessage)[0];
  console.log('Total Supply is:', ethers.formatUnits(totalSupply, 18));
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});

```

## Check Balance Script

To check the balance of an account, create a file scripts/checkBalance.ts with the following content:

```
import { ethers, network } from 'hardhat'
import { encryptDataField, decryptNodeResponse } from '@swisstronik/utils'
import { HardhatEthersProvider } from '@nomicfoundation/hardhat-ethers/internal/hardhat-ethers-provider'
import { JsonRpcProvider } from 'ethers'
import { HttpNetworkConfig } from 'hardhat/types'
import deployedAddress from '../utils/deployed-address'

const sendShieldedQuery = async (
  provider: HardhatEethersProvider | JsonRpcProvider,
  destination: string,
  data: string
) => {
  const rpclink = (network.config as HttpNetworkConfig).url

  const [encryptedData, usedEncryptedKey] = await encryptDataField(rpclink, data)

  const response = await provider.call({
    to: destination,
    data: encryptedData,
  })

  return await decryptNodeResponse(rpclink, response, usedEncryptedKey)
}

async function main() {
  const contractAddress = deployedAddress
  const [signer] = await ethers.getSigners()

  const contractFactory = await ethers.getContractFactory('Zix')
  const contract = contractFactory.attach(contractAddress)

  const functionName = 'balanceOf'
  const functionArgs = [signer.address]
  const responseMessage = await sendShieldedQuery(
    signer.provider,
    contractAddress,
    contract.interface.encodeFunctionData(functionName, functionArgs)
  )
  const totalBalance = contract.interface.decodeFunctionResult(functionName, responseMessage)[0]

  console.log('Total Balance is:', ethers.utils.formatUnits(totalBalance, 18), 'Zix')
}

main().catch((error) => {
  console.error(error)
  process.exitCode = 1
})

```

Run the check balance script with:

```
npx hardhat run scripts/checkBalance.ts --network yourNetwork
```