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
