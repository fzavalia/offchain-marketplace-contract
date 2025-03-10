# CreditsManagerPolygon

## Overview
The CreditsManagerPolygon contract is a sophisticated credit management system designed for the Decentraland ecosystem. It serves as a bridge that allows users to pay for marketplace transactions using pre-signed credits instead of directly spending MANA from their wallets. This creates a more seamless user experience by enabling off-chain credit issuance that can be consumed on-chain, reducing the need for direct MANA transfers from user wallets.

## Table of Contents
- [Key Features](#key-features)
- [Roles and Permissions](#roles-and-permissions)
- [Core Data Structures](#core-data-structures)
- [Main Functionality](#main-functionality)
  - [Credit Management](#credit-management)
  - [External Call Handling](#external-call-handling)
- [Security Features](#security-features)
- [Usage Examples](#usage-examples)

## Key Features
- **Credit System**: Allows users to use signed credits to pay for transactions
- **Marketplace Integration**: Supports both primary and secondary sales in Decentraland's marketplace
- **Access Control**: Comprehensive role-based access control for different operations
- **Meta-transactions**: Supports meta-transactions for improved UX
- **Rate Limiting**: Implements hourly credit consumption limits
- **Custom External Calls**: Enables authorized external contract calls beyond standard marketplace operations

## Roles and Permissions
The contract implements a role-based access control system with the following roles:
- **DEFAULT_ADMIN_ROLE**: Can grant/revoke roles and perform administrative functions
- **SIGNER_ROLE**: Can sign credits that users can later redeem
- **PAUSER_ROLE**: Can pause/unpause the contract functionality
- **DENIER_ROLE**: Can deny specific users from using credits
- **REVOKER_ROLE**: Can revoke previously issued credits
- **EXTERNAL_CALL_SIGNER_ROLE**: Can sign custom external calls
- **EXTERNAL_CALL_REVOKER_ROLE**: Can revoke custom external call signatures

## Core Data Structures
The contract uses several key data structures:

### Credit

Contains the data of a credit, which is to be signed by the address with the SIGNER_ROLE.

```solidity
struct Credit {
    uint256 value;         // How much MANA the credit is worth
    uint256 expiresAt;     // The timestamp when the credit expires
    bytes32 salt;          // Value used to generate unique credits
}
```

### ExternalCall

Contains the data of the external call being made. This contract revolves on determining how much MANA is transferred out of the contract when called and calculate the credits to be used.

```solidity
struct ExternalCall {
    address target;        // The contract address of the external call
    bytes4 selector;       // The selector of the external call
    bytes data;            // The data of the external call
    uint256 expiresAt;     // The timestamp when the external call expires *
    bytes32 salt;          // The salt of the external call *
}

// * Only required for custom external calls. 
//   These are any calls which do not target decentraland marketplace contracts.
```

### UseCreditsArgs

Used for the `useCredits` function which is the main function of the contract.

```solidity
struct UseCreditsArgs {
    Credit[] credits;                   // The credits to use
    bytes[] creditsSignatures;          // The signatures of the credits
    ExternalCall externalCall;          // The external call to make
    bytes customExternalCallSignature;  // The signature of the external call
    uint256 maxUncreditedValue;         // Maximum MANA paid from wallet
    uint256 maxCreditedValue;           // Maximum MANA credited from provided credits
}
```

## Main Functionality

### Credit Management
- **Credit Validation**: Verifies credit signatures, expiration, and consumption status
- **Credit Consumption**: Tracks how much of each credit has been consumed
- **Credit Revocation**: Allows authorized roles to revoke credits
- **Rate Limiting**: Enforces maximum MANA credited per hour

### External Call Handling
The contract supports four types of external calls:
1. **Legacy Marketplace**: For executing orders on the legacy Marketplace contract.
2. **Marketplace**: For accepting trades on the current offchain-marketplace *.
3. **Collection Store**: For minting collection items using the legacy CollectionStore contract.
4. **Custom External Calls**: For other authorized contract interactions

\* Only "Listing" Trades are allowed to consume credits. Listings are Trades which have 1 MANA asset being received by the signer, and 1 or more Decentraland Items/NFTs being sent by the signer.

## Security Features
- **Reentrancy Protection**: Uses ReentrancyGuard to prevent reentrancy attacks
- **Pausable**: Contract can be paused in case of emergencies
- **Access Control**: Strict role-based permissions for sensitive operations
- **Signature Verification**: Validates all signatures before processing
- **Rate Limiting**: Prevents excessive credit usage in short time periods
- **Denial Capability**: Ability to deny malicious users from using the system

## Usage Examples
*Detailed usage examples will be added in a future update*
