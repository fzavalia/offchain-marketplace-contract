// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {AccessControl} from "@openzeppelin/contracts/access/AccessControl.sol";
import {Pausable} from "@openzeppelin/contracts/utils/Pausable.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {NativeMetaTransaction, EIP712} from "src/common/NativeMetaTransaction.sol";
import {IMarketplace} from "src/credits/interfaces/IMarketplace.sol";
import {ILegacyMarketplace} from "src/credits/interfaces/ILegacyMarketplace.sol";
import {ICollectionFactory} from "src/credits/interfaces/ICollectionFactory.sol";
import {ICollectionStore} from "src/credits/interfaces/ICollectionStore.sol";

contract CreditsManagerPolygon is AccessControl, Pausable, ReentrancyGuard, NativeMetaTransaction {
    using ECDSA for bytes32;
    using SafeERC20 for IERC20;

    /// @notice The role that can sign credits.
    bytes32 public constant SIGNER_ROLE = keccak256("SIGNER_ROLE");

    /// @notice The role that can pause the contract.
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /// @notice The role that can deny users from using credits.
    bytes32 public constant DENIER_ROLE = keccak256("DENIER_ROLE");

    /// @notice The role that can revoke credits.
    bytes32 public constant REVOKER_ROLE = keccak256("REVOKER_ROLE");

    /// @notice The role that can sign external calls.
    bytes32 public constant EXTERNAL_CALL_SIGNER_ROLE = keccak256("EXTERNAL_CALL_SIGNER_ROLE");

    /// @notice The role that can revoke external calls.
    bytes32 public constant EXTERNAL_CALL_REVOKER_ROLE = keccak256("EXTERNAL_CALL_REVOKER_ROLE");

    /// @notice Asset type for NFTs for the Marketplace Trade struct.
    uint256 public constant ASSET_TYPE_ERC721 = 3;

    /// @notice Asset type for collection items for the Marketplace Trade struct.
    uint256 public constant ASSET_TYPE_COLLECTION_ITEM = 4;

    /// @notice Whether a user is denied from using credits.
    mapping(address => bool) public isDenied;

    /// @notice Whether a credit has been revoked.
    /// @dev The key is the hash of the credit signature.
    mapping(bytes32 => bool) public isRevoked;

    /// @notice The address of the MANA token.
    IERC20 public immutable mana;

    /// @notice The amount of MANA value used on each credit.
    /// @dev The key is the hash of the credit signature.
    mapping(bytes32 => uint256) spentValue;

    /// @notice Maximum amount of MANA that can be credited per hour.
    uint256 public maxManaCreditedPerHour;

    /// @notice How much MANA has been credited this hour.
    uint256 public manaCreditedThisHour;

    /// @notice The hour of the last MANA credit.
    uint256 public hourOfLastManaCredit;

    /// @notice Whether primary sales are allowed.
    bool public primarySalesAllowed;

    /// @notice Whether secondary sales are allowed.
    bool public secondarySalesAllowed;

    /// @notice Whether bids are allowed.
    bool public bidsAllowed;

    /// @notice The address of the Marketplace contract.
    address public immutable marketplace;

    /// @notice The address of the Legacy Marketplace contract.
    address public immutable legacyMarketplace;

    /// @notice The address of the CollectionStore contract.
    address public immutable collectionStore;

    /// @notice The address of the CollectionFactory contract.
    ICollectionFactory public immutable collectionFactory;

    /// @notice The address of the CollectionFactoryV3 contract.
    ICollectionFactory public immutable collectionFactoryV3;

    /// @notice Tracks the allowed custom external calls.
    mapping(address => mapping(bytes4 => bool)) public allowedCustomExternalCalls;

    /// @notice Tracks the used external call signatures.
    mapping(bytes32 => bool) public usedCustomExternalCallSignature;

    /// @dev Value stored temporarily to check the validity of credits used for bids.
    bytes32 internal tempBidCreditsSignaturesHash;

    /// @dev Value stored temporarily to check the validity of max uncredited value used for bids.
    uint256 internal tempMaxUncreditedValue;

    /// @dev Value stored temporarily to check the validity of max credited value used for bids.
    uint256 internal tempMaxCreditedValue;

    /// @notice The roles to initialize the contract with.
    /// @dev Mainly used to decrease the number of arguments in the constructor.
    /// @param owner The address that acts as default admin.
    /// @param signer The address that can sign credits.
    /// @param pauser The address that can pause the contract.
    /// @param denier The address that can deny users from using credits.
    /// @param revoker The address that can revoke credits.
    /// @param customExternalCallSigner The address that can sign custom external calls.
    /// @param customExternalCallRevoker The address that can revoke custom external calls.
    struct Roles {
        address owner;
        address signer;
        address pauser;
        address denier;
        address revoker;
        address customExternalCallSigner;
        address customExternalCallRevoker;
    }

    /// @notice The arguments for the useCredits function.
    /// @dev This is used to avoid stack too deep errors.
    /// @param credits The credits to use.
    /// @param creditsSignatures The signatures of the credits.
    /// Has to be signed by a wallet that has the signer role.
    /// @param externalCall The external call to make.
    /// @param customExternalCallSignature The signature of the external call.
    /// Only used for custom external calls.
    /// Has to be signed by a wallet that has the customExternalCallSigner role.
    /// @param maxUncreditedValue The maximum amount of MANA the user is willing to pay from their wallet when credits are insufficient to cover the total transaction cost.
    /// @param maxCreditedValue The maximum amount of MANA that can be credited from the provided credits.
    struct UseCreditsArgs {
        Credit[] credits;
        bytes[] creditsSignatures;
        ExternalCall externalCall;
        bytes customExternalCallSignature;
        uint256 maxUncreditedValue;
        uint256 maxCreditedValue;
    }

    /// @param _value How much ERC20 the credit is worth.
    /// @param _expiresAt The timestamp when the credit expires.
    /// @param _salt Value used to generate unique credits.
    struct Credit {
        uint256 value;
        uint256 expiresAt;
        bytes32 salt;
    }

    /// @param target The contract address of the external call.
    /// @param selector The selector of the external call.
    /// @param data The data of the external call.
    /// @param expiresAt The timestamp when the external call expires.
    /// Only used for custom external calls.
    /// @param salt The salt of the external call.
    /// Only used for custom external calls.
    struct ExternalCall {
        address target;
        bytes4 selector;
        bytes data;
        uint256 expiresAt;
        bytes32 salt;
    }

    event UserDenied(address indexed _user);
    event UserAllowed(address indexed _user);
    event CreditRevoked(bytes32 indexed _creditId);
    event CreditUsed(bytes32 indexed _creditId, Credit _credit, uint256 _value);
    event CreditsUsed(uint256 _manaTransferred, uint256 _creditedValue);
    event MaxManaCreditedPerHourUpdated(uint256 _maxManaCreditedPerHour);
    event ERC20Withdrawn(address indexed _token, uint256 _amount, address indexed _to);
    event ERC721Withdrawn(address indexed _token, uint256 _tokenId, address indexed _to);
    event CustomExternalCallAllowed(address indexed _target, bytes4 indexed _selector, bool _allowed);
    event CustomExternalCallRevoked(bytes32 indexed _hashedExternalCallSignature);
    event PrimarySalesAllowedUpdated(bool _primarySalesAllowed);
    event SecondarySalesAllowedUpdated(bool _secondarySalesAllowed);
    event BidsAllowedUpdated(bool _bidsAllowed);

    error CreditExpired(bytes32 _creditId);
    error DeniedUser(address _user);
    error RevokedCredit(bytes32 _creditId);
    error InvalidSignature(bytes32 _creditId, address _recoveredSigner);
    error SpentCredit(bytes32 _creditId);
    error NoMANATransfer();
    error NoCredits();
    error InvalidCreditValue();
    error InvalidExternalCallSelector(address _target, bytes4 _selector);
    error NotDecentralandCollection(address _contractAddress);
    error OnlyOneTradeAllowed();
    error InvalidBeneficiary();
    error InvalidTrade(IMarketplace.Trade _trade);
    error ExternalCallFailed(ExternalCall _externalCall);
    error ExternalCheckNotFound();
    error InvalidAssetsLength();
    error CustomExternalCallNotAllowed(address _target, bytes4 _selector);
    error InvalidCustomExternalCallSignature(address _recoveredSigner);
    error UsedCustomExternalCallSignature(bytes32 _hashedCustomExternalCallSignature);
    error CustomExternalCallExpired(uint256 _expiresAt);
    error MaxUncreditedValueExceeded(uint256 _uncreditedValue, uint256 _maxUncreditedValue);
    error MaxCreditedValueExceeded(uint256 _creditedValue, uint256 _maxCreditedValue);
    error MaxCreditedValueZero();
    error InvalidTradesLength();
    error NotBid();
    error NotListing();
    error OnlyBidsWithSameSignerAllowed();
    error CreditedValueZero();
    error SecondarySalesNotAllowed();
    error PrimarySalesNotAllowed();
    error BidsNotAllowed();
    error MaxManaCreditedPerHourExceeded(uint256 _creditableManaThisHour, uint256 _creditedValue);

    /// @param _roles The roles to initialize the contract with.
    /// @param _maxManaCreditedPerHour The maximum amount of MANA that can be credited per hour.
    /// @param _primarySalesAllowed Whether primary sales are allowed.
    /// @param _secondarySalesAllowed Whether secondary sales are allowed.
    /// @param _bidsAllowed Whether bids are allowed.
    /// @param _mana The MANA token.
    /// @param _marketplace The Marketplace contract.
    /// @param _legacyMarketplace The Legacy Marketplace contract.
    /// @param _collectionStore The CollectionStore contract.
    /// @param _collectionFactory The CollectionFactory contract.
    /// @param _collectionFactoryV3 The CollectionFactoryV3 contract.
    constructor(
        Roles memory _roles,
        uint256 _maxManaCreditedPerHour,
        bool _primarySalesAllowed,
        bool _secondarySalesAllowed,
        bool _bidsAllowed,
        IERC20 _mana,
        address _marketplace,
        address _legacyMarketplace,
        address _collectionStore,
        ICollectionFactory _collectionFactory,
        ICollectionFactory _collectionFactoryV3
    ) EIP712("Decentraland Credits", "1.0.0") {
        _grantRole(DEFAULT_ADMIN_ROLE, _roles.owner);

        _grantRole(SIGNER_ROLE, _roles.signer);

        _grantRole(PAUSER_ROLE, _roles.pauser);
        _grantRole(PAUSER_ROLE, _roles.owner);

        _grantRole(DENIER_ROLE, _roles.denier);
        _grantRole(DENIER_ROLE, _roles.owner);

        _grantRole(REVOKER_ROLE, _roles.revoker);
        _grantRole(REVOKER_ROLE, _roles.owner);

        _grantRole(EXTERNAL_CALL_SIGNER_ROLE, _roles.customExternalCallSigner);

        _grantRole(EXTERNAL_CALL_REVOKER_ROLE, _roles.customExternalCallRevoker);
        _grantRole(EXTERNAL_CALL_REVOKER_ROLE, _roles.owner);

        _updateMaxManaCreditedPerHour(_maxManaCreditedPerHour);

        _updatePrimarySalesAllowed(_primarySalesAllowed);
        _updateSecondarySalesAllowed(_secondarySalesAllowed);
        _updateBidsAllowed(_bidsAllowed);

        mana = _mana;
        marketplace = _marketplace;
        legacyMarketplace = _legacyMarketplace;
        collectionStore = _collectionStore;
        collectionFactory = _collectionFactory;
        collectionFactoryV3 = _collectionFactoryV3;
    }

    /// @notice Pauses the contract.
    function pause() external onlyRole(PAUSER_ROLE) {
        _pause();
    }

    /// @notice Unpauses the contract.
    /// @dev Only the owner can unpause the contract.
    function unpause() external onlyRole(DEFAULT_ADMIN_ROLE) {
        _unpause();
    }

    /// @notice Denies a user from using credits.
    /// @param _user The user to deny.
    function denyUser(address _user) external onlyRole(DENIER_ROLE) {
        isDenied[_user] = true;

        emit UserDenied(_user);
    }

    /// @notice Allows a user to use credits.
    /// @dev Only the owner can allow a user to use credits.
    /// @dev All users are allowed by default.
    /// @param _user The user to allow.
    function allowUser(address _user) external onlyRole(DEFAULT_ADMIN_ROLE) {
        isDenied[_user] = false;

        emit UserAllowed(_user);
    }

    /// @notice Revokes a credit.
    /// @param _credit The hash of the credit signature.
    function revokeCredit(bytes32 _credit) external onlyRole(REVOKER_ROLE) {
        isRevoked[_credit] = true;

        emit CreditRevoked(_credit);
    }

    /// @notice Update the maximum amount of MANA that can be credited per hour.
    /// @param _maxManaCreditedPerHour The new maximum amount of MANA that can be credited per hour.
    function updateMaxManaCreditedPerHour(uint256 _maxManaCreditedPerHour) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateMaxManaCreditedPerHour(_maxManaCreditedPerHour);
    }

    /// @notice Update whether primary sales are allowed.
    /// @param _primarySalesAllowed Whether primary sales are allowed.
    function updatePrimarySalesAllowed(bool _primarySalesAllowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updatePrimarySalesAllowed(_primarySalesAllowed);
    }

    /// @notice Update whether secondary sales are allowed.
    /// @param _secondarySalesAllowed Whether secondary sales are allowed.
    function updateSecondarySalesAllowed(bool _secondarySalesAllowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateSecondarySalesAllowed(_secondarySalesAllowed);
    }

    /// @notice Update whether bids are allowed.
    /// @param _bidsAllowed Whether bids are allowed.
    function updateBidsAllowed(bool _bidsAllowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        _updateBidsAllowed(_bidsAllowed);
    }

    /// @notice Withdraw ERC20 tokens from the contract.
    /// @param _token The address of the ERC20 token.
    /// @param _amount The amount of ERC20 tokens to withdraw.
    /// @param _to The address to send the ERC20 tokens to.
    function withdrawERC20(address _token, uint256 _amount, address _to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC20(_token).safeTransfer(_to, _amount);

        emit ERC20Withdrawn(_token, _amount, _to);
    }

    /// @notice Withdraw ERC721 tokens from the contract.
    /// @param _token The address of the ERC721 token.
    /// @param _tokenId The ID of the ERC721 token.
    /// @param _to The address to send the ERC721 token to.
    function withdrawERC721(address _token, uint256 _tokenId, address _to) external onlyRole(DEFAULT_ADMIN_ROLE) {
        IERC721(_token).safeTransferFrom(address(this), _to, _tokenId);

        emit ERC721Withdrawn(_token, _tokenId, _to);
    }

    /// @notice Allows a custom external call.
    /// @param _target The target of the external call.
    /// @param _selector The selector of the external call.
    /// @param _allowed Whether the external call is allowed.
    function allowCustomExternalCall(address _target, bytes4 _selector, bool _allowed) external onlyRole(DEFAULT_ADMIN_ROLE) {
        allowedCustomExternalCalls[_target][_selector] = _allowed;

        emit CustomExternalCallAllowed(_target, _selector, _allowed);
    }

    /// @notice Revokes a custom external call.
    /// @param _hashedCustomExternalCallSignature The hash of the custom external call signature.
    function revokeCustomExternalCall(bytes32 _hashedCustomExternalCallSignature) external onlyRole(EXTERNAL_CALL_REVOKER_ROLE) {
        usedCustomExternalCallSignature[_hashedCustomExternalCallSignature] = true;

        emit CustomExternalCallRevoked(_hashedCustomExternalCallSignature);
    }

    /// @notice Use credits to pay for external calls that transfer MANA.
    /// @param _args The arguments for the useCredits function.
    function useCredits(UseCreditsArgs calldata _args) external nonReentrant whenNotPaused {
        // Why use this contract if you don't provide any credits?
        if (_args.credits.length == 0) {
            revert NoCredits();
        }

        // Credits cannot be used if the amount to be consumed from them is 0.
        if (_args.maxCreditedValue == 0) {
            revert MaxCreditedValueZero();
        }

        address self = address(this);

        // By default the consumer of the credits is the caller of the function.
        // There is a special case for bids in which the consumer is the signer of the bid instead.
        address creditsConsumer = _msgSender();

        {
            // Cache the values to prevent multiple storage reads.
            bool memPrimarySalesAllowed = primarySalesAllowed;
            bool memSecondarySalesAllowed = secondarySalesAllowed;

            // Legacy Marketplace.
            if (_args.externalCall.target == legacyMarketplace) {
                // Check that only executeOrder is being called.
                // `safeExecuteOrder` is not used on Polygon given that the assets don't validate signatures like with Estates.
                if (_args.externalCall.selector != ILegacyMarketplace.executeOrder.selector) {
                    revert InvalidExternalCallSelector(_args.externalCall.target, _args.externalCall.selector);
                }

                if (!memSecondarySalesAllowed) {
                    revert SecondarySalesNotAllowed();
                }

                // Decode the contract address from the data
                (address contractAddress) = abi.decode(_args.externalCall.data, (address));

                // Check that the sent assets are decentraland collections items or nfts.
                _verifyDecentralandCollection(contractAddress);
            }
            // Offchain Marketplace.
            else if (_args.externalCall.target == marketplace) {
                bool memBidsAllowed = bidsAllowed;

                // Check that only accept or acceptWithCoupon are being called.
                if (
                    _args.externalCall.selector != IMarketplace.accept.selector
                        && _args.externalCall.selector != IMarketplace.acceptWithCoupon.selector
                ) {
                    revert InvalidExternalCallSelector(_args.externalCall.target, _args.externalCall.selector);
                }

                // Decode the trades from the data.
                IMarketplace.Trade[] memory trades = abi.decode(_args.externalCall.data, (IMarketplace.Trade[]));

                // We check that there is at least one trade.
                if (trades.length == 0) {
                    revert InvalidTradesLength();
                }

                // Track if the first trade is a bid or a listing.
                // Having both type of trades in the same call makes it too complex to handle credit consumption so only trades of the same type are allowed.
                bool firstTradeIsBid = false;

                for (uint256 i = 0; i < trades.length; i++) {
                    IMarketplace.Trade memory trade = trades[i];

                    // We have to check if the trade is a valid listing or a valid bid.
                    //
                    // Listing:
                    // - 1 mana asset received by the signer.
                    // - n amount of decentraland assets sent to the caller.
                    // Bid:
                    // - n amount of decentraland assets received by the signer.
                    // - 1 mana asset sent to the caller.
                    //
                    // First we verify if the trade is a listing by checking if the received assets contain only a mana asset.
                    if (trade.received.length == 1 && trade.received[0].contractAddress == address(mana)) {
                        // For the second trade onwards, we check that is is not of the opposite type.
                        // In this case, if the first trade was a bid, it should revert because this one is a listing.
                        if (i > 0 && firstTradeIsBid) {
                            revert NotBid();
                        }

                        uint256 sentLength = trade.sent.length;

                        // We check that there is at least one sent asset.
                        if (sentLength == 0) {
                            revert InvalidAssetsLength();
                        }

                        for (uint256 j = 0; j < sentLength; j++) {
                            IMarketplace.Asset memory asset = trade.sent[j];

                            // We check that the sent assets are decentraland collections items or nfts.
                            _verifyDecentralandCollection(asset.contractAddress);

                            if (asset.assetType == ASSET_TYPE_ERC721 && !memSecondarySalesAllowed) {
                                revert SecondarySalesNotAllowed();
                            }

                            if (asset.assetType == ASSET_TYPE_COLLECTION_ITEM && !memPrimarySalesAllowed) {
                                revert PrimarySalesNotAllowed();
                            }

                            // We check that the beneficiary of the decentraland assets is not 0 so they are not received by this contract.
                            if (asset.beneficiary == address(0)) {
                                revert InvalidBeneficiary();
                            }
                        }
                    }
                    // If it is not a listing, we verify that it is a bid by checking if the sent assets contain only a mana asset.
                    else if (trade.sent.length == 1 && trade.sent[0].contractAddress == address(mana)) {
                        if (!memBidsAllowed) {
                            revert BidsNotAllowed();
                        }

                        // For the second trade onwards, we check that is is not of the opposite type.
                        // In this case, if the first trade was a listing, it should revert because this one is a bid.
                        if (i > 0) {
                            if (!firstTradeIsBid) {
                                revert NotListing();
                            }

                            // If the second trade onwards was not signed by the same address as the first trade, it should revert.
                            if (trade.signer != creditsConsumer) {
                                revert OnlyBidsWithSameSignerAllowed();
                            }
                        } else {
                            // Track that the first trade was a bid.
                            firstTradeIsBid = true;

                            // Given that credits are consumed by one address, to prevent issues, we verify that the signer of all bids is the same.
                            creditsConsumer = trade.signer;
                        }

                        uint256 receivedLength = trade.received.length;

                        // We check that there is at least one received asset.
                        if (receivedLength == 0) {
                            revert InvalidAssetsLength();
                        }

                        for (uint256 j = 0; j < receivedLength; j++) {
                            IMarketplace.Asset memory asset = trade.received[j];

                            // We check that the received assets are decentraland collections items or nfts.
                            // There is no need to check that the beneficiary is not 0 because the signer (bidder) address will be used in that case.
                            _verifyDecentralandCollection(asset.contractAddress);

                            if (asset.assetType == ASSET_TYPE_ERC721 && !memSecondarySalesAllowed) {
                                revert SecondarySalesNotAllowed();
                            }

                            if (asset.assetType == ASSET_TYPE_COLLECTION_ITEM && !memPrimarySalesAllowed) {
                                revert PrimarySalesNotAllowed();
                            }
                        }

                        // We check that the bid has an external check with this contract to verify that the credits provided are
                        // the same as the ones the bidder wants to use.
                        bool hasExternalCheck = false;

                        for (uint256 j = 0; j < trade.checks.externalChecks.length; j++) {
                            IMarketplace.ExternalCheck memory externalCheck = trade.checks.externalChecks[j];

                            // We check that at least one required external check has this contract as target and is calling the bidExternalCheck function.
                            if (
                                externalCheck.contractAddress == address(this) && externalCheck.selector == this.bidExternalCheck.selector
                                    && externalCheck.required
                            ) {
                                hasExternalCheck = true;
                            }
                        }

                        // If we can't find the external check, we revert.
                        if (!hasExternalCheck) {
                            revert ExternalCheckNotFound();
                        }
                    } else {
                        // Reverts if the trade is not a valid bid or listing.
                        revert InvalidTrade(trade);
                    }
                }

                // Stores the hash of the credits to be consumed on the bid so it can be verified on the external check.
                tempBidCreditsSignaturesHash = keccak256(abi.encode(_args.creditsSignatures));

                // Stores the maximum amount of MANA the bidder is willing to pay from their wallet when credits are insufficient to cover the total transaction cost.
                tempMaxUncreditedValue = _args.maxUncreditedValue;

                // Stores the maximum amount of MANA that can be credited from the provided credits.
                tempMaxCreditedValue = _args.maxCreditedValue;
            }
            // CollectionStore.
            else if (_args.externalCall.target == collectionStore) {
                // Check that only buy is being called.
                if (_args.externalCall.selector != ICollectionStore.buy.selector) {
                    revert InvalidExternalCallSelector(_args.externalCall.target, _args.externalCall.selector);
                }

                if (!memPrimarySalesAllowed) {
                    revert PrimarySalesNotAllowed();
                }

                // Decode the items to buy from the data.
                ICollectionStore.ItemToBuy[] memory itemsToBuy = abi.decode(_args.externalCall.data, (ICollectionStore.ItemToBuy[]));

                // We check that there is at least one item to buy.
                if (itemsToBuy.length == 0) {
                    revert InvalidAssetsLength();
                }

                for (uint256 i = 0; i < itemsToBuy.length; i++) {
                    ICollectionStore.ItemToBuy memory itemToBuy = itemsToBuy[i];

                    // We check that the collection has been created by a CollectionFactory and has not been deployed randomly by a malicious actor.
                    _verifyDecentralandCollection(itemToBuy.collection);
                }
            }
            // Custom external call.
            // If the target does not match with any of the coded targets, it is considered a custom external call.
            // These calls can only be performed if they have been allowed by the owner beforehand and have to be signed by a special address.
            else {
                // Check that the external call has been allowed.
                if (!allowedCustomExternalCalls[_args.externalCall.target][_args.externalCall.selector]) {
                    revert CustomExternalCallNotAllowed(_args.externalCall.target, _args.externalCall.selector);
                }

                // Check that the external call has not expired.
                if (_args.externalCall.expiresAt != 0 && block.timestamp > _args.externalCall.expiresAt) {
                    revert CustomExternalCallExpired(_args.externalCall.expiresAt);
                }

                bytes32 hashedCustomExternalCallSignature = keccak256(_args.customExternalCallSignature);

                // Check that the external call has not been used yet.
                if (usedCustomExternalCallSignature[hashedCustomExternalCallSignature]) {
                    revert UsedCustomExternalCallSignature(hashedCustomExternalCallSignature);
                }

                // Mark the external call as used.
                usedCustomExternalCallSignature[hashedCustomExternalCallSignature] = true;

                // Recover the signer of the external call.
                address recoveredSigner =
                    keccak256(abi.encode(creditsConsumer, block.chainid, self, _args.externalCall)).recover(_args.customExternalCallSignature);

                // Check that the signer of the external call has the external call signer role.
                if (!hasRole(EXTERNAL_CALL_SIGNER_ROLE, recoveredSigner)) {
                    revert InvalidCustomExternalCallSignature(recoveredSigner);
                }
            }
        }

        // Check if the consumer has been denied from using credits.
        if (isDenied[creditsConsumer]) {
            revert DeniedUser(creditsConsumer);
        }

        // Transfer the mana the consumer is willing to pay from their wallet to this contract.
        // The consumer will be returned any exceeding amount that was not needed to cover the uncredited amount.
        mana.safeTransferFrom(creditsConsumer, self, _args.maxUncreditedValue);

        // Approves the combined amount of credited and uncredited mana the consumer is willing to pay.
        mana.forceApprove(_args.externalCall.target, _args.maxUncreditedValue + _args.maxCreditedValue);

        // Store the mana balance before the external call.
        uint256 balanceBefore = mana.balanceOf(self);

        // Execute the external call.
        (bool success,) = _args.externalCall.target.call(abi.encodeWithSelector(_args.externalCall.selector, _args.externalCall.data));

        if (!success) {
            revert ExternalCallFailed(_args.externalCall);
        }

        // Handle post execution logic for different targets.
        //
        // Legacy Marketplace.
        if (_args.externalCall.target == legacyMarketplace) {
            (address contractAddress, uint256 tokenId) = abi.decode(_args.externalCall.data, (address, uint256));

            // When an order is executed, the asset is transferred to the caller, which in this case is this contract.
            // We need to transfer the asset back to the user that is using the credits.
            IERC721(contractAddress).safeTransferFrom(address(this), creditsConsumer, tokenId);
        }
        // Offchain Marketplace.
        else if (_args.externalCall.target == marketplace && tempBidCreditsSignaturesHash != bytes32(0)) {
            // To recover some gas after the bid has been executed, we reset the value back to default.
            delete tempBidCreditsSignaturesHash;
        }

        // Store how much MANA was transferred out of the contract after the external call.
        uint256 manaTransferred = balanceBefore - mana.balanceOf(self);

        // Check that mana was transferred out of the contract.
        if (manaTransferred == 0) {
            revert NoMANATransfer();
        }

        // Reset the approval back to 0 in case the amount allowed this hour was more than required.
        mana.forceApprove(_args.externalCall.target, 0);

        // Keeps track of how much MANA is credited by the credits.
        uint256 creditedValue = 0;

        for (uint256 i = 0; i < _args.credits.length; i++) {
            Credit calldata credit = _args.credits[i];

            if (credit.value == 0) {
                revert InvalidCreditValue();
            }

            bytes calldata signature = _args.creditsSignatures[i];

            bytes32 signatureHash = keccak256(signature);

            // Check that the credit has not expired.
            if (block.timestamp > credit.expiresAt) {
                revert CreditExpired(signatureHash);
            }

            // Check that the credit has not been revoked.
            if (isRevoked[signatureHash]) {
                revert RevokedCredit(signatureHash);
            }

            address recoveredSigner = keccak256(abi.encode(creditsConsumer, block.chainid, self, credit)).recover(signature);

            // Check that the signature has been signed by the signer role.
            if (!hasRole(SIGNER_ROLE, recoveredSigner)) {
                revert InvalidSignature(signatureHash, recoveredSigner);
            }

            // Calculate how much of the credit is left to be spent.
            uint256 creditRemainingValue = credit.value - spentValue[signatureHash];

            // If the credit has been completely spent, skip it.
            // This is to prevent bids from failing if they contain credits that were consumed on previous calls.
            if (creditRemainingValue == 0) {
                continue;
            }

            // Calculate how much MANA is left to be credited from the total MANA transferred in the external call.
            uint256 uncreditedValue = manaTransferred - creditedValue;

            // Calculate how much of the credit to spend.
            // If the value of the credit is higher than the required amount, only spend the required amount and leave the rest for future calls.
            uint256 creditValueToSpend = uncreditedValue < creditRemainingValue ? uncreditedValue : creditRemainingValue;

            // Increment the amount consumed from the credit.
            spentValue[signatureHash] += creditValueToSpend;

            // Increment the amount of MANA credited.
            creditedValue += creditValueToSpend;

            emit CreditUsed(signatureHash, credit, creditValueToSpend);

            // If enough credits have been spent, break out of the loop so it doesn't iterate over the remaining credits.
            if (creditedValue == manaTransferred) {
                break;
            }
        }

        // Checks that something was credited.
        // It could happen that all provided credits were already spent.
        if (creditedValue == 0) {
            revert CreditedValueZero();
        }

        // Checks that the amount of MANA credited is not higher than the maximum amount allowed.
        if (creditedValue > _args.maxCreditedValue) {
            revert MaxCreditedValueExceeded(creditedValue, _args.maxCreditedValue);
        }

        if (tempMaxCreditedValue != 0) {
            // Resets the value back to default to optimize gas.
            delete tempMaxCreditedValue;
        }

        uint256 currentHour = block.timestamp / 1 hours;
        uint256 creditableManaThisHour;

        // Calculates how much mana could be credited this hour.
        if (currentHour != hourOfLastManaCredit) {
            // If the current hour is different than the one of the last execution, resets the values.
            manaCreditedThisHour = 0;
            hourOfLastManaCredit = currentHour;

            // This new hour allows the maximum amount to be credited.
            creditableManaThisHour = maxManaCreditedPerHour;
        } else {
            // If it is the same hour, the max creditable amount has to consider the amount already credited.
            creditableManaThisHour = maxManaCreditedPerHour - manaCreditedThisHour;
        }

        // If the credited amount in this transaction is higher than the allowed this hour, it reverts.
        if (creditedValue > creditableManaThisHour) {
            revert MaxManaCreditedPerHourExceeded(creditableManaThisHour, creditedValue);
        }

        // Increase the amount of mana credited this hour.
        manaCreditedThisHour += creditedValue;

        // Calculate how much mana was not covered by credits.
        uint256 uncredited = manaTransferred - creditedValue;

        // If the credits could not amount to the total MANA transferred, the user has to pay back the difference to the contract.
        if (uncredited > 0) {
            // The transaction reverts if the amount defined by the user is lower than the amount that couldn't be credited.
            if (uncredited > _args.maxUncreditedValue) {
                revert MaxUncreditedValueExceeded(uncredited, _args.maxUncreditedValue);
            }

            if (tempMaxUncreditedValue != 0) {
                // Resets the value back to default to optimize gas.
                delete tempMaxUncreditedValue;
            }
        }

        // If the amount that was not covered by credits is less than the maximum allowed by the consumer, transfer the difference back to the consumer.
        if (uncredited < _args.maxUncreditedValue) {
            mana.safeTransfer(creditsConsumer, _args.maxUncreditedValue - uncredited);
        }

        emit CreditsUsed(manaTransferred, creditedValue);
    }

    /// @notice Function used by the Marketplace to verify that the credits being used have been validated by the bid signer.
    /// @param _caller The address of the user that has called the Marketplace (Has to be this contract).
    /// @param _data The data of the external check.
    /// Data which should be composed of:
    /// - The hash of the signatures of the Credits to be used.
    /// - The maximum amount of MANA the bidder is willing to pay from their wallet when credits are insufficient to cover the total transaction cost.
    /// - The maximum amount of MANA that can be credited from the provided credits.
    function bidExternalCheck(address _caller, bytes calldata _data) external view returns (bool) {
        (bytes32 bidCreditsSignaturesHash, uint256 maxUncreditedValue, uint256 maxCreditedValue) = abi.decode(_data, (bytes32, uint256, uint256));

        return _caller == address(this) && bidCreditsSignaturesHash == tempBidCreditsSignaturesHash && maxUncreditedValue == tempMaxUncreditedValue
            && maxCreditedValue == tempMaxCreditedValue;
    }

    /// @dev This is to update the maximum amount of MANA that can be credited per hour.
    function _updateMaxManaCreditedPerHour(uint256 _maxManaCreditedPerHour) internal {
        maxManaCreditedPerHour = _maxManaCreditedPerHour;

        emit MaxManaCreditedPerHourUpdated(_maxManaCreditedPerHour);
    }

    /// @dev Updates whether primary sales are allowed.
    /// @param _primarySalesAllowed Whether primary sales are allowed.
    function _updatePrimarySalesAllowed(bool _primarySalesAllowed) internal {
        primarySalesAllowed = _primarySalesAllowed;

        emit PrimarySalesAllowedUpdated(_primarySalesAllowed);
    }

    /// @dev Updates whether secondary sales are allowed.
    /// @param _secondarySalesAllowed Whether secondary sales are allowed.
    function _updateSecondarySalesAllowed(bool _secondarySalesAllowed) internal {
        secondarySalesAllowed = _secondarySalesAllowed;

        emit SecondarySalesAllowedUpdated(_secondarySalesAllowed);
    }

    /// @dev Updates whether bids are allowed.
    /// @param _bidsAllowed Whether bids are allowed.
    function _updateBidsAllowed(bool _bidsAllowed) internal {
        bidsAllowed = _bidsAllowed;

        emit BidsAllowedUpdated(_bidsAllowed);
    }

    /// @dev This is used to prevent users from consuming credits on non-decentraland collections.
    function _verifyDecentralandCollection(address _contractAddress) internal view {
        if (!collectionFactory.isCollectionFromFactory(_contractAddress) && !collectionFactoryV3.isCollectionFromFactory(_contractAddress)) {
            revert NotDecentralandCollection(_contractAddress);
        }
    }

    /// @dev This is to support meta-transactions.
    function _msgSender() internal view override returns (address) {
        return _getMsgSender();
    }
}
