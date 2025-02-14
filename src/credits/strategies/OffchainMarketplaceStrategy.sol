// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

import {CreditManagerBase} from "src/credits/CreditManagerBase.sol";
import {MarketplaceWithCouponManager} from "src/marketplace/MarketplaceWithCouponManager.sol";
import {DecentralandMarketplacePolygonAssetTypes} from "src/marketplace/DecentralandMarketplacePolygonAssetTypes.sol";
import {IManaUsdRateProvider} from "src/credits/rates/interfaces/IManaUsdRateProvider.sol";
import {ICoupon} from "src/coupons/interfaces/ICoupon.sol";

abstract contract OffchainMarketplaceStrategy is CreditManagerBase, DecentralandMarketplacePolygonAssetTypes {
    using SafeERC20 for IERC20;

    MarketplaceWithCouponManager public immutable offchainMarketplace;
    IManaUsdRateProvider public immutable manaUsdRateProvider;

    /// @param _offchainMarketplace The offchain marketplace contract.
    /// @param _manaUsdRateProvider The MANA/USD rate provider contract.
    struct OffchainMarketplaceStrategyInit {
        MarketplaceWithCouponManager offchainMarketplace;
        IManaUsdRateProvider manaUsdRateProvider;
    }

    /// @param _init The initialization parameters for the contract.
    constructor(OffchainMarketplaceStrategyInit memory _init) {
        offchainMarketplace = _init.offchainMarketplace;
        manaUsdRateProvider = _init.manaUsdRateProvider;
    }

    function executeOffchainMarketplaceAcceptListing(
        MarketplaceWithCouponManager.Trade[] calldata _trades,
        MarketplaceWithCouponManager.Coupon[] calldata _coupons,
        Credit[] calldata _credits
    ) external nonReentrant {
        _validateListingTrades(_trades);

        uint256 couponsLength = _coupons.length;
        uint256 tradesLength = _trades.length;
        uint256 totalManaToTransfer;

        if (couponsLength == 0) {
            totalManaToTransfer = _computeTotalManaToTransfer(_trades);
        } else {
            MarketplaceWithCouponManager.Trade[] memory tradesWithAppliedCoupons = _trades;

            for (uint256 i = 0; i < tradesLength; i++) {
                address couponAddress = _coupons[i].couponAddress;
                ICoupon coupon = ICoupon(couponAddress);
                tradesWithAppliedCoupons[i] = coupon.applyCoupon(tradesWithAppliedCoupons[i], _coupons[i]);
            }

            totalManaToTransfer = _computeTotalManaToTransfer(tradesWithAppliedCoupons);
        }

        uint256 manaToCredit = _computeTotalManaToCredit(_credits, totalManaToTransfer);

        mana.forceApprove(address(offchainMarketplace), totalManaToTransfer);

        uint256 balanceBefore = mana.balanceOf(address(this));
        MarketplaceWithCouponManager.Trade[] memory tradesWithUpdatedBeneficiaries = _trades;

        for (uint256 i = 0; i < tradesLength; i++) {
            tradesWithUpdatedBeneficiaries[i].received[0].beneficiary = _msgSender();
        }

        if (couponsLength == 0) {
            offchainMarketplace.accept(tradesWithUpdatedBeneficiaries);
        } else {
            offchainMarketplace.acceptWithCoupon(tradesWithUpdatedBeneficiaries, _coupons);
        }

        _validateResultingBalance(balanceBefore, totalManaToTransfer);

        _executeManaTransfers(manaToCredit, totalManaToTransfer);
    }

    function _validateListingTrades(MarketplaceWithCouponManager.Trade[] calldata _trades) private view {
        uint256 tradesLength = _trades.length;

        if (tradesLength == 0) {
            revert("Invalid Trades Length");
        }

        for (uint256 i = 0; i < tradesLength; i++) {
            MarketplaceWithCouponManager.Trade calldata trade = _trades[i];

            _validateManaAssets(trade.received);

            _validateNonManaAssets(trade.sent);
        }
    }

    function _validateBidTrades(MarketplaceWithCouponManager.Trade[] calldata _trades) private view {
        uint256 tradesLength = _trades.length;

        if (tradesLength == 0) {
            revert("Invalid Trades Length");
        }

        for (uint256 i = 0; i < tradesLength; i++) {
            MarketplaceWithCouponManager.Trade calldata trade = _trades[i];

            _validateManaAssets(trade.sent);

            _validateNonManaAssets(trade.received);
        }
    }

    function _validateManaAssets(MarketplaceWithCouponManager.Asset[] calldata _assets) private view {
        if (_assets.length != 1) {
            revert("Invalid Assets Length");
        }

        MarketplaceWithCouponManager.Asset calldata asset = _assets[0];

        if (asset.contractAddress != address(mana)) {
            revert("Invalid Contract Address");
        }

        if (asset.assetType != ASSET_TYPE_ERC20 && asset.assetType != ASSET_TYPE_USD_PEGGED_MANA) {
            revert("Invalid Asset Type");
        }
    }

    function _validateNonManaAssets(MarketplaceWithCouponManager.Asset[] calldata _assets) private view {
        if (_assets.length == 0) {
            revert("Invalid Received Length");
        }

        for (uint256 j = 0; j < _assets.length; j++) {
            MarketplaceWithCouponManager.Asset calldata asset = _assets[j];

            _validateContractAddress(asset.contractAddress);

            if (asset.assetType == ASSET_TYPE_ERC721) {
                _validateSecondarySalesAllowed();
            } else if (asset.assetType == ASSET_TYPE_COLLECTION_ITEM) {
                _validatePrimarySalesAllowed();
            } else {
                revert("Invalid Received Asset Type");
            }
        }
    }

    function _computeTotalManaToTransfer(MarketplaceWithCouponManager.Trade[] memory _trades) private view returns (uint256 totalManaToTransfer) {
        uint256 manaUsdRate = manaUsdRateProvider.getManaUsdRate();

        for (uint256 i = 0; i < _trades.length; i++) {
            MarketplaceWithCouponManager.Asset memory received = _trades[i].received[0];

            if (received.assetType == ASSET_TYPE_ERC20) {
                totalManaToTransfer += received.value;
            } else if (received.assetType == ASSET_TYPE_USD_PEGGED_MANA) {
                totalManaToTransfer += received.value * 1e18 / manaUsdRate;
            }
        }
    }
}
