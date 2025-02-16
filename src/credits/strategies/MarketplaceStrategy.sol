// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {SafeERC20} from "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";

import {CreditManagerBase} from "src/credits/CreditManagerBase.sol";
import {IMarketplace} from "src/credits/interfaces/IMarketplace.sol";

/// @notice Strategy to handle credits for marketplace order execution.
abstract contract MarketplaceStrategy is CreditManagerBase {
    using SafeERC20 for IERC20;

    /// @notice The marketplace contract.
    IMarketplace public immutable marketplace;

    /// @param _marketplace The marketplace contract.
    struct MarketplaceStrategyInit {
        IMarketplace marketplace;
    }

    /// @param _init The initialization parameters for the contract.
    constructor(MarketplaceStrategyInit memory _init) {
        marketplace = _init.marketplace;
    }

    /// @notice Executes a marketplace order applying the credits.
    function executeMarketplaceExecuteOrder(
        address _contractAddress,
        uint256 _tokenId,
        uint256 _price,
        bytes calldata _fingerprint,
        Credit[] calldata _credits
    ) external nonReentrant {
        _validateSecondarySalesAllowed();

        uint256 manaToCredit = _computeTotalManaToCredit(_credits, _price);

        mana.forceApprove(address(marketplace), _price);

        uint256 balanceBefore = mana.balanceOf(address(this));

        if (_fingerprint.length > 0) {
            marketplace.safeExecuteOrder(_contractAddress, _tokenId, _price, _fingerprint);
        } else {
            marketplace.executeOrder(_contractAddress, _tokenId, _price);
        }

        _validateResultingBalance(balanceBefore, _price);

        _transferDiffBackToContract(manaToCredit, _price);

        IERC721(_contractAddress).safeTransferFrom(address(this), _msgSender(), _tokenId);
    }
}
