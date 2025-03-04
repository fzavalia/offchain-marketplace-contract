// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IERC721} from "@openzeppelin/contracts/token/ERC721/IERC721.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {CreditsManagerPolygon} from "src/credits/CreditsManagerPolygon.sol";
import {ICollectionFactory} from "src/credits/interfaces/ICollectionFactory.sol";

contract CreditsManagerPolygonHarness is CreditsManagerPolygon {
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
    )
        CreditsManagerPolygon(
            _roles,
            _maxManaCreditedPerHour,
            _primarySalesAllowed,
            _secondarySalesAllowed,
            _bidsAllowed,
            _mana,
            _marketplace,
            _legacyMarketplace,
            _collectionStore,
            _collectionFactory,
            _collectionFactoryV3
        )
    {}

    function updateTempBidCreditsSignaturesHash(bytes32 _tempBidCreditsSignaturesHash) external {
        tempBidCreditsSignaturesHash = _tempBidCreditsSignaturesHash;
    }

    function updateTempMaxUncreditedValue(uint256 _tempMaxUncreditedValue) external {
        tempMaxUncreditedValue = _tempMaxUncreditedValue;
    }

    function updateTempMaxCreditedValue(uint256 _tempMaxCreditedValue) external {
        tempMaxCreditedValue = _tempMaxCreditedValue;
    }
}

contract MockExternalCallTarget {
    CreditsManagerPolygonHarness public creditsManager;
    IERC20 public mana;
    uint256 public amount;

    constructor(CreditsManagerPolygonHarness _creditsManager, IERC20 _mana, uint256 _amount) {
        creditsManager = _creditsManager;
        mana = _mana;
        amount = _amount;
    }

    function someFunction() external {
        mana.transferFrom(address(creditsManager), address(this), amount);
    }
}

contract CreditsManagerPolygonTestBase is Test {
    address internal owner;
    address internal signer;
    uint256 internal signerPk;
    address internal pauser;
    address internal denier;
    address internal revoker;
    address internal customExternalCallSigner;
    uint256 internal customExternalCallSignerPk;
    address internal customExternalCallRevoker;
    address internal mana;
    uint256 internal maxManaCreditedPerHour;
    bool internal primarySalesAllowed;
    bool internal secondarySalesAllowed;
    bool internal bidsAllowed;
    address internal marketplace;
    address internal legacyMarketplace;
    address internal collectionStore;
    address internal collectionFactory;
    address internal collectionFactoryV3;

    CreditsManagerPolygonHarness internal creditsManager;

    address internal manaHolder;

    address internal collection;
    uint256 internal collectionTokenId;
    address internal collectionOwner;

    address internal other;

    event UserDenied(address indexed _user);
    event UserAllowed(address indexed _user);
    event CreditRevoked(bytes32 indexed _creditId);
    event MaxManaCreditedPerHourUpdated(uint256 _maxManaCreditedPerHour);
    event PrimarySalesAllowedUpdated(bool _primarySalesAllowed);
    event SecondarySalesAllowedUpdated(bool _secondarySalesAllowed);
    event BidsAllowedUpdated(bool _bidsAllowed);
    event CustomExternalCallAllowed(address indexed _target, bytes4 indexed _selector, bool _allowed);
    event CustomExternalCallRevoked(bytes32 indexed _hashedExternalCallSignature);
    event CreditUsed(bytes32 indexed _creditId, CreditsManagerPolygon.Credit _credit, uint256 _value);
    event CreditsUsed(uint256 _manaTransferred, uint256 _creditedValue);
    event ERC20Withdrawn(address indexed _token, uint256 _amount, address indexed _to);
    event ERC721Withdrawn(address indexed _collection, uint256 _tokenId, address indexed _to);

    function setUp() public {
        vm.selectFork(vm.createFork("https://rpc.decentraland.org/polygon"));

        owner = makeAddr("owner");
        (signer, signerPk) = makeAddrAndKey("signer");
        pauser = makeAddr("pauser");
        denier = makeAddr("denier");
        revoker = makeAddr("revoker");
        (customExternalCallSigner, customExternalCallSignerPk) = makeAddrAndKey("customExternalCallSigner");
        customExternalCallRevoker = makeAddr("customExternalCallRevoker");

        CreditsManagerPolygon.Roles memory roles = CreditsManagerPolygon.Roles({
            owner: owner,
            signer: signer,
            pauser: pauser,
            denier: denier,
            revoker: revoker,
            customExternalCallSigner: customExternalCallSigner,
            customExternalCallRevoker: customExternalCallRevoker
        });

        mana = 0xA1c57f48F0Deb89f569dFbE6E2B7f46D33606fD4;
        maxManaCreditedPerHour = 100 ether;
        primarySalesAllowed = true;
        secondarySalesAllowed = true;
        bidsAllowed = true;
        marketplace = 0x540fb08eDb56AaE562864B390542C97F562825BA;
        legacyMarketplace = 0x480a0f4e360E8964e68858Dd231c2922f1df45Ef;
        collectionStore = 0x214ffC0f0103735728dc66b61A22e4F163e275ae;
        collectionFactory = 0xB549B2442b2BD0a53795BC5cDcBFE0cAF7ACA9f8;
        collectionFactoryV3 = 0x3195e88aE10704b359764CB38e429D24f1c2f781;

        creditsManager = new CreditsManagerPolygonHarness(
            roles,
            maxManaCreditedPerHour,
            primarySalesAllowed,
            secondarySalesAllowed,
            bidsAllowed,
            IERC20(mana),
            marketplace,
            legacyMarketplace,
            collectionStore,
            ICollectionFactory(collectionFactory),
            ICollectionFactory(collectionFactoryV3)
        );

        manaHolder = 0xB08E3e7cc815213304d884C88cA476ebC50EaAB2;

        collection = 0xdD30F60f92F0BE0920e4D6dC4f696E3F6eC3e9ae;
        collectionTokenId = 1;
        collectionOwner = IERC721(collection).ownerOf(collectionTokenId);

        other = makeAddr("other");
    }
}

contract CreditsManagerPolygonCoreTest is CreditsManagerPolygonTestBase {
    function test_constructor() public view {
        assertEq(creditsManager.hasRole(creditsManager.DEFAULT_ADMIN_ROLE(), owner), true);
        assertEq(creditsManager.hasRole(creditsManager.SIGNER_ROLE(), signer), true);
        assertEq(creditsManager.hasRole(creditsManager.PAUSER_ROLE(), pauser), true);
        assertEq(creditsManager.hasRole(creditsManager.PAUSER_ROLE(), owner), true);
        assertEq(creditsManager.hasRole(creditsManager.DENIER_ROLE(), denier), true);
        assertEq(creditsManager.hasRole(creditsManager.DENIER_ROLE(), owner), true);
        assertEq(creditsManager.hasRole(creditsManager.REVOKER_ROLE(), revoker), true);
        assertEq(creditsManager.hasRole(creditsManager.REVOKER_ROLE(), owner), true);
        assertEq(creditsManager.hasRole(creditsManager.EXTERNAL_CALL_SIGNER_ROLE(), customExternalCallSigner), true);
        assertEq(creditsManager.hasRole(creditsManager.EXTERNAL_CALL_REVOKER_ROLE(), customExternalCallRevoker), true);
        assertEq(creditsManager.hasRole(creditsManager.EXTERNAL_CALL_REVOKER_ROLE(), owner), true);

        assertEq(creditsManager.maxManaCreditedPerHour(), maxManaCreditedPerHour);
        assertEq(creditsManager.primarySalesAllowed(), primarySalesAllowed);
        assertEq(creditsManager.secondarySalesAllowed(), secondarySalesAllowed);
        assertEq(creditsManager.bidsAllowed(), bidsAllowed);

        assertEq(address(creditsManager.mana()), mana);
        assertEq(creditsManager.marketplace(), marketplace);
        assertEq(creditsManager.legacyMarketplace(), legacyMarketplace);
        assertEq(creditsManager.collectionStore(), collectionStore);
        assertEq(address(creditsManager.collectionFactory()), collectionFactory);
        assertEq(address(creditsManager.collectionFactoryV3()), collectionFactoryV3);
    }

    function test_pause_RevertsWhenNotPauser() public {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.PAUSER_ROLE()));
        creditsManager.pause();
    }

    function test_pause_WhenPauser() public {
        vm.prank(pauser);
        creditsManager.pause();
    }

    function test_pause_WhenOwner() public {
        vm.prank(owner);
        creditsManager.pause();
    }

    function test_unpause_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.unpause();
    }

    function test_unpause_RevertsWhenPauser() public {
        vm.startPrank(pauser);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, pauser, creditsManager.DEFAULT_ADMIN_ROLE()));
        creditsManager.unpause();
        vm.stopPrank();
    }

    function test_unpause_WhenOwner() public {
        vm.startPrank(owner);
        creditsManager.pause();
        creditsManager.unpause();
        vm.stopPrank();
    }

    function test_denyUser_RevertsWhenNotDenier() public {
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DENIER_ROLE()));
        creditsManager.denyUser(address(this));
    }

    function test_denyUser_WhenDenier() public {
        vm.expectEmit(address(creditsManager));
        emit UserDenied(address(this));
        vm.prank(denier);
        creditsManager.denyUser(address(this));
        assertTrue(creditsManager.isDenied(address(this)));
    }

    function test_denyUser_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit UserDenied(address(this));
        vm.prank(owner);
        creditsManager.denyUser(address(this));
        assertTrue(creditsManager.isDenied(address(this)));
    }

    function test_allowUser_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.allowUser(address(this));
    }

    function test_allowUser_RevertsWhenDenier() public {
        vm.startPrank(denier);
        vm.expectRevert(abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, denier, creditsManager.DEFAULT_ADMIN_ROLE()));
        creditsManager.allowUser(address(this));
        vm.stopPrank();
    }

    function test_allowUser_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit UserAllowed(address(this));
        vm.prank(owner);
        creditsManager.allowUser(address(this));
        assertFalse(creditsManager.isDenied(address(this)));
    }

    function test_revokeCredit_RevertsWhenNotRevoker() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.REVOKER_ROLE())
        );
        creditsManager.revokeCredit(bytes32(0));
    }

    function test_revokeCredit_WhenRevoker() public {
        vm.expectEmit(address(creditsManager));
        emit CreditRevoked(bytes32(0));
        vm.prank(revoker);
        creditsManager.revokeCredit(bytes32(0));
        assertTrue(creditsManager.isRevoked(bytes32(0)));
    }

    function test_revokeCredit_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit CreditRevoked(bytes32(0));
        vm.prank(owner);
        creditsManager.revokeCredit(bytes32(0));
        assertTrue(creditsManager.isRevoked(bytes32(0)));
    }

    function test_updateMaxManaCreditedPerHour_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.updateMaxManaCreditedPerHour(maxManaCreditedPerHour);
    }

    function test_updateMaxManaCreditedPerHour_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit MaxManaCreditedPerHourUpdated(1);
        vm.prank(owner);
        creditsManager.updateMaxManaCreditedPerHour(1);
        assertEq(creditsManager.maxManaCreditedPerHour(), 1);
    }

    function test_updatePrimarySalesAllowed_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.updatePrimarySalesAllowed(primarySalesAllowed);
    }

    function test_updatePrimarySalesAllowed_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit PrimarySalesAllowedUpdated(false);
        vm.prank(owner);
        creditsManager.updatePrimarySalesAllowed(false);
        assertEq(creditsManager.primarySalesAllowed(), false);

        vm.expectEmit(address(creditsManager));
        emit PrimarySalesAllowedUpdated(true);
        vm.prank(owner);
        creditsManager.updatePrimarySalesAllowed(true);
        assertEq(creditsManager.primarySalesAllowed(), true);
    }

    function test_updateSecondarySalesAllowed_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.updateSecondarySalesAllowed(secondarySalesAllowed);
    }

    function test_updateSecondarySalesAllowed_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit SecondarySalesAllowedUpdated(false);
        vm.prank(owner);
        creditsManager.updateSecondarySalesAllowed(false);
        assertEq(creditsManager.secondarySalesAllowed(), false);

        vm.expectEmit(address(creditsManager));
        emit SecondarySalesAllowedUpdated(true);
        vm.prank(owner);
        creditsManager.updateSecondarySalesAllowed(true);
        assertEq(creditsManager.secondarySalesAllowed(), true);
    }

    function test_updateBidsAllowed_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.updateBidsAllowed(bidsAllowed);
    }

    function test_updateBidsAllowed_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit BidsAllowedUpdated(false);
        vm.prank(owner);
        creditsManager.updateBidsAllowed(false);
        assertEq(creditsManager.bidsAllowed(), false);

        vm.expectEmit(address(creditsManager));
        emit BidsAllowedUpdated(true);
        vm.prank(owner);
        creditsManager.updateBidsAllowed(true);
        assertEq(creditsManager.bidsAllowed(), true);
    }

    function test_bidExternalCheck_ReturnsFalseWhenNotSelf() public view {
        bytes memory data = abi.encode(bytes32(uint256(1)), uint256(2), uint256(3));
        assertFalse(creditsManager.bidExternalCheck(address(this), data));
    }

    function test_bidExternalCheck_ReturnsFalseWhenCreditsSignaturesHashIsDifferent() public {
        bytes32 bidCreditsSignaturesHash = bytes32(uint256(1));
        uint256 maxUncreditedValue = 2;
        uint256 maxCreditedValue = 3;

        creditsManager.updateTempBidCreditsSignaturesHash(bidCreditsSignaturesHash);
        creditsManager.updateTempMaxUncreditedValue(maxUncreditedValue);
        creditsManager.updateTempMaxCreditedValue(maxCreditedValue);

        bytes memory data = abi.encode(bytes32(uint256(0)), maxUncreditedValue, maxCreditedValue);
        assertFalse(creditsManager.bidExternalCheck(address(creditsManager), data));
    }

    function test_bidExternalCheck_ReturnsFalseWhenMaxUncreditedValueIsDifferent() public {
        bytes32 bidCreditsSignaturesHash = bytes32(uint256(1));
        uint256 maxUncreditedValue = 2;
        uint256 maxCreditedValue = 3;

        creditsManager.updateTempBidCreditsSignaturesHash(bidCreditsSignaturesHash);
        creditsManager.updateTempMaxUncreditedValue(maxUncreditedValue);
        creditsManager.updateTempMaxCreditedValue(maxCreditedValue);

        bytes memory data = abi.encode(bidCreditsSignaturesHash, 0, maxCreditedValue);
        assertFalse(creditsManager.bidExternalCheck(address(creditsManager), data));
    }

    function test_bidExternalCheck_ReturnsFalseWhenMaxCreditedValueIsDifferent() public {
        bytes32 bidCreditsSignaturesHash = bytes32(uint256(1));
        uint256 maxUncreditedValue = 2;
        uint256 maxCreditedValue = 3;

        creditsManager.updateTempBidCreditsSignaturesHash(bidCreditsSignaturesHash);
        creditsManager.updateTempMaxUncreditedValue(maxUncreditedValue);
        creditsManager.updateTempMaxCreditedValue(maxCreditedValue);

        bytes memory data = abi.encode(bidCreditsSignaturesHash, maxUncreditedValue, 0);
        assertFalse(creditsManager.bidExternalCheck(address(creditsManager), data));
    }

    function test_bidExternalCheck_ReturnsTrueWhenAllValuesAreSame() public {
        bytes32 bidCreditsSignaturesHash = bytes32(uint256(1));
        uint256 maxUncreditedValue = 2;
        uint256 maxCreditedValue = 3;

        creditsManager.updateTempBidCreditsSignaturesHash(bidCreditsSignaturesHash);
        creditsManager.updateTempMaxUncreditedValue(maxUncreditedValue);
        creditsManager.updateTempMaxCreditedValue(maxCreditedValue);

        bytes memory data = abi.encode(bidCreditsSignaturesHash, maxUncreditedValue, maxCreditedValue);
        assertTrue(creditsManager.bidExternalCheck(address(creditsManager), data));
    }

    function test_allowCustomExternalCall_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.allowCustomExternalCall(address(this), bytes4(0), true);
    }

    function test_allowCustomExternalCall_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit CustomExternalCallAllowed(address(this), bytes4(0), true);
        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(this), bytes4(0), true);
    }

    function test_revokeCustomExternalCall_RevertsWhenNotCustomExternalCallRevoker() public {
        vm.expectRevert(
            abi.encodeWithSelector(
                IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.EXTERNAL_CALL_REVOKER_ROLE()
            )
        );
        creditsManager.revokeCustomExternalCall(bytes32(0));
    }

    function test_revokeCustomExternalCall_WhenCustomExternalCallRevoker() public {
        vm.expectEmit(address(creditsManager));
        emit CustomExternalCallRevoked(bytes32(0));
        vm.prank(customExternalCallRevoker);
        creditsManager.revokeCustomExternalCall(bytes32(0));

        assertTrue(creditsManager.usedCustomExternalCallSignature(bytes32(0)));
    }

    function test_revokeCustomExternalCall_WhenOwner() public {
        vm.expectEmit(address(creditsManager));
        emit CustomExternalCallRevoked(bytes32(0));
        vm.prank(owner);
        creditsManager.revokeCustomExternalCall(bytes32(0));

        assertTrue(creditsManager.usedCustomExternalCallSignature(bytes32(0)));
    }

    function test_withdrawERC20_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.withdrawERC20(address(mana), 1 ether, address(this));
    }

    function test_withdrawERC20_WhenOwner() public {
        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        uint256 creditsManagerBalanceBefore = IERC20(mana).balanceOf(address(creditsManager));

        vm.expectEmit(address(creditsManager));
        emit ERC20Withdrawn(address(mana), 1 ether, owner);
        vm.prank(owner);
        creditsManager.withdrawERC20(address(mana), 1 ether, owner);

        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 1 ether);
        assertEq(IERC20(mana).balanceOf(owner), 1 ether);

        vm.expectEmit(address(creditsManager));
        emit ERC20Withdrawn(address(mana), 1 ether, address(this));
        vm.prank(owner);
        creditsManager.withdrawERC20(address(mana), 1 ether, address(this));

        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 2 ether);
        assertEq(IERC20(mana).balanceOf(address(this)), 1 ether);
    }

    function test_withdrawERC721_RevertsWhenNotOwner() public {
        vm.expectRevert(
            abi.encodeWithSelector(IAccessControl.AccessControlUnauthorizedAccount.selector, address(this), creditsManager.DEFAULT_ADMIN_ROLE())
        );
        creditsManager.withdrawERC721(collection, collectionTokenId, address(this));
    }

    function test_withdrawERC721_WhenOwner() public {
        vm.prank(collectionOwner);
        IERC721(collection).transferFrom(collectionOwner, address(creditsManager), collectionTokenId);

        assertEq(IERC721(collection).ownerOf(collectionTokenId), address(creditsManager));

        vm.expectEmit(address(creditsManager));
        emit ERC721Withdrawn(collection, collectionTokenId, other);
        vm.prank(owner);
        creditsManager.withdrawERC721(collection, collectionTokenId, other);

        assertEq(IERC721(collection).ownerOf(collectionTokenId), other);
    }
}

contract CreditsManagerPolygonUseCreditsCustomExternalCallTest is CreditsManagerPolygonTestBase {
    function test_useCredits_RevertsWhenNoCredits() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](0);

        bytes[] memory creditsSignatures = new bytes[](0);

        CreditsManagerPolygon.ExternalCall memory externalCall =
            CreditsManagerPolygon.ExternalCall({target: address(this), selector: bytes4(0), data: bytes(""), expiresAt: 0, salt: bytes32(0)});

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 0
        });

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.NoCredits.selector));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditsSignaturesLengthIsDifferentFromCreditsLength() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](0);

        CreditsManagerPolygon.ExternalCall memory externalCall =
            CreditsManagerPolygon.ExternalCall({target: address(this), selector: bytes4(0), data: bytes(""), expiresAt: 0, salt: bytes32(0)});

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 0
        });

        vm.expectRevert(CreditsManagerPolygon.InvalidCreditsSignaturesLength.selector);
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenMaxCreditedValueZero() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        CreditsManagerPolygon.ExternalCall memory externalCall =
            CreditsManagerPolygon.ExternalCall({target: address(this), selector: bytes4(0), data: bytes(""), expiresAt: 0, salt: bytes32(0)});

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 0
        });

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.MaxCreditedValueZero.selector));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCustomExternalCallNotAllowed() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        CreditsManagerPolygon.ExternalCall memory externalCall =
            CreditsManagerPolygon.ExternalCall({target: address(0), selector: bytes4(0), data: bytes(""), expiresAt: 0, salt: bytes32(0)});

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.CustomExternalCallNotAllowed.selector, address(0), bytes4(0)));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCustomExternalCallHasExpired() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        CreditsManagerPolygon.ExternalCall memory externalCall =
            CreditsManagerPolygon.ExternalCall({target: address(0), selector: bytes4(0), data: bytes(""), expiresAt: 0, salt: bytes32(0)});

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(0), bytes4(0), true);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.CustomExternalCallExpired.selector, 0));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCustomExternalCallECDSAInvalidSignatureLength() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(0),
            selector: bytes4(0),
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        bytes memory customExternalCallSignature = bytes("");

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(0), bytes4(0), true);

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 0));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenInvalidCustomExternalCallSignature() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(0),
            selector: bytes4(0),
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid + 1, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(0), bytes4(0), true);

        vm.expectRevert(
            abi.encodeWithSelector(CreditsManagerPolygon.InvalidCustomExternalCallSignature.selector, 0xeCc32Fcec42A961891851b4956374578C918Bc79)
        );
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenNoManaWasTransferred() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 0);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.NoMANATransfer.selector));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenNotEnoughManaWasApproved() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0,
            maxCreditedValue: 1
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.ExternalCallFailed.selector, externalCall));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCallerBalanceIsNotEnough() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.expectRevert("ERC20: transfer amount exceeds balance");
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCallerDidNotApproveEnoughMana() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.expectRevert("ERC20: transfer amount exceeds allowance");
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditsManagerDoesNotHaveEnoughMana() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.ExternalCallFailed.selector, externalCall));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditDoesNotHaveEnoughValue() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 0, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(CreditsManagerPolygon.InvalidCreditValue.selector);
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditIsExpired() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: 0, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.CreditExpired.selector, keccak256(creditsSignatures[0])));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditECDSAInvalidSignatureLength() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(ECDSA.ECDSAInvalidSignatureLength.selector, 0));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditInvalidSignature() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) =
            vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid + 1, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(
            abi.encodeWithSelector(
                CreditsManagerPolygon.InvalidSignature.selector, keccak256(creditsSignatures[0]), 0xcc9A69fee0faf31e970174cFc1FA3075d15eA28C
            )
        );
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenMaxCreditedValueExceeded() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 1 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.MaxCreditedValueExceeded.selector, 100 ether, 1 ether));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenMaxManaCreditedPerHourExceeded() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 101 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 101 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 101 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.MaxManaCreditedPerHourExceeded.selector, 100 ether, 101 ether));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenMaxManaCreditedPerHourExceeded_DifferentCalls() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 200 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 51 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 51 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), type(uint256).max);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        creditsManager.useCredits(args);

        externalCall.salt = bytes32(uint256(1));
        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));
        args.customExternalCallSignature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.MaxManaCreditedPerHourExceeded.selector, 49 ether, 51 ether));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenExecuteCallIsReused() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 200 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 51 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 51 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), type(uint256).max);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        creditsManager.useCredits(args);

        vm.expectRevert(
            abi.encodeWithSelector(CreditsManagerPolygon.UsedCustomExternalCallSignature.selector, keccak256(customExternalCallSignature))
        );
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenUserIsDenied() public {
        vm.prank(denier);
        creditsManager.denyUser(address(this));

        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.DeniedUser.selector, address(this)));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditWasRevoked() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        vm.prank(owner);
        creditsManager.revokeCredit(keccak256(creditsSignatures[0]));

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.RevokedCredit.selector, keccak256(creditsSignatures[0])));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenCreditedValueIsZero() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 200 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        creditsManager.useCredits(args);

        externalCall.salt = bytes32(uint256(1));
        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));
        args.customExternalCallSignature = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.CreditedValueZero.selector));
        creditsManager.useCredits(args);
    }

    function test_useCredits_RevertsWhenMaxUncreditedValueIsExceeded() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 50 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 0 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 50 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 50 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 100 ether);

        vm.expectRevert(abi.encodeWithSelector(CreditsManagerPolygon.MaxUncreditedValueExceeded.selector, 50 ether, 0));
        creditsManager.useCredits(args);
    }

    function test_useCredits_Success() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 100 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        uint256 callerBalanceBefore = IERC20(mana).balanceOf(address(this));
        uint256 creditsManagerBalanceBefore = IERC20(mana).balanceOf(address(creditsManager));
        uint256 externalCallTargetBalanceBefore = IERC20(mana).balanceOf(address(externalCallTarget));

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 0);

        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[0]), credits[0], 100 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditsUsed(100 ether, 100 ether);
        creditsManager.useCredits(args);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 100 ether);

        assertEq(IERC20(mana).balanceOf(address(this)), callerBalanceBefore);
        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 100 ether);
        assertEq(IERC20(mana).balanceOf(address(externalCallTarget)), externalCallTargetBalanceBefore + 100 ether);
    }

    function test_useCredits_Success_MaxManaCreditedPerHourIsResetAfterHour() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](1);

        credits[0] = CreditsManagerPolygon.Credit({value: 200 ether, expiresAt: type(uint256).max, salt: bytes32(0)});

        bytes[] memory creditsSignatures = new bytes[](1);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 200 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        uint256 callerBalanceBefore = IERC20(mana).balanceOf(address(this));
        uint256 creditsManagerBalanceBefore = IERC20(mana).balanceOf(address(creditsManager));
        uint256 externalCallTargetBalanceBefore = IERC20(mana).balanceOf(address(externalCallTarget));

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 0);

        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[0]), credits[0], 100 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditsUsed(100 ether, 100 ether);
        creditsManager.useCredits(args);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 100 ether);

        assertEq(IERC20(mana).balanceOf(address(this)), callerBalanceBefore);
        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 100 ether);
        assertEq(IERC20(mana).balanceOf(address(externalCallTarget)), externalCallTargetBalanceBefore + 100 ether);

        externalCall.salt = bytes32(uint256(1));
        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));
        args.customExternalCallSignature = abi.encodePacked(r, s, v);

        vm.warp(block.timestamp + 1 hours);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 100 ether);

        creditsManager.useCredits(args);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 200 ether);

        assertEq(IERC20(mana).balanceOf(address(this)), callerBalanceBefore);
        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 200 ether);
        assertEq(IERC20(mana).balanceOf(address(externalCallTarget)), externalCallTargetBalanceBefore + 200 ether);
    }

    function test_useCredits_Success_TwoCredits() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](2);

        credits[0] = CreditsManagerPolygon.Credit({value: 50 ether, expiresAt: type(uint256).max, salt: bytes32(0)});
        credits[1] = CreditsManagerPolygon.Credit({value: 50 ether, expiresAt: type(uint256).max, salt: bytes32(uint256(1))});

        bytes[] memory creditsSignatures = new bytes[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[1])));

        creditsSignatures[1] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 0);
        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[1])), 0);

        uint256 callerBalanceBefore = IERC20(mana).balanceOf(address(this));
        uint256 creditsManagerBalanceBefore = IERC20(mana).balanceOf(address(creditsManager));
        uint256 externalCallTargetBalanceBefore = IERC20(mana).balanceOf(address(externalCallTarget));

        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[0]), credits[0], 50 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[1]), credits[1], 50 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditsUsed(100 ether, 100 ether);
        creditsManager.useCredits(args);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 50 ether);
        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[1])), 50 ether);

        assertEq(IERC20(mana).balanceOf(address(this)), callerBalanceBefore);
        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 100 ether);
        assertEq(IERC20(mana).balanceOf(address(externalCallTarget)), externalCallTargetBalanceBefore + 100 ether);
    }

    function test_useCredits_Success_TwoCredits_WithUncreditedValue() public {
        CreditsManagerPolygon.Credit[] memory credits = new CreditsManagerPolygon.Credit[](2);

        credits[0] = CreditsManagerPolygon.Credit({value: 50 ether, expiresAt: type(uint256).max, salt: bytes32(0)});
        credits[1] = CreditsManagerPolygon.Credit({value: 25 ether, expiresAt: type(uint256).max, salt: bytes32(uint256(1))});

        bytes[] memory creditsSignatures = new bytes[](2);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[0])));

        creditsSignatures[0] = abi.encodePacked(r, s, v);

        (v, r, s) = vm.sign(signerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), credits[1])));

        creditsSignatures[1] = abi.encodePacked(r, s, v);

        MockExternalCallTarget externalCallTarget = new MockExternalCallTarget(creditsManager, IERC20(mana), 100 ether);

        CreditsManagerPolygon.ExternalCall memory externalCall = CreditsManagerPolygon.ExternalCall({
            target: address(externalCallTarget),
            selector: externalCallTarget.someFunction.selector,
            data: bytes(""),
            expiresAt: type(uint256).max,
            salt: bytes32(0)
        });

        externalCall.data = abi.encode(bytes32(uint256(0)), uint256(1), uint256(2));

        (v, r, s) = vm.sign(customExternalCallSignerPk, keccak256(abi.encode(address(this), block.chainid, address(creditsManager), externalCall)));

        bytes memory customExternalCallSignature = abi.encodePacked(r, s, v);

        CreditsManagerPolygon.UseCreditsArgs memory args = CreditsManagerPolygon.UseCreditsArgs({
            credits: credits,
            creditsSignatures: creditsSignatures,
            externalCall: externalCall,
            customExternalCallSignature: customExternalCallSignature,
            maxUncreditedValue: 99 ether,
            maxCreditedValue: 100 ether
        });

        vm.prank(owner);
        creditsManager.allowCustomExternalCall(address(externalCallTarget), externalCallTarget.someFunction.selector, true);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(this), 1000 ether);

        vm.prank(address(this));
        IERC20(mana).approve(address(creditsManager), 99 ether);

        vm.prank(manaHolder);
        IERC20(mana).transfer(address(creditsManager), 1000 ether);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 0);
        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[1])), 0);

        uint256 callerBalanceBefore = IERC20(mana).balanceOf(address(this));
        uint256 creditsManagerBalanceBefore = IERC20(mana).balanceOf(address(creditsManager));
        uint256 externalCallTargetBalanceBefore = IERC20(mana).balanceOf(address(externalCallTarget));

        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[0]), credits[0], 50 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditUsed(keccak256(creditsSignatures[1]), credits[1], 25 ether);
        vm.expectEmit(address(creditsManager));
        emit CreditsUsed(100 ether, 75 ether);
        creditsManager.useCredits(args);

        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[0])), 50 ether);
        assertEq(creditsManager.spentValue(keccak256(creditsSignatures[1])), 25 ether);

        assertEq(IERC20(mana).balanceOf(address(this)), callerBalanceBefore - 25 ether);
        assertEq(IERC20(mana).balanceOf(address(creditsManager)), creditsManagerBalanceBefore - 75 ether);
        assertEq(IERC20(mana).balanceOf(address(externalCallTarget)), externalCallTargetBalanceBefore + 100 ether);
    }
}
