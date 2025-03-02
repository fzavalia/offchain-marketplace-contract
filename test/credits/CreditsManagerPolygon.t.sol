// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import {Test} from "forge-std/Test.sol";
import {IERC20} from "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import {IAccessControl} from "@openzeppelin/contracts/access/IAccessControl.sol";
import {CreditsManagerPolygon} from "src/credits/CreditsManagerPolygon.sol";
import {ICollectionFactory} from "src/credits/interfaces/ICollectionFactory.sol";

contract CreditsManagerPolygonHarness is CreditsManagerPolygon {
    constructor(
        Roles memory _roles,
        IERC20 _mana,
        uint256 _maxManaCreditedPerHour,
        bool _primarySalesAllowed,
        bool _secondarySalesAllowed,
        bool _bidsAllowed,
        address _marketplace,
        address _legacyMarketplace,
        address _collectionStore,
        ICollectionFactory _collectionFactory,
        ICollectionFactory _collectionFactoryV3
    )
        CreditsManagerPolygon(
            _roles,
            _mana,
            _maxManaCreditedPerHour,
            _primarySalesAllowed,
            _secondarySalesAllowed,
            _bidsAllowed,
            _marketplace,
            _legacyMarketplace,
            _collectionStore,
            _collectionFactory,
            _collectionFactoryV3
        )
    {}
}

contract CreditsManagerPolygonTest is Test {
    address owner;
    address signer;
    address pauser;
    address denier;
    address revoker;
    address customExternalCallSigner;
    address customExternalCallRevoker;
    address mana;
    uint256 maxManaCreditedPerHour;
    bool primarySalesAllowed;
    bool secondarySalesAllowed;
    bool bidsAllowed;
    address marketplace;
    address legacyMarketplace;
    address collectionStore;
    address collectionFactory;
    address collectionFactoryV3;

    CreditsManagerPolygonHarness creditsManager;

    function setUp() public {
        owner = makeAddr("owner");
        signer = makeAddr("signer");
        pauser = makeAddr("pauser");
        denier = makeAddr("denier");
        revoker = makeAddr("revoker");
        customExternalCallSigner = makeAddr("customExternalCallSigner");
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
            IERC20(mana),
            maxManaCreditedPerHour,
            primarySalesAllowed,
            secondarySalesAllowed,
            bidsAllowed,
            marketplace,
            legacyMarketplace,
            collectionStore,
            ICollectionFactory(collectionFactory),
            ICollectionFactory(collectionFactoryV3)
        );
    }

    function test_constructor() public {
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
        vm.prank(denier);
        creditsManager.denyUser(address(this));

        assertTrue(creditsManager.isDenied(address(this)));
    }

    function test_denyUser_WhenOwner() public {
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
        vm.prank(revoker);
        creditsManager.revokeCredit(bytes32(0));

        assertTrue(creditsManager.isRevoked(bytes32(0)));
    }

    function test_revokeCredit_WhenOwner() public {
        vm.prank(owner);
        creditsManager.revokeCredit(bytes32(0));

        assertTrue(creditsManager.isRevoked(bytes32(0)));
    }
}
