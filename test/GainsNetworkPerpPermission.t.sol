// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {GainsNetworkPerpPermission} from "../contracts/templates/GainsNetworkPerpPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract GainsNetworkPerpPermissionTest is Test {
    GainsNetworkPerpPermission perm;

    address constant SAFE          = address(0x5AFE);
    address constant GTRADE_ROUTER = address(0xD111);
    address constant SIGNER        = address(0x5161);
    address constant STRANGER      = address(0x9999);

    uint256 constant PAIR_BTC        = 0;
    uint256 constant PAIR_ETH        = 1;
    uint256 constant PAIR_LINK       = 2;
    uint256 constant PAIR_DISALLOWED = 99;

    uint256 constant MAX_SIZE_DAI = 100_000e18;
    uint256 constant MAX_LEVERAGE = 50;

    // Selectors — recomputed locally to keep the test self-contained
    bytes4 constant OPEN_TRADE_SELECTOR = bytes4(
        keccak256(
            "openTrade((address,uint256,uint256,uint256,uint256,bool,uint256,uint256,uint256),uint8,uint256,uint256,address)"
        )
    );
    bytes4 constant CLOSE_TRADE_SELECTOR = bytes4(keccak256("closeTrade(uint256,uint256)"));

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        uint256[] memory pairs = new uint256[](3);
        pairs[0] = PAIR_BTC;
        pairs[1] = PAIR_ETH;
        pairs[2] = PAIR_LINK;

        perm = new GainsNetworkPerpPermission(
            GTRADE_ROUTER,
            pairs,
            true,           // allowLong
            true,           // allowShort
            MAX_SIZE_DAI,
            MAX_LEVERAGE,
            SIGNER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    struct _Trade {
        address trader;
        uint256 pairIndex;
        uint256 index;
        uint256 positionSizeDai;
        uint256 openPrice;
        bool    buy;
        uint256 leverage;
        uint256 tp;
        uint256 sl;
    }

    function _openTrade(
        address trader,
        uint256 pairIndex,
        uint256 positionSizeDai,
        bool    buy,
        uint256 leverage
    ) internal pure returns (bytes memory) {
        _Trade memory t = _Trade({
            trader:          trader,
            pairIndex:       pairIndex,
            index:           0,
            positionSizeDai: positionSizeDai,
            openPrice:       0,
            buy:             buy,
            leverage:        leverage,
            tp:              0,
            sl:              0
        });
        return abi.encodeWithSelector(
            OPEN_TRADE_SELECTOR,
            t,
            uint8(0),    // _type (MARKET)
            uint256(0),  // spreadReductionId
            uint256(0),  // slippageP
            address(0)   // referral
        );
    }

    function _closeTrade(uint256 pairIndex, uint256 index) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(CLOSE_TRADE_SELECTOR, pairIndex, index);
    }

    function _ctx(bytes memory data) internal pure returns (Context memory) {
        bytes4 sel;
        if (data.length >= 4) assembly { sel := mload(add(data, 32)) }
        return Context({account: SAFE, manager: address(0), target: GTRADE_ROUTER, selector: sel, value: 0});
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsFields() public view {
        assertEq(perm.gTradeRouter(),       GTRADE_ROUTER);
        assertEq(perm.permissionSigner(),   SIGNER);
        assertEq(perm.maxPositionSizeDai(), MAX_SIZE_DAI);
        assertEq(perm.maxLeverageX(),       MAX_LEVERAGE);
        assertTrue(perm.allowLong());
        assertTrue(perm.allowShort());
    }

    function test_Constructor_SetsPairAllowlist() public view {
        assertTrue(perm.isAllowedPair(PAIR_BTC));
        assertTrue(perm.isAllowedPair(PAIR_ETH));
        assertTrue(perm.isAllowedPair(PAIR_LINK));
        assertFalse(perm.isAllowedPair(PAIR_DISALLOWED));
    }

    function test_Constructor_RevertsOnZeroRouter() public {
        uint256[] memory pairs = new uint256[](0);
        vm.expectRevert(GainsNetworkPerpPermission.ZeroAddress.selector);
        new GainsNetworkPerpPermission(address(0), pairs, true, true, MAX_SIZE_DAI, MAX_LEVERAGE, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        uint256[] memory pairs = new uint256[](0);
        vm.expectRevert(GainsNetworkPerpPermission.ZeroAddress.selector);
        new GainsNetworkPerpPermission(GTRADE_ROUTER, pairs, true, true, MAX_SIZE_DAI, MAX_LEVERAGE, address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_GoldenPath_OpenLongBTC() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true, 10);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_OpenShortETH() public view {
        bytes memory data = _openTrade(SAFE, PAIR_ETH, 50_000e18, false, 25);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_CloseTrade() public view {
        bytes memory data = _closeTrade(PAIR_BTC, 0);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 1: target check
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTarget_ReturnsFalse() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true, 10);
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   STRANGER,     // wrong target
            selector: OPEN_TRADE_SELECTOR,
            value:    0
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 2: selector check
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSelector_ReturnsFalse() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", GTRADE_ROUTER, 1e18);
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   GTRADE_ROUTER,
            selector: bytes4(keccak256("approve(address,uint256)")),
            value:    0
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: calldata field checks — openTrade
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongPair_OpenTrade_ReturnsFalse() public view {
        bytes memory data = _openTrade(SAFE, PAIR_DISALLOWED, 10_000e18, true, 10);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_WrongTrader_ReturnsFalse() public view {
        bytes memory data = _openTrade(STRANGER, PAIR_BTC, 10_000e18, true, 10);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_OversizedPosition_ReturnsFalse() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, MAX_SIZE_DAI + 1, true, 10);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_AtSizeCap_ReturnsTrue() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, MAX_SIZE_DAI, true, 10);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_OverLeveraged_ReturnsFalse() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true, MAX_LEVERAGE + 1);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_AtLeverageCap_ReturnsTrue() public view {
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true, MAX_LEVERAGE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_LongBlocked_WhenShortOnly() public {
        // Redeploy with allowLong=false, allowShort=true
        uint256[] memory pairs = new uint256[](1);
        pairs[0] = PAIR_BTC;
        GainsNetworkPerpPermission p = new GainsNetworkPerpPermission(
            GTRADE_ROUTER, pairs, false, true, MAX_SIZE_DAI, MAX_LEVERAGE, SIGNER
        );
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true /* long */, 10);
        assertFalse(p.evaluate(data, _ctx(data)));
    }

    function test_ShortBlocked_WhenLongOnly() public {
        // Redeploy with allowLong=true, allowShort=false
        uint256[] memory pairs = new uint256[](1);
        pairs[0] = PAIR_BTC;
        GainsNetworkPerpPermission p = new GainsNetworkPerpPermission(
            GTRADE_ROUTER, pairs, true, false, MAX_SIZE_DAI, MAX_LEVERAGE, SIGNER
        );
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, false /* short */, 10);
        assertFalse(p.evaluate(data, _ctx(data)));
    }

    function test_LongAllowed_WhenLongOnly() public {
        // Redeploy with allowLong=true, allowShort=false
        uint256[] memory pairs = new uint256[](1);
        pairs[0] = PAIR_BTC;
        GainsNetworkPerpPermission p = new GainsNetworkPerpPermission(
            GTRADE_ROUTER, pairs, true, false, MAX_SIZE_DAI, MAX_LEVERAGE, SIGNER
        );
        bytes memory data = _openTrade(SAFE, PAIR_BTC, 10_000e18, true /* long */, 10);
        assertTrue(p.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: calldata field checks — closeTrade
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongPair_CloseTrade_ReturnsFalse() public view {
        bytes memory data = _closeTrade(PAIR_DISALLOWED, 0);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxPositionSizeDai
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxPositionSizeDai_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxPositionSizeDai(50_000e18);
        assertEq(perm.maxPositionSizeDai(), 50_000e18);
    }

    function test_SetMaxPositionSizeDai_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit GainsNetworkPerpPermission.MaxPositionSizeDaiUpdated(MAX_SIZE_DAI, 50_000e18);
        vm.prank(SIGNER);
        perm.setMaxPositionSizeDai(50_000e18);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxLeverageX
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxLeverageX_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxLeverageX(25);
        assertEq(perm.maxLeverageX(), 25);
    }

    function test_SetMaxLeverageX_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit GainsNetworkPerpPermission.MaxLeverageUpdated(MAX_LEVERAGE, 25);
        vm.prank(SIGNER);
        perm.setMaxLeverageX(25);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Access control
    // ─────────────────────────────────────────────────────────────────────────

    function test_Setter_RevertsIfNotSigner() public {
        vm.prank(STRANGER);
        vm.expectRevert(GainsNetworkPerpPermission.NotPermissionSigner.selector);
        perm.setMaxPositionSizeDai(1e18);

        vm.prank(STRANGER);
        vm.expectRevert(GainsNetworkPerpPermission.NotPermissionSigner.selector);
        perm.setMaxLeverageX(1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Calldata length guards
    // ─────────────────────────────────────────────────────────────────────────

    function test_TooShortCalldata_OpenTrade_ReturnsFalse() public view {
        bytes memory full = _openTrade(SAFE, PAIR_BTC, 10_000e18, true, 10);
        // full.length should be exactly 420; truncate by 1
        assertEq(full.length, 420);
        bytes memory short_ = new bytes(419);
        for (uint256 i; i < 419; i++) short_[i] = full[i];
        // Build context using the selector from the full calldata
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   GTRADE_ROUTER,
            selector: OPEN_TRADE_SELECTOR,
            value:    0
        });
        assertFalse(perm.evaluate(short_, ctx));
    }

    function test_TooShortCalldata_CloseTrade_ReturnsFalse() public view {
        bytes memory full = _closeTrade(PAIR_BTC, 0);
        // full.length should be exactly 68; truncate by 1
        assertEq(full.length, 68);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   GTRADE_ROUTER,
            selector: CLOSE_TRADE_SELECTOR,
            value:    0
        });
        assertFalse(perm.evaluate(short_, ctx));
    }
}
