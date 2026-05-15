// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SynthetixPerpPermission} from "../contracts/templates/SynthetixPerpPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";

contract SynthetixPerpPermissionTest is Test {
    SynthetixPerpPermission perm;

    address constant SAFE        = address(0x5AFE);
    address constant PERPS_PROXY = address(0xD111);
    address constant SIGNER      = address(0x5161);
    address constant STRANGER    = address(0x9999);

    uint128 constant MARKET_BTC        = uint128(100);
    uint128 constant MARKET_ETH        = uint128(200);
    uint128 constant MARKET_LINK       = uint128(300);
    uint128 constant MARKET_DISALLOWED = uint128(999);

    uint128 constant SYNTH_SUSD       = uint128(0);
    uint128 constant SYNTH_ETH        = uint128(1);
    uint128 constant SYNTH_DISALLOWED = uint128(99);

    int128  constant MAX_SIZE = int128(10_000e18);

    bytes4 private constant COMMIT_ORDER_SELECTOR =
        bytes4(keccak256("commitOrder(uint128,uint128,int128,uint128,uint256,bytes32,address)"));

    bytes4 private constant MODIFY_COLLATERAL_SELECTOR =
        bytes4(keccak256("modifyCollateral(uint128,uint128,int256)"));

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        uint128[] memory markets = new uint128[](3);
        markets[0] = MARKET_BTC;
        markets[1] = MARKET_ETH;
        markets[2] = MARKET_LINK;

        uint128[] memory synths = new uint128[](2);
        synths[0] = SYNTH_SUSD;
        synths[1] = SYNTH_ETH;

        perm = new SynthetixPerpPermission(
            PERPS_PROXY,
            markets,
            MAX_SIZE,
            true,  // allowLong
            true,  // allowShort
            synths,
            SIGNER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _commitOrder(uint128 marketId, int128 sizeDelta) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            COMMIT_ORDER_SELECTOR,
            uint128(0),    // accountId
            marketId,
            sizeDelta,
            uint128(0),    // settlementStrategyId
            uint256(0),    // acceptablePrice
            bytes32(0),    // trackingCode
            address(0)     // referrer
        );
    }

    function _modifyCollateral(uint128 synthMarketId, int256 amountDelta) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            MODIFY_COLLATERAL_SELECTOR,
            uint128(0),   // accountId
            synthMarketId,
            amountDelta
        );
    }

    function _ctx(bytes memory data) internal pure returns (Context memory) {
        bytes4 sel;
        if (data.length >= 4) assembly { sel := mload(add(data, 32)) }
        return Context({account: SAFE, manager: address(0), target: PERPS_PROXY, selector: sel, value: 0});
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsFields() public view {
        assertEq(perm.perpsMarketProxy(),     PERPS_PROXY);
        assertEq(perm.permissionSigner(),     SIGNER);
        assertEq(perm.maxAbsoluteSizeDelta(), MAX_SIZE);
        assertTrue(perm.allowLong());
        assertTrue(perm.allowShort());
    }

    function test_Constructor_SetsMarketAllowlist() public view {
        assertTrue(perm.isAllowedMarket(MARKET_BTC));
        assertTrue(perm.isAllowedMarket(MARKET_ETH));
        assertTrue(perm.isAllowedMarket(MARKET_LINK));
        assertFalse(perm.isAllowedMarket(MARKET_DISALLOWED));
    }

    function test_Constructor_SetsSynthMarketAllowlist() public view {
        assertTrue(perm.isAllowedSynthMarket(SYNTH_SUSD));
        assertTrue(perm.isAllowedSynthMarket(SYNTH_ETH));
        assertFalse(perm.isAllowedSynthMarket(SYNTH_DISALLOWED));
    }

    function test_Constructor_RevertsOnZeroProxy() public {
        uint128[] memory markets = new uint128[](0);
        uint128[] memory synths  = new uint128[](0);
        vm.expectRevert(SynthetixPerpPermission.ZeroAddress.selector);
        new SynthetixPerpPermission(address(0), markets, MAX_SIZE, true, true, synths, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        uint128[] memory markets = new uint128[](0);
        uint128[] memory synths  = new uint128[](0);
        vm.expectRevert(SynthetixPerpPermission.ZeroAddress.selector);
        new SynthetixPerpPermission(PERPS_PROXY, markets, MAX_SIZE, true, true, synths, address(0));
    }

    function test_Constructor_RevertsOnNegativeMaxSize() public {
        uint128[] memory markets = new uint128[](0);
        uint128[] memory synths  = new uint128[](0);
        vm.expectRevert(SynthetixPerpPermission.NegativeMaxSizeDelta.selector);
        new SynthetixPerpPermission(PERPS_PROXY, markets, int128(-1), true, true, synths, SIGNER);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_GoldenPath_CommitLong() public view {
        bytes memory data = _commitOrder(MARKET_BTC, MAX_SIZE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_CommitShort() public view {
        bytes memory data = _commitOrder(MARKET_ETH, -(MAX_SIZE / 2));
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_ModifyCollateral_AddSUSD() public view {
        bytes memory data = _modifyCollateral(SYNTH_SUSD, 100e18);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_ModifyCollateral_AddETH() public view {
        bytes memory data = _modifyCollateral(SYNTH_ETH, 1e18);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 1: wrong target
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTarget_ReturnsFalse() public view {
        bytes memory data = _commitOrder(MARKET_BTC, MAX_SIZE);
        bytes4 sel;
        assembly { sel := mload(add(data, 32)) }
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   address(0xDEAD),
            selector: sel,
            value:    0
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 2: wrong selector
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSelector_ReturnsFalse() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", PERPS_PROXY, 1e18);
        bytes4 sel;
        assembly { sel := mload(add(data, 32)) }
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   PERPS_PROXY,
            selector: sel,
            value:    0
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3a: commitOrder blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongMarket_CommitOrder_ReturnsFalse() public view {
        bytes memory data = _commitOrder(MARKET_DISALLOWED, MAX_SIZE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_OversizedLong_ReturnsFalse() public view {
        bytes memory data = _commitOrder(MARKET_BTC, MAX_SIZE + 1);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_OversizedShort_ReturnsFalse() public view {
        bytes memory data = _commitOrder(MARKET_BTC, -(MAX_SIZE + 1));
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_AtSizeCap_ReturnsTrue() public view {
        bytes memory data = _commitOrder(MARKET_BTC, MAX_SIZE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_AtNegativeSizeCap_ReturnsTrue() public view {
        bytes memory data = _commitOrder(MARKET_BTC, -MAX_SIZE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_LongBlocked_WhenShortOnly() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);
        bytes memory data = _commitOrder(MARKET_BTC, int128(1e18));
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ShortBlocked_WhenLongOnly() public {
        vm.prank(SIGNER);
        perm.setDirection(true, false);
        bytes memory data = _commitOrder(MARKET_BTC, -int128(1e18));
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3b: modifyCollateral blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSynthMarket_ModifyCollateral_ReturnsFalse() public view {
        bytes memory data = _modifyCollateral(SYNTH_DISALLOWED, 100e18);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxAbsoluteSizeDelta
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxSizeDelta_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxAbsoluteSizeDelta(int128(500e18));
        assertEq(perm.maxAbsoluteSizeDelta(), int128(500e18));
    }

    function test_SetMaxSizeDelta_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit SynthetixPerpPermission.MaxSizeDeltaUpdated(MAX_SIZE, int128(500e18));
        vm.prank(SIGNER);
        perm.setMaxAbsoluteSizeDelta(int128(500e18));
    }

    function test_SetMaxSizeDelta_RevertsIfNegative() public {
        vm.prank(SIGNER);
        vm.expectRevert(SynthetixPerpPermission.NegativeMaxSizeDelta.selector);
        perm.setMaxAbsoluteSizeDelta(int128(-1));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setDirection
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetDirection_Updates() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);
        assertFalse(perm.allowLong());
        assertTrue(perm.allowShort());
    }

    function test_SetDirection_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit SynthetixPerpPermission.DirectionUpdated(false, true);
        vm.prank(SIGNER);
        perm.setDirection(false, true);
    }

    function test_Setter_RevertsIfNotSigner() public {
        vm.prank(STRANGER);
        vm.expectRevert(SynthetixPerpPermission.NotPermissionSigner.selector);
        perm.setMaxAbsoluteSizeDelta(int128(1e18));

        vm.prank(STRANGER);
        vm.expectRevert(SynthetixPerpPermission.NotPermissionSigner.selector);
        perm.setDirection(false, false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Calldata length guards
    // ─────────────────────────────────────────────────────────────────────────

    function test_TooShortCalldata_CommitOrder_ReturnsFalse() public view {
        bytes memory full  = _commitOrder(MARKET_BTC, MAX_SIZE);
        assertEq(full.length, 228);

        bytes memory short_ = new bytes(227);
        for (uint256 i; i < 227; i++) short_[i] = full[i];

        // Build ctx manually so selector matches
        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   PERPS_PROXY,
            selector: COMMIT_ORDER_SELECTOR,
            value:    0
        });
        assertFalse(perm.evaluate(short_, ctx));
    }

    function test_TooShortCalldata_ModifyCollateral_ReturnsFalse() public view {
        bytes memory full  = _modifyCollateral(SYNTH_SUSD, 100e18);
        assertEq(full.length, 100);

        bytes memory short_ = new bytes(99);
        for (uint256 i; i < 99; i++) short_[i] = full[i];

        Context memory ctx = Context({
            account:  SAFE,
            manager:  address(0),
            target:   PERPS_PROXY,
            selector: MODIFY_COLLATERAL_SELECTOR,
            value:    0
        });
        assertFalse(perm.evaluate(short_, ctx));
    }
}
