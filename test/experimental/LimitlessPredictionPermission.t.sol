// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {LimitlessPredictionPermission} from "../../contracts/experimental/LimitlessPredictionPermission.sol";
import {Context} from "../../contracts/interfaces/IPermission.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

contract LimitlessPredictionPermissionTest is Test {
    LimitlessPredictionPermission perm;

    address constant SAFE     = address(0x5AFE);
    address constant EXCHANGE = address(0xCEEF);
    address constant SIGNER   = address(0x5161);
    address constant OTHER    = address(0x9999);

    // CTF conditional token IDs (32-byte token IDs in Polymarket/Limitless)
    uint256 constant MARKET_YES  = uint256(keccak256("YES_TOKEN_A"));
    uint256 constant MARKET_NO   = uint256(keccak256("NO_TOKEN_A"));
    uint256 constant MARKET_YES2 = uint256(keccak256("YES_TOKEN_B"));
    uint256 constant MARKET_BLOCKED = uint256(keccak256("UNKNOWN_MARKET"));

    uint256 constant MAX_SIZE = 500e6; // 500 USDC

    uint8 constant SIDE_BUY  = 0;
    uint8 constant SIDE_SELL = 1;

    bytes4 private constant FILL_ORDER = bytes4(
        keccak256(
            "fillOrder((address,address,address,uint256,uint256,uint256,uint256,uint256,uint256,uint256,uint8,uint8,bytes),uint256)"
        )
    );

    // ── decode-only struct ────────────────────────────────────────────────────

    struct Order {
        address maker;
        address signer;
        address taker;
        uint256 tokenId;
        uint256 makerAmount;
        uint256 takerAmount;
        uint256 salt;
        uint256 expiration;
        uint256 nonce;
        uint256 feeRateBps;
        uint8   side;
        uint8   signatureType;
        bytes   signature;
    }

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        uint256[] memory markets = new uint256[](3);
        markets[0] = MARKET_YES;
        markets[1] = MARKET_NO;
        markets[2] = MARKET_YES2;

        perm = LimitlessPredictionPermission(Clones.clone(address(new LimitlessPredictionPermission())));
        perm.initialize(
            EXCHANGE,
            markets,
            MAX_SIZE,
            true,  // allowLong (BUY)
            true,  // allowShort (SELL)
            SIGNER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _buildOrder(
        address maker,
        uint256 tokenId,
        uint256 makerAmount,
        uint8   side
    ) internal view returns (bytes memory) {
        Order memory order = Order({
            maker:         maker,
            signer:        maker,
            taker:         address(0),
            tokenId:       tokenId,
            makerAmount:   makerAmount,
            takerAmount:   makerAmount * 2,
            salt:          block.timestamp,
            expiration:    block.timestamp + 1 days,
            nonce:         0,
            feeRateBps:    100,
            side:          side,
            signatureType: 2,
            signature:     ""
        });
        return abi.encodeWithSelector(FILL_ORDER, order, makerAmount);
    }

    function _ctx(bytes memory /*data*/) internal view returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         EXCHANGE,
            selector:       FILL_ORDER,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsFields() public view {
        assertEq(perm.limitlessExchange(), EXCHANGE);
        assertEq(perm.permissionSigner(),  SIGNER);
        assertEq(perm.maxPositionSize(),   MAX_SIZE);
        assertTrue(perm.allowLong());
        assertTrue(perm.allowShort());
    }

    function test_Constructor_SetsMarketAllowlist() public view {
        assertTrue(perm.isAllowedMarket(MARKET_YES));
        assertTrue(perm.isAllowedMarket(MARKET_NO));
        assertTrue(perm.isAllowedMarket(MARKET_YES2));
        assertFalse(perm.isAllowedMarket(MARKET_BLOCKED));
    }

    function test_Constructor_RevertsOnZeroExchange() public {
        uint256[] memory markets = new uint256[](0);
        LimitlessPredictionPermission _tmp = LimitlessPredictionPermission(Clones.clone(address(new LimitlessPredictionPermission())));
        vm.expectRevert(LimitlessPredictionPermission.ZeroAddress.selector);
        _tmp.initialize(address(0), markets, MAX_SIZE, true, true, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        uint256[] memory markets = new uint256[](0);
        LimitlessPredictionPermission _tmp = LimitlessPredictionPermission(Clones.clone(address(new LimitlessPredictionPermission())));
        vm.expectRevert(LimitlessPredictionPermission.ZeroAddress.selector);
        _tmp.initialize(EXCHANGE, markets, MAX_SIZE, true, true, address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_GoldenPath_BuyYES() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_SellYES() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_SELL);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_BuyNO() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_NO, MAX_SIZE / 2, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_AmountAtCap() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES2, MAX_SIZE, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_AmountBelowCap() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, 1, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 1: wrong target
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTarget_ReturnsFalse() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: address(0xDEAD), selector: FILL_ORDER, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 2: wrong selector
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSelector_ReturnsFalse() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: EXCHANGE, selector: bytes4(0xdeadbeef), value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: maker == ctx.account
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongMaker_ReturnsFalse() public view {
        bytes memory data = _buildOrder(OTHER, MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ZeroMaker_ReturnsFalse() public view {
        bytes memory data = _buildOrder(address(0), MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: tokenId allowlist
    // ─────────────────────────────────────────────────────────────────────────

    function test_BlockedMarket_ReturnsFalse() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_BLOCKED, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_UnknownTokenId_ReturnsFalse() public view {
        bytes memory data = _buildOrder(SAFE, 0, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: makerAmount cap
    // ─────────────────────────────────────────────────────────────────────────

    function test_OversizedAmount_ReturnsFalse() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE + 1, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ZeroAmount_ReturnsTrue() public view {
        bytes memory data = _buildOrder(SAFE, MARKET_YES, 0, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3: direction
    // ─────────────────────────────────────────────────────────────────────────

    function test_BuyBlocked_WhenLongDisabled() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);

        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_SellBlocked_WhenShortDisabled() public {
        vm.prank(SIGNER);
        perm.setDirection(true, false);

        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_SELL);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_BuyAllowed_WhenShortDisabled() public {
        vm.prank(SIGNER);
        perm.setDirection(true, false);

        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_SellAllowed_WhenLongDisabled() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);

        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_SELL);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Calldata length guard
    // ─────────────────────────────────────────────────────────────────────────

    function test_TooShortCalldata_ReturnsFalse() public view {
        bytes memory short_ = new bytes(515);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: EXCHANGE, selector: FILL_ORDER, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(short_, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxPositionSize
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxPositionSize_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxPositionSize(100e6);
        assertEq(perm.maxPositionSize(), 100e6);
    }

    function test_SetMaxPositionSize_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit LimitlessPredictionPermission.MaxPositionSizeUpdated(MAX_SIZE, 100e6);
        vm.prank(SIGNER);
        perm.setMaxPositionSize(100e6);
    }

    function test_SetMaxPositionSize_BlocksOversizedOrders() public {
        vm.prank(SIGNER);
        perm.setMaxPositionSize(100e6);

        bytes memory data = _buildOrder(SAFE, MARKET_YES, 101e6, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_SetMaxPositionSize_RevertsIfNotSigner() public {
        vm.prank(OTHER);
        vm.expectRevert(LimitlessPredictionPermission.NotPermissionSigner.selector);
        perm.setMaxPositionSize(100e6);
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
        emit LimitlessPredictionPermission.DirectionUpdated(false, true);
        vm.prank(SIGNER);
        perm.setDirection(false, true);
    }

    function test_SetDirection_RevertsIfNotSigner() public {
        vm.prank(OTHER);
        vm.expectRevert(LimitlessPredictionPermission.NotPermissionSigner.selector);
        perm.setDirection(false, false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // discriminator
    // ─────────────────────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("LimitlessPredictionPermission"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // fuzz
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_AmountAtOrBelowCap_Passes(uint256 amount) public view {
        amount = bound(amount, 0, MAX_SIZE);
        bytes memory data = _buildOrder(SAFE, MARKET_YES, amount, SIDE_BUY);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function testFuzz_AmountAboveCap_Fails(uint256 amount) public view {
        // cap at max/2 to avoid overflow in _buildOrder's takerAmount = makerAmount * 2
        amount = bound(amount, MAX_SIZE + 1, type(uint256).max / 2);
        bytes memory data = _buildOrder(SAFE, MARKET_YES, amount, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function testFuzz_WrongMaker_Fails(address maker) public view {
        vm.assume(maker != SAFE);
        bytes memory data = _buildOrder(maker, MARKET_YES, MAX_SIZE, SIDE_BUY);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function testFuzz_WrongTarget_Fails(address target) public view {
        vm.assume(target != EXCHANGE);
        bytes memory data = _buildOrder(SAFE, MARKET_YES, MAX_SIZE, SIDE_BUY);
        Context memory ctx = Context({account: SAFE, manager: address(0), submitter: address(0), target: target, selector: FILL_ORDER, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number});
        assertFalse(perm.evaluate(data, ctx));
    }
}
