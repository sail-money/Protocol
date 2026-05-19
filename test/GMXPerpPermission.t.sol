// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {GMXPerpPermission} from "../contracts/templates/GMXPerpPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Local struct mirrors (used only for abi.encode in helpers)
// ─────────────────────────────────────────────────────────────────────────────

struct _TAddresses {
    address receiver;
    address callbackContract;
    address uiFeeReceiver;
    address market;
    address initialCollateralToken;
    address[] swapPath;
}

struct _TNumbers {
    uint256 sizeDeltaUsd;
    uint256 initialCollateralDeltaAmount;
    uint256 triggerPrice;
    uint256 acceptablePrice;
    uint256 executionFee;
    uint256 callbackGasLimit;
    uint256 minOutputAmount;
}

struct _TParams {
    _TAddresses addresses;
    _TNumbers numbers;
    uint8 orderType;
    uint8 decreasePositionSwapType;
    bool isLong;
    bool shouldUnwrapNativeToken;
    bytes32 referralCode;
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract GMXPerpPermissionTest is Test {
    GMXPerpPermission perm;

    address constant SAFE             = address(0x5AFE);
    address constant EXCHANGE_ROUTER  = address(0xE111);
    address constant MARKET_BTC       = address(0xBBBB);
    address constant MARKET_ETH       = address(0xEEEE);
    address constant MARKET_LINK      = address(0xCCCC); // not allowed
    address constant COLLATERAL_USDC  = address(0xAAAA);
    address constant COLLATERAL_WETH  = address(0x1234);
    address constant SIGNER           = address(0x5161);
    address constant STRANGER         = address(0x9999);

    uint256 constant MAX_SIZE = 1_000_000e30; // 1 M USD in 1e30 terms

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory markets     = new address[](2);
        markets[0] = MARKET_BTC;
        markets[1] = MARKET_ETH;

        address[] memory collaterals = new address[](2);
        collaterals[0] = COLLATERAL_USDC;
        collaterals[1] = COLLATERAL_WETH;

        perm = GMXPerpPermission(Clones.clone(address(new GMXPerpPermission())));
        perm.initialize(
            EXCHANGE_ROUTER,
            markets,
            collaterals,
            true,    // allowLong
            true,    // allowShort
            MAX_SIZE,
            SIGNER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    /// @dev Builds createOrder calldata with selector 0x0b686a6a.
    function _createOrderCalldata(
        address market,
        address collateral,
        uint256 sizeDeltaUsd,
        bool    isLong,
        address receiver
    ) internal pure returns (bytes memory) {
        address[] memory emptyPath = new address[](0);

        _TAddresses memory addrs = _TAddresses({
            receiver:                  receiver,
            callbackContract:          address(0),
            uiFeeReceiver:             address(0),
            market:                    market,
            initialCollateralToken:    collateral,
            swapPath:                  emptyPath
        });

        _TNumbers memory nums = _TNumbers({
            sizeDeltaUsd:                sizeDeltaUsd,
            initialCollateralDeltaAmount: 1_000e6,
            triggerPrice:                0,
            acceptablePrice:             0,
            executionFee:                1e15,
            callbackGasLimit:            0,
            minOutputAmount:             0
        });

        _TParams memory params = _TParams({
            addresses:                  addrs,
            numbers:                    nums,
            orderType:                  2,     // MarketIncrease
            decreasePositionSwapType:   0,
            isLong:                     isLong,
            shouldUnwrapNativeToken:    false,
            referralCode:               bytes32(0)
        });

        return abi.encodeWithSelector(bytes4(0x0b686a6a), params);
    }

    /// @dev Build a Context from calldata bytes (target = EXCHANGE_ROUTER, account = SAFE).
    function _ctx(bytes memory data) internal view returns (Context memory) {
        bytes4 sel;
        if (data.length >= 4) assembly { sel := mload(add(data, 32)) }
        return Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         EXCHANGE_ROUTER,
            selector:       sel,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor tests
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsFields() public view {
        assertEq(perm.exchangeRouter(),    EXCHANGE_ROUTER);
        assertTrue(perm.allowLong());
        assertTrue(perm.allowShort());
        assertEq(perm.maxPositionSizeUsd(), MAX_SIZE);
        assertEq(perm.permissionSigner(),  SIGNER);
    }

    function test_Constructor_SetsMarketAllowlist() public view {
        assertTrue(perm.isAllowedMarket(MARKET_BTC));
        assertTrue(perm.isAllowedMarket(MARKET_ETH));
        assertFalse(perm.isAllowedMarket(MARKET_LINK));
    }

    function test_Constructor_SetsCollateralAllowlist() public view {
        assertTrue(perm.isAllowedCollateral(COLLATERAL_USDC));
        assertTrue(perm.isAllowedCollateral(COLLATERAL_WETH));
    }

    function test_Constructor_RevertsOnZeroRouter() public {
        address[] memory e = new address[](0);
        GMXPerpPermission _tmp = GMXPerpPermission(Clones.clone(address(new GMXPerpPermission())));
        vm.expectRevert(GMXPerpPermission.ZeroAddress.selector);
        _tmp.initialize(address(0), e, e, true, true, MAX_SIZE, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory e = new address[](0);
        GMXPerpPermission _tmp = GMXPerpPermission(Clones.clone(address(new GMXPerpPermission())));
        vm.expectRevert(GMXPerpPermission.ZeroAddress.selector);
        _tmp.initialize(EXCHANGE_ROUTER, e, e, true, true, MAX_SIZE, address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Golden-path tests
    // ─────────────────────────────────────────────────────────────────────────

    function test_GoldenPath_LongBTC() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, SAFE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_GoldenPath_ShortETH() public view {
        bytes memory data = _createOrderCalldata(MARKET_ETH, COLLATERAL_WETH, 500_000e30, false, SAFE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 1 — target check
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTarget_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, SAFE);
        bytes4 sel;
        assembly { sel := mload(add(data, 32)) }
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         address(0xBAD),
            selector:       sel,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 2 — selector check
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongSelector_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, SAFE);
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         EXCHANGE_ROUTER,
            selector:       bytes4(0xDEAD0000),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gate 3 — field checks
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongMarket_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_LINK, COLLATERAL_USDC, 100_000e30, true, SAFE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_WrongCollateral_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, address(0xBAD), 100_000e30, true, SAFE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_OversizedPosition_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, MAX_SIZE + 1, true, SAFE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_AtSizeCap_ReturnsTrue() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, MAX_SIZE, true, SAFE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    function test_WrongReceiver_ReturnsFalse() public view {
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, address(0xBAD));
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Direction checks
    // ─────────────────────────────────────────────────────────────────────────

    function test_LongOnly_ShortBlocked() public {
        vm.prank(SIGNER);
        perm.setDirection(true, false);
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, false, SAFE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_ShortOnly_LongBlocked() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, SAFE);
        assertFalse(perm.evaluate(data, _ctx(data)));
    }

    function test_LongOnly_LongAllowed() public {
        vm.prank(SIGNER);
        perm.setDirection(true, false);
        bytes memory data = _createOrderCalldata(MARKET_BTC, COLLATERAL_USDC, 100_000e30, true, SAFE);
        assertTrue(perm.evaluate(data, _ctx(data)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Setter: setMaxPositionSizeUsd
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxPositionSizeUsd_Updates() public {
        vm.prank(SIGNER);
        perm.setMaxPositionSizeUsd(500_000e30);
        assertEq(perm.maxPositionSizeUsd(), 500_000e30);
    }

    function test_SetMaxPositionSizeUsd_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit GMXPerpPermission.MaxPositionSizeUpdated(MAX_SIZE, 250_000e30);
        vm.prank(SIGNER);
        perm.setMaxPositionSizeUsd(250_000e30);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Setter: setDirection
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetDirection_Updates() public {
        vm.prank(SIGNER);
        perm.setDirection(false, true);
        assertFalse(perm.allowLong());
        assertTrue(perm.allowShort());
    }

    function test_SetDirection_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit GMXPerpPermission.DirectionUpdated(false, true);
        vm.prank(SIGNER);
        perm.setDirection(false, true);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Access control
    // ─────────────────────────────────────────────────────────────────────────

    function test_Setter_RevertsIfNotSigner() public {
        vm.prank(STRANGER);
        vm.expectRevert(GMXPerpPermission.NotPermissionSigner.selector);
        perm.setMaxPositionSizeUsd(1);

        vm.prank(STRANGER);
        vm.expectRevert(GMXPerpPermission.NotPermissionSigner.selector);
        perm.setDirection(false, false);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Calldata edge cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_TooShortCalldata_ReturnsFalse() public view {
        // Provide only 10 bytes — well below the 676-byte minimum
        bytes memory data = new bytes(10);
        // Manually set selector bytes so the context selector matches CREATE_ORDER
        data[0] = 0x0b;
        data[1] = 0x68;
        data[2] = 0x6a;
        data[3] = 0x6a;
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         EXCHANGE_ROUTER,
            selector:       bytes4(0x0b686a6a),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate(data, ctx));
    }

    function test_InvalidCalldata_ReturnsFalse() public view {
        // Correct selector but junk payload — abi.decode should revert → false
        bytes memory junk = new bytes(676);
        // Write the CREATE_ORDER selector
        junk[0] = 0x0b;
        junk[1] = 0x68;
        junk[2] = 0x6a;
        junk[3] = 0x6a;
        // Remaining bytes are zero — the inner ABI offsets will point out of bounds
        // causing abi.decode to revert
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         EXCHANGE_ROUTER,
            selector:       bytes4(0x0b686a6a),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate(junk, ctx));
    }
}
