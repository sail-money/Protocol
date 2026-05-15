// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates Gains Network (gTrade) perpetual trades so the manager can only
///         open/close positions through the canonical gTradeRouter, on approved
///         pairs, within configurable position-size and leverage caps, and — for
///         openTrade — only in the direction(s) explicitly enabled.
///
///         Supported selectors:
///           OPEN_TRADE   openTrade((address,uint256,uint256,uint256,uint256,bool,uint256,uint256,uint256),uint8,uint256,uint256,address)
///           CLOSE_TRADE  closeTrade(uint256,uint256)
contract GainsNetworkPerpPermission is IPermission {
    // openTrade((address,uint256,uint256,uint256,uint256,bool,uint256,uint256,uint256),uint8,uint256,uint256,address)
    bytes4 private constant OPEN_TRADE = bytes4(
        keccak256(
            "openTrade((address,uint256,uint256,uint256,uint256,bool,uint256,uint256,uint256),uint8,uint256,uint256,address)"
        )
    );
    // closeTrade(uint256,uint256)
    bytes4 private constant CLOSE_TRADE = bytes4(keccak256("closeTrade(uint256,uint256)"));

    // selector(4) + Trade struct (9 × 32 = 288) + 4 trailing args (4 × 32 = 128) = 420
    uint256 private constant LEN_OPEN  = 420;
    // selector(4) + 2 × 32 = 68
    uint256 private constant LEN_CLOSE = 68;

    // ── internal decode type ───────────────────────────────────────────────────

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

    // ── immutables ────────────────────────────────────────────────────────────
    address public immutable gTradeRouter;

    // ── allowlists ────────────────────────────────────────────────────────────
    mapping(uint256 pairIndex => bool) public isAllowedPair;

    // ── tunable parameters ────────────────────────────────────────────────────
    bool    public allowLong;
    bool    public allowShort;
    uint256 public maxPositionSizeDai;
    uint256 public maxLeverageX;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────
    event MaxPositionSizeDaiUpdated(uint256 oldSize, uint256 newSize);
    event MaxLeverageUpdated(uint256 oldLeverage, uint256 newLeverage);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotPermissionSigner();
    error ZeroAddress();

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address _gTradeRouter,
        uint256[] memory allowedPairIndexes,
        bool    _allowLong,
        bool    _allowShort,
        uint256 _maxPositionSizeDai,
        uint256 _maxLeverageX,
        address _permissionSigner
    ) {
        if (_gTradeRouter    == address(0)) revert ZeroAddress();
        if (_permissionSigner == address(0)) revert ZeroAddress();

        gTradeRouter       = _gTradeRouter;
        allowLong          = _allowLong;
        allowShort         = _allowShort;
        maxPositionSizeDai = _maxPositionSizeDai;
        maxLeverageX       = _maxLeverageX;
        permissionSigner   = _permissionSigner;

        for (uint256 i; i < allowedPairIndexes.length; i++) {
            isAllowedPair[allowedPairIndexes[i]] = true;
        }
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxPositionSizeDai(uint256 newSize) external onlyPermissionSigner {
        uint256 old = maxPositionSizeDai;
        maxPositionSizeDai = newSize;
        emit MaxPositionSizeDaiUpdated(old, newSize);
    }

    function setMaxLeverageX(uint256 newLeverage) external onlyPermissionSigner {
        uint256 old = maxLeverageX;
        maxLeverageX = newLeverage;
        emit MaxLeverageUpdated(old, newLeverage);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Gate 1: target must be the gTradeRouter
        if (ctx.target != gTradeRouter) return false;

        // Gate 2: selector must be OPEN_TRADE or CLOSE_TRADE
        if (ctx.selector != OPEN_TRADE && ctx.selector != CLOSE_TRADE) return false;

        // ── openTrade ─────────────────────────────────────────────────────────
        if (ctx.selector == OPEN_TRADE) {
            if (txData.length < LEN_OPEN) return false;

            (_Trade memory t,,,,) = abi.decode(
                txData[4:],
                (_Trade, uint8, uint256, uint256, address)
            );

            if (t.trader != ctx.account)           return false;
            if (!isAllowedPair[t.pairIndex])       return false;
            if (t.buy  && !allowLong)              return false;
            if (!t.buy && !allowShort)             return false;
            if (t.positionSizeDai > maxPositionSizeDai) return false;
            if (t.leverage        > maxLeverageX)       return false;

            return true;
        }

        // ── closeTrade ────────────────────────────────────────────────────────
        if (txData.length < LEN_CLOSE) return false;

        (uint256 pairIndex,) = abi.decode(txData[4:], (uint256, uint256));

        if (!isAllowedPair[pairIndex]) return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("GainsNetworkPerpPermission");
    }
}
