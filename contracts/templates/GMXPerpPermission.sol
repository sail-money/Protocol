// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {CloneInitializable}   from "./base/CloneInitializable.sol";

/// @notice Gates GMX V2 ExchangeRouter `createOrder` calls so the manager can
///         only open/increase perp positions through approved markets, with
///         approved collateral, within a position-size cap, and in the allowed
///         direction (long / short).
///
///         Supported selector:
///           0x0b686a6a  createOrder  (GMX V2 ExchangeRouter)
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use MandateFactory.deployAndAttach to create per-account clones.
contract GMXPerpPermission is IPermission, CloneInitializable {
    /// @notice Marks this as a single-account template (not a shared multi-account deployment).
    bool public constant IS_SINGLE_ACCOUNT = true;
    // createOrder((addresses,numbers,orderType,decreasePositionSwapType,isLong,shouldUnwrapNativeToken,referralCode))
    bytes4 private constant CREATE_ORDER = 0x0b686a6a;

    // Minimum calldata length:
    //   4   selector
    //  32   outer ABI offset to tuple
    // 416   params head:
    //         32  offset-to-addresses tuple
    //        7×32 numbers (sizeDeltaUsd, initialCollateralDeltaAmount, triggerPrice,
    //                      acceptablePrice, executionFee, callbackGasLimit, minOutputAmount)
    //        5×32 flags   (orderType, decreasePositionSwapType, isLong,
    //                      shouldUnwrapNativeToken, referralCode)
    // 192   addresses head:
    //         32  offset-to-swapPath array
    //        5×32 fields (receiver, callbackContract, uiFeeReceiver, market,
    //                     initialCollateralToken)
    //  32   empty swapPath (length word = 0)
    // ─────────────────────────────────────────────────────────────────────────
    // Total = 4 + 32 + 416 + 192 + 32 = 676
    uint256 private constant MIN_CALLDATA_LEN = 676;

    // ── decode-only structs ───────────────────────────────────────────────────

    struct _CreateOrderAddresses {
        address receiver;
        address callbackContract;
        address uiFeeReceiver;
        address market;
        address initialCollateralToken;
        address[] swapPath;
    }

    struct _CreateOrderNumbers {
        uint256 sizeDeltaUsd;
        uint256 initialCollateralDeltaAmount;
        uint256 triggerPrice;
        uint256 acceptablePrice;
        uint256 executionFee;
        uint256 callbackGasLimit;
        uint256 minOutputAmount;
    }

    struct _CreateOrderParams {
        _CreateOrderAddresses addresses;
        _CreateOrderNumbers numbers;
        uint8 orderType;
        uint8 decreasePositionSwapType;
        bool isLong;
        bool shouldUnwrapNativeToken;
        bytes32 referralCode;
    }

    // ── state ─────────────────────────────────────────────────────────────────

    address public exchangeRouter;

    mapping(address market     => bool) public isAllowedMarket;
    mapping(address collateral => bool) public isAllowedCollateral;

    bool    public allowLong;
    bool    public allowShort;
    uint256 public maxPositionSizeUsd;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────

    event MaxPositionSizeUpdated(uint256 oldSize, uint256 newSize);
    event DirectionUpdated(bool allowLong, bool allowShort);

    // ── errors ────────────────────────────────────────────────────────────────

    error NotPermissionSigner();
    error ZeroAddress();

    // ── modifier ─────────────────────────────────────────────────────────────

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // ── constructor / initialize ──────────────────────────────────────────────

    constructor() { _disableInitializers(); }

    /// @notice Called once by MandateFactory after cloning the logic contract.
    function initialize(
        address _exchangeRouter,
        address[] memory allowedMarkets,
        address[] memory allowedCollateralTokens,
        bool _allowLong,
        bool _allowShort,
        uint256 _maxPositionSizeUsd,
        address _permissionSigner
    ) external initializer {
        if (_exchangeRouter  == address(0)) revert ZeroAddress();
        if (_permissionSigner == address(0)) revert ZeroAddress();

        exchangeRouter    = _exchangeRouter;
        allowLong         = _allowLong;
        allowShort        = _allowShort;
        maxPositionSizeUsd = _maxPositionSizeUsd;
        permissionSigner  = _permissionSigner;

        for (uint256 i; i < allowedMarkets.length;           i++) isAllowedMarket[allowedMarkets[i]]               = true;
        for (uint256 i; i < allowedCollateralTokens.length;  i++) isAllowedCollateral[allowedCollateralTokens[i]]  = true;
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxPositionSizeUsd(uint256 newSize) external onlyPermissionSigner {
        uint256 old = maxPositionSizeUsd;
        maxPositionSizeUsd = newSize;
        emit MaxPositionSizeUpdated(old, newSize);
    }

    function setDirection(bool _allowLong, bool _allowShort) external onlyPermissionSigner {
        allowLong  = _allowLong;
        allowShort = _allowShort;
        emit DirectionUpdated(_allowLong, _allowShort);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Gate 1 — target must be the GMX ExchangeRouter
        if (ctx.target != exchangeRouter) return false;

        // Gate 2 — selector must be createOrder
        if (ctx.selector != CREATE_ORDER) return false;

        // Gate 3 — calldata length guard then decode + field checks
        if (txData.length < MIN_CALLDATA_LEN) return false;
        // Reject pathologically large calldata to prevent OOG in external decode call.
        if (txData.length > 4096) return false;

        _CreateOrderParams memory params;
        try this._decodeOrder(txData[4:]) returns (_CreateOrderParams memory decoded) {
            params = decoded;
        } catch {
            return false;
        }

        if (params.addresses.receiver != ctx.account)              return false;
        if (!isAllowedMarket[params.addresses.market])             return false;
        if (!isAllowedCollateral[params.addresses.initialCollateralToken]) return false;
        if (params.numbers.sizeDeltaUsd > maxPositionSizeUsd)      return false;
        if (params.isLong  && !allowLong)                          return false;
        if (!params.isLong && !allowShort)                         return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("GMXPerpPermission");
    }

    // ── external decode helper (used via try/catch in evaluate) ───────────────

    /// @dev External so it can be called with try/catch for revert-safe decoding.
    ///      Pure — no state reads or writes.
    function _decodeOrder(bytes calldata data) external pure returns (_CreateOrderParams memory) {
        return abi.decode(data, (_CreateOrderParams));
    }
}
