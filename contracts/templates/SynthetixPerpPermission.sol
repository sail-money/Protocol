// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates Synthetix V3 perps interactions so the manager can only trade
///         on approved markets, within a size cap, and in permitted directions;
///         and can only add/remove approved synth collateral.
///
///         Supported selectors:
///           commitOrder(uint128,uint128,int128,uint128,uint256,bytes32,address)
///           modifyCollateral(uint128,uint128,int256)
contract SynthetixPerpPermission is IPermission {
    // commitOrder(uint128 accountId, uint128 marketId, int128 sizeDelta,
    //             uint128 settlementStrategyId, uint256 acceptablePrice,
    //             bytes32 trackingCode, address referrer)
    bytes4 private constant COMMIT_ORDER =
        bytes4(keccak256("commitOrder(uint128,uint128,int128,uint128,uint256,bytes32,address)"));

    // modifyCollateral(uint128 accountId, uint128 synthMarketId, int256 amountDelta)
    bytes4 private constant MODIFY_COLLATERAL =
        bytes4(keccak256("modifyCollateral(uint128,uint128,int256)"));

    // selector(4) + 7 params × 32 = 228
    uint256 private constant LEN_COMMIT_ORDER    = 228;
    // selector(4) + 3 params × 32 = 100
    uint256 private constant LEN_MODIFY_COLLATERAL = 100;

    // ── immutable ─────────────────────────────────────────────────────────────
    address public immutable perpsMarketProxy;

    // ── allowlists ────────────────────────────────────────────────────────────
    /// @notice Markets allowed in commitOrder calls.
    mapping(uint128 marketId => bool) public isAllowedMarket;
    /// @notice Synth markets (collateral) allowed in modifyCollateral calls.
    mapping(uint128 synthMarketId => bool) public isAllowedSynthMarket;

    // ── tunable parameters ────────────────────────────────────────────────────
    int128  public maxAbsoluteSizeDelta;
    bool    public allowLong;
    bool    public allowShort;
    address public permissionSigner;

    /// @notice Maximum collateral withdrawal per transaction in absolute token units.
    ///         Only enforced for negative amountDelta (withdrawals). 0 = no cap.
    uint256 public maxWithdrawalPerTx;

    // ── events ────────────────────────────────────────────────────────────────
    event MaxSizeDeltaUpdated(int128 oldMax, int128 newMax);
    event DirectionUpdated(bool allowLong, bool allowShort);
    event MaxWithdrawalUpdated(uint256 oldMax, uint256 newMax);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotPermissionSigner();
    error ZeroAddress();
    error NegativeMaxSizeDelta();

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address _perpsMarketProxy,
        uint128[] memory allowedMarketIds,
        int128  _maxAbsoluteSizeDelta,
        bool    _allowLong,
        bool    _allowShort,
        uint128[] memory allowedCollateralSynthMarketIds,
        address _permissionSigner,
        uint256 _maxWithdrawalPerTx
    ) {
        if (_perpsMarketProxy == address(0)) revert ZeroAddress();
        if (_permissionSigner  == address(0)) revert ZeroAddress();
        if (_maxAbsoluteSizeDelta < 0)        revert NegativeMaxSizeDelta();

        perpsMarketProxy     = _perpsMarketProxy;
        maxAbsoluteSizeDelta = _maxAbsoluteSizeDelta;
        allowLong            = _allowLong;
        allowShort           = _allowShort;
        permissionSigner     = _permissionSigner;
        maxWithdrawalPerTx   = _maxWithdrawalPerTx;

        for (uint256 i; i < allowedMarketIds.length; i++) {
            isAllowedMarket[allowedMarketIds[i]] = true;
        }
        for (uint256 i; i < allowedCollateralSynthMarketIds.length; i++) {
            isAllowedSynthMarket[allowedCollateralSynthMarketIds[i]] = true;
        }
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxAbsoluteSizeDelta(int128 newMax) external onlyPermissionSigner {
        if (newMax < 0) revert NegativeMaxSizeDelta();
        int128 old = maxAbsoluteSizeDelta;
        maxAbsoluteSizeDelta = newMax;
        emit MaxSizeDeltaUpdated(old, newMax);
    }

    function setDirection(bool _allowLong, bool _allowShort) external onlyPermissionSigner {
        allowLong  = _allowLong;
        allowShort = _allowShort;
        emit DirectionUpdated(_allowLong, _allowShort);
    }

    /// @notice Update the maximum collateral withdrawal per transaction.
    /// @param  newMax New cap in absolute token units. Set to 0 to disable the cap.
    function setMaxWithdrawalPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxWithdrawalPerTx;
        maxWithdrawalPerTx = newMax;
        emit MaxWithdrawalUpdated(old, newMax);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Gate 1: must target the perps market proxy
        if (ctx.target != perpsMarketProxy) return false;

        // Gate 2: selector must be commitOrder or modifyCollateral
        bytes4 sel = ctx.selector;
        if (sel != COMMIT_ORDER && sel != MODIFY_COLLATERAL) return false;

        // Gate 3a: commitOrder
        if (sel == COMMIT_ORDER) {
            if (txData.length < LEN_COMMIT_ORDER) return false;

            (
                ,              // accountId  (uint128)
                uint128 marketId,
                int128  sizeDelta,
                ,              // settlementStrategyId (uint128)
                ,              // acceptablePrice      (uint256)
                ,              // trackingCode         (bytes32)
                               // referrer             (address)
            ) = abi.decode(
                txData[4:],
                (uint128, uint128, int128, uint128, uint256, bytes32, address)
            );

            if (!isAllowedMarket[marketId]) return false;

            if (sizeDelta > 0 && !allowLong)  return false;
            if (sizeDelta < 0 && !allowShort) return false;

            // Compute absolute value — maxAbsoluteSizeDelta >= 0 so cast is safe
            uint128 absDelta = sizeDelta >= 0
                ? uint128(sizeDelta)
                : uint128(-sizeDelta);

            if (absDelta > uint128(maxAbsoluteSizeDelta)) return false;

            return true;
        }

        // Gate 3b: modifyCollateral
        // sel == MODIFY_COLLATERAL
        if (txData.length < LEN_MODIFY_COLLATERAL) return false;

        (
            ,                    // accountId     (uint128)
            uint128 synthMarketId,
            int256  amountDelta
        ) = abi.decode(txData[4:], (uint128, uint128, int256));

        if (!isAllowedSynthMarket[synthMarketId]) return false;
        if (amountDelta < 0 && maxWithdrawalPerTx != 0 && uint256(-amountDelta) > maxWithdrawalPerTx) return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("SynthetixPerpPermission");
    }
}
