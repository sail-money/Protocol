// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates Azuro V3 Core `betFor` calls so the manager can only place
///         prediction-market bets on behalf of the Safe account, within an
///         approved set of condition IDs, within a payout cap, and with
///         combo-bet allowance enforced.
///
///         Supported selector:
///           betFor((address,(uint256,uint256,uint8,uint64[],uint128[],uint128,uint8)[],uint8,address,bytes,bytes,bytes)[])
contract AzuroPredictionPermission is IPermission {
    // betFor((address,(uint256,uint256,uint8,uint64[],uint128[],uint128,uint8)[],uint8,address,bytes,bytes,bytes)[])
    bytes4 private constant BET_FOR = bytes4(
        keccak256(
            "betFor((address,(uint256,uint256,uint8,uint64[],uint128[],uint128,uint8)[],uint8,address,bytes,bytes,bytes)[])"
        )
    );

    // Minimum calldata: 4 selector + 32 array offset + 32 array length + 32 first element offset
    uint256 private constant MIN_CALLDATA_LEN = 100;

    // ── decode-only structs ───────────────────────────────────────────────────

    struct _ConditionData {
        uint256  gameId;
        uint256  conditionId;
        uint8    conditionKind;
        uint64[] odds;
        uint128[] outcomes;
        uint128  payoutLimit;
        uint8    winningOutcomesCount;
    }

    struct _OrderData {
        address          betOwner;
        _ConditionData[] conditionDatas;
        uint8            betType;
        address          oracle;
        bytes            clientBetData;
        bytes            bettorSignature;
        bytes            oracleSignature;
    }

    // ── state ─────────────────────────────────────────────────────────────────

    address public immutable azuroCore;
    address public immutable azuroLP;

    mapping(uint256 conditionId => bool) public isAllowedCondition;

    uint128 public maxPayoutLimit;
    bool    public allowComboBets;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────

    event MaxPayoutLimitUpdated(uint128 oldLimit, uint128 newLimit);
    event AllowComboBetsUpdated(bool allowed);

    // ── errors ────────────────────────────────────────────────────────────────

    error NotPermissionSigner();
    error ZeroAddress();

    // ── modifier ─────────────────────────────────────────────────────────────

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // ── constructor ───────────────────────────────────────────────────────────

    constructor(
        address _azuroCore,
        address _azuroLP,
        uint256[] memory allowedConditionIds,
        uint128 _maxPayoutLimit,
        bool _allowComboBets,
        address _permissionSigner
    ) {
        if (_azuroCore       == address(0)) revert ZeroAddress();
        if (_azuroLP         == address(0)) revert ZeroAddress();
        if (_permissionSigner == address(0)) revert ZeroAddress();

        azuroCore        = _azuroCore;
        azuroLP          = _azuroLP;
        maxPayoutLimit   = _maxPayoutLimit;
        allowComboBets   = _allowComboBets;
        permissionSigner = _permissionSigner;

        for (uint256 i; i < allowedConditionIds.length; i++) {
            isAllowedCondition[allowedConditionIds[i]] = true;
        }
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxPayoutLimit(uint128 newLimit) external onlyPermissionSigner {
        uint128 old = maxPayoutLimit;
        maxPayoutLimit = newLimit;
        emit MaxPayoutLimitUpdated(old, newLimit);
    }

    function setAllowComboBets(bool allowed) external onlyPermissionSigner {
        allowComboBets = allowed;
        emit AllowComboBetsUpdated(allowed);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Gate 1 — target must be Azuro Core
        if (ctx.target != azuroCore) return false;

        // Gate 2 — selector must be betFor
        if (ctx.selector != BET_FOR) return false;

        // Gate 3 — length guard then decode + field checks
        if (txData.length < MIN_CALLDATA_LEN) return false;

        _OrderData[] memory orders;
        try this._decodeOrders(txData[4:]) returns (_OrderData[] memory decoded) {
            orders = decoded;
        } catch {
            return false;
        }

        if (orders.length == 0) return false;

        for (uint256 i; i < orders.length; i++) {
            _OrderData memory order = orders[i];

            // betOwner must be the managed Safe account
            if (order.betOwner != ctx.account) return false;

            // combo bets require explicit allowance
            if (!allowComboBets && order.conditionDatas.length > 1) return false;

            if (order.conditionDatas.length == 0) return false;

            for (uint256 j; j < order.conditionDatas.length; j++) {
                _ConditionData memory cd = order.conditionDatas[j];

                if (!isAllowedCondition[cd.conditionId]) return false;
                if (cd.payoutLimit > maxPayoutLimit)      return false;
            }
        }

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("AzuroPredictionPermission");
    }

    // ── external decode helper (used via try/catch in evaluate) ──────────────

    /// @dev External so it can be called with try/catch for revert-safe decoding.
    function _decodeOrders(bytes calldata data) external pure returns (_OrderData[] memory) {
        return abi.decode(data, (_OrderData[]));
    }
}
