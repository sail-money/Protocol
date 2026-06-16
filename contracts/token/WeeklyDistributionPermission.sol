// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}                 from "../interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../interfaces/IBatchPermission.sol";
import {IPermissionIntrospection}             from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities}                     from "../interfaces/SailCapabilities.sol";
import {IERC20}                               from "@openzeppelin/contracts/token/ERC20/IERC20.sol";

/// @notice Batch-aware permission that authorises $SAIL reward distributions: a batch of plain
///         ERC-20 `transfer(address,uint256)` calls, all on the configured SailToken, paying out
///         from the rewards SMA. Serves BOTH the manual genesis distribution (~50 recipients split
///         across ceil(50/16)=4 dispatchBatch calls) and the weekly Season-1 distributions — same
///         contract, no special-casing.
///
/// @dev    MODELLED ON SharedApproveAndCallBatchPermission. Reuses its proven validation patterns:
///         exact per-call shape checks BEFORE any decode, bounds-checked calldata slicing, and
///         fail-closed denial (return false / revert on anything malformed — the kernel treats both
///         as denial under staticcall).
///
///         ADVERSARY MODEL. A malicious Manager (or a compromised distribution agent) signs/builds
///         the batch. They control every field of every `Call`. This permission must reject every
///         batch that is not EXACTLY a set of well-formed reward transfers from the rewards SMA:
///           • wrong target (anything but the SailToken)            → drains/needs other contracts
///           • wrong selector (approve / transferFrom / arbitrary)  → standing allowance / pull / call
///           • non-zero msg.value                                   → unexpected ETH movement
///           • malformed calldata length                            → ambiguous decode
///           • to == 0 / to == SAIL / to == rewards SMA             → burns / lost funds / self-churn
///           • amt == 0                                             → spam / no-op
///           • per-recipient or per-batch sum over the caps         → oversized payout
///           • sum over the SMA's live balance                      → drains beyond what was minted
///           • wrong account / oversized / empty batch              → misuse on another vault
///
///         BUDGET BOUND IS STATELESS. `evaluateBatch` is a view called via staticcall, so it cannot
///         carry state across dispatches. The authoritative cumulative bound is therefore the SMA's
///         LIVE token balance: `sum <= IERC20(SAIL).balanceOf(REWARDS_SMA)`. Each dispatch re-reads
///         the (post-prior-batch) balance, so a sequence of batches can drain the SMA but can never
///         collectively exceed what emission minted into it — no per-permission state required.
///         MAX_PER_RECIPIENT and MAX_PER_BATCH are immutable secondary sanity ceilings.
///
///         NO CONFIGURE. All parameters are immutable constructor args; there is no per-account
///         configuration surface to mis-set or front-run. This contract does NOT inherit
///         BaseSharedPermission — less code, less surface.
///
/// @custom:security-contact security@sail.money
contract WeeklyDistributionPermission is IPermission, IBatchPermission, IPermissionIntrospection {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @dev ERC-20 `transfer(address,uint256)` selector. The ONLY selector this permission allows.
    bytes4 private constant TRANSFER_SELECTOR = 0xa9059cbb;

    /// @dev Exact calldata length for `transfer(address,uint256)`:
    ///      4 (selector) + 32 (to) + 32 (amount) = 68 bytes. Anything else is rejected — trailing
    ///      bytes and short calldata are both ambiguous and never produced by a well-formed transfer.
    uint256 private constant TRANSFER_CALLDATA_LEN = 68;

    /// @dev Maximum recipients per batch. Mirrors SailKernel.MAX_BATCH_LENGTH (16); the kernel also
    ///      enforces this, so the local check is defense-in-depth.
    uint256 public constant MAX_RECIPIENTS = 16;

    // -------------------------------------------------------------------------
    // Immutable configuration
    // -------------------------------------------------------------------------

    /// @notice The SailToken. The ONLY valid `target` for every subcall.
    address public immutable SAIL;

    /// @notice The rewards SMA — the only account this permission serves. A dispatch on any other
    ///         account is rejected (defense-in-depth; registration is the primary trust anchor).
    address public immutable REWARDS_SMA;

    /// @notice Immutable per-recipient sanity ceiling (a single transfer may not exceed this).
    uint256 public immutable MAX_PER_RECIPIENT;

    /// @notice Immutable per-batch sanity ceiling (the sum of one batch may not exceed this).
    uint256 public immutable MAX_PER_BATCH;

    // -------------------------------------------------------------------------
    // Errors (constructor only — evaluateBatch is fail-closed via `return false`)
    // -------------------------------------------------------------------------

    error ZeroAddress();
    error ZeroCap();
    error PerRecipientExceedsBatch();
    error TokenIsRewardsSMA();

    constructor(
        address sail,
        address rewardsSMA,
        uint256 maxPerRecipient,
        uint256 maxPerBatch
    ) {
        if (sail == address(0) || rewardsSMA == address(0)) revert ZeroAddress();
        if (sail == rewardsSMA) revert TokenIsRewardsSMA();
        if (maxPerRecipient == 0 || maxPerBatch == 0) revert ZeroCap();
        // A single recipient must never be allowed to exceed the whole-batch ceiling.
        if (maxPerRecipient > maxPerBatch) revert PerRecipientExceedsBatch();

        SAIL              = sail;
        REWARDS_SMA       = rewardsSMA;
        MAX_PER_RECIPIENT = maxPerRecipient;
        MAX_PER_BATCH     = maxPerBatch;
    }

    // -------------------------------------------------------------------------
    // IPermission — single dispatch is never authorised (batch-only template)
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    /// @dev Always false. To use this permission the manager must call `dispatchBatch` naming it.
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) {
        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("WeeklyDistributionPermission");
    }

    // -------------------------------------------------------------------------
    // IBatchPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IBatchPermission
    function isBatchPermission() external pure returns (bool) {
        return true;
    }

    /// @inheritdoc IBatchPermission
    ///
    /// @dev Authorises a batch iff EVERY subcall is a well-formed `transfer(to, amt)` on the
    ///      SailToken, paying from the rewards SMA, within the per-recipient / per-batch / live-
    ///      balance bounds. Any deviation returns false (or reverts on malformed slicing) — the
    ///      kernel treats both as denial and reverts the whole dispatch.
    ///
    ///      MUST be view + side-effect-free (staticcall context). The single external call is
    ///      `IERC20(SAIL).balanceOf` (~2,600 gas); total cost is far under BATCH_EVAL_GAS_CAP.
    function evaluateBatch(Call[] calldata calls, BatchContext calldata ctx)
        external
        view
        returns (bool)
    {
        uint256 n = calls.length;
        if (n == 0 || n > MAX_RECIPIENTS) return false;     // empty / oversized
        if (ctx.account != REWARDS_SMA)   return false;     // only the rewards SMA

        uint256 sum;
        for (uint256 i; i < n;) {
            Call calldata c = calls[i];

            // ── per-call shape: validate BEFORE decoding ──────────────────────
            if (c.target != SAIL)                       return false; // only the token
            if (c.value != 0)                           return false; // no ETH
            if (c.data.length != TRANSFER_CALLDATA_LEN) return false; // exact transfer shape
            if (bytes4(c.data[0:4]) != TRANSFER_SELECTOR) return false; // only transfer()

            // ── decode (length guaranteed == 68 above) ────────────────────────
            (address to, uint256 amt) = _decodeTransfer(c.data);

            // ── per-recipient invariants ──────────────────────────────────────
            if (to == address(0))      return false; // burn / lost funds
            if (to == SAIL)            return false; // lost funds (tokens to the token)
            if (to == REWARDS_SMA)     return false; // self-churn
            if (amt == 0)              return false; // no-op / spam
            if (amt > MAX_PER_RECIPIENT) return false;

            sum += amt; // checked arithmetic: an overflow reverts -> kernel denies
            unchecked { ++i; }
        }

        // ── whole-batch bounds ────────────────────────────────────────────────
        if (sum > MAX_PER_BATCH) return false;                       // immutable per-batch ceiling
        // Authoritative cumulative bound: never move more than the SMA actually holds. Re-read live,
        // so sequential batches drain but cannot collectively exceed what emission minted.
        if (sum > IERC20(SAIL).balanceOf(REWARDS_SMA)) return false;

        return true;
    }

    // -------------------------------------------------------------------------
    // Internal calldata decoding (bounds guaranteed by caller: length == 68)
    // -------------------------------------------------------------------------

    /// @dev Decode `transfer(address,uint256)` calldata via calldata slicing. The `to` address is
    ///      masked to 160 bits exactly as the ERC-20 itself will interpret it, so dirty upper bits
    ///      cannot make our checks disagree with the token's effective recipient.
    function _decodeTransfer(bytes calldata data) internal pure returns (address to, uint256 amount) {
        to     = address(uint160(uint256(bytes32(data[4:36]))));
        amount = uint256(bytes32(data[36:68]));
    }

    // -------------------------------------------------------------------------
    // IPermissionIntrospection
    // -------------------------------------------------------------------------

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.WeeklyDistributionPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.BATCH_DISPATCH;
    }
}
