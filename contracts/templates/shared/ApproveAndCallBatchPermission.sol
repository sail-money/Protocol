// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}                 from "../../interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../../interfaces/IBatchPermission.sol";
import {IPermissionIntrospection}             from "../../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities}                     from "../../interfaces/SailCapabilities.sol";
import {ConfigurablePermission}                 from "./ConfigurablePermission.sol";

/// @notice UNAUDITED EXAMPLE — NOT PART OF THE TRUSTED CORE.
///         This permission is a reference example demonstrating how to express a bounded
///         mandate against the Sail kernel. It is provided as-is, is NOT covered by the
///         protocol audit of the trusted core (SailKernel, SailGovernance, MandateFactory,
///         StandardFeePolicy, SafeModuleEnabler), and carries no warranty. The kernel
///         evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly
///         enforces what its NatSpec claims. Anyone registering this permission is
///         responsible for reviewing it. See docs/SECURITY.md for the audit-scope documentation.
///
///         Shared multi-tenant batch permission for the canonical
///         "approve / consuming-call / reset-to-zero" pattern.
///
/// @dev    The batch shape this template authorises is exactly:
///           [0] approve(spender, amount)  on an allowlisted ERC-20 token
///           [1] consuming call            on an allowlisted (target, selector)
///           [2] approve(spender, 0)       reset the allowance back to zero
///
///         This is the safest way to bracket a single protocol interaction:
///         the allowance exists only for the lifetime of the batch and is
///         strictly reset before the transaction completes. There is no
///         window in which the allowance can be exploited by a third party.
///
///         The template inherits the standard EIP-712 `configure(...)` flow
///         from ConfigurablePermission. Per-account configuration is stored
///         in mappings keyed by account address.
///
/// @dev    Decoding philosophy: every decode is bounds-checked. Malformed
///         calldata reverts. The kernel treats a revert as denial (fail-closed).
///
/// @dev    KNOWN BOUNDARY (output recipient is NOT constrained): the approve →
///         consume → reset bracket bounds the allowance — how much the spender may
///         pull (≤ the per-token cap) — and guarantees the allowance is reset to
///         zero in the same atomic batch. It does NOT constrain where the consuming
///         call (calls[1]) delivers its output: that field is venue/selector-specific
///         and is intentionally not decoded (a fixed-offset decode would be fragile
///         and unsafe across venues). Operators MUST only allowlist
///         (consumingTarget, consumingSelector) pairs whose semantics they trust to
///         deliver output to the account, or pair this template with a separate
///         permission that constrains the destination.
contract ApproveAndCallBatchPermission is ConfigurablePermission, IBatchPermission, IPermissionIntrospection {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @dev Maximum number of entries in any allowlist array.
    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    /// @dev ERC-20 `approve(address,uint256)` selector.
    bytes4 private constant APPROVE_SELECTOR = 0x095ea7b3;

    /// @dev Minimum calldata length for `approve(address,uint256)`:
    ///      4 (selector) + 32 (spender) + 32 (amount) = 68 bytes.
    uint256 private constant APPROVE_CALLDATA_LEN = 68;

    /// @dev Minimum calldata length for the consuming call:
    ///      4 (selector) + 32 (first uint256 arg) = 36 bytes.
    ///      Required when `requireAmountMatch == true`; for other shapes only
    ///      the 4-byte selector is required, but enforcing 36 keeps decoding
    ///      uniform.
    uint256 private constant CONSUMING_MIN_LEN = 36;

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /// @notice Per-account configuration for the approve / call / reset pattern.
    /// @dev    `tokens` and `maxApprovalAmounts` are index-parallel: maxApprovalAmounts[i]
    ///         is the cap for tokens[i]. Length mismatch reverts during configure.
    struct Config {
        /// @dev Allowlisted ERC-20 tokens that may be approved.
        address[] tokens;
        /// @dev Allowlisted spenders that may receive the allowance.
        address[] spenders;
        /// @dev Allowlisted consuming-call targets (often the same as spenders).
        address[] consumingTargets;
        /// @dev Allowlisted selectors for the consuming call (calls[1]).
        bytes4[]  consumingSelectors;
        /// @dev Max approve amount per token, index-parallel with `tokens`.
        uint256[] maxApprovalAmounts;
        /// @dev When true, the first uint256 argument of the consuming call's
        ///      calldata must equal the approve amount. Useful for swaps and
        ///      transfers where the consumed amount is the leading arg.
        bool      requireAmountMatch;
    }

    mapping(address account => Config) private _cfg;

    // O(1) allowlist lookups (rebuilt on each configure)
    mapping(address account => mapping(address token            => uint256)) public maxApprovalAmount; // 0 = not allowlisted
    mapping(address account => mapping(address spender          => bool))    public isSpender;
    mapping(address account => mapping(address consumingTarget  => bool))    public isConsumingTarget;
    mapping(address account => mapping(bytes4  consumingSelector => bool))   public isConsumingSelector;

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    error TokensAndAmountsLengthMismatch(uint256 tokensLen, uint256 amountsLen);
    error EmptyAllowlist();
    error AllowlistTooLong();

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "ApproveAndCallBatchPermission", "1")
    {
        author = _author;
    }

    // -------------------------------------------------------------------------
    // View accessors
    // -------------------------------------------------------------------------

    function getConfig(address account) external view returns (Config memory) {
        return _cfg[account];
    }

    // -------------------------------------------------------------------------
    // ConfigurablePermission hook
    // -------------------------------------------------------------------------

    function _applyConfig(address account, bytes calldata params) internal override {
        Config memory cfg = abi.decode(params, (Config));

        if (
            cfg.tokens.length            > MAX_ALLOWLIST_LENGTH ||
            cfg.spenders.length          > MAX_ALLOWLIST_LENGTH ||
            cfg.consumingTargets.length  > MAX_ALLOWLIST_LENGTH ||
            cfg.consumingSelectors.length > MAX_ALLOWLIST_LENGTH
        ) revert AllowlistTooLong();

        if (cfg.tokens.length != cfg.maxApprovalAmounts.length) {
            revert TokensAndAmountsLengthMismatch(cfg.tokens.length, cfg.maxApprovalAmounts.length);
        }
        if (
            cfg.tokens.length == 0 ||
            cfg.spenders.length == 0 ||
            cfg.consumingTargets.length == 0 ||
            cfg.consumingSelectors.length == 0
        ) revert EmptyAllowlist();

        // Clear previous lookup mappings
        Config storage prev = _cfg[account];
        for (uint256 i; i < prev.tokens.length; i++)             maxApprovalAmount[account][prev.tokens[i]]             = 0;
        for (uint256 i; i < prev.spenders.length; i++)           isSpender[account][prev.spenders[i]]                   = false;
        for (uint256 i; i < prev.consumingTargets.length; i++)   isConsumingTarget[account][prev.consumingTargets[i]]   = false;
        for (uint256 i; i < prev.consumingSelectors.length; i++) isConsumingSelector[account][prev.consumingSelectors[i]] = false;

        // Write new mappings
        for (uint256 i; i < cfg.tokens.length; i++) {
            // Reject zero/duplicate token or zero max
            address t = cfg.tokens[i];
            uint256 m = cfg.maxApprovalAmounts[i];
            if (t == address(0) || m == 0) revert EmptyAllowlist();
            maxApprovalAmount[account][t] = m;
        }
        for (uint256 i; i < cfg.spenders.length; i++) {
            if (cfg.spenders[i] == address(0)) revert EmptyAllowlist();
            isSpender[account][cfg.spenders[i]] = true;
        }
        for (uint256 i; i < cfg.consumingTargets.length; i++) {
            if (cfg.consumingTargets[i] == address(0)) revert EmptyAllowlist();
            isConsumingTarget[account][cfg.consumingTargets[i]] = true;
        }
        for (uint256 i; i < cfg.consumingSelectors.length; i++) {
            isConsumingSelector[account][cfg.consumingSelectors[i]] = true;
        }

        _cfg[account] = cfg;
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @notice This template is batch-only. Single dispatch is never authorised.
    /// @dev    `evaluate` always returns false. To use this template, the manager must
    ///         call `dispatchBatch` with this contract named as the batch permission.
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) {
        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("ApproveAndCallBatchPermission");
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
    /// @dev Validates the strict 3-call shape:
    ///        calls[0] = approve(spender, amount)           on an allowlisted token
    ///        calls[1] = <selector>(amount, ...)            on an allowlisted (target, selector)
    ///        calls[2] = approve(spender, 0)                same token, same spender, amount==0
    ///
    ///      Any deviation — wrong length, wrong token/spender/target/selector, amount above cap,
    ///      amount mismatch (when configured), non-zero reset, malformed calldata — causes the
    ///      function to return false or revert (kernel treats either as denial).
    ///
    ///      NOTE: the output recipient of calls[1] is NOT validated here — see the contract-level
    ///      "KNOWN BOUNDARY" note. This bracket bounds the allowance, not the output destination.
    function evaluateBatch(Call[] calldata calls, BatchContext calldata ctx)
        external
        view
        returns (bool)
    {
        // Exact 3-call shape required
        if (calls.length != 3) return false;

        address account = ctx.account;

        // ── calls[0] ── approve(spender, amount) on an allowlisted token ──────
        Call calldata c0 = calls[0];
        if (c0.value != 0) return false;
        if (c0.data.length != APPROVE_CALLDATA_LEN) return false;
        if (bytes4(c0.data[0:4]) != APPROVE_SELECTOR) return false;

        address token = c0.target;
        uint256 cap   = maxApprovalAmount[account][token];
        if (cap == 0) return false;     // token not in allowlist

        (address spender, uint256 approveAmount) = _decodeApprove(c0.data);
        if (!isSpender[account][spender]) return false;
        if (approveAmount == 0) return false;
        if (approveAmount > cap) return false;

        // ── calls[1] ── consuming call on allowlisted (target, selector) ──────
        Call calldata c1 = calls[1];
        if (c1.value != 0) return false;
        if (!isConsumingTarget[account][c1.target]) return false;
        if (c1.data.length < CONSUMING_MIN_LEN) return false;
        bytes4 sel = bytes4(c1.data[0:4]);
        if (!isConsumingSelector[account][sel]) return false;

        if (_cfg[account].requireAmountMatch) {
            uint256 consumedAmount = _decodeFirstUint256(c1.data);
            if (consumedAmount != approveAmount) return false;
        }

        // ── calls[2] ── approve(spender, 0) — strict reset of same token & spender ──
        Call calldata c2 = calls[2];
        if (c2.value != 0) return false;
        if (c2.target != token) return false;
        if (c2.data.length != APPROVE_CALLDATA_LEN) return false;
        if (bytes4(c2.data[0:4]) != APPROVE_SELECTOR) return false;

        (address resetSpender, uint256 resetAmount) = _decodeApprove(c2.data);
        if (resetSpender != spender) return false;
        if (resetAmount != 0) return false;

        return true;
    }

    // -------------------------------------------------------------------------
    // Internal calldata decoding
    // -------------------------------------------------------------------------

    /// @dev Decode `approve(address,uint256)` calldata. Caller must ensure length == 68.
    ///      Uses calldata slicing to avoid the cost of a full abi.decode.
    function _decodeApprove(bytes calldata data) internal pure returns (address spender, uint256 amount) {
        // The address occupies the right-most 20 bytes of the first 32-byte arg slot.
        spender = address(uint160(uint256(bytes32(data[4:36]))));
        amount  = uint256(bytes32(data[36:68]));
    }

    /// @dev Decode the first uint256 argument of an arbitrary call. Caller must
    ///      ensure data.length >= 36.
    function _decodeFirstUint256(bytes calldata data) internal pure returns (uint256) {
        return uint256(bytes32(data[4:36]));
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.ApproveAndCallBatchPermission.v1");
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
