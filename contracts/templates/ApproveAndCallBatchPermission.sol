// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}                 from "../interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../interfaces/IBatchPermission.sol";
import {IPermissionIntrospection}             from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities}                     from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission}                 from "./ConfigurablePermission.sol";

/// @title  ApproveAndCallBatchPermission — atomic approve / consume / reset bracket
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
///         WHAT IT IS. A shared multi-tenant batch permission for the canonical
///         "approve / consuming-call / reset-to-zero" pattern. The batch shape it authorises
///         is exactly:
///           [0] approve(spender, amount)  on an allowlisted ERC-20 token
///           [1] consuming call            on an allowlisted (target, selector) PAIR
///           [2] approve(spender, 0)       reset the allowance back to zero
///         The allowance exists only for the lifetime of the batch and is strictly reset before
///         the transaction completes, so there is no window in which it can be exploited by a
///         third party.
///
///         WHAT IT ENFORCES. For every batch: the exact 3-call shape; the approved token, spender,
///         and amount (≤ a per-token cap); that the consuming call's (target, selector) is an
///         allowlisted PAIR — a selector is valid only on the specific target it was authorized
///         with, never on any other allowlisted target; optionally that the consuming call's
///         leading uint256 argument equals the approved amount (requireAmountMatch); and that
///         calls[2] resets the same token/spender allowance to zero.
///
///         OUTPUT RECIPIENT (requireRecipientIsAccount). The consuming call's output destination
///         is, by default, NOT constrained — see the honest boundary below. The OPTIONAL
///         per-account mode `requireRecipientIsAccount` tightens this: when ON, the consuming
///         call's output recipient is decoded and must equal the account. Because a recipient can
///         only be located for selectors whose calldata layout places it at a known fixed offset,
///         the mode covers a specific decodable set and DENIES every other consuming selector
///         (fail closed). The decodable set is:
///           - swapExactTokensForTokens(uint256,uint256,address[],address,uint256)   — `to`
///           - exactInputSingle(...)  (Uniswap V3 SwapRouter, with deadline)         — `recipient`
///           - exactInputSingle(...)  (Uniswap SwapRouter02, no deadline)            — `recipient`
///           - supply(address,uint256,address,uint16)  (Aave V3)                     — `onBehalfOf`
///           - deposit(address,uint256,address,uint16) (Aave V2)                     — `onBehalfOf`
///           - deposit(uint256,address) (ERC-4626)                                   — `receiver`
///           - mint(uint256,address)    (ERC-4626)                                   — `receiver`
///         Selectors whose recipient is nested behind a dynamic offset or inside an opaque blob —
///         e.g. Uniswap V3 exactInput (dynamic `bytes path`), the Universal Router execute, or
///         bridge/aggregator calldata — are intentionally NOT decoded and DENY under this mode.
///         OPERATORS SHOULD PREFER requireRecipientIsAccount = true whenever every consuming
///         selector they authorize is in the decodable set; it is the safer configuration.
///
///         HONEST BOUNDARY — what it does NOT do. With requireRecipientIsAccount OFF (the default),
///         the output recipient of the consuming call is UNCONSTRAINED: the bracket bounds how much
///         the spender may pull (≤ the cap) and guarantees the allowance is reset to zero, but it
///         does NOT constrain where the consuming call delivers its output. With the mode ON, only
///         the decodable selector set above is covered; any other consuming selector is denied, and
///         the operator must still understand which consuming calls they authorize. This template
///         does not inspect token balances or post-conditions.
///
/// @dev    Decoding philosophy: every decode is bounds-checked. A consuming payload too short to
///         hold the field being read fails closed (denies) rather than reading out of bounds.
///         The kernel additionally treats any revert as denial.
///
/// @dev    Config blob: abi.encode(Config) — see the Config struct. NOTE: the consuming allowlist
///         is a single array of bound (target, selector) PAIRS (ConsumingPair[]), not two parallel
///         target and selector lists.
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

    // ── Safely-decodable consuming selectors (output recipient at a fixed head-word offset) ──
    // The recipient of each of these sits at a static head word whose byte offset does not vary
    // with the call's dynamic data, and is stable across mainstream implementations/forks.
    bytes4 private constant SWAP_EXACT_TOKENS_FOR_TOKENS = 0x38ed1739; // swapExactTokensForTokens(uint256,uint256,address[],address,uint256) — `to` @ word 3
    bytes4 private constant EXACT_INPUT_SINGLE           = 0x414bf389; // exactInputSingle(...) Uniswap V3 SwapRouter (with deadline) — `recipient` @ word 3
    bytes4 private constant EXACT_INPUT_SINGLE_02        = 0x04e45aaf; // exactInputSingle(...) Uniswap SwapRouter02 (no deadline)   — `recipient` @ word 3
    bytes4 private constant AAVE_V3_SUPPLY               = 0x617ba037; // supply(address,uint256,address,uint16)  Aave V3 — `onBehalfOf` @ word 2
    bytes4 private constant AAVE_V2_DEPOSIT              = 0xe8eda9df; // deposit(address,uint256,address,uint16) Aave V2 — `onBehalfOf` @ word 2
    bytes4 private constant ERC4626_DEPOSIT             = 0x6e553f65; // deposit(uint256,address) ERC-4626 — `receiver` @ word 1
    bytes4 private constant ERC4626_MINT                = 0x94bf804d; // mint(uint256,address)    ERC-4626 — `receiver` @ word 1

    /// @dev Minimum calldata lengths to read the recipient word at each offset class:
    ///      word 3 = bytes [100:132]; word 2 = bytes [68:100]; word 1 = bytes [36:68].
    uint256 private constant LEN_RECIPIENT_WORD3 = 132; // 4 + 4*32
    uint256 private constant LEN_RECIPIENT_WORD2 = 100; // 4 + 3*32
    uint256 private constant LEN_RECIPIENT_WORD1 = 68;  // 4 + 2*32

    // -------------------------------------------------------------------------
    // Configuration
    // -------------------------------------------------------------------------

    /// @notice A bound consuming (target, selector) pair. A selector is authorised only on the
    ///         specific target it is paired with — never on any other allowlisted target.
    struct ConsumingPair {
        address target;
        bytes4  selector;
    }

    /// @notice Per-account configuration for the approve / call / reset pattern.
    /// @dev    `tokens` and `maxApprovalAmounts` are index-parallel: maxApprovalAmounts[i]
    ///         is the cap for tokens[i]. Length mismatch reverts during configure.
    struct Config {
        /// @dev Allowlisted ERC-20 tokens that may be approved.
        address[] tokens;
        /// @dev Allowlisted spenders that may receive the allowance.
        address[] spenders;
        /// @dev Allowlisted consuming (target, selector) pairs for calls[1].
        ConsumingPair[] consumingPairs;
        /// @dev Max approve amount per token, index-parallel with `tokens`.
        uint256[] maxApprovalAmounts;
        /// @dev When true, the first uint256 argument of the consuming call's
        ///      calldata must equal the approve amount. Useful for swaps and
        ///      transfers where the consumed amount is the leading arg.
        bool      requireAmountMatch;
        /// @dev When true, the consuming call's output recipient is decoded and must equal the
        ///      account; consuming selectors outside the decodable set are denied (fail closed).
        ///      When false (default), the output recipient is unconstrained.
        bool      requireRecipientIsAccount;
    }

    mapping(address account => Config) private _cfg;

    // O(1) allowlist lookups (rebuilt on each configure)
    mapping(address account => mapping(address token   => uint256)) public maxApprovalAmount; // 0 = not allowlisted
    mapping(address account => mapping(address spender => bool))    public isSpender;
    /// @dev Keyed by keccak256(abi.encodePacked(target, selector)) — binds the pair together.
    mapping(address account => mapping(bytes32 pairKey => bool))    public isConsumingPair;

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

    /// @notice Convenience accessor: is this (target, selector) pair allowlisted for the account?
    function isConsumingPairAllowed(address account, address target, bytes4 selector)
        external
        view
        returns (bool)
    {
        return isConsumingPair[account][_pairKey(target, selector)];
    }

    // -------------------------------------------------------------------------
    // ConfigurablePermission hook
    // -------------------------------------------------------------------------

    function _applyConfig(address account, bytes calldata params) internal override {
        Config memory cfg = abi.decode(params, (Config));

        if (
            cfg.tokens.length         > MAX_ALLOWLIST_LENGTH ||
            cfg.spenders.length       > MAX_ALLOWLIST_LENGTH ||
            cfg.consumingPairs.length > MAX_ALLOWLIST_LENGTH
        ) revert AllowlistTooLong();

        if (cfg.tokens.length != cfg.maxApprovalAmounts.length) {
            revert TokensAndAmountsLengthMismatch(cfg.tokens.length, cfg.maxApprovalAmounts.length);
        }
        if (
            cfg.tokens.length == 0 ||
            cfg.spenders.length == 0 ||
            cfg.consumingPairs.length == 0
        ) revert EmptyAllowlist();

        // Clear previous lookup mappings
        Config storage prev = _cfg[account];
        for (uint256 i; i < prev.tokens.length; i++)   maxApprovalAmount[account][prev.tokens[i]] = 0;
        for (uint256 i; i < prev.spenders.length; i++) isSpender[account][prev.spenders[i]]       = false;
        for (uint256 i; i < prev.consumingPairs.length; i++) {
            isConsumingPair[account][_pairKey(prev.consumingPairs[i].target, prev.consumingPairs[i].selector)] = false;
        }

        // Write new mappings
        for (uint256 i; i < cfg.tokens.length; i++) {
            // Reject zero token or zero max
            address t = cfg.tokens[i];
            uint256 m = cfg.maxApprovalAmounts[i];
            if (t == address(0) || m == 0) revert EmptyAllowlist();
            maxApprovalAmount[account][t] = m;
        }
        for (uint256 i; i < cfg.spenders.length; i++) {
            if (cfg.spenders[i] == address(0)) revert EmptyAllowlist();
            isSpender[account][cfg.spenders[i]] = true;
        }
        for (uint256 i; i < cfg.consumingPairs.length; i++) {
            ConsumingPair memory p = cfg.consumingPairs[i];
            if (p.target == address(0) || p.selector == bytes4(0)) revert EmptyAllowlist();
            isConsumingPair[account][_pairKey(p.target, p.selector)] = true;
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
    ///        calls[1] = <selector>(amount, ...)            on an allowlisted (target, selector) pair
    ///        calls[2] = approve(spender, 0)                same token, same spender, amount==0
    ///
    ///      Any deviation — wrong length, wrong token/spender, unauthorised (target, selector)
    ///      pair, amount above cap, amount mismatch (when configured), recipient not the account
    ///      (when requireRecipientIsAccount is on), non-zero reset, malformed calldata — causes the
    ///      function to return false or revert (kernel treats either as denial).
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

        // ── calls[1] ── consuming call on an allowlisted (target, selector) PAIR ──────
        Call calldata c1 = calls[1];
        if (c1.value != 0) return false;
        // Length guard first: a payload too short to even hold a selector + leading word fails
        // closed, so every decode below reads within bounds.
        if (c1.data.length < CONSUMING_MIN_LEN) return false;
        bytes4 sel = bytes4(c1.data[0:4]);
        // Bind target and selector: the selector is authorised only on the target it was paired
        // with. Two independent allowlists would form a cartesian product (any selector on any
        // target); the pair key prevents that.
        if (!isConsumingPair[account][_pairKey(c1.target, sel)]) return false;

        if (_cfg[account].requireAmountMatch) {
            uint256 consumedAmount = _decodeFirstUint256(c1.data);
            if (consumedAmount != approveAmount) return false;
        }

        // Optional: constrain where the consuming call delivers its output to the account itself.
        if (_cfg[account].requireRecipientIsAccount) {
            (bool decodable, address recipient) = _decodeRecipient(sel, c1.data);
            // A selector outside the decodable set has no recipient at a known fixed offset.
            // Guessing an offset could assert a recipient that does not exist, so deny instead.
            if (!decodable) return false;
            if (recipient != account) return false;
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

    /// @dev Deterministic key binding a consuming target to a selector.
    function _pairKey(address target, bytes4 selector) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked(target, selector));
    }

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

    /// @dev Decode the output recipient of a consuming call for the selectors whose recipient sits
    ///      at a known, fixed head-word offset (see the constant table). Returns (true, recipient)
    ///      for those; (false, address(0)) for any other selector. Each branch length-guards its
    ///      payload before slicing, so a too-short call fails closed rather than reading out of
    ///      bounds. Selectors NOT handled here (e.g. exactInput with a dynamic `bytes path`, the
    ///      Universal Router execute, bridge/aggregator calldata) carry their recipient behind a
    ///      dynamic offset or inside an opaque blob; a fixed-offset read would assert a recipient
    ///      that may not exist, so they are reported not-decodable and the caller denies.
    function _decodeRecipient(bytes4 sel, bytes calldata data)
        internal
        pure
        returns (bool decodable, address recipient)
    {
        // Recipient at word 3 (bytes [100:132]): both V3 exactInputSingle layouts and the V2
        // swapExactTokensForTokens `to`. The V2 `path` is dynamic but its head slot is fixed, so
        // `to` keeps a fixed offset regardless of path length.
        if (sel == EXACT_INPUT_SINGLE || sel == EXACT_INPUT_SINGLE_02 || sel == SWAP_EXACT_TOKENS_FOR_TOKENS) {
            if (data.length < LEN_RECIPIENT_WORD3) return (false, address(0));
            return (true, address(uint160(uint256(bytes32(data[100:132])))));
        }
        // Recipient at word 2 (bytes [68:100]): Aave supply / deposit `onBehalfOf`.
        if (sel == AAVE_V3_SUPPLY || sel == AAVE_V2_DEPOSIT) {
            if (data.length < LEN_RECIPIENT_WORD2) return (false, address(0));
            return (true, address(uint160(uint256(bytes32(data[68:100])))));
        }
        // Recipient at word 1 (bytes [36:68]): ERC-4626 deposit / mint `receiver`.
        if (sel == ERC4626_DEPOSIT || sel == ERC4626_MINT) {
            if (data.length < LEN_RECIPIENT_WORD1) return (false, address(0));
            return (true, address(uint160(uint256(bytes32(data[36:68])))));
        }
        // Unknown selector: recipient cannot be located without guessing → not decodable.
        return (false, address(0));
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
