// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context}                 from "../interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../interfaces/IBatchPermission.sol";
import {IPermissionIntrospection}             from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities}                     from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission}                 from "./ConfigurablePermission.sol";

/// @title  ApproveAndCallBatchPermission — atomic approve / consume / reset bracket
/// @notice REFERENCE LAUNCH TEMPLATE — part of the hardened reference set, NOT part of the
///         trusted core. This is one of the seven hardened launch templates.
///         It is documented with the honest boundaries below
///         ("what this cannot protect against"). It sits OUTSIDE the trusted core
///         (SailKernel, SailGovernance, MandateFactory, StandardFeePolicy, SafeModuleEnabler):
///         a bug here cannot reach the kernel or accounts that have not registered it. The
///         kernel evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly enforces
///         what its NatSpec claims, so registrants remain responsible for reviewing it. The
///         loud "UNAUDITED — EXPERIMENTAL" banner is reserved for the future experimental template
///         set (currently empty), not this hardened launch set. See docs/SECURITY.md for the
///         reference-template documentation.
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
///         and amount (≤ a per-token cap); that the pre-batch allowance on the approved (token,
///         spender) pair is already zero (no stale allowance can be consumed beyond the bracket);
///         that the consuming call's (target, selector) is an allowlisted PAIR — a selector is valid
///         only on the specific target it was authorized with, never on any other allowlisted target;
///         that the consuming call targets the very spender approved in calls[0] AND pulls the very
///         token approved in calls[0] — the consumed asset is decoded for the standard-ABI selector
///         set below and any selector whose consumed asset cannot be located safely is denied (fail
///         closed); optionally that the consuming call's leading uint256 argument equals the approved
///         amount (requireAmountMatch); and that calls[2] resets the same token/spender allowance to
///         zero. Because the consumed asset must be decodable, the consuming selector is restricted to
///         the decodable set below regardless of requireRecipientIsAccount.
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
///         the spender may pull (≤ the cap), binds that pull to the approved (token, spender), and
///         guarantees the allowance is reset to zero, but it does NOT constrain where the consuming
///         call delivers its output. With the mode ON, the output recipient is additionally pinned to
///         the account. Either way the consuming selector must be in the decodable set above (so the
///         consumed asset can be bound); any other selector is denied, and the operator must still
///         understand which consuming calls they authorize. This template does not inspect token
///         balances or post-conditions.
///
///         CONFIG FRESHNESS (fail-closed). evaluateBatch denies unless this account is configured AND
///         its stored config epoch equals the kernel's current registration epoch for this
///         (account, permission). A configuration left over from a prior registration — e.g. after a
///         revoke / re-register cycle — is never honoured.
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

    /// @dev `IERC20.allowance(address,address)` selector — read pre-batch allowance via staticcall.
    bytes4 private constant ALLOWANCE_SELECTOR = 0xdd62ed3e;

    /// @dev `IERC4626.asset()` selector — the only consumed-asset that is not in the calldata and
    ///      must be read from the vault (the consuming target) directly.
    bytes4 private constant ERC4626_ASSET_SELECTOR = 0x38d52e0f;

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
        ConfigurablePermission(_kernel, "ApproveAndCallBatchPermission", "2")
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
    ///        calls[0] = approve(spender, amount)           on an allowlisted token, pre-batch allowance 0
    ///        calls[1] = <selector>(amount, ...)            on an allowlisted (target, selector) pair,
    ///                                                      target == spender, consumed asset == token
    ///        calls[2] = approve(spender, 0)                same token, same spender, amount==0
    ///
    ///      Any deviation — wrong length, wrong token/spender, non-zero pre-batch allowance,
    ///      unauthorised (target, selector) pair, consuming target != spender, consumed asset != token,
    ///      non-decodable consuming selector, amount above cap, amount mismatch (when configured),
    ///      recipient not the account (when requireRecipientIsAccount is on), non-zero reset, malformed
    ///      calldata — causes the function to return false or revert (kernel treats either as denial).
    function evaluateBatch(Call[] calldata calls, BatchContext calldata ctx)
        external
        view
        returns (bool)
    {
        // Fail closed unless the stored config is current for this registration epoch.
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
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

        // A residual (stale) allowance on the SAME (token, spender) pair could be consumed beyond the
        // bracket this batch establishes — e.g. a token whose nonzero approve returns false without
        // reverting leaves the prior allowance in place. Require the pre-batch allowance to be zero so
        // the consuming call can only ever draw the allowance this batch grants and then resets.
        if (!_allowanceIsZero(token, account, spender)) return false;

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

        // ── Bind the consuming call to the approved (token, spender) ──────────────────
        // Two bindings, both unconditional (independent of requireRecipientIsAccount):
        //   (i)  the consuming call must hit the exact spender approved in calls[0]. Combined with
        //        the pre-batch allowance==0 check above, the ONLY allowance this call can draw is the
        //        one this batch grants (≤ cap) and resets — never a stale allowance to some other
        //        puller/router.
        //   (ii) the asset the call pulls must be the token approved in calls[0]. The consumed asset
        //        is decoded for the same standard-ABI selector set the recipient pin uses; a selector
        //        whose consumed asset cannot be located safely (aggregators, the Universal Router,
        //        opaque command blobs) is denied (fail closed) rather than left unbound.
        if (c1.target != spender) return false;
        (bool assetDecodable, address consumedAsset) = _decodeConsumedAsset(sel, c1.data, c1.target);
        if (!assetDecodable) return false;
        if (consumedAsset != token) return false;

        if (_cfg[account].requireAmountMatch) {
            // The "consumed amount" lives at a different calldata word per selector, so it must be
            // decoded selector-aware (a fixed word-0 read would compare the approved amount against a
            // token ADDRESS for the V3/Aave shapes, or against a SHARE count for ERC-4626 mint).
            // A selector whose consumed amount cannot be located in calldata (e.g. mint, where the
            // pulled assets are previewMint(shares), off-chain) is reported not-decodable → deny.
            (bool amtDecodable, uint256 consumedAmount) = _decodeConsumedAmount(sel, c1.data);
            if (!amtDecodable) return false;
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

    /// @dev Decode the amount the consuming call pulls from the account, selector-aware, for the same
    ///      decodable selector set the asset/recipient pins use. Returns (true, amount) when the
    ///      pulled amount sits at a known fixed head-word offset; (false, 0) otherwise so the caller
    ///      denies (fail closed). The offset differs per shape, so this must NOT read a fixed word:
    ///        - swapExactTokensForTokens: amountIn  @ word 0  ([4:36])
    ///        - ERC-4626 deposit(assets,receiver): assets @ word 0 ([4:36])
    ///        - Aave V3 supply / V2 deposit:        amount @ word 1 ([36:68])
    ///        - V3 exactInputSingle (SwapRouter, w/ deadline): amountIn @ word 5 ([164:196])
    ///        - V3 exactInputSingle (SwapRouter02, no deadline): amountIn @ word 4 ([132:164])
    ///        - ERC-4626 mint(shares,receiver): the pulled assets are previewMint(shares), which is
    ///          NOT in calldata, so the approved amount cannot be bound to it → not decodable.
    ///      Each branch length-guards before slicing.
    function _decodeConsumedAmount(bytes4 sel, bytes calldata data)
        internal
        pure
        returns (bool decodable, uint256 amount)
    {
        // amount at word 0 — caller guarantees data.length >= CONSUMING_MIN_LEN (36).
        if (sel == SWAP_EXACT_TOKENS_FOR_TOKENS || sel == ERC4626_DEPOSIT) {
            return (true, uint256(bytes32(data[4:36])));
        }
        // amount at word 1: Aave supply/deposit (asset, amount, ...).
        if (sel == AAVE_V3_SUPPLY || sel == AAVE_V2_DEPOSIT) {
            if (data.length < 68) return (false, 0);
            return (true, uint256(bytes32(data[36:68])));
        }
        // amountIn at word 5: Uniswap V3 SwapRouter exactInputSingle (params struct carries a deadline).
        if (sel == EXACT_INPUT_SINGLE) {
            if (data.length < 196) return (false, 0);
            return (true, uint256(bytes32(data[164:196])));
        }
        // amountIn at word 4: SwapRouter02 exactInputSingle (no deadline field).
        if (sel == EXACT_INPUT_SINGLE_02) {
            if (data.length < 164) return (false, 0);
            return (true, uint256(bytes32(data[132:164])));
        }
        // ERC-4626 mint and any other selector: consumed amount not locatable in calldata → deny.
        return (false, 0);
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

    /// @dev Decode the asset the consuming call pulls from the account, for the same decodable
    ///      selector set the recipient pin uses. Returns (true, asset) when it can be located safely;
    ///      (false, 0) otherwise, so the caller denies (fail closed). Mirrors how each protocol reads
    ///      the asset, so the bound asset is exactly the one the call will move.
    function _decodeConsumedAsset(bytes4 sel, bytes calldata data, address target)
        internal
        view
        returns (bool decodable, address asset)
    {
        // Head word 0 (bytes [4:36]): Uniswap V3 exactInputSingle `tokenIn` (the params struct is all
        // static, so it is encoded inline) and Aave supply/deposit `asset` both occupy the first
        // argument slot. data.length >= CONSUMING_MIN_LEN (36) is guaranteed by the caller.
        if (sel == EXACT_INPUT_SINGLE || sel == EXACT_INPUT_SINGLE_02 || sel == AAVE_V3_SUPPLY || sel == AAVE_V2_DEPOSIT) {
            return (true, address(uint160(uint256(bytes32(data[4:36])))));
        }
        // Uniswap V2 swapExactTokensForTokens: the pulled asset is path[0]. `path` is dynamic, so its
        // elements live at the offset declared in head word 2. Follow that offset — exactly as the
        // router's own abi.decode does, which permits a non-canonical offset — instead of assuming
        // 0xa0, and bounds-check every read so a malformed payload fails closed.
        if (sel == SWAP_EXACT_TOKENS_FOR_TOKENS) {
            if (data.length < LEN_RECIPIENT_WORD2) return (false, address(0)); // need head word 2
            uint256 off = uint256(bytes32(data[68:100]));         // offset of `path`, relative to args
            if (off > data.length) return (false, address(0));    // out of bounds → deny
            uint256 lenPos = 4 + off;                              // path length word position
            if (data.length < lenPos + 64) return (false, address(0)); // need length word + path[0]
            if (uint256(bytes32(data[lenPos:lenPos + 32])) == 0) return (false, address(0)); // empty path
            uint256 elemPos = lenPos + 32;
            return (true, address(uint160(uint256(bytes32(data[elemPos:elemPos + 32])))));
        }
        // ERC-4626 deposit/mint: the pulled asset is the vault's underlying, which is not in the
        // calldata. The vault is the consuming target (== the approved spender, enforced by the
        // caller), so read it via a bounded asset() staticcall; any failure / short return denies.
        if (sel == ERC4626_DEPOSIT || sel == ERC4626_MINT) {
            (bool ok, bytes memory ret) = target.staticcall(abi.encodeWithSelector(ERC4626_ASSET_SELECTOR));
            if (!ok || ret.length < 32) return (false, address(0));
            return (true, abi.decode(ret, (address)));
        }
        // Any other selector: the consumed asset cannot be located safely → not decodable.
        return (false, address(0));
    }

    /// @dev True iff the pre-batch ERC-20 allowance on (token, spender) is zero. Read via a bounded
    ///      staticcall so a code-less or misbehaving token denies (fail closed) rather than reverting
    ///      the whole evaluation.
    function _allowanceIsZero(address token, address account, address spender) internal view returns (bool) {
        (bool ok, bytes memory ret) =
            token.staticcall(abi.encodeWithSelector(ALLOWANCE_SELECTOR, account, spender));
        if (!ok || ret.length < 32) return false;
        return abi.decode(ret, (uint256)) == 0;
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
