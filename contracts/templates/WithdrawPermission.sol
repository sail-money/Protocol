// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @title  WithdrawPermission — bounded ERC-20 move to a single pinned recipient
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
///         WHAT IT IS. A reference withdraw template. One deployment serves any number of accounts;
///         each account stores its own token allowlist, a single pinned recipient, and a per-tx cap.
///         It gates ERC-20 movements so funds can only ever reach the account's configured
///         allowedRecipient (typically the owner's own Safe — e.g. safe-to-safe consolidation).
///
///         WHAT IT ENFORCES. For every call: the token (call target) is allowlisted; the amount is
///         within the per-tx cap; the destination equals the single configured allowedRecipient
///         (not an open set); and on transferFrom the `from` is the account itself (so the manager
///         cannot pull tokens a third party approved to the account). Calls carrying native ETH
///         (msg.value != 0) are rejected.
///
///         SELECTOR BOUNDARY. Recognizes the two ERC-20 movement selectors only:
///           - transfer(address to, uint256 amount)
///           - transferFrom(address from, address to, uint256 amount)
///         Any other selector (including approve) is denied. This moves ERC-20s to a pinned address;
///         it is NOT a protocol-withdraw interface — it does NOT recognize vault/pool redeem or
///         withdraw calls. To redeem from a vault, pair it with a separate permission.
///
///         HONEST BOUNDARY — what it does NOT do. The pinned recipient is whatever the latest
///         configuration set; the permissionSigner can change it by reconfiguring, so the pin is
///         only as trustworthy as the permissionSigner key. The cap is per-transaction, NOT
///         cumulative — a manager may make many at-cap moves to the pinned recipient. A
///         maxAmountPerTx of 0 is accepted and blocks every non-zero withdrawal (fail-closed).
///
///         CONFIG FRESHNESS (fail-closed). Evaluation denies unless this account is configured AND
///         its stored config epoch equals the kernel's current registration epoch for this
///         (account, permission). A configuration left over from a prior registration — e.g. after a
///         revoke / re-register cycle — is never honoured.
///
/// @dev    Config blob:
///             abi.encode(
///                 address[] tokens,
///                 address   allowedRecipient,
///                 uint256   maxAmountPerTx
///             )
/// @custom:security-contact hello@sail.money
contract WithdrawPermission is ConfigurablePermission, IPermissionIntrospection {
    /// @dev transfer(address,uint256) — ERC-20 standard transfer.
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;
    /// @dev transferFrom(address,address,uint256) — ERC-20 approved pull.
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    uint256 private constant LEN_TRANSFER     = 68;  // selector(4) + to(32) + amount(32)
    uint256 private constant LEN_TRANSFERFROM = 100; // selector(4) + from(32) + to(32) + amount(32)

    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    struct Slot {
        address[] tokens;
        address   allowedRecipient;
        uint256   maxAmountPerTx;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedToken;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error AllowlistTooLong();
    error EmptyAllowlist();

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "WithdrawPermission", "2")
    {
        author = _author;
    }

    function getConfig(address account)
        external
        view
        returns (address[] memory tokens, address allowedRecipient, uint256 maxAmountPerTx)
    {
        Slot storage s = _slots[account];
        return (s.tokens, s.allowedRecipient, s.maxAmountPerTx);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (address[] memory tokens, address allowedRecipient, uint256 maxAmountPerTx) =
            abi.decode(params, (address[], address, uint256));

        // Config validation (reference-grade): bound the allowlist, reject an empty token
        // list, and reject zero-address tokens / recipient. maxAmountPerTx == 0 is allowed
        // (fail-closed: blocks all non-zero withdrawals).
        if (tokens.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (tokens.length == 0) revert EmptyAllowlist();
        if (allowedRecipient == address(0)) revert ZeroAddress();
        for (uint256 i; i < tokens.length; i++) if (tokens[i] == address(0)) revert ZeroAddress();

        Slot storage s = _slots[account];
        for (uint256 i; i < s.tokens.length; i++) isAllowedToken[account][s.tokens[i]] = false;
        for (uint256 i; i < tokens.length; i++)   isAllowedToken[account][tokens[i]]   = true;

        s.tokens           = tokens;
        s.allowedRecipient = allowedRecipient;
        s.maxAmountPerTx   = maxAmountPerTx;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Fail closed unless the stored config is current for this registration epoch.
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
        // ERC-20 calls carry no ETH.
        if (ctx.value != 0) return false;
        // Token must be on the account's allowlist.
        if (!isAllowedToken[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == TRANSFER_SELECTOR) {
            if (txData.length < LEN_TRANSFER) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            if (amount > s.maxAmountPerTx) return false;
            return to == s.allowedRecipient;
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            if (txData.length < LEN_TRANSFERFROM) return false;
            (address from, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            // `from` must be the account itself to prevent pulling tokens from arbitrary approvers.
            if (from != ctx.account) return false;
            if (amount > s.maxAmountPerTx) return false;
            return to == s.allowedRecipient;
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("WithdrawPermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.WithdrawPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.WITHDRAW;
    }
}
