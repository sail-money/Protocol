// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @title  TransferPermission — bounded ERC-20 transfer to an allowlisted recipient set
/// @notice REFERENCE LAUNCH TEMPLATE — part of the audited reference set, NOT part of the
///         trusted core. This is one of the seven launch templates Octane is auditing
///         post-freeze: it is hardened and documented with the honest boundaries below
///         ("what this cannot protect against"). It sits OUTSIDE the trusted core
///         (SailKernel, SailGovernance, MandateFactory, StandardFeePolicy, SafeModuleEnabler):
///         a bug here cannot reach the kernel or accounts that have not registered it. The
///         kernel evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly enforces
///         what its NatSpec claims, so registrants remain responsible for reviewing it. The
///         loud "UNAUDITED EXAMPLE" banner is reserved for the future experimental template
///         set (currently empty), not this hardened launch set. See docs/SECURITY.md for the
///         audit-scope documentation.
///
///         WHAT IT IS. A reference transfer template. One deployment serves any number of accounts;
///         each account stores its own recipient allowlist, token allowlist, and per-tx amount cap.
///         It gates a manager's ERC-20 transfers so funds only move to pre-approved recipients, in
///         pre-approved tokens, within a per-transaction size cap.
///
///         WHAT IT ENFORCES. For every call: the token (call target) is allowlisted; the amount is
///         within the per-tx cap; the destination is in the recipient allowlist; and on
///         transferFrom the `from` is the account itself (so the manager cannot pull tokens a third
///         party approved to the account). Calls carrying native ETH (msg.value != 0) are rejected.
///
///         SELECTOR BOUNDARY. Recognizes the two ERC-20 movement selectors only:
///           - transfer(address to, uint256 amount)
///           - transferFrom(address from, address to, uint256 amount)
///         Any other selector (including approve) is denied. This is a plain ERC-20 transfer gate;
///         it does NOT interpret vault/pool/router calldata or any protocol-specific interface.
///
///         HONEST BOUNDARY — what it does NOT do. Recipients are an open SET the permissionSigner
///         controls; a compromised permissionSigner can add a recipient, and an allowlisted
///         recipient that is itself a malicious contract is not vetted here. The cap is
///         per-transaction, NOT cumulative — a manager may make many at-cap transfers. A
///         maxAmountPerTx of 0 is accepted and blocks every non-zero transfer (fail-closed).
///
///         CONFIG FRESHNESS (fail-closed). Evaluation denies unless this account is configured AND
///         its stored config epoch equals the kernel's current registration epoch for this
///         (account, permission). A configuration left over from a prior registration — e.g. after a
///         revoke / re-register cycle — is never honoured (Octane #2 / #8).
///
/// @dev    Config blob:
///             abi.encode(
///                 address[] allowedRecipients,
///                 address[] allowedTokens,
///                 uint256   maxAmountPerTx
///             )
contract TransferPermission is ConfigurablePermission, IPermissionIntrospection {
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    uint256 private constant LEN_TRANSFER     = 68;
    uint256 private constant LEN_TRANSFERFROM = 100;

    uint256 private constant MAX_ALLOWLIST_LENGTH = 50;

    struct Slot {
        address[] recipients;
        address[] tokens;
        uint256   maxAmountPerTx;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedRecipient;
    mapping(address account => mapping(address => bool)) public isAllowedToken;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error AllowlistTooLong();
    error EmptyAllowlist();

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "TransferPermission", "2")
    {
        author = _author;
    }

    function getConfig(address account)
        external
        view
        returns (address[] memory recipients, address[] memory tokens, uint256 maxAmountPerTx)
    {
        Slot storage s = _slots[account];
        return (s.recipients, s.tokens, s.maxAmountPerTx);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (address[] memory recipients, address[] memory tokens, uint256 maxAmountPerTx) =
            abi.decode(params, (address[], address[], uint256));

        // Config validation (reference-grade): bound array sizes, reject empty allowlists,
        // and reject zero-address recipients/tokens. evaluate() logic is unchanged.
        if (recipients.length > MAX_ALLOWLIST_LENGTH || tokens.length > MAX_ALLOWLIST_LENGTH) revert AllowlistTooLong();
        if (recipients.length == 0 || tokens.length == 0) revert EmptyAllowlist();
        for (uint256 i; i < recipients.length; i++) if (recipients[i] == address(0)) revert ZeroAddress();
        for (uint256 i; i < tokens.length; i++)     if (tokens[i] == address(0))     revert ZeroAddress();

        Slot storage s = _slots[account];
        for (uint256 i; i < s.recipients.length; i++) isAllowedRecipient[account][s.recipients[i]] = false;
        for (uint256 i; i < s.tokens.length; i++)     isAllowedToken[account][s.tokens[i]]         = false;

        for (uint256 i; i < recipients.length; i++) isAllowedRecipient[account][recipients[i]] = true;
        for (uint256 i; i < tokens.length; i++)     isAllowedToken[account][tokens[i]]         = true;

        s.recipients     = recipients;
        s.tokens         = tokens;
        s.maxAmountPerTx = maxAmountPerTx;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Fail closed unless the stored config is current for this registration epoch (Octane #2/#8).
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
        if (ctx.value != 0) return false;
        if (!isAllowedToken[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == TRANSFER_SELECTOR) {
            if (txData.length < LEN_TRANSFER) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            if (amount > s.maxAmountPerTx) return false;
            return isAllowedRecipient[ctx.account][to];
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            if (txData.length < LEN_TRANSFERFROM) return false;
            (address from, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            // `from` must be the Safe itself to prevent pulling tokens from arbitrary approvers.
            if (from != ctx.account) return false;
            if (amount > s.maxAmountPerTx) return false;
            return isAllowedRecipient[ctx.account][to];
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("TransferPermission");
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.TransferPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.TRANSFER_TARGET;
    }
}
