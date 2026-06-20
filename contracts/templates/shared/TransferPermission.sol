// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

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
///         Reference transfer permission. One deployment serves any number of accounts;
///         each account stores its own recipient and token allowlists.
///
///         Config blob:
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
        ConfigurablePermission(_kernel, "TransferPermission", "1")
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
