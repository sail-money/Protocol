// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../../interfaces/IPermission.sol";
import {IPermissionIntrospection} from "../../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";

/// @notice Reference withdraw permission. One deployment serves any number of accounts;
///         each account stores its own token allowlist, pinned recipient, and amount cap.
///
///         Gates ERC-20 movements so funds only ever reach the account's configured
///         `allowedRecipient` (typically the account's own Safe), the token is allowlisted,
///         and the amount is within the per-tx cap. Native ETH is rejected.
///
///         Supported selectors:
///           transfer(address to, uint256 amount)               — direct send from the account
///           transferFrom(address from, address to, uint256)    — pull (from MUST be the account)
///         Any other selector (including approve) is denied.
///
///         Config blob:
///             abi.encode(
///                 address[] tokens,
///                 address   allowedRecipient,
///                 uint256   maxAmountPerTx
///             )
/// @custom:security-contact security@sail.money
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
        ConfigurablePermission(_kernel, "WithdrawPermission", "1")
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
