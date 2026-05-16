// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @title  TransferTargetPermission
/// @notice Gates ERC-20 token transfers and plain ETH sends to an operator-controlled
///         recipient allowlist.
///
///         Unlike BoundedWithdrawPermission — which enforces a single immutable Safe
///         recipient — this permission allows transfers to any pre-approved external
///         address. Suitable for whitelisting partner protocols, CEX deposit addresses,
///         or co-manager wallets.
///
///         Supported operations:
///           transfer(address,uint256)               — ERC-20 standard transfer
///           transferFrom(address,address,uint256)   — ERC-20 approved pull
///           plain ETH send (calldata length < 4)    — native ETH to an allowed recipient
///
/// @dev    For ERC-20 paths, `ctx.target` is the token contract; `to` in calldata is the
///         recipient. Both the token and the recipient are independently checked.
///
///         For plain ETH sends, `ctx.target` IS the recipient. There is no token check;
///         the ETH amount (`ctx.value`) is checked against `maxAmountPerTx`.
///
///         The `transferFrom` path does NOT validate the `from` field. A manager can pull
///         tokens from any address that has previously approved the Safe (e.g., an
///         integrated DeFi protocol). If only pulling from the Safe's own balance is
///         intended, use the `transfer` path exclusively.
///
///         The recipient allowlist is mutable — `permissionSigner` can add and remove
///         addresses after deployment. Operators should use a multisig or time-locked
///         address as `permissionSigner` in production.
/// @custom:security-contact security@sail.money
contract TransferTargetPermission is IPermission {
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev transfer(address to, uint256 amount) — ERC-20 standard transfer.
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;

    /// @dev transferFrom(address from, address to, uint256 amount) — ERC-20 approved pull.
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    // -------------------------------------------------------------------------
    // Allowlists and parameters
    // -------------------------------------------------------------------------

    /// @notice Addresses the manager may send tokens or ETH to.
    mapping(address recipient => bool) public isAllowedRecipient;

    /// @notice ERC-20 tokens the manager is permitted to transfer.
    ///         Not checked for plain ETH sends — ETH gating is done via
    ///         `isAllowedRecipient` and `maxAmountPerTx` only.
    mapping(address token => bool) public isAllowedToken;

    /// @notice Per-transaction amount cap (inclusive). 0 blocks all non-zero transfers.
    ///         For ERC-20 paths this is denominated in token units; for ETH it is in wei.
    uint256 public maxAmountPerTx;

    /// @notice Address authorised to update `maxAmountPerTx` and the recipient allowlist.
    address public permissionSigner;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when `maxAmountPerTx` is updated.
    /// @param  oldMax Previous cap value.
    /// @param  newMax New cap value.
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

    /// @notice Emitted when an address is added to or removed from `isAllowedRecipient`.
    /// @param  recipient The address whose status changed.
    /// @param  allowed   True if added to the allowlist, false if removed.
    event RecipientAllowlistUpdated(address indexed recipient, bool allowed);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown when a caller other than `permissionSigner` invokes a guarded setter.
    error NotPermissionSigner();

    /// @dev Thrown when a required address argument is the zero address.
    error ZeroAddress();

    // -------------------------------------------------------------------------
    // Modifier
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotPermissionSigner when caller is not `permissionSigner`.
    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy with initial allowlists, a cap, and a signer.
    /// @param  allowedRecipients  Addresses the manager may send tokens or ETH to.
    /// @param  allowedTokens      ERC-20 token addresses the manager may transfer.
    ///                            Not applied to plain ETH sends.
    /// @param  _maxAmountPerTx    Initial per-transaction amount cap (inclusive).
    /// @param  _permissionSigner  Address permitted to update the allowlist and cap.
    constructor(
        address[] memory allowedRecipients,
        address[] memory allowedTokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i = 0; i < allowedRecipients.length; i++) isAllowedRecipient[allowedRecipients[i]] = true;
        for (uint256 i = 0; i < allowedTokens.length;    i++) isAllowedToken[allowedTokens[i]]         = true;
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Update the per-transaction amount cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all non-zero transfers.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    /// @notice Add or remove an address from the recipient allowlist.
    /// @param  recipient  Address to update. Must not be the zero address.
    /// @param  allowed    True to permit transfers to this address, false to revoke.
    function setAllowedRecipient(address recipient, bool allowed) external onlyPermissionSigner {
        if (recipient == address(0)) revert ZeroAddress();
        isAllowedRecipient[recipient] = allowed;
        emit RecipientAllowlistUpdated(recipient, allowed);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    /// @dev Evaluation logic by path:
    ///      - Plain ETH send (txData.length < 4): check isAllowedRecipient[ctx.target] and ctx.value <= cap.
    ///      - ERC-20 transfer/transferFrom: check isAllowedToken[ctx.target], decode `to`, check
    ///        isAllowedRecipient[to] and amount <= cap. Non-zero ETH value is rejected.
    ///      Any other selector or malformed calldata returns false.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // ── plain ETH send (no function selector) ────────────────────────────
        // ctx.target is the ETH recipient; ctx.value is the amount being sent.
        // Require exactly zero calldata — 1–3 byte inputs fall through to the selector
        // check below, which will fail to match any valid selector, returning false.
        if (txData.length == 0) {
            return isAllowedRecipient[ctx.target] && ctx.value <= maxAmountPerTx;
        }

        // ERC-20 calls carry no ETH
        if (ctx.value != 0) return false;

        // Token contract must be on the allowlist
        if (!isAllowedToken[ctx.target]) return false;

        // ── transfer(address to, uint256 amount) ─────────────────────────────
        if (ctx.selector == TRANSFER_SELECTOR) {
            // selector(4) + to(32) + amount(32) = 68 bytes minimum
            if (txData.length < 68) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            return isAllowedRecipient[to] && amount <= maxAmountPerTx;
        }

        // ── transferFrom(address from, address to, uint256 amount) ───────────
        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            // selector(4) + from(32) + to(32) + amount(32) = 100 bytes minimum
            if (txData.length < 100) return false;
            (, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            // WARNING: the `from` field is not validated. A manager can pull tokens from any
            // address that has previously approved the Safe (e.g., an integrated DeFi protocol).
            // Use the `transfer` path if only pulling from the Safe's own balance is intended.
            return isAllowedRecipient[to] && amount <= maxAmountPerTx;
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("TransferTargetPermission");
    }
}
