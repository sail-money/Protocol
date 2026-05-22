// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {CloneInitializable} from "./base/CloneInitializable.sol";

/// @title  BoundedWithdrawPermission
/// @notice Gates ERC-20 withdrawals so the recipient is always the designated Safe,
///         the token is on the allowlist, and the amount is within the per-tx cap.
///
///         Supported selectors:
///           transfer(address,uint256)               — direct transfer from the Safe
///           transferFrom(address,address,uint256)   — pull from a pre-approved address
///
/// @dev    The `transferFrom` path validates that `from == ctx.account` (the Safe itself),
///         preventing a manager from pulling tokens from arbitrary addresses that may have
///         previously approved the Safe.
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use MandateFactory.deployAndAttach to create per-account clones.
contract BoundedWithdrawPermission is IPermission, CloneInitializable {
    /// @notice Marks this as a single-account template (not a shared multi-account deployment).
    bool public constant IS_SINGLE_ACCOUNT = true;
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev transfer(address to, uint256 amount) — ERC-20 standard transfer.
    bytes4 private constant TRANSFER_SELECTOR     = 0xa9059cbb;

    /// @dev transferFrom(address from, address to, uint256 amount) — ERC-20 approved pull.
    bytes4 private constant TRANSFERFROM_SELECTOR = 0x23b872dd;

    // -------------------------------------------------------------------------
    // State
    // -------------------------------------------------------------------------

    /// @notice The only address permitted to receive tokens (the owner's Safe).
    address public allowedRecipient;

    // -------------------------------------------------------------------------
    // Allowlist and parameters
    // -------------------------------------------------------------------------

    /// @notice ERC-20 tokens the manager is permitted to move.
    mapping(address token => bool) public isAllowedToken;

    /// @notice Per-transaction amount cap (inclusive). 0 blocks all non-zero transfers.
    uint256 public maxAmountPerTx;

    /// @notice Address authorised to update mutable settings.
    address public permissionSigner;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when `maxAmountPerTx` is updated.
    /// @param  oldMax Previous cap value.
    /// @param  newMax New cap value.
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

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
    // Constructor / Initialize
    // -------------------------------------------------------------------------

    constructor() { _disableInitializers(); }

    /// @notice Called once by MandateFactory after cloning the logic contract.
    /// @param  safe               The Safe address that must receive all tokens.
    ///                            Set once at initialization; not changeable afterward.
    /// @param  allowedTokens      ERC-20 addresses to pre-populate the token allowlist.
    /// @param  _maxAmountPerTx    Initial per-transaction amount cap.
    /// @param  _permissionSigner  Address permitted to call `setMaxAmountPerTx`.
    function initialize(
        address safe,
        address[] memory allowedTokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) external initializer {
        if (safe == address(0) || _permissionSigner == address(0)) revert ZeroAddress();
        allowedRecipient = safe;
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i = 0; i < allowedTokens.length; i++) {
            isAllowedToken[allowedTokens[i]] = true;
        }
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

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    /// @dev Decodes transfer() and transferFrom() calldata and enforces three invariants:
    ///      recipient == allowedRecipient, token in allowlist, amount <= cap.
    ///      Any other selector, malformed calldata, or non-zero ETH value returns false.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // ERC-20 calls carry no ETH
        if (ctx.value != 0) return false;

        // Token must be on the allowlist
        if (!isAllowedToken[ctx.target]) return false;

        if (ctx.selector == TRANSFER_SELECTOR) {
            // Encoded: selector(4) + to(32) + amount(32) = 68 bytes minimum
            if (txData.length < 68) return false;
            (address to, uint256 amount) = abi.decode(txData[4:], (address, uint256));
            return to == allowedRecipient && amount <= maxAmountPerTx;
        }

        if (ctx.selector == TRANSFERFROM_SELECTOR) {
            // Encoded: selector(4) + from(32) + to(32) + amount(32) = 100 bytes minimum
            if (txData.length < 100) return false;
            (address from, address to, uint256 amount) = abi.decode(txData[4:], (address, address, uint256));
            // `from` must be the Safe itself to prevent pulling tokens from arbitrary approvers.
            if (from != ctx.account) return false;
            return to == allowedRecipient && amount <= maxAmountPerTx;
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedWithdrawPermission");
    }
}
