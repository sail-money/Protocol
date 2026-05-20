// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {CloneInitializable} from "./base/CloneInitializable.sol";

/// @title  BoundedApprovePermission
/// @notice Gates ERC-20 `approve` calls so the manager can only grant allowance
///         on allowlisted tokens to allowlisted spenders, capped per call.
///
///         Supported selectors:
///           approve(address spender, uint256 amount)       — ERC-20 standard
///
///         The token being approved is `ctx.target`; the spender and amount are
///         decoded from calldata.
///
/// @dev    Custody model: `approve` itself moves no funds — it only authorises a
///         spender to call `transferFrom` later. The safety of this permission
///         therefore rests entirely on the spender allowlist: every address the
///         manager can approve must be a trusted protocol contract that will not
///         move funds in ways the operator hasn't sanctioned (e.g., Uniswap
///         routers, Aave pools, ERC-4626 vaults).
///
///         To preserve Safe custody end-to-end, this permission MUST be paired
///         with a permission that constrains the actual deposit/swap calls —
///         BoundedSwapPermission, BoundedDepositPermission, or equivalent —
///         so the spender, once authorised, can only pull funds within the
///         allowed action surface.
///
///         The `maxAmountPerTx` cap bounds blast radius if an allowed spender
///         is later found to be misbehaving: operators can rotate the allowlist
///         and revoke prior approvals by registering a follow-up approve(spender, 0).
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use PermissionFactory.deployAndAttach to create per-account clones.
contract BoundedApprovePermission is IPermission, CloneInitializable {
    // -------------------------------------------------------------------------
    // Clone identity
    // -------------------------------------------------------------------------

    /// @notice Signals that each clone of this template is bound to a single Safe account.
    bool public constant IS_SINGLE_ACCOUNT = true;

    // -------------------------------------------------------------------------
    // Selector
    // -------------------------------------------------------------------------

    /// @dev approve(address spender, uint256 amount)
    bytes4 private constant APPROVE = 0x095ea7b3;

    /// @dev Minimum calldata length for approve: selector(4) + 2 × word(32) = 68.
    uint256 private constant LEN_APPROVE = 68;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice ERC-20 tokens whose allowance may be set via this permission.
    mapping(address token   => bool) public isAllowedToken;

    /// @notice Contracts that may receive an allowance on the allowed tokens.
    mapping(address spender => bool) public isAllowedSpender;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on the approval amount (inclusive).
    /// @dev    Set to type(uint256).max to allow unlimited approvals (common pattern
    ///         when integrating with mature protocols where infinite allowance is
    ///         the norm). Set to 0 to block all NEW (non-zero) approvals while still
    ///         permitting amount=0 revocations — a useful operator knob for freezing
    ///         further authorisations without losing the ability to revoke.
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

    /// @notice Called once by PermissionFactory after cloning the logic contract.
    /// @param  allowedTokens     ERC-20 tokens that may be approved through this permission.
    /// @param  allowedSpenders   Contract addresses that may receive allowance from the Safe.
    /// @param  _maxAmountPerTx   Initial per-transaction amount cap (use type(uint256).max for unlimited).
    /// @param  _permissionSigner Address permitted to call `setMaxAmountPerTx`.
    function initialize(
        address[] memory allowedTokens,
        address[] memory allowedSpenders,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) external initializer {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i; i < allowedTokens.length;   i++) isAllowedToken[allowedTokens[i]]     = true;
        for (uint256 i; i < allowedSpenders.length; i++) isAllowedSpender[allowedSpenders[i]] = true;
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Update the per-transaction approval cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all non-zero
    ///                approvals; amount=0 revocations remain possible.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (ctx.selector != APPROVE)            return false;
        if (txData.length < LEN_APPROVE)        return false;
        if (!isAllowedToken[ctx.target])        return false;

        (address spender, uint256 amount) = abi.decode(txData[4:], (address, uint256));
        if (!isAllowedSpender[spender])         return false;
        if (amount > maxAmountPerTx)            return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedApprovePermission");
    }
}
