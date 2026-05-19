// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {CloneInitializable} from "./base/CloneInitializable.sol";

/// @title  BoundedLiFiPermission
/// @notice Gates LiFi aggregator swap calls so the manager can only route the
///         Safe's tokens through allowlisted LiFi diamonds and selectors,
///         with the output always returning to the Safe itself.
///
///         Supported selectors (all from LiFi's GenericSwapFacet / V3 facets):
///           0x4630a0d8  swapTokensGeneric(...)
///           0x4666fc80  swapTokensSingleV3ERC20ToERC20(...)
///           0x733214a3  swapTokensSingleV3ERC20ToNative(...)
///           0xaf7060fd  swapTokensSingleV3NativeToERC20(...)
///           0x5fd9ae2e  swapTokensMultipleV3ERC20ToERC20(...)
///
///         Operators choose which of these to enable per-instance via the
///         `allowedSelectors` constructor argument; an unlisted selector is denied.
///
/// @dev    Custody model: every supported LiFi entry shares the same fixed
///         calldata head:
///
///           bytes32  _transactionId   // 32 bytes inline
///           string   _integrator      // 32 bytes offset (dynamic)
///           string   _referrer        // 32 bytes offset (dynamic)
///           address  _receiver        // 32 bytes inline   ← ENFORCED == ctx.account
///           uint256  _minAmount       // 32 bytes inline
///           ...                       // (SwapData / SwapData[])
///
///         The `_receiver` field therefore lives at `txData[100:132]` for every
///         supported selector. The permission decodes that single slot and
///         denies any call where the receiver is not the Safe itself, which
///         prevents the manager from redirecting LiFi's output anywhere but
///         back to the Safe.
///
///         Input-side custody is delegated to `BoundedApprovePermission`: the
///         Safe can only have authorised LiFi to pull tokens within the
///         operator-specified token/spender allowlist. The composition of the
///         two permissions enforces:
///           1. LiFi can only pull tokens the operator pre-approved (approve perm)
///           2. LiFi must deliver output back to the Safe (this perm)
///
///         What this permission does NOT validate:
///           • The inner `SwapData.callTo` / `callData` — LiFi's own facet logic
///             must be trusted to route only to safe DEXes. LiFi's V3 single
///             facets enforce an internal allowlist on callTo; the GenericSwap
///             facet is more permissive. Operators who want tighter constraints
///             on callTo should restrict the allowed selectors to the V3 variants.
///           • Per-call input amount caps. The approve permission caps allowance;
///             this permission does not separately re-cap fromAmount. If a tighter
///             per-call input cap is desired, compose with a second instance of
///             this permission against a token-specific approve permission and
///             rotate the allowance per intended swap.
///           • Bridge entry points. Only swap selectors are supported here;
///             cross-chain bridging is intentionally out of scope (a bridge call
///             moves funds to another chain where Sail's permission framework
///             does not extend).
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use PermissionFactory.deployAndAttach to create per-account clones.
contract BoundedLiFiPermission is IPermission, CloneInitializable {
    // -------------------------------------------------------------------------
    // Calldata layout
    // -------------------------------------------------------------------------

    /// @dev Byte offset (relative to start of txData, including selector) at
    ///      which the `_receiver` slot lives in every supported LiFi entry.
    ///      Layout: selector(4) + bytes32(32) + stringOffset(32) + stringOffset(32) = 100.
    uint256 private constant RECEIVER_OFFSET = 100;

    /// @dev Minimum calldata length to safely read `_receiver` and `_minAmount`.
    ///      selector(4) + 5 head words (transactionId, intOffset, refOffset, receiver, minAmount) × 32 = 164.
    uint256 private constant LEN_MIN_HEAD = 164;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice LiFi diamond addresses (per-chain canonical) the manager may route through.
    mapping(address diamond  => bool) public isAllowedDiamond;

    /// @notice LiFi function selectors the manager may invoke. Configurable per-instance
    ///         so operators can opt into only the entries they have reviewed (e.g., the
    ///         V3 single-swap variants but not the more permissive GenericSwap).
    mapping(bytes4  selector => bool) public isAllowedSelector;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on `_minAmount` (inclusive). This bounds the
    ///         claimed minimum output the manager can request; it does NOT cap
    ///         the input. Use BoundedApprovePermission with a tight allowance
    ///         cap to bound the input side.
    /// @dev    Set to type(uint256).max to disable the cap entirely.
    uint256 public maxMinAmountPerTx;

    /// @notice Address authorised to update mutable settings.
    address public permissionSigner;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when `maxMinAmountPerTx` is updated.
    event MaxMinAmountUpdated(uint256 oldMax, uint256 newMax);

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

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor / Initialize
    // -------------------------------------------------------------------------

    constructor() {}

    /// @notice Called once by PermissionFactory after cloning the logic contract.
    /// @param  allowedDiamonds      LiFi diamond addresses (one per chain you support).
    /// @param  allowedSelectors     LiFi function selectors the manager may invoke.
    /// @param  _maxMinAmountPerTx   Initial cap on `_minAmount` field per call.
    /// @param  _permissionSigner    Address permitted to update mutable settings.
    function initialize(
        address[] memory allowedDiamonds,
        bytes4[]  memory allowedSelectors,
        uint256          _maxMinAmountPerTx,
        address          _permissionSigner
    ) external initializer {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        maxMinAmountPerTx = _maxMinAmountPerTx;
        permissionSigner  = _permissionSigner;
        for (uint256 i; i < allowedDiamonds.length;  i++) isAllowedDiamond[allowedDiamonds[i]]   = true;
        for (uint256 i; i < allowedSelectors.length; i++) isAllowedSelector[allowedSelectors[i]] = true;
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    function setMaxMinAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxMinAmountPerTx;
        maxMinAmountPerTx = newMax;
        emit MaxMinAmountUpdated(old, newMax);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedDiamond[ctx.target])      return false;
        if (!isAllowedSelector[ctx.selector])   return false;
        if (txData.length < LEN_MIN_HEAD)       return false;

        // Decode the two inline fields we care about. The dynamic string offsets
        // at positions 1 and 2 (`_integrator`, `_referrer`) are ignored — they
        // do not affect custody and cannot be used to redirect funds.
        address receiver  = abi.decode(txData[RECEIVER_OFFSET:RECEIVER_OFFSET + 32], (address));
        uint256 minAmount = abi.decode(txData[RECEIVER_OFFSET + 32:RECEIVER_OFFSET + 64], (uint256));

        if (receiver  != ctx.account)            return false;
        if (minAmount > maxMinAmountPerTx)       return false;

        return true;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedLiFiPermission");
    }
}
