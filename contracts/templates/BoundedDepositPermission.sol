// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {CloneInitializable} from "./base/CloneInitializable.sol";

/// @title  BoundedDepositPermission
/// @notice Gates ERC-20 deposits into lending and vault protocols.
///         For each supported selector the kernel enforces:
///           • `ctx.target` is in the allowed-targets list
///           • asset (when present in calldata) is in the allowed-tokens list
///           • amount / shares does not exceed the per-tx cap
///           • receiver / onBehalfOf is the Safe itself (`ctx.account`)
///
///         Supported selectors and their expected calldata layouts:
///
///           deposit(uint256,address)                     — ERC-4626 / simple vault
///           deposit(address,uint256,address,uint16)      — Aave v2
///           mint(uint256,address)                        — ERC-4626
///           supply(address,uint256,address,uint16)       — Aave v3
///
/// @dev    For selectors where the asset does not appear in calldata
///         (DEPOSIT_SIMPLE, MINT), token safety is delegated entirely to the
///         `isAllowedTarget` allowlist. Operators must ensure each allowed target
///         only accepts tokens they intend to permit.
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use MandateFactory.deployAndAttach to create per-account clones.
contract BoundedDepositPermission is IPermission, CloneInitializable {
    /// @notice Marks this as a single-account template (not a shared multi-account deployment).
    bool public constant IS_SINGLE_ACCOUNT = true;
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev deposit(uint256 assets, address receiver) — ERC-4626 / simple vault.
    bytes4 private constant DEPOSIT_SIMPLE  = bytes4(keccak256("deposit(uint256,address)"));

    /// @dev deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) — Aave v2.
    bytes4 private constant DEPOSIT_AAVE    = bytes4(keccak256("deposit(address,uint256,address,uint16)"));

    /// @dev mint(uint256 shares, address receiver) — ERC-4626.
    bytes4 private constant MINT            = bytes4(keccak256("mint(uint256,address)"));

    /// @dev supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) — Aave v3.
    bytes4 private constant SUPPLY_AAVE     = bytes4(keccak256("supply(address,uint256,address,uint16)"));

    // -------------------------------------------------------------------------
    // Calldata length constants
    // -------------------------------------------------------------------------

    /// @dev Minimum calldata length for 2-argument calls: selector(4) + 2 × word(32) = 68.
    uint256 private constant LEN_2ARG = 68;

    /// @dev Minimum calldata length for 4-argument calls: selector(4) + 4 × word(32) = 132.
    uint256 private constant LEN_4ARG = 132;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice Protocols (vault / lending pool addresses) the manager may deposit into.
    mapping(address target => bool) public isAllowedTarget;

    /// @notice ERC-20 tokens the manager may deposit.
    ///         Checked only when the asset address appears explicitly in calldata
    ///         (DEPOSIT_AAVE, SUPPLY_AAVE). For DEPOSIT_SIMPLE and MINT, token
    ///         safety is implicitly enforced via `isAllowedTarget`.
    mapping(address token => bool) public isAllowedToken;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on the deposit amount or share count (inclusive).
    /// @dev    For MINT calls this cap is in shares, not underlying assets. At high
    ///         share prices (e.g., 1 share = 1000 USDC), the effective asset cap is
    ///         maxAmountPerTx × sharePrice. Operators must account for this.
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
    /// @param  allowedTargets     Vault / lending pool addresses to pre-populate the allowlist.
    /// @param  allowedTokens      ERC-20 token addresses to pre-populate the token allowlist.
    /// @param  _maxAmountPerTx    Initial per-transaction amount / shares cap.
    /// @param  _permissionSigner  Address permitted to call `setMaxAmountPerTx`.
    function initialize(
        address[] memory allowedTargets,
        address[] memory allowedTokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) external initializer {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i = 0; i < allowedTargets.length; i++) isAllowedTarget[allowedTargets[i]] = true;
        for (uint256 i = 0; i < allowedTokens.length;  i++) isAllowedToken[allowedTokens[i]]   = true;
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Update the per-transaction deposit cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all deposits.
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
        // Protocol must be on the allowlist
        if (!isAllowedTarget[ctx.target]) return false;

        // ── deposit(uint256 assets, address receiver) ─────────────────────────
        if (ctx.selector == DEPOSIT_SIMPLE) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 amount, address receiver) = abi.decode(txData[4:], (uint256, address));
            // Asset not in calldata — token check delegated to allowedTargets trust.
            return receiver == ctx.account && amount <= maxAmountPerTx;
        }

        // ── deposit(address asset, uint256 amount, address onBehalfOf, uint16) ─
        if (ctx.selector == DEPOSIT_AAVE) {
            if (txData.length < LEN_4ARG) return false;
            (address asset, uint256 amount, address onBehalfOf,) =
                abi.decode(txData[4:], (address, uint256, address, uint16));
            return isAllowedToken[asset]
                && amount <= maxAmountPerTx
                && onBehalfOf == ctx.account;
        }

        // ── mint(uint256 shares, address receiver) ────────────────────────────
        if (ctx.selector == MINT) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 shares, address receiver) = abi.decode(txData[4:], (uint256, address));
            // WARNING: `maxAmountPerTx` is denominated in SHARES, not underlying assets.
            // At high share prices (e.g., 1 share = 1000 USDC), the effective asset cap
            // is maxAmountPerTx × sharePrice. Operators must set this value accordingly.
            // Asset not in calldata — token check delegated to allowedTargets trust.
            return receiver == ctx.account && shares <= maxAmountPerTx;
        }

        // ── supply(address asset, uint256 amount, address onBehalfOf, uint16) ─
        if (ctx.selector == SUPPLY_AAVE) {
            if (txData.length < LEN_4ARG) return false;
            (address asset, uint256 amount, address onBehalfOf,) =
                abi.decode(txData[4:], (address, uint256, address, uint16));
            return isAllowedToken[asset]
                && amount <= maxAmountPerTx
                && onBehalfOf == ctx.account;
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedDepositPermission");
    }
}
