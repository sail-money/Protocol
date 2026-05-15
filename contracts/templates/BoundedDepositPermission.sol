// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @notice Gates ERC-20 deposits into lending/vault protocols.
///         For each supported selector the kernel enforces:
///           • ctx.target is in the allowed-targets list
///           • asset (when present in calldata) is in the allowed-tokens list
///           • amount/shares does not exceed the per-tx cap
///           • receiver/onBehalfOf is the Safe itself (ctx.account)
contract BoundedDepositPermission is IPermission {
    // deposit(uint256 assets, address receiver)          — ERC-4626 / simple vault
    bytes4 private constant DEPOSIT_SIMPLE  = bytes4(keccak256("deposit(uint256,address)"));
    // deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode) — Aave v2
    bytes4 private constant DEPOSIT_AAVE    = bytes4(keccak256("deposit(address,uint256,address,uint16)"));
    // mint(uint256 shares, address receiver)             — ERC-4626
    bytes4 private constant MINT            = bytes4(keccak256("mint(uint256,address)"));
    // supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)  — Aave v3
    bytes4 private constant SUPPLY_AAVE     = bytes4(keccak256("supply(address,uint256,address,uint16)"));

    // Minimum calldata lengths (selector + args, all padded to 32 bytes each)
    uint256 private constant LEN_2ARG = 68;   // 4 + 32 + 32
    uint256 private constant LEN_4ARG = 132;  // 4 + 32 + 32 + 32 + 32

    /// @notice Protocols the manager may deposit into.
    mapping(address target => bool) public isAllowedTarget;

    /// @notice Tokens the manager may deposit (checked when asset appears in calldata).
    mapping(address token => bool) public isAllowedToken;

    /// @notice Per-transaction amount/shares cap (inclusive).
    uint256 public maxAmountPerTx;

    /// @notice Address authorised to update mutable settings.
    address public permissionSigner;

    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

    error NotPermissionSigner();
    error ZeroAddress();

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address[] memory allowedTargets,
        address[] memory allowedTokens,
        uint256 _maxAmountPerTx,
        address _permissionSigner
    ) {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        maxAmountPerTx   = _maxAmountPerTx;
        permissionSigner = _permissionSigner;
        for (uint256 i = 0; i < allowedTargets.length; i++) isAllowedTarget[allowedTargets[i]] = true;
        for (uint256 i = 0; i < allowedTokens.length;  i++) isAllowedToken[allowedTokens[i]]   = true;
    }

    /// @notice Update the per-transaction cap. Only permissionSigner may call.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Protocol must be on the allowlist
        if (!isAllowedTarget[ctx.target]) return false;

        // ── deposit(uint256 assets, address receiver) ─────────────────────────
        if (ctx.selector == DEPOSIT_SIMPLE) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 amount, address receiver) = abi.decode(txData[4:], (uint256, address));
            // Asset not in calldata — token check delegated to allowedTargets trust
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
