// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";

/// @title  BoundedBorrowPermission
/// @notice Gates ERC-20 borrows from lending protocols.
///         For each supported selector the kernel enforces:
///           • `ctx.target` is in the allowed-targets list
///           • asset (when present in calldata) is in the allowed-tokens list
///           • amount does not exceed the per-tx cap
///           • onBehalfOf / receiver is the Safe itself (`ctx.account`)
///
///         Supported selectors and their expected calldata layouts:
///
///           borrow(address,uint256,uint256,uint16,address)  — Aave v2 / v3
///           borrow(uint256,address)                          — ERC-4626-style / simple lending
///
/// @dev    This permission enforces a per-transaction borrow cap (`maxAmountPerTx`),
///         NOT a lifetime LTV cap. Outstanding borrows across multiple transactions are
///         not tracked on-chain. For portfolio-level exposure control, operators should
///         either rely on the lending protocol's own health-factor enforcement or compose
///         this permission with a position-monitoring permission that reads the protocol's
///         borrow state via staticcall.
///
///         For the BORROW_SIMPLE selector, the asset does not appear in calldata;
///         token safety is delegated to the `isAllowedTarget` allowlist. Operators must
///         ensure each allowed target only accepts tokens they intend to permit.
/// @custom:security-contact security@sail.money
contract BoundedBorrowPermission is IPermission {
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) — Aave v2 / v3.
    bytes4 private constant BORROW_AAVE   = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));

    /// @dev borrow(uint256 assets, address receiver) — ERC-4626-style / simple lending.
    bytes4 private constant BORROW_SIMPLE = bytes4(keccak256("borrow(uint256,address)"));

    // -------------------------------------------------------------------------
    // Calldata length constants
    // -------------------------------------------------------------------------

    /// @dev Minimum calldata length for 2-argument calls: selector(4) + 2 × word(32) = 68.
    uint256 private constant LEN_2ARG = 68;

    /// @dev Minimum calldata length for 5-argument calls: selector(4) + 5 × word(32) = 164.
    uint256 private constant LEN_5ARG = 164;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice Lending protocol addresses the manager may borrow from.
    mapping(address target => bool) public isAllowedTarget;

    /// @notice ERC-20 tokens the manager may borrow.
    ///         Checked only when the asset address appears explicitly in calldata (BORROW_AAVE).
    ///         For BORROW_SIMPLE, token safety is implicitly enforced via `isAllowedTarget`.
    mapping(address token => bool) public isAllowedToken;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on the borrow amount (inclusive).
    /// @dev    Denominated in the borrowed token's native units. For BORROW_SIMPLE
    ///         (ERC-4626 shares), the cap is in shares, not underlying assets.
    ///         This is a per-call limit; cumulative exposure across multiple borrows
    ///         is not tracked. See contract-level @dev for LTV guidance.
    uint256 public maxAmountPerTx;

    /// @notice Address authorised to update `maxAmountPerTx`.
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
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy with a set of allowed targets, tokens, a cap, and a signer.
    /// @param  allowedTargets     Lending protocol addresses to pre-populate the allowlist.
    /// @param  allowedTokens      ERC-20 token addresses to pre-populate the token allowlist.
    ///                            Only checked on BORROW_AAVE; see @dev for BORROW_SIMPLE.
    /// @param  _maxAmountPerTx    Initial per-transaction borrow amount cap (inclusive).
    /// @param  _permissionSigner  Address permitted to call `setMaxAmountPerTx`.
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

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Update the per-transaction borrow cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all non-zero borrows.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    /// @dev Decodes borrow calldata and enforces three invariants:
    ///      protocol in allowlist, token in allowlist (Aave path), amount <= cap,
    ///      and onBehalfOf / receiver == ctx.account (the Safe).
    ///      Any other selector, malformed calldata, or non-zero ETH value returns false.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        // Borrow calls carry no ETH
        if (ctx.value != 0) return false;

        // Lending protocol must be on the allowlist
        if (!isAllowedTarget[ctx.target]) return false;

        // ── borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) ─
        if (ctx.selector == BORROW_AAVE) {
            if (txData.length < LEN_5ARG) return false;
            (address asset, uint256 amount,,,address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            return isAllowedToken[asset] && amount <= maxAmountPerTx && onBehalfOf == ctx.account;
        }

        // ── borrow(uint256 assets, address receiver) ─────────────────────────
        if (ctx.selector == BORROW_SIMPLE) {
            if (txData.length < LEN_2ARG) return false;
            (uint256 amount, address receiver) = abi.decode(txData[4:], (uint256, address));
            // Asset not in calldata — token check delegated to allowedTargets trust.
            return receiver == ctx.account && amount <= maxAmountPerTx;
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedBorrowPermission");
    }
}
