// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IOracle}              from "../interfaces/IOracle.sol";
import {Math}                 from "@openzeppelin/contracts/utils/math/Math.sol";
import {CloneInitializable}   from "./base/CloneInitializable.sol";

/// @title  BoundedBorrowPermission
/// @notice Gates ERC-20 borrows from lending protocols.
///         For each supported selector the kernel enforces:
///           • `ctx.target` is in the allowed-protocols list
///           • asset is in the allowed-assets list
///           • amount does not exceed the per-tx cap
///           • onBehalfOf / receiver is the Safe itself (`ctx.account`)
///           • if oracles are configured, LTV does not exceed `maxLtvBps`
///
///         Supported selectors and their expected calldata layouts:
///
///           borrow(address,uint256,uint256,uint16,address)  — Aave v2 / v3
///           borrow(address,uint256,address,address)          — Morpho
///           borrow(uint256)                                  — Compound v2
///
/// @dev    LTV enforcement requires both `collateralOracle` and `borrowOracle` to be set.
///         When either is address(0) the LTV check is skipped and only the per-tx amount cap
///         applies. Both oracles must use the same denomination and decimals.
///
///         Compound v2 path: `ctx.target` is the cToken contract, which also identifies the
///         borrowed asset. `onBehalfOf` is implicitly the Safe (the Safe executes the call
///         via its module interface, so msg.sender inside the cToken is the Safe).
///
///         Oracle decimal values above 77 are not supported — 10^78 overflows uint256.
///         The LTV check skips such oracles (treats them as unset).
/// @custom:security-contact security@sail.money
/// @dev CLONE TEMPLATE: Deploy the logic contract once; use MandateFactory.deployAndAttach to create per-account clones.
contract BoundedBorrowPermission is IPermission, CloneInitializable {
    /// @notice Marks this as a single-account template (not a shared multi-account deployment).
    bool public constant IS_SINGLE_ACCOUNT = true;
    // -------------------------------------------------------------------------
    // Selectors
    // -------------------------------------------------------------------------

    /// @dev borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf) — Aave v2 / v3.
    bytes4 private constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));

    /// @dev borrow(address asset, uint256 amount, address onBehalf, address receiver) — Morpho.
    bytes4 private constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));

    /// @dev borrow(uint256 borrowAmount) — Compound v2. Target is the cToken contract.
    bytes4 private constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));

    // -------------------------------------------------------------------------
    // Calldata length constants
    // -------------------------------------------------------------------------

    /// @dev selector(4) + 5 × word(32) = 164 bytes.
    uint256 private constant LEN_AAVE     = 164;

    /// @dev selector(4) + 4 × word(32) = 132 bytes.
    uint256 private constant LEN_MORPHO   = 132;

    /// @dev selector(4) + 1 × word(32) = 36 bytes.
    uint256 private constant LEN_COMPOUND = 36;

    // -------------------------------------------------------------------------
    // Allowlists
    // -------------------------------------------------------------------------

    /// @notice Lending protocol addresses the manager may borrow from.
    mapping(address protocol => bool) public isAllowedProtocol;

    /// @notice ERC-20 assets the manager may borrow.
    ///         For Compound v2, the cToken address is used as the asset identifier.
    mapping(address asset => bool) public isAllowedAsset;

    // -------------------------------------------------------------------------
    // Mutable parameters
    // -------------------------------------------------------------------------

    /// @notice Per-transaction cap on the borrow amount (inclusive).
    ///         Denominated in the borrowed token's native units.
    uint256 public maxAmountPerTx;

    /// @notice Maximum LTV in basis points (e.g. 7 500 = 75%). 0 means no LTV check.
    ///         Enforced only when both oracles are set.
    uint256 public maxLtvBps;

    /// @notice Oracle returning the Safe's total collateral value.
    ///         Called as `getPrice(account, address(0))` → (totalCollateralValue, decimals).
    ///         Set to address(0) to disable the LTV check.
    address public collateralOracle;

    /// @notice Oracle returning the price per unit of the borrow asset.
    ///         Called as `getPrice(asset, address(0))` → (pricePerUnit, decimals).
    ///         Must use the same denomination and decimals as `collateralOracle`.
    ///         Set to address(0) to disable the LTV check.
    address public borrowOracle;

    /// @notice Maximum acceptable oracle price age in seconds. 0 = no freshness check.
    uint256 public maxPriceAgeSec;

    /// @notice Address authorised to update mutable parameters.
    address public permissionSigner;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when `maxAmountPerTx` is updated.
    /// @param  oldMax Previous cap value.
    /// @param  newMax New cap value.
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);

    /// @notice Emitted when `maxLtvBps` is updated.
    /// @param  oldBps Previous LTV cap in basis points.
    /// @param  newBps New LTV cap in basis points.
    event MaxLtvUpdated(uint256 oldBps, uint256 newBps);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown when a caller other than `permissionSigner` invokes a guarded setter.
    error NotPermissionSigner();

    /// @dev Thrown when a required address argument is the zero address.
    error ZeroAddress();

    /// @dev Thrown when a requested `maxLtvBps` exceeds 10 000 (100%).
    error LtvBpsTooLarge(uint256 bps);

    /// @dev Thrown when `collateralOracle` and `borrowOracle` report different decimals.
    ///      Both must use the same denomination and precision for the LTV ratio to be valid.
    error OracleDecimalMismatch(uint8 collateralDec, uint8 borrowDec);

    /// @notice Thrown when both LTV oracles are configured but no freshness bound is set.
    error MissingPriceAge();

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
    /// @param  allowedProtocols   Lending protocol addresses to pre-populate the allowlist.
    /// @param  allowedAssets      ERC-20 / cToken addresses to pre-populate the asset allowlist.
    /// @param  _maxAmountPerTx    Initial per-transaction borrow amount cap (inclusive).
    /// @param  _maxLtvBps         Initial LTV cap in basis points. 0 disables LTV enforcement.
    ///                            Must not exceed 10 000.
    /// @param  _collateralOracle  Oracle for the Safe's collateral value. address(0) skips LTV.
    /// @param  _borrowOracle      Oracle for borrow asset price. address(0) skips LTV.
    /// @param  _maxPriceAgeSec    Maximum acceptable oracle price age in seconds. 0 = no check.
    /// @param  _permissionSigner  Address permitted to update mutable parameters.
    /// @dev    Oracle decimal alignment is verified at initialization only if both oracles
    ///         successfully respond to a zero-address probe. If either oracle reverts on
    ///         zero-address input (e.g., it requires a real asset), the decimal check is
    ///         silently skipped — callers must ensure both oracles use the same denomination
    ///         and decimal precision, or the runtime LTV calculation will be silently wrong.
    function initialize(
        address[] memory allowedProtocols,
        address[] memory allowedAssets,
        uint256 _maxAmountPerTx,
        uint256 _maxLtvBps,
        address _collateralOracle,
        address _borrowOracle,
        uint256 _maxPriceAgeSec,
        address _permissionSigner
    ) external initializer {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        if (_maxLtvBps > 10_000) revert LtvBpsTooLarge(_maxLtvBps);
        // The LTV check runs only when both oracles are set; in that case a freshness bound
        // is mandatory. 0 would silently accept arbitrarily stale prices and re-open the gap.
        if (_collateralOracle != address(0) && _borrowOracle != address(0) && _maxPriceAgeSec == 0) {
            revert MissingPriceAge();
        }

        // When both oracles are set, verify at construction that they report the same
        // decimals so the LTV ratio (borrowValue / collateralValue) is dimensionally
        // consistent. A mismatch would silently produce an off-by-orders-of-magnitude LTV.
        if (_collateralOracle != address(0) && _borrowOracle != address(0)) {
            try IOracle(_collateralOracle).getPrice(address(0), address(0)) returns (uint256, uint8 colDec, uint256) {
                // If the collateral oracle probe succeeds, require the borrow oracle to also
                // respond so we can verify decimal alignment. A revert here means the borrow
                // oracle doesn't support address(0) probing — replace with a real asset address
                // or use a wrapper oracle that accepts zero-address inputs.
                (, uint8 borDec,) = IOracle(_borrowOracle).getPrice(address(0), address(0));
                if (colDec != borDec) revert OracleDecimalMismatch(colDec, borDec);
            } catch {}
            // If the collateral oracle itself reverts on the zero-address probe, the check is
            // skipped entirely. Callers are responsible for supplying matching-decimal oracles.
        }

        maxAmountPerTx   = _maxAmountPerTx;
        maxLtvBps        = _maxLtvBps;
        collateralOracle = _collateralOracle;
        borrowOracle     = _borrowOracle;
        maxPriceAgeSec   = _maxPriceAgeSec;
        permissionSigner = _permissionSigner;

        for (uint256 i; i < allowedProtocols.length; i++) isAllowedProtocol[allowedProtocols[i]] = true;
        for (uint256 i; i < allowedAssets.length;    i++) isAllowedAsset[allowedAssets[i]]        = true;
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    /// @notice Add or remove a lending protocol from the allowed-protocols list.
    /// @param  protocol  Address of the lending protocol.
    /// @param  allowed   True to permit borrows from this protocol, false to revoke.
    function setAllowedProtocol(address protocol, bool allowed) external onlyPermissionSigner {
        isAllowedProtocol[protocol] = allowed;
    }

    /// @notice Add or remove an asset from the allowed-assets list.
    /// @param  asset    Address of the ERC-20 / cToken asset.
    /// @param  allowed  True to permit borrows of this asset, false to revoke.
    function setAllowedAsset(address asset, bool allowed) external onlyPermissionSigner {
        isAllowedAsset[asset] = allowed;
    }

    /// @notice Update the per-transaction borrow cap.
    /// @param  newMax New cap value (inclusive). Setting to 0 blocks all non-zero borrows.
    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    /// @notice Update the LTV cap.
    /// @param  newBps New cap in basis points. Must not exceed 10 000. Set to 0 to disable LTV.
    function setMaxLtvBps(uint256 newBps) external onlyPermissionSigner {
        if (newBps > 10_000) revert LtvBpsTooLarge(newBps);
        uint256 old = maxLtvBps;
        maxLtvBps = newBps;
        emit MaxLtvUpdated(old, newBps);
    }

    // -------------------------------------------------------------------------
    // IPermission
    // -------------------------------------------------------------------------

    /// @inheritdoc IPermission
    /// @dev Enforces: allowed protocol, allowed asset, amount <= cap, correct recipient,
    ///      and (if both oracles set) LTV <= maxLtvBps. Returns false for any unknown
    ///      selector, malformed calldata, or violated invariant.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedProtocol[ctx.target]) return false;

        // ── Aave v2 / v3 ─────────────────────────────────────────────────────
        if (ctx.selector == AAVE_BORROW) {
            if (txData.length < LEN_AAVE) return false;
            (address asset, uint256 amount,,,address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            if (!isAllowedAsset[asset])    return false;
            if (amount > maxAmountPerTx)   return false;
            if (onBehalfOf != ctx.account) return false;
            return _ltvCheck(asset, amount, ctx.account);
        }

        // ── Morpho ────────────────────────────────────────────────────────────
        if (ctx.selector == MORPHO_BORROW) {
            if (txData.length < LEN_MORPHO) return false;
            (address asset, uint256 amount, address onBehalf, address receiver) =
                abi.decode(txData[4:], (address, uint256, address, address));
            if (!isAllowedAsset[asset])    return false;
            if (amount > maxAmountPerTx)   return false;
            if (onBehalf  != ctx.account)  return false;
            if (receiver  != ctx.account)  return false;
            return _ltvCheck(asset, amount, ctx.account);
        }

        // ── Compound v2 ───────────────────────────────────────────────────────
        if (ctx.selector == COMPOUND_BORROW) {
            if (txData.length < LEN_COMPOUND) return false;
            uint256 amount = abi.decode(txData[4:], (uint256));
            // ctx.target is the cToken contract, which identifies the borrowed asset.
            if (!isAllowedAsset[ctx.target]) return false;
            if (amount > maxAmountPerTx)     return false;
            return _ltvCheck(ctx.target, amount, ctx.account);
        }

        return false;
    }

    /// @inheritdoc IPermission
    function discriminator() external pure returns (bytes32) {
        return keccak256("BoundedBorrowPermission");
    }

    // -------------------------------------------------------------------------
    // Internal
    // -------------------------------------------------------------------------

    /// @dev Returns true immediately when either oracle is address(0).
    ///      ltvBps = (amount × borrowPrice / 10^borDec) × 10_000 / (colValue / 10^colDec).
    ///      Both oracle values are normalised by their reported decimal precision so that
    ///      oracles with different decimal encodings (e.g. 0-dec USD vs 18-dec WAD) compare
    ///      correctly. Uses Math.mulDiv for overflow-safe 512-bit intermediate multiplication.
    ///      Oracle decimals above 77 are unsupported (10^78 overflows uint256) — fail-closed.
    function _ltvCheck(address asset, uint256 amount, address account) internal view returns (bool) {
        if (collateralOracle == address(0) || borrowOracle == address(0)) return true;

        // On L2s, also check sequencer-uptime before trusting prices.
        (uint256 colValue, uint8 colDec, uint256 colUpdatedAt) = IOracle(collateralOracle).getPrice(account, address(0));
        (uint256 borPrice, uint8 borDec, uint256 borUpdatedAt) = IOracle(borrowOracle).getPrice(asset, address(0));
        if (maxPriceAgeSec > 0) {
            if (colUpdatedAt == 0 || block.timestamp - colUpdatedAt > maxPriceAgeSec) return false;
            if (borUpdatedAt == 0 || block.timestamp - borUpdatedAt > maxPriceAgeSec) return false;
        }

        if (colDec > 77 || borDec > 77) return false;
        if (colValue == 0) return false;
        if (borPrice == 0) return false; // fail-closed: unpriced asset blocks all borrows

        // Normalise both oracle values to unitless quantities:
        //   borrowScaled = amount * borPrice / 10^borDec
        //   colNorm      = colValue / 10^colDec
        // ltvBps = borrowScaled * 10_000 / colNorm
        uint256 borrowScaled = Math.mulDiv(amount, borPrice, 10 ** uint256(borDec));
        uint256 colNorm      = colValue / (10 ** uint256(colDec));
        if (colNorm == 0) return false; // colValue too small vs precision — fail-closed
        uint256 ltvBps       = Math.mulDiv(borrowScaled, 10_000, colNorm);
        return ltvBps <= maxLtvBps;
    }
}
