// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IPermission, Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Gates protocol borrows so the manager can only borrow through approved
///         protocols, with approved assets, within an amount cap, and — when
///         oracles are configured — within an LTV ceiling.
///
///         Supported selectors:
///           Aave V3  borrow(address,uint256,uint256,uint16,address)
///           Morpho   borrow(address,uint256,address,address)
///           Compound borrow(uint256)
contract BoundedBorrowPermission is IPermission {
    // Aave V3: borrow(address asset, uint256 amount, uint256 interestRateMode,
    //                 uint16 referralCode, address onBehalfOf)
    bytes4 private constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    // Morpho: borrow(address asset, uint256 amount, address onBehalf, address receiver)
    bytes4 private constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    // Compound V2: borrow(uint256 borrowAmount)
    bytes4 private constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));

    // selector(4) + 5 slots × 32 = 164
    uint256 private constant LEN_AAVE     = 164;
    // selector(4) + 4 slots × 32 = 132
    uint256 private constant LEN_MORPHO   = 132;
    // selector(4) + 1 slot  × 32 = 36
    uint256 private constant LEN_COMPOUND = 36;

    // ── allowlists ────────────────────────────────────────────────────────────
    mapping(address protocol => bool) public isAllowedProtocol;
    mapping(address asset    => bool) public isAllowedAsset;

    // ── tunable parameters ────────────────────────────────────────────────────
    uint256 public maxAmountPerTx;
    /// @notice Maximum LTV in basis points. 7500 = 75%. 0 = no borrow allowed via LTV check.
    uint256 public maxLtvBps;
    /// @notice Oracle that returns total collateral value of the Safe.
    ///         Called as getPrice(account, address(0)); return is (totalColValue, decimals).
    address public collateralOracle;
    /// @notice Oracle that returns price per wei of the borrow asset.
    ///         Called as getPrice(asset, address(0)); return is (pricePerWei, decimals).
    ///         Must use the same denomination and decimals as collateralOracle.
    address public borrowOracle;
    address public permissionSigner;

    // ── events ────────────────────────────────────────────────────────────────
    event MaxAmountUpdated(uint256 oldMax, uint256 newMax);
    event MaxLtvUpdated(uint256 oldBps, uint256 newBps);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotPermissionSigner();
    error ZeroAddress();
    error LtvBpsTooLarge(uint256 bps);

    modifier onlyPermissionSigner() {
        if (msg.sender != permissionSigner) revert NotPermissionSigner();
        _;
    }

    constructor(
        address[] memory allowedProtocols,
        address[] memory allowedAssets,
        uint256 _maxAmountPerTx,
        uint256 _maxLtvBps,
        address _collateralOracle,
        address _borrowOracle,
        address _permissionSigner
    ) {
        if (_permissionSigner == address(0)) revert ZeroAddress();
        if (_maxLtvBps > 10_000) revert LtvBpsTooLarge(_maxLtvBps);

        maxAmountPerTx   = _maxAmountPerTx;
        maxLtvBps        = _maxLtvBps;
        collateralOracle = _collateralOracle;
        borrowOracle     = _borrowOracle;
        permissionSigner = _permissionSigner;

        for (uint256 i; i < allowedProtocols.length; i++) isAllowedProtocol[allowedProtocols[i]] = true;
        for (uint256 i; i < allowedAssets.length;    i++) isAllowedAsset[allowedAssets[i]]        = true;
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setMaxAmountPerTx(uint256 newMax) external onlyPermissionSigner {
        uint256 old = maxAmountPerTx;
        maxAmountPerTx = newMax;
        emit MaxAmountUpdated(old, newMax);
    }

    function setMaxLtvBps(uint256 newBps) external onlyPermissionSigner {
        if (newBps > 10_000) revert LtvBpsTooLarge(newBps);
        uint256 old = maxLtvBps;
        maxLtvBps = newBps;
        emit MaxLtvUpdated(old, newBps);
    }

    // ── IPermission ───────────────────────────────────────────────────────────

    /// @inheritdoc IPermission
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedProtocol[ctx.target]) return false;

        // ── Aave V3 borrow ────────────────────────────────────────────────────
        if (ctx.selector == AAVE_BORROW) {
            if (txData.length < LEN_AAVE) return false;
            (address asset, uint256 amount, , , address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            if (!isAllowedAsset[asset])    return false;
            if (amount > maxAmountPerTx)   return false;
            if (onBehalfOf != ctx.account) return false;
            return _ltvCheck(asset, amount, ctx.account);
        }

        // ── Morpho borrow ─────────────────────────────────────────────────────
        if (ctx.selector == MORPHO_BORROW) {
            if (txData.length < LEN_MORPHO) return false;
            (address asset, uint256 amount, address onBehalf, address receiver) =
                abi.decode(txData[4:], (address, uint256, address, address));
            if (!isAllowedAsset[asset])    return false;
            if (amount > maxAmountPerTx)   return false;
            if (onBehalf != ctx.account)   return false;
            if (receiver != ctx.account)   return false;
            return _ltvCheck(asset, amount, ctx.account);
        }

        // ── Compound V2 borrow ────────────────────────────────────────────────
        if (ctx.selector == COMPOUND_BORROW) {
            if (txData.length < LEN_COMPOUND) return false;
            uint256 amount = abi.decode(txData[4:], (uint256));
            // For Compound, the cToken contract (ctx.target) identifies the borrowed asset.
            // onBehalfOf is implicitly the Safe (msg.sender in the Safe-executed call).
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

    // ── internal ──────────────────────────────────────────────────────────────

    /// @dev Passes immediately when either oracle is unset (address(0)).
    ///      collateralOracle.getPrice(account, 0) → total collateral value scaled by 10^dec.
    ///      borrowOracle.getPrice(asset, 0)        → price per wei of borrow asset, same scale.
    ///      LTV (bps) = amount × borrowPrice × 10_000 / collateralValue.
    ///      Both oracles must return values in the same denomination and decimals.
    function _ltvCheck(address asset, uint256 amount, address account) internal view returns (bool) {
        if (collateralOracle == address(0) || borrowOracle == address(0)) return true;

        (uint256 colValue,) = IOracle(collateralOracle).getPrice(account, address(0));
        (uint256 borPrice,) = IOracle(borrowOracle).getPrice(asset, address(0));

        if (colValue == 0) return false;
        if (borPrice == 0) return true; // zero borrow asset price → zero borrow value → LTV = 0

        // ltvBps = amount × borPrice × 10_000 / colValue
        // Math.mulDiv handles 512-bit intermediate mul; borPrice × amount never overflows
        // in practice (largest realistic price ~1e36; max supply ~1e30; 1e66 << 2^256)
        uint256 borrowScaled = Math.mulDiv(amount, borPrice, 1);
        uint256 ltvBps       = Math.mulDiv(borrowScaled, 10_000, colValue);
        return ltvBps <= maxLtvBps;
    }
}
