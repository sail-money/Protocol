// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice UNAUDITED EXAMPLE — NOT PART OF THE TRUSTED CORE.
///         This permission is a reference example demonstrating how to express a bounded
///         mandate against the Sail kernel. It is provided as-is, is NOT covered by the
///         protocol audit of the trusted core (SailKernel, SailGovernance, MandateFactory,
///         StandardFeePolicy, SafeModuleEnabler), and carries no warranty. The kernel
///         evaluates any permission safely under staticcall + a gas cap + fail-closed
///         semantics, but it does NOT verify that this permission's logic correctly
///         enforces what its NatSpec claims. Anyone registering this permission is
///         responsible for reviewing it. See docs/SECURITY.md for the audit-scope documentation.
///
///         Reference borrow permission. One deployment serves any number of accounts.
///         Supports Aave V3, Morpho, and Compound V2 borrow selectors.
///
///         Config blob:
///             abi.encode(
///                 address[] protocols,
///                 address[] assets,
///                 uint256   maxAmountPerTx,
///                 uint256   maxLtvBps,
///                 address   collateralOracle,
///                 address   borrowOracle,
///                 uint256   maxPriceAgeSec
///             )
contract BorrowPermission is ConfigurablePermission, IPermissionIntrospection {
    bytes4 private constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 private constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    bytes4 private constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));

    uint256 private constant LEN_AAVE     = 164;
    uint256 private constant LEN_MORPHO   = 132;
    uint256 private constant LEN_COMPOUND = 36;

    struct Slot {
        address[] protocols;
        address[] assets;
        uint256   maxAmountPerTx;
        uint256   maxLtvBps;
        address   collateralOracle;
        address   borrowOracle;
        uint256   maxPriceAgeSec;
    }

    mapping(address account => Slot) private _slots;
    mapping(address account => mapping(address => bool)) public isAllowedProtocol;
    mapping(address account => mapping(address => bool)) public isAllowedAsset;

    /// @notice Tooling-layer attribution for the template author. The kernel never reads this.
    address public immutable author;

    error LtvBpsTooLarge(uint256 bps);

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "BorrowPermission", "1")
    {
        author = _author;
    }

    function getConfig(address account)
        external
        view
        returns (
            address[] memory protocols,
            address[] memory assets,
            uint256 maxAmountPerTx,
            uint256 maxLtvBps,
            address collateralOracle,
            address borrowOracle,
            uint256 maxPriceAgeSec
        )
    {
        Slot storage s = _slots[account];
        return (s.protocols, s.assets, s.maxAmountPerTx, s.maxLtvBps, s.collateralOracle, s.borrowOracle, s.maxPriceAgeSec);
    }

    function _applyConfig(address account, bytes calldata params) internal override {
        (
            address[] memory protocols,
            address[] memory assets,
            uint256 maxAmountPerTx,
            uint256 maxLtvBps,
            address collateralOracle,
            address borrowOracle,
            uint256 maxPriceAgeSec
        ) = abi.decode(params, (address[], address[], uint256, uint256, address, address, uint256));

        if (maxLtvBps > 10_000) revert LtvBpsTooLarge(maxLtvBps);
        // The LTV check runs only when both oracles are set; in that case a freshness bound
        // is mandatory. 0 would silently accept arbitrarily stale prices and re-open the gap.
        if (collateralOracle != address(0) && borrowOracle != address(0) && maxPriceAgeSec == 0) {
            revert MissingPriceAge();
        }

        Slot storage s = _slots[account];
        for (uint256 i; i < s.protocols.length; i++) isAllowedProtocol[account][s.protocols[i]] = false;
        for (uint256 i; i < s.assets.length; i++)    isAllowedAsset[account][s.assets[i]]       = false;

        for (uint256 i; i < protocols.length; i++) isAllowedProtocol[account][protocols[i]] = true;
        for (uint256 i; i < assets.length; i++)    isAllowedAsset[account][assets[i]]       = true;

        s.protocols        = protocols;
        s.assets           = assets;
        s.maxAmountPerTx   = maxAmountPerTx;
        s.maxLtvBps        = maxLtvBps;
        s.collateralOracle = collateralOracle;
        s.borrowOracle     = borrowOracle;
        s.maxPriceAgeSec   = maxPriceAgeSec;
    }

    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool) {
        if (!isAllowedProtocol[ctx.account][ctx.target]) return false;
        Slot storage s = _slots[ctx.account];

        if (ctx.selector == AAVE_BORROW) {
            if (txData.length < LEN_AAVE) return false;
            (address asset, uint256 amount, , , address onBehalfOf) =
                abi.decode(txData[4:], (address, uint256, uint256, uint16, address));
            if (!isAllowedAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)           return false;
            if (onBehalfOf != ctx.account)           return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        if (ctx.selector == MORPHO_BORROW) {
            if (txData.length < LEN_MORPHO) return false;
            (address asset, uint256 amount, address onBehalf, address receiver) =
                abi.decode(txData[4:], (address, uint256, address, address));
            if (!isAllowedAsset[ctx.account][asset]) return false;
            if (amount > s.maxAmountPerTx)           return false;
            if (onBehalf != ctx.account)             return false;
            if (receiver != ctx.account)             return false;
            return _ltvCheck(s, asset, amount, ctx.account);
        }

        if (ctx.selector == COMPOUND_BORROW) {
            if (txData.length < LEN_COMPOUND) return false;
            uint256 amount = abi.decode(txData[4:], (uint256));
            if (!isAllowedAsset[ctx.account][ctx.target]) return false;
            if (amount > s.maxAmountPerTx)                return false;
            return _ltvCheck(s, ctx.target, amount, ctx.account);
        }

        return false;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("BorrowPermission");
    }

    function _ltvCheck(Slot storage s, address asset, uint256 amount, address account)
        internal
        view
        returns (bool)
    {
        if (s.collateralOracle == address(0) || s.borrowOracle == address(0)) return true;

        // On L2s, check sequencer-uptime first.
        (uint256 colValue, uint8 colDec, uint256 colUpdatedAt) = IOracle(s.collateralOracle).getPrice(account, address(0));
        (uint256 borPrice, uint8 borDec, uint256 borUpdatedAt) = IOracle(s.borrowOracle).getPrice(asset, address(0));
        if (s.maxPriceAgeSec > 0) {
            if (colUpdatedAt == 0 || block.timestamp - colUpdatedAt > s.maxPriceAgeSec) return false;
            if (borUpdatedAt == 0 || block.timestamp - borUpdatedAt > s.maxPriceAgeSec) return false;
        }

        if (colDec > 77 || borDec > 77) return false;
        if (colValue == 0) return false;
        if (borPrice == 0) return false;

        // Normalise both oracle values to unitless quantities before forming the ratio:
        //   borrowScaled = amount * borPrice / 10^borDec
        //   colNorm      = colValue / 10^colDec
        // Dividing by raw colValue (ignoring colDec) would understate LTV by 10^colDec and
        // silently defeat the ceiling whenever the collateral oracle reports non-zero decimals.
        uint256 borrowScaled = Math.mulDiv(amount, borPrice, 10 ** uint256(borDec));
        uint256 colNorm      = colValue / (10 ** uint256(colDec));
        if (colNorm == 0) return false; // colValue too small vs precision — fail-closed
        uint256 ltvBps       = Math.mulDiv(borrowScaled, 10_000, colNorm);
        return ltvBps <= s.maxLtvBps;
    }

    // ── IPermissionIntrospection ──────────────────────────────────────────────

    function permissionId() external pure override returns (bytes32) {
        return keccak256("sail.permission.BorrowPermission.v1");
    }

    function permissionVersion() external pure override returns (bytes32) {
        return keccak256("v1");
    }

    function metadataURI() external pure override returns (string memory) {
        return "";
    }

    function capabilityIds() external pure override returns (bytes32[] memory ids) {
        ids = new bytes32[](1);
        ids[0] = SailCapabilities.BOUNDED_BORROW;
    }
}
