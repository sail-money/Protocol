// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Context} from "../interfaces/IPermission.sol";
import {IOracle} from "../interfaces/IOracle.sol";
import {IPermissionIntrospection} from "../interfaces/IPermissionIntrospection.sol";
import {SailCapabilities} from "../interfaces/SailCapabilities.sol";
import {ConfigurablePermission} from "./ConfigurablePermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @dev Minimal Compound V2 cToken surface: the underlying ERC-20 a cToken market wraps.
///      Used to resolve the cToken (the borrow call target) to its underlying borrow asset.
interface ICErc20 {
    function underlying() external view returns (address);
}

/// @title  BorrowPermission — bounded borrow with optional LTV ceiling
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
///         WHAT IT IS. A reference borrow permission. One deployment serves any number of accounts;
///         each stores its own protocol and asset allowlists, a per-tx amount cap, an LTV ceiling,
///         and a pair of price oracles. Supports Aave V3, Morpho, and Compound V2 borrow selectors.
///
///         WHAT IT ENFORCES. For every borrow: the protocol (call target) and asset are
///         allowlisted; the amount is within the per-tx cap; the position is credited to the
///         account itself (onBehalfOf / receiver == account); and, when oracles are configured, the
///         resulting loan-to-value is within maxLtvBps.
///
///         ORACLE MODES. Oracles are configured in matched pairs:
///           - ZERO oracles  → amount-cap-only borrowing. NO LTV ceiling is applied; only the
///                             per-tx cap and the allowlists bound the borrow.
///           - BOTH oracles  → the LTV ceiling is enforced against the collateral and borrow feeds.
///         Exactly ONE oracle is rejected at configure() (OracleConfigInconsistent): loan-to-value
///         is a ratio of borrow value to collateral value, and a single feed can price only one
///         side, so a one-oracle config cannot compute a ratio and is a configuration error.
///
///         HONEST BOUNDARY — what it does NOT do. With zero oracles, ONLY the size cap applies —
///         there is no LTV ceiling, despite maxLtvBps being stored. When oracles are set, the LTV
///         ceiling is only as good as the configured oracles' honesty and freshness; it does NOT
///         protect against a manipulated or compromised feed. The collateral oracle is trusted to
///         report the account's aggregate collateral value (it is queried by account address). LTV
///         is checked at borrow time only — it does NOT monitor ongoing position health after the
///         borrow, and the cap is per-transaction, not cumulative. Likewise maxLtvBps bounds each
///         borrow step's size against the collateral valuation at the moment of that call; it does
///         NOT bound the cumulative LTV of a position built across multiple borrows (e.g. a leverage
///         loop). For cumulative-position safety, rely on the lending protocol's own health factor
///         and/or a separate position-monitoring permission.
///
/// @dev    Config blob:
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
    /// @notice Thrown when exactly one oracle is configured. LTV is a ratio of borrow value to
    ///         collateral value; a single feed prices only one side and cannot form the ratio.
    ///         Configure either zero oracles (amount-cap-only) or both.
    error OracleConfigInconsistent();

    constructor(address _kernel, address _author)
        ConfigurablePermission(_kernel, "BorrowPermission", "2")
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
        // Oracles must come as a matched pair. LTV is a ratio of borrow value to collateral value;
        // a single feed can price only one side, so exactly one oracle cannot form the ratio and is
        // a meaningless config. Require zero (amount-cap-only) or both — rejecting the in-between at
        // config time, where it is debuggable, rather than silently disabling the ceiling later.
        bool colSet = collateralOracle != address(0);
        bool borSet = borrowOracle != address(0);
        if (colSet != borSet) revert OracleConfigInconsistent();
        // When the oracles are set, a freshness bound is mandatory; 0 would silently accept
        // arbitrarily stale prices and re-open the gap the oracle is meant to close.
        if (colSet && maxPriceAgeSec == 0) revert MissingPriceAge();

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
        // Fail closed unless the stored config is current for this registration epoch (Octane #2/#8).
        if (!_configCurrent(ctx.account, ctx.configEpoch)) return false;
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
            // The Compound borrow target is the cToken, but `amount` and the allowlist/oracle are
            // denominated in the UNDERLYING asset. Resolve it via cToken.underlying() and key both
            // the allowlist and the LTV check on the underlying.
            // Targets that don't expose underlying() (e.g. cETH) resolve nothing and are denied — fail-closed by design.
            address underlying;
            try ICErc20(ctx.target).underlying() returns (address u) { underlying = u; }
            catch { return false; }
            if (!isAllowedAsset[ctx.account][underlying]) return false;
            if (amount > s.maxAmountPerTx)                return false;
            return _ltvCheck(s, underlying, amount, ctx.account);
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
        // Defense-in-depth: configure() rejects a single-oracle config, so reaching here with one
        // oracle unset means BOTH are unset — the amount-cap-only mode, where no LTV ceiling applies.
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

        // Enforce trueLTV <= maxLtvBps, i.e.
        //     amount * borPrice / 10^borDec  <=  (maxLtvBps / 10_000) * colValue / 10^colDec
        // rearranged into the largest borrow amount the ceiling permits:
        //     maxAmountAllowed = colValue * maxLtvBps * 10^borDec / (10_000 * 10^colDec * borPrice)
        // and compared against the integer `amount` directly. Two properties matter:
        //   (1) Fail-CLOSED. Every step floors, all in the borrower's disfavour, so maxAmountAllowed
        //       never exceeds the true ceiling and an over-LTV borrow can never slip through. This
        //       also closes the prior bug where pre-flooring the borrow value to whole numeraire
        //       units (borrowScaled) collapsed any sub-1-unit borrow to 0 and passed ANY ceiling.
        //   (2) No collateral truncation. The LTV fraction is applied to the full-precision colValue
        //       mantissa FIRST; only then is the decimal scale collapsed by dividing by 10^colDec.
        //       Folding 10^colDec in before taking the fraction would floor away fractional
        //       collateral and over-block borrows that are genuinely within the ceiling.
        // colValue != 0, borPrice != 0 and decimals <= 77 are all guarded above, so every divisor is
        // non-zero and 10^colDec / 10^borDec cannot overflow; mulDiv carries each product at full
        // precision in a 512-bit intermediate.
        uint256 scaledBound      = Math.mulDiv(colValue, s.maxLtvBps, 10_000);
        uint256 maxAmountAllowed = Math.mulDiv(scaledBound, 10 ** uint256(borDec), 10 ** uint256(colDec)) / borPrice;
        return amount <= maxAmountAllowed;
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
