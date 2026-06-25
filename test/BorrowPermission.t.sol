// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}          from "../contracts/interfaces/IPermission.sol";
import {IOracle}          from "../contracts/interfaces/IOracle.sol";
import {SailCapabilities} from "../contracts/interfaces/SailCapabilities.sol";
import {BorrowPermission} from "../contracts/templates/BorrowPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract BorrowMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    function configs(address) external view returns (address) { return signer; }
}

/// @dev Oracle keyed by (base, quote) with a settable timestamp for staleness tests.
contract BorrowOracle is IOracle {
    mapping(bytes32 => uint256) private _p;
    mapping(bytes32 => uint8)   private _d;
    uint256 public ts; // 0 => report block.timestamp (fresh)

    function set(address a, address b, uint256 p, uint8 d) external {
        bytes32 k = keccak256(abi.encode(a, b));
        _p[k] = p; _d[k] = d;
    }
    function setTs(uint256 _ts) external { ts = _ts; }

    function getPrice(address a, address b) external view returns (uint256, uint8, uint256) {
        bytes32 k = keccak256(abi.encode(a, b));
        return (_p[k], _d[k], ts == 0 ? block.timestamp : ts);
    }
}

/// @dev Minimal Compound V2 cToken: exposes underlying() like a cErc20 market.
contract MockCToken {
    address private immutable _u;
    constructor(address u) { _u = u; }
    function underlying() external view returns (address) { return _u; }
}

/// @dev A cToken-shaped market with NO underlying() (models Compound's native cETH market):
///      resolving underlying() reverts, exercising the fail-closed try/catch deny.
contract MockCEther {
    function isCToken() external pure returns (bool) { return true; }
}

/// @notice Tests for BorrowPermission: the matched-oracle-pair requirement at configure() (a
///         single oracle is rejected), the full-precision LTV math (no collateral truncation), and
///         the standard decode / allowlist / cap / pin / oracle-health denials.
contract BorrowPermissionTest is Test {
    bytes4 internal constant AAVE_BORROW     = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 internal constant MORPHO_BORROW   = bytes4(keccak256("borrow(address,uint256,address,address)"));
    bytes4 internal constant COMPOUND_BORROW = bytes4(keccak256("borrow(uint256)"));

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant AAVE    = address(0xAA0E);
    address internal constant MORPHO  = address(0x110F);
    address internal constant CTOKEN  = address(0xC701);
    address internal constant ASSET   = address(0xA55E);
    address internal constant OTHER   = address(0xBEEF);

    uint256 internal constant CAP = 1e30;

    BorrowMockKernel internal kernel;
    BorrowPermission internal borrow;
    BorrowOracle     internal colOracle;
    BorrowOracle     internal borOracle;

    function setUp() public {
        kernel    = new BorrowMockKernel(address(this));
        borrow    = new BorrowPermission(address(kernel), AUTHOR);
        colOracle = new BorrowOracle();
        borOracle = new BorrowOracle();
        // The Compound branch resolves the borrow asset via cToken.underlying(); install a cToken
        // whose underlying is ASSET at the CTOKEN test address so CTOKEN.underlying() == ASSET.
        vm.etch(CTOKEN, address(new MockCToken(ASSET)).code);
    }

    // ── config helpers ────────────────────────────────────────────────────────

    function _two(address a, address b) internal pure returns (address[] memory arr) {
        arr = new address[](2); arr[0] = a; arr[1] = b;
    }
    function _three(address a, address b, address c) internal pure returns (address[] memory arr) {
        arr = new address[](3); arr[0] = a; arr[1] = b; arr[2] = c;
    }

    /// @dev Configure with all three protocols + ASSET + CTOKEN allowlisted.
    function _configure(uint256 maxLtv, address col, address bor, uint256 ageSec) internal {
        address[] memory protocols = _three(AAVE, MORPHO, CTOKEN);
        address[] memory assets    = _two(ASSET, CTOKEN);
        borrow.configureDirect(ACCOUNT, abi.encode(protocols, assets, CAP, maxLtv, col, bor, ageSec));
    }

    function _ctx(address target, bytes4 selector) internal view returns (Context memory c) {
        c = Context({
            account:        ACCOUNT,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       selector,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    // borrow calldata builders
    function _aave(address asset, uint256 amount, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(AAVE_BORROW, asset, amount, uint256(2), uint16(0), onBehalfOf);
    }
    function _morpho(address asset, uint256 amount, address onBehalf, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(MORPHO_BORROW, asset, amount, onBehalf, receiver);
    }
    function _compound(uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(COMPOUND_BORROW, amount);
    }

    // ── introspection ───────────────────────────────────────────────────────────

    function test_Introspection_Ids() public view {
        assertEq(borrow.discriminator(), keccak256("BorrowPermission"));
        assertEq(borrow.permissionId(),  keccak256("sail.permission.BorrowPermission.v1"));
        assertEq(borrow.capabilityIds()[0], SailCapabilities.BOUNDED_BORROW);
        assertEq(borrow.author(), AUTHOR);
    }

    // ── matched-oracle-pair requirement at configure() ───────────────────────────

    function test_Configure_RejectsSingleOracle_CollateralOnly() public {
        vm.expectRevert(BorrowPermission.OracleConfigInconsistent.selector);
        _configure(7500, address(colOracle), address(0), 3600);
    }

    function test_Configure_RejectsSingleOracle_BorrowOnly() public {
        vm.expectRevert(BorrowPermission.OracleConfigInconsistent.selector);
        _configure(7500, address(0), address(borOracle), 3600);
    }

    function test_Configure_ZeroOracles_Succeeds() public {
        _configure(7500, address(0), address(0), 0);
        assertTrue(borrow.isConfigured(ACCOUNT));
    }

    function test_Configure_BothOracles_Succeeds() public {
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertTrue(borrow.isConfigured(ACCOUNT));
    }

    function test_Configure_BothOracles_ZeroPriceAge_Reverts() public {
        vm.expectRevert(); // MissingPriceAge
        _configure(7500, address(colOracle), address(borOracle), 0);
    }

    function test_Configure_LtvBpsTooLarge_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(BorrowPermission.LtvBpsTooLarge.selector, uint256(10_001)));
        _configure(10_001, address(0), address(0), 0);
    }

    // ── zero-oracle mode: amount-cap-only, NO LTV ceiling ────────────────────────

    function test_ZeroOracles_NoLtvCeiling_AllowsWithinCap() public {
        _configure(1, address(0), address(0), 0); // maxLtv=1bps but NO oracles → not enforced
        // A large borrow (within the per-tx cap) is allowed: with no oracles there is no LTV check.
        assertTrue(borrow.evaluate(_aave(ASSET, 1e24, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    // ── both-oracle mode: LTV enforced ───────────────────────────────────────────

    function test_BothOracles_WithinLtv_Allows() public {
        // colValue=10_000 (dec 0), borPrice=1 (dec 0); amount=5_000 → ltv 50% < 75%.
        colOracle.set(ACCOUNT, address(0), 10_000, 0);
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertTrue(borrow.evaluate(_aave(ASSET, 5_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_BothOracles_OverLtv_Denies() public {
        colOracle.set(ACCOUNT, address(0), 10_000, 0);
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(5000, address(colOracle), address(borOracle), 3600); // 50% cap
        assertFalse(borrow.evaluate(_aave(ASSET, 8_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW))); // 80% > 50%
    }

    // ── full-precision LTV math (no collateral truncation) ───────────────────────

    /// @notice Near-ceiling borrow that the old truncating math wrongly DENIED now correctly
    ///         ALLOWS, and a genuinely over-ceiling borrow still DENIES.
    ///         Setup: colValue = 150.9 units at 18 decimals, borPrice = 1 at 0 decimals,
    ///         maxLtv = 7500 (75%).
    ///           - amount 113 → true LTV 113*10000/150.9 = 7488 bps (74.88%) → ALLOW.
    ///             Old math: colNorm = floor(150.9) = 150 → 7533 bps → wrongly DENY.
    ///           - amount 120 → true LTV 7952 bps (79.52%) → still DENY.
    function test_FullPrecisionLtv_NearCeiling_Allows_OldWouldDeny() public {
        colOracle.set(ACCOUNT, address(0), uint256(1509) * 1e17, 18); // 150.9e18
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertTrue(borrow.evaluate(_aave(ASSET, 113, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_FullPrecisionLtv_OverCeiling_StillDenies() public {
        colOracle.set(ACCOUNT, address(0), uint256(1509) * 1e17, 18); // 150.9e18
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 120, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    // ── #6: sub-1-unit borrow no longer bypasses the LTV ceiling (fail-closed) ────

    /// @notice A sub-1-numeraire-unit borrow that the OLD truncating math APPROVED (the borrow
    ///         value floored to borrowScaled = 0 → ltvBps = 0 → passed ANY ceiling) is now correctly
    ///         DENIED when its true value exceeds the per-step LTV. colValue = 1 numeraire unit
    ///         (dec 0); borPrice = 1 at 18 decimals, so each base unit is worth 1e-18 numeraire;
    ///         maxLtv = 5000 (50%) → ceiling = 0.5 numeraire. A borrow of 9e17 base units is worth
    ///         0.9 numeraire > 0.5 → DENY. The old code floored 0.9 → 0 and ALLOWED it.
    function test_SubUnitBorrow_ExceedingLtv_Denies_OldWouldAllow() public {
        colOracle.set(ACCOUNT, address(0), 1, 0);   // 1 numeraire unit of collateral
        borOracle.set(ASSET, address(0), 1, 18);    // 1 base unit = 1e-18 numeraire
        _configure(5000, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 9e17, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    /// @notice Marginal over-ceiling borrow (true LTV just above maxLtvBps) is DENIED. The old
    ///         floor-rounding could let it slip; the amount-based form rounds against the borrower.
    ///         colValue = 1000 (dec 0), borPrice = 1 (dec 0), maxLtv = 5000 (50%) → ceiling 500 units.
    function test_MarginalOverCeiling_Denies() public {
        colOracle.set(ACCOUNT, address(0), 1000, 0);
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(5000, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 501, ACCOUNT), _ctx(AAVE, AAVE_BORROW))); // 50.1%
    }

    /// @notice A borrow exactly AT the ceiling still PASSES — the fail-closed form does not
    ///         over-block legitimate borrows into uselessness. Same setup: ceiling = 500 units.
    function test_ExactlyAtCeiling_Allows() public {
        colOracle.set(ACCOUNT, address(0), 1000, 0);
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(5000, address(colOracle), address(borOracle), 3600);
        assertTrue(borrow.evaluate(_aave(ASSET, 500, ACCOUNT), _ctx(AAVE, AAVE_BORROW))); // 50.0%
    }

    // ── #11: Compound borrow resolves the cToken to its underlying ────────────────

    /// @notice With the cToken's UNDERLYING allowlisted and priced (not the cToken), a Compound
    ///         borrow resolves CTOKEN.underlying() == ASSET, keys both the allowlist and the borrow
    ///         oracle on ASSET, and the LTV check prices it correctly → ALLOW. (The old code keyed
    ///         on the cToken, for which the borrow oracle has no entry → price 0 → wrongful deny.)
    function test_Compound_UnderlyingAllowlisted_WithOracles_Allows() public {
        colOracle.set(ACCOUNT, address(0), 10_000, 0);
        borOracle.set(ASSET, address(0), 1, 0); // borrow oracle keyed on the UNDERLYING (ASSET)
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertTrue(borrow.evaluate(_compound(5_000), _ctx(CTOKEN, COMPOUND_BORROW)));
    }

    /// @notice A cToken-shaped target with no underlying() (Compound's native cETH market) reverts
    ///         the resolution staticcall and is denied fail-closed.
    function test_Compound_NoUnderlyingFn_Denies() public {
        MockCEther cEther = new MockCEther();
        address[] memory protocols = _three(AAVE, MORPHO, address(cEther));
        address[] memory assets    = _two(ASSET, address(cEther));
        borrow.configureDirect(
            ACCOUNT, abi.encode(protocols, assets, CAP, uint256(0), address(0), address(0), uint256(0))
        );
        assertFalse(borrow.evaluate(_compound(100), _ctx(address(cEther), COMPOUND_BORROW)));
    }

    // ── decode paths: each selector, happy path (zero-oracle to isolate decode) ───

    function test_Aave_Borrow_Allowed() public {
        _configure(0, address(0), address(0), 0);
        assertTrue(borrow.evaluate(_aave(ASSET, 100, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_Morpho_Borrow_Allowed() public {
        _configure(0, address(0), address(0), 0);
        assertTrue(borrow.evaluate(_morpho(ASSET, 100, ACCOUNT, ACCOUNT), _ctx(MORPHO, MORPHO_BORROW)));
    }

    function test_Compound_Borrow_Allowed() public {
        _configure(0, address(0), address(0), 0);
        assertTrue(borrow.evaluate(_compound(100), _ctx(CTOKEN, COMPOUND_BORROW)));
    }

    // ── structural denials ───────────────────────────────────────────────────────

    function test_DisallowedProtocol_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_aave(ASSET, 100, ACCOUNT), _ctx(OTHER, AAVE_BORROW)));
    }

    function test_Aave_DisallowedAsset_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_aave(OTHER, 100, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_Aave_OverCap_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_aave(ASSET, CAP + 1, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_Aave_OnBehalfOfNotAccount_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_aave(ASSET, 100, OTHER), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_Morpho_OnBehalfNotAccount_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_morpho(ASSET, 100, OTHER, ACCOUNT), _ctx(MORPHO, MORPHO_BORROW)));
    }

    function test_Morpho_ReceiverNotAccount_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_morpho(ASSET, 100, ACCOUNT, OTHER), _ctx(MORPHO, MORPHO_BORROW)));
    }

    function test_UnknownSelector_Denies() public {
        _configure(0, address(0), address(0), 0);
        assertFalse(borrow.evaluate(_aave(ASSET, 100, ACCOUNT), _ctx(AAVE, 0xdeadbeef)));
    }

    function test_Aave_ShortCalldata_Denies() public {
        _configure(0, address(0), address(0), 0);
        bytes memory short = abi.encodeWithSelector(AAVE_BORROW, ASSET);
        assertFalse(borrow.evaluate(short, _ctx(AAVE, AAVE_BORROW)));
    }

    function test_Morpho_ShortCalldata_Denies() public {
        _configure(0, address(0), address(0), 0);
        bytes memory short = abi.encodeWithSelector(MORPHO_BORROW, ASSET);
        assertFalse(borrow.evaluate(short, _ctx(MORPHO, MORPHO_BORROW)));
    }

    function test_Compound_ShortCalldata_Denies() public {
        _configure(0, address(0), address(0), 0);
        bytes memory short = abi.encodePacked(COMPOUND_BORROW); // 4 bytes, < 36
        assertFalse(borrow.evaluate(short, _ctx(CTOKEN, COMPOUND_BORROW)));
    }

    // ── oracle-health denials (both oracles set) ─────────────────────────────────

    function test_StaleCollateralPrice_Denies() public {
        vm.warp(1_000_000);
        colOracle.set(ACCOUNT, address(0), 10_000, 0);
        borOracle.set(ASSET, address(0), 1, 0);
        colOracle.setTs(1); // ancient
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 5_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_ZeroCollateralValue_Denies() public {
        colOracle.set(ACCOUNT, address(0), 0, 0); // colValue 0
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 5_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_ZeroBorrowPrice_Denies() public {
        colOracle.set(ACCOUNT, address(0), 10_000, 0);
        borOracle.set(ASSET, address(0), 0, 0); // borPrice 0
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 5_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }

    function test_DecimalsTooLarge_Denies() public {
        colOracle.set(ACCOUNT, address(0), 10_000, 78); // dec > 77
        borOracle.set(ASSET, address(0), 1, 0);
        _configure(7500, address(colOracle), address(borOracle), 3600);
        assertFalse(borrow.evaluate(_aave(ASSET, 5_000, ACCOUNT), _ctx(AAVE, AAVE_BORROW)));
    }
}
