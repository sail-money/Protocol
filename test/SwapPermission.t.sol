// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}          from "../contracts/interfaces/IPermission.sol";
import {IOracle}          from "../contracts/interfaces/IOracle.sol";
import {SailCapabilities} from "../contracts/interfaces/SailCapabilities.sol";
import {SwapPermission}   from "../contracts/templates/SwapPermission.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract OracleSwapMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    uint256 public regEpoch;
    function registrationEpoch(address, address) external view returns (uint256) { return regEpoch; }
    function setRegEpoch(uint256 e) external { regEpoch = e; }
    function configs(address) external view returns (address) { return signer; }
}

/// @dev Configurable oracle: settable price, decimals, and updatedAt (for staleness tests).
contract ConfigurableOracle is IOracle {
    uint256 public p;
    uint8   public d;
    uint256 public ts; // 0 => report block.timestamp (fresh)

    function set(uint256 _p, uint8 _d) external { p = _p; d = _d; }
    function setTs(uint256 _ts) external { ts = _ts; }

    function getPrice(address, address) external view returns (uint256, uint8, uint256) {
        return (p, d, ts == 0 ? block.timestamp : ts);
    }
}

/// @notice Tests for the oracle-gated SwapPermission: the T-3 truncation-to-zero fix (fail-closed),
///         the mandatory-oracle requirement at configure(), normal oracle-validated swaps, both V2
///         and V3/SwapRouter02 decode paths, and the structural denials.
contract SwapPermissionTest is Test {
    bytes4 internal constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    bytes4 internal constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf;
    bytes4 internal constant SWAP_EXACT_TOKENS     = 0x38ed1739;

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant ROUTER  = address(0x9000);
    address internal constant TOKIN   = address(0x0100);
    address internal constant TOKOUT  = address(0x0200);
    address internal constant OTHER   = address(0xBEEF);

    OracleSwapMockKernel internal kernel;
    SwapPermission       internal swap;
    ConfigurableOracle   internal oracle;

    function setUp() public {
        kernel = new OracleSwapMockKernel(address(this));
        swap   = new SwapPermission(address(kernel), AUTHOR);
        oracle = new ConfigurableOracle();
        oracle.set(2e8, 8); // realistic 8-decimal (Chainlink-style) feed: 1 tokenIn = 2 tokenOut
        _configure(1000 ether, 200, address(oracle), 3600); // 2% band, 1h freshness
    }

    // ── helpers ─────────────────────────────────────────────────────────────

    function _one(address a) internal pure returns (address[] memory arr) { arr = new address[](1); arr[0] = a; }

    function _configure(uint256 cap, uint256 bps, address orc, uint256 ageSec) internal {
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _one(TOKIN), _one(TOKOUT), cap, bps, orc, ageSec));
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
            blockNumber:    block.number,
            configEpoch:    0
        });
    }

    function _ctxVal(address target, bytes4 selector, uint256 value) internal view returns (Context memory c) {
        c = _ctx(target, selector);
        c.value = value;
    }

    function _v3(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1,
            tokenIn, tokenOut, uint24(3000), recipient,
            uint256(block.timestamp + 1), amtIn, amtOutMin, uint160(0)
        );
    }

    function _v3_02(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V2, tokenIn, tokenOut, uint24(3000), recipient, amtIn, amtOutMin, uint160(0)
        );
    }

    function _v2(address[] memory path, address to, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(SWAP_EXACT_TOKENS, amtIn, amtOutMin, path, to, block.timestamp + 1);
    }

    function _path(address a, address b) internal pure returns (address[] memory p) {
        p = new address[](2); p[0] = a; p[1] = b;
    }

    // ── introspection ───────────────────────────────────────────────────────────

    function test_Introspection_Ids() public view {
        assertEq(swap.discriminator(), keccak256("SwapPermission"));
        assertEq(swap.permissionId(),  keccak256("sail.permission.SwapPermission.v1"));
        assertEq(swap.capabilityIds()[0], SailCapabilities.BOUNDED_SWAP);
    }

    // ── T-3 regression: truncation-to-zero now fails closed ──────────────────────

    /// @notice expectedOut itself floors to zero. Realistic 8-decimal feed (Chainlink-style)
    ///         quoting a low-priced, high-decimal token; a small trade makes
    ///         expectedOut = mulDiv(amountIn, price, 10**8) round down to 0, so oracleMinOut = 0.
    ///         The fix denies; the pre-fix `amountOutMin >= 0` would have PASSED these exact inputs.
    function test_T3_TruncationToZero_FailsClosed() public {
        // 8-decimal feed, price mantissa 1 (price = 1e-8 — a very low unit price), amountIn = 1e7.
        //   expectedOut  = mulDiv(1e7, 1, 1e8)        = 0   (1e7 * 1 / 1e8 floors to 0)
        //   oracleMinOut = mulDiv(0, 10_000-200, 1e4) = 0
        // Even under a normal 2% band, the floor is 0. Old code: (amountOutMin 1 >= 0) == true.
        oracle.set(1, 8);
        _configure(1000 ether, 200, address(oracle), 3600);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 1e7, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    /// @notice Distinct path: expectedOut is POSITIVE, but the slippage multiplier floors
    ///         oracleMinOut to 0. Same realistic 8-decimal feed.
    function test_T3_OracleMinOutFloorsToZero_HighSlippage_FailsClosed() public {
        // amountIn = 9_999 * 1e8 → expectedOut = mulDiv(9_999e8, 1, 1e8) = 9_999  (> 0).
        //   oracleMinOut = mulDiv(9_999, 10_000-9_999, 10_000) = mulDiv(9_999, 1, 10_000) = 0.
        // expectedOut is non-zero yet the floor is 0 — old code would still pass (1 >= 0).
        oracle.set(1, 8);
        _configure(1000 ether, 9_999, address(oracle), 3600);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 9_999 * 1e8, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── oracle required at configure() ───────────────────────────────────────────

    function test_Configure_RevertsWithoutOracle() public {
        vm.expectRevert(SwapPermission.OracleRequired.selector);
        _configure(1000 ether, 200, address(0), 3600);
    }

    function test_Configure_RevertsOracleWithoutFreshness() public {
        vm.expectRevert(); // MissingPriceAge
        _configure(1000 ether, 200, address(oracle), 0);
    }

    // ── normal oracle-validated swaps ────────────────────────────────────────────

    function test_Normal_WithinBand_Allows_V3() public view {
        // 100 in @ price 2 → expectedOut 200; 2% band → oracleMinOut 196. minOut 196 passes.
        assertTrue(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_Normal_BelowBand_Denies_V3() public view {
        // minOut 195 < oracleMinOut 196 → denied.
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 195e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_Normal_WithinBand_Allows_V3_02() public view {
        assertTrue(swap.evaluate(_v3_02(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_Normal_WithinBand_Allows_V2() public view {
        assertTrue(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_Normal_BelowBand_Denies_V2() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 100e18, 195e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── oracle health denials ────────────────────────────────────────────────────

    function test_StalePrice_Denies() public {
        oracle.setTs(1); // ancient timestamp, far older than maxPriceAgeSec
        vm.warp(1_000_000);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_ZeroPrice_Denies() public {
        oracle.set(0, 0);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_DecimalsTooLarge_Denies() public {
        oracle.set(2, 78); // dec > 77
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── structural denials ───────────────────────────────────────────────────────

    function test_DisallowedRouter_Denies() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(OTHER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_DisallowedTokenIn_Denies() public view {
        assertFalse(swap.evaluate(_v3(OTHER, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_DisallowedTokenOut_Denies() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, OTHER, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_RecipientNotAccount_Denies() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, OTHER, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_OverCap_Denies() public {
        _configure(1 ether, 200, address(oracle), 3600);
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 5 ether, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_UnknownSelector_Denies() public view {
        assertFalse(swap.evaluate(_v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, 0xdeadbeef)));
    }

    // ── ctx.value guard: an otherwise-valid swap carrying ETH is denied ──────────

    function test_NonzeroValue_Denies() public view {
        // Identical to test_Normal_WithinBand_Allows_V3, but with ETH attached. The router is
        // payable; forwarding this value would let it be swept via refundETH. Must deny.
        bytes memory data = _v3(TOKIN, TOKOUT, ACCOUNT, 100e18, 196e18);
        assertFalse(swap.evaluate(data, _ctxVal(ROUTER, EXACT_INPUT_SINGLE_V1, 90 ether)));
        // The same swap with value == 0 still passes — the guard does not over-block.
        assertTrue(swap.evaluate(data, _ctxVal(ROUTER, EXACT_INPUT_SINGLE_V1, 0)));
    }

    function test_SlippageBpsTooLarge_RevertsAtConfigure() public {
        vm.expectRevert(abi.encodeWithSelector(SwapPermission.SlippageBpsTooLarge.selector, uint256(10_000)));
        _configure(1000 ether, 10_000, address(oracle), 3600);
    }

    // ── per-path denials: SwapRouter02 (V3-02) ──────────────────────────────────

    function test_V3_02_DisallowedTokenIn_Denies() public view {
        assertFalse(swap.evaluate(_v3_02(OTHER, TOKOUT, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_DisallowedTokenOut_Denies() public view {
        assertFalse(swap.evaluate(_v3_02(TOKIN, OTHER, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_RecipientNotAccount_Denies() public view {
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKOUT, OTHER, 100e18, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_OverCap_Denies() public {
        _configure(1 ether, 200, address(oracle), 3600);
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKOUT, ACCOUNT, 5 ether, 196e18), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    function test_V3_02_ShortCalldata_Denies() public view {
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V2, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    // ── per-path denials: V2 swapExactTokensForTokens ───────────────────────────

    function test_V2_DisallowedTokenIn_Denies() public view {
        assertFalse(swap.evaluate(_v2(_path(OTHER, TOKOUT), ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_DisallowedTokenOut_Denies() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, OTHER), ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_RecipientNotAccount_Denies() public view {
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), OTHER, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_OverCap_Denies() public {
        _configure(1 ether, 200, address(oracle), 3600);
        assertFalse(swap.evaluate(_v2(_path(TOKIN, TOKOUT), ACCOUNT, 5 ether, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_ShortPath_Denies() public view {
        address[] memory p = new address[](1); p[0] = TOKIN;
        assertFalse(swap.evaluate(_v2(p, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V1_ShortCalldata_Denies() public view {
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V1, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V2_ShortCalldata_Denies() public view {
        bytes memory short = abi.encodeWithSelector(SWAP_EXACT_TOKENS, uint256(1));
        assertFalse(swap.evaluate(short, _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── F1: same-token (self-route) denials ─────────────────────────────────────

    /// @dev Config where TOKIN is allowed as BOTH input and output, so a self-route would clear the
    ///      allowlists — isolating the same-token guard as the reason for denial.
    function _configureSelfRoutable() internal {
        address[] memory tin  = new address[](1); tin[0]  = TOKIN;
        address[] memory tout = new address[](2); tout[0] = TOKOUT; tout[1] = TOKIN;
        swap.configureDirect(
            ACCOUNT,
            abi.encode(_one(ROUTER), tin, tout, uint256(1000 ether), uint256(200), address(oracle), uint256(3600))
        );
    }

    /// @dev Load-bearing case: a V2 round-trip path [A,B,A] executes and burns AMM fees; denied.
    function test_SelfRoute_V2RoundTrip_Denied() public {
        _configureSelfRoutable();
        address[] memory path = new address[](3);
        path[0] = TOKIN; path[1] = TOKOUT; path[2] = TOKIN;
        assertFalse(swap.evaluate(_v2(path, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    /// @dev V3 same-token denied at the permission (earlier clean deny than the router's own revert).
    function test_SelfRoute_V3SameToken_Denied() public {
        _configureSelfRoutable();
        assertFalse(swap.evaluate(_v3(TOKIN, TOKIN, ACCOUNT, 100e18, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_SelfRoute_V3_02SameToken_Denied() public {
        _configureSelfRoutable();
        assertFalse(swap.evaluate(_v3_02(TOKIN, TOKIN, ACCOUNT, 100e18, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    /// @dev A distinct-token multi-hop route [A,B,C] (distinct endpoints) is unaffected by the guard.
    function test_DistinctRoute_V2MultiHop_StillAllowed() public view {
        address[] memory path = new address[](3);
        path[0] = TOKIN; path[1] = OTHER; path[2] = TOKOUT; // endpoints distinct; intermediate unchecked
        assertTrue(swap.evaluate(_v2(path, ACCOUNT, 100e18, 196e18), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── F3: allowlist length cap (parity with the other launch templates) ───────

    function _addrs(uint256 n) internal pure returns (address[] memory a) {
        a = new address[](n);
        for (uint256 i; i < n; i++) a[i] = address(uint160(i + 1));
    }

    function test_Config_RevertsTooLongRouters() public {
        vm.expectRevert(SwapPermission.AllowlistTooLong.selector);
        swap.configureDirect(ACCOUNT, abi.encode(_addrs(51), _one(TOKIN), _one(TOKOUT), uint256(1), uint256(200), address(oracle), uint256(3600)));
    }

    function test_Config_RevertsTooLongTokensIn() public {
        vm.expectRevert(SwapPermission.AllowlistTooLong.selector);
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _addrs(51), _one(TOKOUT), uint256(1), uint256(200), address(oracle), uint256(3600)));
    }

    function test_Config_RevertsTooLongTokensOut() public {
        vm.expectRevert(SwapPermission.AllowlistTooLong.selector);
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _one(TOKIN), _addrs(51), uint256(1), uint256(200), address(oracle), uint256(3600)));
    }

    function test_Config_AtCap_Succeeds() public {
        swap.configureDirect(ACCOUNT, abi.encode(_addrs(50), _addrs(50), _addrs(50), uint256(1), uint256(200), address(oracle), uint256(3600)));
        assertTrue(swap.isConfigured(ACCOUNT));
    }
}
