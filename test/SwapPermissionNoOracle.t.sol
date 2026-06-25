// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}       from "../contracts/interfaces/SailCapabilities.sol";
import {SwapPermissionNoOracle} from "../contracts/templates/SwapPermissionNoOracle.sol";

/// @dev Minimal kernel view: every account registered; this test contract is the permissionSigner.
contract NoOracleMockKernel {
    address public immutable signer;
    constructor(address _signer) { signer = _signer; }
    function registered(address) external pure returns (bool) { return true; }
    uint256 public regEpoch;
    function registrationEpoch(address, address) external view returns (uint256) { return regEpoch; }
    function setRegEpoch(uint256 e) external { regEpoch = e; }
    function configs(address) external view returns (address) { return signer; }
}

/// @dev Mock Uniswap V2-style pair. token0()/token1() are auto-generated getters.
contract MockV2Pair {
    address public token0;
    address public token1;
    uint112 private _r0;
    uint112 private _r1;
    bool public broken;
    constructor(address t0, address t1) { token0 = t0; token1 = t1; }
    function setReserves(uint112 r0, uint112 r1) external { _r0 = r0; _r1 = r1; }
    function setBroken(bool v) external { broken = v; }
    function getReserves() external view returns (uint112, uint112, uint32) {
        require(!broken, "broken");
        return (_r0, _r1, 0);
    }
}

/// @dev Mock Uniswap V3-style pool. token0()/token1() are auto-generated getters.
contract MockV3Pool {
    address public token0;
    address public token1;
    uint160 private _sqrtPriceX96;
    uint128 private _liquidity;
    bool public broken;
    constructor(address t0, address t1) { token0 = t0; token1 = t1; }
    function set(uint160 sp, uint128 liq) external { _sqrtPriceX96 = sp; _liquidity = liq; }
    function setBroken(bool v) external { broken = v; }
    function slot0() external view returns (uint160, int24, uint16, uint16, uint16, uint8, bool) {
        require(!broken, "broken");
        return (_sqrtPriceX96, 0, 0, 0, 0, 0, true);
    }
    function liquidity() external view returns (uint128) { return _liquidity; }
}

/// @notice Tests for the redesigned SwapPermissionNoOracle: structural bounds (unchanged) plus a
///         per-pair, operator-named-pool-referenced hallucination sanity band. The band catches an
///         honest agent's price mistake; it is NOT manipulation-resistant — a documented case below
///         shows a manipulated reference pool letting a bad-looking swap through, which is the
///         in-scope-OUT boundary, not a bug.
contract SwapPermissionNoOracleTest is Test {
    bytes4 internal constant EXACT_INPUT_SINGLE_V1 = 0x414bf389;
    bytes4 internal constant EXACT_INPUT_SINGLE_V2 = 0x04e45aaf;
    bytes4 internal constant SWAP_EXACT_TOKENS     = 0x38ed1739;

    uint160 internal constant SQRT_P1 = uint160(2 ** 96); // price = 1.0 (token1 per token0)

    address internal constant AUTHOR  = address(0xA11CE);
    address internal constant ACCOUNT = address(0xACC0);
    address internal constant ROUTER  = address(0x9000);
    address internal constant TOKIN   = address(0x0100);
    address internal constant TOKOUT  = address(0x0200);
    address internal constant DAI     = address(0x0300);
    address internal constant OTHER   = address(0xBEEF);

    NoOracleMockKernel     internal kernel;
    SwapPermissionNoOracle internal swap;
    MockV2Pair             internal v2;
    MockV3Pool             internal v3;

    function setUp() public {
        kernel = new NoOracleMockKernel(address(this));
        swap   = new SwapPermissionNoOracle(address(kernel), AUTHOR);
        // Reference pools for the TOKIN->TOKOUT pair (token0 = TOKIN, token1 = TOKOUT).
        v2 = new MockV2Pair(TOKIN, TOKOUT);
        v3 = new MockV3Pool(TOKIN, TOKOUT);
    }

    // ── config helpers ──────────────────────────────────────────────────────────

    function _one(address a) internal pure returns (address[] memory arr) { arr = new address[](1); arr[0] = a; }

    function _ref(address tokenIn, address tokenOut, address pool, SwapPermissionNoOracle.PoolKind kind, uint256 tol)
        internal pure returns (SwapPermissionNoOracle.ReferencePool memory r)
    {
        r = SwapPermissionNoOracle.ReferencePool({
            tokenIn: tokenIn, tokenOut: tokenOut, pool: pool, kind: kind, toleranceBps: tol
        });
    }

    function _refs1(SwapPermissionNoOracle.ReferencePool memory a)
        internal pure returns (SwapPermissionNoOracle.ReferencePool[] memory arr)
    {
        arr = new SwapPermissionNoOracle.ReferencePool[](1);
        arr[0] = a;
    }

    function _configure(SwapPermissionNoOracle.ReferencePool[] memory refs) internal {
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _one(TOKIN), _one(TOKOUT), uint256(1000 ether), refs));
    }

    /// @dev Configure with a single V2 reference pool for TOKIN->TOKOUT at the given tolerance.
    function _configV2(uint256 tol) internal {
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(v2), SwapPermissionNoOracle.PoolKind.V2, tol)));
    }
    /// @dev Configure with a single V3 reference pool for TOKIN->TOKOUT at the given tolerance.
    function _configV3(uint256 tol) internal {
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(v3), SwapPermissionNoOracle.PoolKind.V3, tol)));
    }

    function _ctx(address target, bytes4 selector) internal view returns (Context memory c) {
        c = Context({
            account: ACCOUNT, manager: address(0), submitter: address(0),
            target: target, selector: selector, value: 0,
            blockTimestamp: block.timestamp, blockNumber: block.number,
            configEpoch: 0
        });
    }

    function _ctxVal(address target, bytes4 selector, uint256 value) internal view returns (Context memory c) {
        c = _ctx(target, selector);
        c.value = value;
    }

    function _v3cd(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V1, tokenIn, tokenOut, uint24(3000), recipient,
            uint256(block.timestamp + 1), amtIn, amtOutMin, uint160(0)
        );
    }
    function _v3_02cd(address tokenIn, address tokenOut, address recipient, uint256 amtIn, uint256 amtOutMin)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSelector(
            EXACT_INPUT_SINGLE_V2, tokenIn, tokenOut, uint24(3000), recipient, amtIn, amtOutMin, uint160(0)
        );
    }
    function _v2cd(address[] memory path, address to, uint256 amtIn, uint256 amtOutMin)
        internal view returns (bytes memory)
    {
        return abi.encodeWithSelector(SWAP_EXACT_TOKENS, amtIn, amtOutMin, path, to, block.timestamp + 1);
    }
    function _path(address a, address b) internal pure returns (address[] memory p) {
        p = new address[](2); p[0] = a; p[1] = b;
    }

    // ── introspection (ids unchanged — name kept) ────────────────────────────────

    function test_Introspection_Ids() public view {
        assertEq(swap.author(), AUTHOR);
        assertEq(swap.discriminator(), keccak256("SwapPermissionNoOracle"));
        assertEq(swap.permissionId(),  keccak256("sail.permission.SwapPermissionNoOracle.v1"));
        assertEq(swap.capabilityIds()[0], SailCapabilities.SWAP_NO_ORACLE);
    }

    // ── fair price within tolerance PASSES ───────────────────────────────────────

    function test_V2_FairWithinTolerance_Passes() public {
        v2.setReserves(1000 ether, 2000 ether); // price = 2 TOKOUT per TOKIN
        _configV2(200); // 2%
        // amountIn 1e18 → expectedOut 2e18 → floor 1.96e18. minOut 1.96e18 clears.
        assertTrue(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V3_FairWithinTolerance_Passes() public {
        v3.set(SQRT_P1, 1 ether); // price = 1
        _configV3(200);
        // amountIn 1e18 → expectedOut 1e18 → floor 0.98e18. minOut 0.98e18 clears.
        assertTrue(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.98 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V3_02_Path_FairWithinTolerance_Passes() public {
        v3.set(SQRT_P1, 1 ether);
        _configV3(200);
        assertTrue(swap.evaluate(_v3_02cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.98 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    // ── amountOutMin far below pool floor DENIES (the hallucination catch) ────────

    function test_V2_FarBelowFloor_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); // price 2 → floor 1.96e18 at 2%
        _configV2(200);
        // Agent willing to accept only 1e18 for a trade the pool prices at ~2e18 → caught.
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V3_FarBelowFloor_Denies() public {
        v3.set(SQRT_P1, 1 ether); // price 1 → floor 0.98e18
        _configV3(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.5 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── illiquid / unreadable DENY (fail-closed) ─────────────────────────────────

    function test_V2_ZeroReserves_Denies() public {
        v2.setReserves(0, 0);
        _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_GetReservesReverts_Denies() public {
        v2.setReserves(1000 ether, 2000 ether);
        _configV2(200);
        v2.setBroken(true);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V3_ZeroLiquidity_Denies() public {
        v3.set(SQRT_P1, 0); // zero liquidity
        _configV3(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.98 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V3_ZeroSqrtPrice_Denies() public {
        v3.set(0, 1 ether); // zero price
        _configV3(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V3_Slot0Reverts_Denies() public {
        v3.set(SQRT_P1, 1 ether);
        _configV3(200);
        v3.setBroken(true);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.98 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── truncation-to-zero DENY ──────────────────────────────────────────────────

    function test_V2_ExpectedOutTruncatesToZero_Denies() public {
        // reserveOut tiny vs reserveIn → expectedOut = mulDiv(1, 1, 2000e18) = 0 → deny.
        v2.setReserves(2000 ether, 1);
        _configV2(0);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    function test_V2_PoolFloorTruncatesToZero_Denies() public {
        // expectedOut = 1 (amountIn 1, price 1), tolerance 200 → floor = mulDiv(1, 9800, 10000) = 0 → deny.
        v2.setReserves(1000 ether, 1000 ether); // price 1
        _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1, 1), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── kept floor: amountOutMin == 0 denies ─────────────────────────────────────

    function test_AmountOutMinZero_Denies() public {
        v2.setReserves(1000 ether, 2000 ether);
        _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 0), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── structural bounds still enforced ─────────────────────────────────────────

    function test_DisallowedRouter_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(OTHER, SWAP_EXACT_TOKENS)));
    }
    function test_DisallowedTokenOut_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        // TOKIN->OTHER: OTHER not in tokensOut → denied before the pool check.
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, OTHER), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }
    function test_RecipientNotAccount_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), OTHER, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }
    function test_OverCap_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1001 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }
    function test_UnknownSelector_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, 0xdeadbeef)));
    }
    function test_ShortCalldata_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V1, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_NonzeroValue_Denies() public {
        // Identical to test_V1_FairWithinTolerance_Passes, but with ETH attached. The router is
        // payable; forwarding this value would let it be swept via refundETH. Must deny.
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        bytes memory data = _v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1.96 ether);
        assertFalse(swap.evaluate(data, _ctxVal(ROUTER, EXACT_INPUT_SINGLE_V1, 90 ether)));
        // The same swap with value == 0 still passes — the guard does not over-block.
        assertTrue(swap.evaluate(data, _ctxVal(ROUTER, EXACT_INPUT_SINGLE_V1, 0)));
    }

    // ── reverse orientation (tokenIn == pool.token1) ─────────────────────────────

    function test_V2_ReverseOrientation_Passes() public {
        // Pool oriented token0 = TOKOUT, token1 = TOKIN; swap still TOKIN->TOKOUT.
        MockV2Pair rev = new MockV2Pair(TOKOUT, TOKIN);
        rev.setReserves(2000 ether, 1000 ether); // token0=TOKOUT reserve 2000, token1=TOKIN reserve 1000 → 1 TOKIN = 2 TOKOUT
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(rev), SwapPermissionNoOracle.PoolKind.V2, 200)));
        assertTrue(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── MANIPULATION BOUNDARY (documented, in-scope-OUT) ─────────────────────────

    /// @notice A swap that should be caught (minOut far below the true ~2e18 quote) PASSES once the
    ///         reference pool is moved to a low price. This is the explicit limitation: a single
    ///         pool's live price is atomically manipulable in-transaction, so this band provides NO
    ///         protection against a manipulator. It guards honest mistakes only. Asserting it passes
    ///         documents the boundary — it is not a defect.
    function test_ManipulatedPool_AllowsBadSwap_DocumentsBoundary() public {
        v2.setReserves(1000 ether, 2000 ether); // fair price 2 → a 0.1e18 minOut would normally be caught
        _configV2(200);
        // Same swap with a tiny minOut is caught at the fair price:
        assertFalse(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 0.1 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
        // Now an attacker moves the reference pool to price ~0.1 (as a flash-loan sandwich would):
        v2.setReserves(10_000 ether, 1000 ether); // 1 TOKIN = 0.1 TOKOUT → expectedOut 0.1e18, floor 0.098e18
        // The same bad-looking swap now PASSES — the manipulated reference let it through.
        assertTrue(swap.evaluate(_v2cd(_path(TOKIN, TOKOUT), ACCOUNT, 1 ether, 0.1 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── configure() validation ───────────────────────────────────────────────────

    function test_Configure_ToleranceTooLarge_Reverts() public {
        vm.expectRevert(abi.encodeWithSelector(SwapPermissionNoOracle.ToleranceTooLarge.selector, uint256(5001)));
        _configV2(5001);
    }
    function test_Configure_ZeroPool_Reverts() public {
        vm.expectRevert(SwapPermissionNoOracle.ZeroPool.selector);
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(0), SwapPermissionNoOracle.PoolKind.V2, 200)));
    }
    function test_Configure_PairOutsideAllowlist_Reverts() public {
        // ref tokenIn = OTHER, not in tokensIn=[TOKIN]
        vm.expectRevert(abi.encodeWithSelector(SwapPermissionNoOracle.PairNotAllowlisted.selector, OTHER, TOKOUT));
        _configure(_refs1(_ref(OTHER, TOKOUT, address(v2), SwapPermissionNoOracle.PoolKind.V2, 200)));
    }
    function test_Configure_PoolTokenMismatch_Reverts() public {
        MockV2Pair bad = new MockV2Pair(OTHER, TOKOUT); // pool tokens != {TOKIN, TOKOUT}
        vm.expectRevert(abi.encodeWithSelector(SwapPermissionNoOracle.PoolTokenMismatch.selector, address(bad)));
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(bad), SwapPermissionNoOracle.PoolKind.V2, 200)));
    }
    function test_Configure_MissingReferencePool_Reverts() public {
        // tokensOut = [TOKOUT, DAI] but only (TOKIN,TOKOUT) has a ref → (TOKIN,DAI) uncovered.
        SwapPermissionNoOracle.ReferencePool[] memory refs = _refs1(_ref(TOKIN, TOKOUT, address(v2), SwapPermissionNoOracle.PoolKind.V2, 200));
        address[] memory outs = new address[](2); outs[0] = TOKOUT; outs[1] = DAI;
        vm.expectRevert(abi.encodeWithSelector(SwapPermissionNoOracle.MissingReferencePool.selector, TOKIN, DAI));
        swap.configureDirect(ACCOUNT, abi.encode(_one(ROUTER), _one(TOKIN), outs, uint256(1000 ether), refs));
    }
    function test_Configure_Valid_StoresPoolRef() public {
        v2.setReserves(1000 ether, 2000 ether);
        _configV2(200);
        SwapPermissionNoOracle.PoolRef memory rp = swap.referencePoolFor(ACCOUNT, TOKIN, TOKOUT);
        assertEq(rp.pool, address(v2));
        assertEq(uint8(rp.kind), uint8(SwapPermissionNoOracle.PoolKind.V2));
        assertEq(rp.toleranceBps, 200);
        assertTrue(rp.tokenInIsToken0);
    }

    // ── reconfigure clears prior pool refs ───────────────────────────────────────

    function test_Reconfigure_ClearsOldPoolRef() public {
        _configV2(200);
        // Reconfigure with the V3 pool instead; the (TOKIN,TOKOUT) ref must now point at v3.
        _configV3(300);
        SwapPermissionNoOracle.PoolRef memory rp = swap.referencePoolFor(ACCOUNT, TOKIN, TOKOUT);
        assertEq(rp.pool, address(v3));
        assertEq(rp.toleranceBps, 300);
    }

    // ── per-path structural denials: V3 SwapRouter (V1) ──────────────────────────

    function test_V1_DisallowedTokenIn_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3cd(OTHER, TOKOUT, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
    function test_V1_DisallowedTokenOut_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, OTHER, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
    function test_V1_RecipientNotAccount_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, OTHER, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
    function test_V1_OverCap_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1001 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
    function test_V1_FairWithinTolerance_Passes() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200); // price 2 via V2 pool
        assertTrue(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    // ── per-path structural denials: SwapRouter02 (V3_02) ────────────────────────

    function test_V3_02_DisallowedTokenIn_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3_02cd(OTHER, TOKOUT, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }
    function test_V3_02_DisallowedTokenOut_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3_02cd(TOKIN, OTHER, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }
    function test_V3_02_RecipientNotAccount_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3_02cd(TOKIN, TOKOUT, OTHER, 1 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }
    function test_V3_02_OverCap_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v3_02cd(TOKIN, TOKOUT, ACCOUNT, 1001 ether, 1.96 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }
    function test_V3_02_ShortCalldata_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        bytes memory short = abi.encodeWithSelector(EXACT_INPUT_SINGLE_V2, TOKIN);
        assertFalse(swap.evaluate(short, _ctx(ROUTER, EXACT_INPUT_SINGLE_V2)));
    }

    // ── V2 path extra denials ────────────────────────────────────────────────────

    function test_V2_DisallowedTokenIn_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        assertFalse(swap.evaluate(_v2cd(_path(OTHER, TOKOUT), ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }
    function test_V2_ShortPath_Denies() public {
        v2.setReserves(1000 ether, 2000 ether); _configV2(200);
        address[] memory p = new address[](1); p[0] = TOKIN;
        assertFalse(swap.evaluate(_v2cd(p, ACCOUNT, 1 ether, 1.96 ether), _ctx(ROUTER, SWAP_EXACT_TOKENS)));
    }

    // ── V3 reverse orientation + V3 truncation (exercise the V3 math both ways) ───

    function test_V3_ReverseOrientation_Passes() public {
        // Pool token0 = TOKOUT, token1 = TOKIN; sqrtPrice 1 → 1 TOKIN = 1 TOKOUT. swap TOKIN->TOKOUT.
        MockV3Pool rev = new MockV3Pool(TOKOUT, TOKIN);
        rev.set(SQRT_P1, 1 ether);
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(rev), SwapPermissionNoOracle.PoolKind.V3, 200)));
        assertTrue(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.98 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V3_ReverseOrientation_FarBelow_Denies() public {
        MockV3Pool rev = new MockV3Pool(TOKOUT, TOKIN);
        rev.set(SQRT_P1, 1 ether);
        _configure(_refs1(_ref(TOKIN, TOKOUT, address(rev), SwapPermissionNoOracle.PoolKind.V3, 200)));
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1 ether, 0.5 ether), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }

    function test_V3_PoolFloorTruncatesToZero_Denies() public {
        v3.set(SQRT_P1, 1 ether); // price 1
        _configV3(200);
        // amountIn 1 → expectedOut 1 → floor mulDiv(1, 9800, 10000) = 0 → deny.
        assertFalse(swap.evaluate(_v3cd(TOKIN, TOKOUT, ACCOUNT, 1, 1), _ctx(ROUTER, EXACT_INPUT_SINGLE_V1)));
    }
}
