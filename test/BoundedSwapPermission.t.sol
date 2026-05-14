// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {BoundedSwapPermission} from "../contracts/templates/BoundedSwapPermission.sol";
import {IOracle} from "../contracts/interfaces/IOracle.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Mock oracle
// ─────────────────────────────────────────────────────────────────────────────

contract MockOracle is IOracle {
    struct PriceData { uint256 price; uint8 decimals; }
    mapping(address => mapping(address => PriceData)) private _prices;

    function setPrice(address base, address quote, uint256 price, uint8 decimals) external {
        _prices[base][quote] = PriceData(price, decimals);
    }

    function getPrice(address base, address quote)
        external view returns (uint256 price, uint8 decimals)
    {
        PriceData memory pd = _prices[base][quote];
        return (pd.price, pd.decimals);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract BoundedSwapPermissionTest is Test {
    BoundedSwapPermission perm;
    MockOracle            oracle;

    address constant SAFE      = address(0x5AFE);
    address constant ROUTER    = address(0xD111); // e.g., Uniswap router
    address constant ROUTER2   = address(0xD222);
    address constant TOKEN_IN  = address(0xAAAA); // allowedTokenIn
    address constant TOKEN_OUT = address(0xBBBB); // allowedTokenOut
    address constant TOKEN_MID = address(0xCCCC); // intermediate (not in either allowlist)
    address constant SIGNER    = address(0x5161);
    address constant STRANGER  = address(0x9999);

    uint256 constant MAX_AMOUNT    = 1_000e18;
    uint256 constant SLIPPAGE_BPS  = 200; // 2%

    // Oracle math constants (price = 2e18 at 18 decimals → 2 tokenOut per tokenIn)
    uint256 constant ORACLE_PRICE     = 2e18;
    uint8   constant ORACLE_DECIMALS  = 18;
    // For amountIn = 100e18: expectedOut = 200e18, oracleMinOut = 196e18
    uint256 constant AMOUNT_IN        = 100e18;
    uint256 constant EXPECTED_OUT     = 200e18;
    uint256 constant ORACLE_MIN_OUT   = 196e18; // 200e18 * 9800 / 10000

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        oracle = new MockOracle();
        oracle.setPrice(TOKEN_IN, TOKEN_OUT, ORACLE_PRICE, ORACLE_DECIMALS);

        address[] memory routers   = _arr1(ROUTER);
        address[] memory tokensIn  = _arr1(TOKEN_IN);
        address[] memory tokensOut = _arr1(TOKEN_OUT);

        perm = new BoundedSwapPermission(
            routers, tokensIn, tokensOut,
            MAX_AMOUNT, SLIPPAGE_BPS, address(oracle), SIGNER
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _arr1(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1); arr[0] = a;
    }

    function _path2(address a, address b) internal pure returns (address[] memory p) {
        p = new address[](2); p[0] = a; p[1] = b;
    }

    function _path3(address a, address b, address c) internal pure returns (address[] memory p) {
        p = new address[](3); p[0] = a; p[1] = b; p[2] = c;
    }

    /// Build V3 exactInputSingle calldata.
    function _v3(
        address tokenIn,
        address tokenOut,
        address recipient,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(0x414bf389),
            tokenIn, tokenOut, uint24(3000), recipient,
            type(uint256).max,   // deadline
            amountIn, amountOutMin,
            uint160(0)           // sqrtPriceLimitX96
        );
    }

    /// Build V2 swapExactTokensForTokens calldata.
    function _v2(
        uint256 amountIn,
        uint256 amountOutMin,
        address[] memory path,
        address to
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(0x38ed1739),
            amountIn, amountOutMin, path, to, type(uint256).max
        );
    }

    function _ctx(address router, bytes memory data) internal pure returns (Context memory) {
        bytes4 sel;
        if (data.length >= 4) assembly { sel := mload(add(data, 32)) }
        return Context({account: SAFE, manager: address(0), target: router, selector: sel, value: 0});
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsValues() public view {
        assertEq(perm.permissionSigner(), SIGNER);
        assertEq(perm.maxAmountPerTx(),   MAX_AMOUNT);
        assertEq(perm.maxSlippageBps(),   SLIPPAGE_BPS);
        assertEq(perm.priceOracle(),      address(oracle));
        assertTrue(perm.isAllowedRouter(ROUTER));
        assertTrue(perm.isAllowedTokenIn(TOKEN_IN));
        assertTrue(perm.isAllowedTokenOut(TOKEN_OUT));
        assertFalse(perm.isAllowedRouter(STRANGER));
        assertFalse(perm.isAllowedTokenIn(TOKEN_OUT));
        assertFalse(perm.isAllowedTokenOut(TOKEN_IN));
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory e = new address[](0);
        vm.expectRevert(BoundedSwapPermission.ZeroAddress.selector);
        new BoundedSwapPermission(e, e, e, 0, 0, address(0), address(0));
    }

    function test_Constructor_RevertsOnExcessiveSlippage() public {
        address[] memory e = new address[](0);
        vm.expectRevert(abi.encodeWithSelector(BoundedSwapPermission.SlippageBpsTooLarge.selector, 10_001));
        new BoundedSwapPermission(e, e, e, 0, 10_001, address(0), SIGNER);
    }

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedSwapPermission"));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V3 exactInputSingle — golden paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_V3_GoldenPath_NoOracle() public {
        // Deploy a fresh instance without oracle
        address[] memory r = _arr1(ROUTER);
        address[] memory ti = _arr1(TOKEN_IN);
        address[] memory to_ = _arr1(TOKEN_OUT);
        BoundedSwapPermission p = new BoundedSwapPermission(r, ti, to_, MAX_AMOUNT, 0, address(0), SIGNER);

        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, 1);
        assertTrue(p.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_GoldenPath_WithOracle() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_AmountOutMinAboveExpected() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, EXPECTED_OUT + 1e18);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_ExactlyAtAmountCap() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, MAX_AMOUNT, ORACLE_MIN_OUT * MAX_AMOUNT / AMOUNT_IN);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_ExactlyAtSlippageLimit() public view {
        // ORACLE_MIN_OUT is the floor — exactly at limit passes
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V3 — blocked cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_V3_WrongRouter() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_V3_WrongTokenIn() public view {
        bytes memory data = _v3(TOKEN_OUT, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_WrongTokenOut() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_IN, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_WrongRecipient() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, STRANGER, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_RecipientIsZeroAddress() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, address(0), AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_AmountOverCap() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, MAX_AMOUNT + 1, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_SlippageViolation() public view {
        // One below the oracle minimum
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT - 1);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_OracleZeroPrice_Blocked() public {
        // Oracle returns price=0 → blocked
        oracle.setPrice(TOKEN_IN, TOKEN_OUT, 0, 18);
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, 0);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V3 — oracle-disabled paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_V3_OracleDisabled_NoAddress() public {
        address[] memory r = _arr1(ROUTER);
        address[] memory ti = _arr1(TOKEN_IN);
        address[] memory to_ = _arr1(TOKEN_OUT);
        BoundedSwapPermission p = new BoundedSwapPermission(
            r, ti, to_, MAX_AMOUNT, SLIPPAGE_BPS, address(0), SIGNER
        );
        // amountOutMin=1 would fail the oracle check if it were active
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, 1);
        assertTrue(p.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_OracleDisabled_ZeroSlippageBps() public {
        address[] memory r = _arr1(ROUTER);
        address[] memory ti = _arr1(TOKEN_IN);
        address[] memory to_ = _arr1(TOKEN_OUT);
        BoundedSwapPermission p = new BoundedSwapPermission(
            r, ti, to_, MAX_AMOUNT, 0, address(oracle), SIGNER
        );
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, 1);
        assertTrue(p.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V3_SetSlippageToZero_DisablesOracleCheck() public {
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(0);
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, 1);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V3 — calldata edge cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_V3_TooShort_259Bytes() public view {
        bytes memory full  = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertEq(full.length, 260);
        bytes memory short_ = new bytes(259);
        for (uint256 i; i < 259; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(ROUTER, full)));
    }

    function test_V3_ExactlyMinLength_260Bytes() public view {
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertEq(data.length, 260);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V2 swapExactTokensForTokens — golden paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_V2_GoldenPath_NoOracle() public {
        address[] memory r = _arr1(ROUTER);
        address[] memory ti = _arr1(TOKEN_IN);
        address[] memory to_ = _arr1(TOKEN_OUT);
        BoundedSwapPermission p = new BoundedSwapPermission(
            r, ti, to_, MAX_AMOUNT, 0, address(0), SIGNER
        );
        bytes memory data = _v2(AMOUNT_IN, 1, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertTrue(p.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_GoldenPath_WithOracle() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_ExactlyAtAmountCap() public view {
        uint256 minOut = Math.mulDiv(
            Math.mulDiv(MAX_AMOUNT, ORACLE_PRICE, 10 ** uint256(ORACLE_DECIMALS)),
            10_000 - SLIPPAGE_BPS, 10_000
        );
        bytes memory data = _v2(MAX_AMOUNT, minOut, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_ExactlyAtSlippageLimit() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ── multi-hop ─────────────────────────────────────────────────────────────

    function test_V2_MultiHop_3Tokens() public view {
        // TOKEN_MID is intermediate — not in either allowlist, but that's OK
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path3(TOKEN_IN, TOKEN_MID, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_IntermediateTokenNotCheckedAgainstAllowlists() public view {
        // Intermediate token (TOKEN_MID) is neither allowedTokenIn nor allowedTokenOut — still passes
        assertFalse(perm.isAllowedTokenIn(TOKEN_MID));
        assertFalse(perm.isAllowedTokenOut(TOKEN_MID));
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path3(TOKEN_IN, TOKEN_MID, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_MultiHop_OracleUsesFirstAndLastToken() public {
        // Oracle must be set for (path[0], path[last]) — not for intermediates
        oracle.setPrice(TOKEN_IN, TOKEN_OUT, ORACLE_PRICE, ORACLE_DECIMALS);
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path3(TOKEN_IN, TOKEN_MID, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V2 — blocked cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_V2_WrongRouter() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_V2_WrongTokenIn() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_OUT, TOKEN_OUT), SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_WrongTokenOut() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_IN), SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_WrongRecipient() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), STRANGER);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_RecipientIsZeroAddress() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), address(0));
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_AmountOverCap() public view {
        bytes memory data = _v2(MAX_AMOUNT + 1, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_SlippageViolation() public view {
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT - 1, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_PathLengthOne() public view {
        address[] memory path = new address[](1);
        path[0] = TOKEN_IN;
        bytes memory data = _v2(AMOUNT_IN, 0, path, SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_V2_PathLengthZero() public view {
        address[] memory path = new address[](0);
        bytes memory data = _v2(AMOUNT_IN, 0, path, SAFE);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // V2 — calldata edge cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_V2_TooShort_195Bytes() public view {
        // Build valid calldata then truncate to just below LEN_V2_MIN
        bytes memory full  = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        bytes memory short_ = new bytes(195);
        for (uint256 i; i < 195; i++) short_[i] = full[i];
        // Truncated data gets context selector from the first 4 bytes of full
        Context memory ctx = _ctx(ROUTER, full);
        assertFalse(perm.evaluate(short_, ctx));
    }

    function test_V2_ExactlyMinLength_Valid() public view {
        // A path-of-2 swap produces exactly 260 bytes
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertGe(data.length, 260);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Unknown / unsupported calldata
    // ═════════════════════════════════════════════════════════════════════════

    function test_EmptyCalldata() public view {
        Context memory ctx = Context({
            account: SAFE, manager: address(0),
            target: ROUTER, selector: bytes4(0), value: 0
        });
        assertFalse(perm.evaluate("", ctx));
    }

    function test_UnknownSelector_Approve() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", ROUTER, MAX_AMOUNT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function test_UnknownSelector_ExactOutput() public view {
        // exactOutputSingle — different selector
        bytes memory data = abi.encodeWithSignature("exactOutputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
            TOKEN_IN, TOKEN_OUT, uint24(3000), SAFE, type(uint256).max, AMOUNT_IN, MAX_AMOUNT, uint160(0));
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != bytes4(0x414bf389) && sel != bytes4(0x38ed1739));
        // Build 260-byte payload to pass length checks
        bytes memory data = abi.encodePacked(
            sel,
            abi.encode(TOKEN_IN, TOKEN_OUT, uint24(3000), SAFE, type(uint256).max, AMOUNT_IN, ORACLE_MIN_OUT, uint160(0))
        );
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Fuzz: access control
    // ═════════════════════════════════════════════════════════════════════════

    function testFuzz_V3_WrongRouter(address router) public view {
        vm.assume(router != ROUTER);
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(router, data)));
    }

    function testFuzz_V3_WrongRecipient(address recipient) public view {
        vm.assume(recipient != SAFE);
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, recipient, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function testFuzz_V2_WrongRecipient(address to) public view {
        vm.assume(to != SAFE);
        bytes memory data = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), to);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function testFuzz_V3_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, MAX_AMOUNT);
        // Compute oracle-derived minimum for this amount
        uint256 minOut = Math.mulDiv(
            Math.mulDiv(amount, ORACLE_PRICE, 10 ** uint256(ORACLE_DECIMALS)),
            10_000 - SLIPPAGE_BPS, 10_000
        );
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, amount, minOut);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function testFuzz_V3_AmountOverCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, MAX_AMOUNT + excess, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    function testFuzz_SetMaxAmountPerTx_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedSwapPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    function testFuzz_SetMaxSlippageBps_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedSwapPermission.NotPermissionSigner.selector);
        perm.setMaxSlippageBps(100);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // setMaxAmountPerTx
    // ═════════════════════════════════════════════════════════════════════════

    function test_SetMaxAmountPerTx_Succeeds() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(500e18);
        assertEq(perm.maxAmountPerTx(), 500e18);
    }

    function test_SetMaxAmountPerTx_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BoundedSwapPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedSwapPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function test_SetMaxAmountPerTx_TakesEffect() public {
        // Currently AMOUNT_IN (100e18) <= MAX_AMOUNT (1000e18) → passes
        bytes memory data = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertTrue(perm.evaluate(data, _ctx(ROUTER, data)));

        // Lower cap below AMOUNT_IN
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(AMOUNT_IN - 1);

        assertFalse(perm.evaluate(data, _ctx(ROUTER, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // setMaxSlippageBps
    // ═════════════════════════════════════════════════════════════════════════

    function test_SetMaxSlippageBps_Succeeds() public {
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(500);
        assertEq(perm.maxSlippageBps(), 500);
    }

    function test_SetMaxSlippageBps_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BoundedSwapPermission.MaxSlippageUpdated(SLIPPAGE_BPS, 100);
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(100);
    }

    function test_SetMaxSlippageBps_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedSwapPermission.NotPermissionSigner.selector);
        perm.setMaxSlippageBps(100);
    }

    function test_SetMaxSlippageBps_RevertsAbove10000() public {
        vm.prank(SIGNER);
        vm.expectRevert(abi.encodeWithSelector(BoundedSwapPermission.SlippageBpsTooLarge.selector, 10_001));
        perm.setMaxSlippageBps(10_001);
    }

    function test_SetMaxSlippageBps_AtExactly10000_Passes() public {
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(10_000); // 100% slippage = any amount passes oracle check
        assertEq(perm.maxSlippageBps(), 10_000);
    }

    function test_SetMaxSlippageBps_TakesEffect_Tighter() public {
        // Tighten slippage from 2% to 0.5% (50 bps)
        // ORACLE_MIN_OUT (196e18) was valid at 2%; now minimum becomes 199e18
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(50); // 0.5%
        // newMinOut = 200e18 * 9950 / 10000 = 199e18
        uint256 newMinOut = Math.mulDiv(EXPECTED_OUT, 9_950, 10_000);

        // Old minimum 196e18 now fails
        bytes memory dataBad = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, ORACLE_MIN_OUT);
        assertFalse(perm.evaluate(dataBad, _ctx(ROUTER, dataBad)));

        // New minimum passes
        bytes memory dataGood = _v3(TOKEN_IN, TOKEN_OUT, SAFE, AMOUNT_IN, newMinOut);
        assertTrue(perm.evaluate(dataGood, _ctx(ROUTER, dataGood)));
    }

    function test_SetMaxSlippageBps_TakesEffect_V2() public {
        vm.prank(SIGNER);
        perm.setMaxSlippageBps(50);
        uint256 newMinOut = Math.mulDiv(EXPECTED_OUT, 9_950, 10_000);

        bytes memory dataBad = _v2(AMOUNT_IN, ORACLE_MIN_OUT, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertFalse(perm.evaluate(dataBad, _ctx(ROUTER, dataBad)));

        bytes memory dataGood = _v2(AMOUNT_IN, newMinOut, _path2(TOKEN_IN, TOKEN_OUT), SAFE);
        assertTrue(perm.evaluate(dataGood, _ctx(ROUTER, dataGood)));
    }
}
