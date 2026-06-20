// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../support/FactoryTestBase.sol";
import "../../contracts/experimental/SharedPendlePermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Mock Pendle Router — stubs with correct signatures (no real logic needed)
// ─────────────────────────────────────────────────────────────────────────────

struct ApproxParams {
    uint256 guessMin;
    uint256 guessMax;
    uint256 guessOffchain;
    uint256 maxIteration;
    uint256 eps;
}

struct SwapData {
    uint8   swapType;
    address extRouter;
    bytes   extCalldata;
    bool    needScale;
}

struct TokenInput {
    address  tokenIn;
    uint256  netTokenIn;
    address  tokenMintSy;
    address  pendleSwap;
    SwapData swapData;
}

struct TokenOutput {
    address  tokenOut;
    uint256  minTokenOut;
    address  tokenRedeemSy;
    address  pendleSwap;
    SwapData swapData;
}

struct Order {
    uint256 salt;
    uint256 expiry;
    uint256 nonce;
    uint8   orderType;
    address token;
    address YT;
    address maker;
    address receiver;
    uint256 makingAmount;
    uint256 lnImpliedRate;
    uint256 failSafeRate;
    bytes   permit;
}

struct FillOrderParams {
    Order   order;
    bytes   signature;
    uint256 makingAmount;
}

struct LimitOrderData {
    address           limitRouter;
    uint256           epsSkipMarket;
    FillOrderParams[] normalFills;
    FillOrderParams[] flashFills;
    bytes             optData;
}

contract MockPendleRouter {
    // Liquidity
    function addLiquidityDualSyAndPt(address, address, uint256, uint256, uint256)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function addLiquidityDualTokenAndPt(address, address, TokenInput calldata, uint256, uint256)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function addLiquiditySingleSy(address, address, uint256, uint256, ApproxParams calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function addLiquiditySingleToken(address, address, uint256, ApproxParams calldata, TokenInput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function addLiquiditySinglePt(address, address, uint256, uint256, ApproxParams calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function removeLiquidityDualSyAndPt(address, address, uint256, uint256, uint256)
        external pure returns (uint256, uint256) { return (0, 0); }

    function removeLiquidityDualTokenAndPt(address, address, uint256, TokenOutput calldata, uint256)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function removeLiquiditySingleSy(address, address, uint256, uint256, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function removeLiquiditySingleToken(address, address, uint256, TokenOutput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function removeLiquiditySinglePt(address, address, uint256, uint256, ApproxParams calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    // PT swaps
    function swapExactSyForPt(address, address, uint256, uint256, ApproxParams calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function swapExactPtForSy(address, address, uint256, uint256, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function swapExactTokenForPt(address, address, uint256, ApproxParams calldata, TokenInput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function swapExactPtForToken(address, address, uint256, TokenOutput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    // YT swaps
    function swapExactSyForYt(address, address, uint256, uint256, ApproxParams calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function swapExactYtForSy(address, address, uint256, uint256, LimitOrderData calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function swapExactTokenForYt(address, address, uint256, ApproxParams calldata, TokenInput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function swapExactYtForToken(address, address, uint256, TokenOutput calldata, LimitOrderData calldata)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    // Mint / Redeem
    function mintPyFromToken(address, address, uint256, TokenInput calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function mintPyFromSy(address, address, uint256, uint256)
        external pure returns (uint256) { return 0; }

    function redeemPyToToken(address, address, uint256, TokenOutput calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function redeemPyToSy(address, address, uint256, uint256)
        external pure returns (uint256) { return 0; }

    function redeemDueInterestAndRewards(address, address[] calldata, address[] calldata, address[] calldata)
        external pure {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────

contract SharedPendlePermissionTest is FactoryTestBase {
    SharedPendlePermission internal perm;
    MockPendleRouter        internal router;

    // A second Safe for isolation tests
    MockSafe   internal safe2;

    address constant MARKET    = address(0xAA01);
    address constant MARKET2   = address(0xAA02);
    address constant YT        = address(0xBB01);
    address constant STRANGER  = address(0x9999);

    uint128 constant MAX_AMOUNT = 100 ether;

    // ── selectors (must match contract constants) ─────────────────────────────
    bytes4 constant SEL_ADD_DUAL_SY_PT     = bytes4(keccak256("addLiquidityDualSyAndPt(address,address,uint256,uint256,uint256)"));
    bytes4 constant SEL_REMOVE_SINGLE_PT   = 0x6b77ac9e;
    bytes4 constant SEL_SWAP_TOK_FOR_PT    = 0xc81f847a;
    bytes4 constant SEL_SWAP_PT_FOR_TOK    = 0x594a88cc;
    bytes4 constant SEL_SWAP_TOK_FOR_YT    = 0xed48907e;
    bytes4 constant SEL_MINT_PY_FROM_TOK   = 0xd0f42385;
    bytes4 constant SEL_REDEEM_PY_TO_TOK   = 0x47f1de22;
    bytes4 constant SEL_MINT_PY_FROM_SY    = bytes4(keccak256("mintPyFromSy(address,address,uint256,uint256)"));
    bytes4 constant SEL_REDEEM_PY_TO_SY    = bytes4(keccak256("redeemPyToSy(address,address,uint256,uint256)"));
    bytes4 constant SEL_CLAIM_YIELD        = bytes4(keccak256("redeemDueInterestAndRewards(address,address[],address[],address[])"));
    bytes4 constant SEL_SWAP_SY_FOR_PT     = 0x2a50917c;
    bytes4 constant SEL_SWAP_YT_FOR_TOK    = 0x05eb5327;
    bytes4 constant SEL_ADD_DUAL_TOK_PT    = 0x2756ce06;

    function setUp() public override {
        super.setUp();
        perm   = new SharedPendlePermission(address(kernel));
        router = new MockPendleRouter();

        // Register a second safe
        safe2 = new MockSafe();
        vm.prank(address(safe2));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _arr1(address a) internal pure returns (address[] memory r) {
        r = new address[](1); r[0] = a;
    }

    function _empty() internal pure returns (address[] memory) {
        return new address[](0);
    }

    function _ctx(address account, address target, bytes4 sel) internal view returns (Context memory) {
        return Context({
            account:        account,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       sel,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    /// @dev Signs and calls perm.configure() for an account.
    function _configure(
        address account,
        address pendleRouter,
        address[] memory markets,
        uint128 maxAmt,
        bool liq,
        bool pt,
        bool yt,
        bool mintRedeem,
        bool claim
    ) internal {
        bytes memory params = abi.encode(pendleRouter, markets, maxAmt, liq, pt, yt, mintRedeem, claim);
        uint256 deadline    = block.timestamp + 1 hours;
        bytes memory sig    = _signConfigure(perm, account, params, deadline, PERM_SIGNER_KEY);
        perm.configure(account, params, deadline, sig);
    }

    function _configureDefault(address account) internal {
        _configure(account, address(router), _arr1(MARKET), MAX_AMOUNT, true, true, true, true, true);
    }

    // ── calldata encoders ─────────────────────────────────────────────────────

    function _emptyApprox() internal pure returns (ApproxParams memory) {
        return ApproxParams(0, type(uint256).max, 0, 256, 1e15);
    }

    function _emptySwapData() internal pure returns (SwapData memory) {
        return SwapData(0, address(0), "", false);
    }

    function _emptyLimit() internal pure returns (LimitOrderData memory) {
        return LimitOrderData(address(0), 0, new FillOrderParams[](0), new FillOrderParams[](0), "");
    }

    function _emptyTokenInput(uint256 amount) internal pure returns (TokenInput memory) {
        return TokenInput(address(0), amount, address(0), address(0), _emptySwapData());
    }

    function _emptyTokenOutput() internal pure returns (TokenOutput memory) {
        return TokenOutput(address(0), 0, address(0), address(0), _emptySwapData());
    }

    // --- liquidity ---

    function _encodeAddLiquidityDualSyAndPt(
        address receiver, address market, uint256 amount
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_ADD_DUAL_SY_PT, receiver, market, amount, uint256(0), uint256(0)
        );
    }

    function _encodeAddLiquidityDualTokenAndPt(
        address receiver, address market, uint256 netTokenIn
    ) internal pure returns (bytes memory) {
        TokenInput memory input = _emptyTokenInput(netTokenIn);
        return abi.encodeWithSelector(
            SEL_ADD_DUAL_TOK_PT, receiver, market, input, uint256(0), uint256(0)
        );
    }

    function _encodeRemoveLiquiditySinglePt(
        address receiver, address market, uint256 netLpToRemove
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_REMOVE_SINGLE_PT,
            receiver, market, netLpToRemove, uint256(0), _emptyApprox(), _emptyLimit()
        );
    }

    // --- PT swaps ---

    function _encodeSwapExactTokenForPt(
        address receiver, address market, uint256 netTokenIn
    ) internal pure returns (bytes memory) {
        TokenInput memory input = _emptyTokenInput(netTokenIn);
        return abi.encodeWithSelector(
            SEL_SWAP_TOK_FOR_PT,
            receiver, market, uint256(0), _emptyApprox(), input, _emptyLimit()
        );
    }

    function _encodeSwapExactPtForToken(
        address receiver, address market, uint256 exactPtIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_SWAP_PT_FOR_TOK,
            receiver, market, exactPtIn, _emptyTokenOutput(), _emptyLimit()
        );
    }

    function _encodeSwapExactSyForPt(
        address receiver, address market, uint256 exactSyIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_SWAP_SY_FOR_PT,
            receiver, market, exactSyIn, uint256(0), _emptyApprox(), _emptyLimit()
        );
    }

    // --- YT swaps ---

    function _encodeSwapExactTokenForYt(
        address receiver, address market, uint256 netTokenIn
    ) internal pure returns (bytes memory) {
        TokenInput memory input = _emptyTokenInput(netTokenIn);
        return abi.encodeWithSelector(
            SEL_SWAP_TOK_FOR_YT,
            receiver, market, uint256(0), _emptyApprox(), input, _emptyLimit()
        );
    }

    function _encodeSwapExactYtForToken(
        address receiver, address market, uint256 exactYtIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_SWAP_YT_FOR_TOK,
            receiver, market, exactYtIn, _emptyTokenOutput(), _emptyLimit()
        );
    }

    // --- mint/redeem ---

    function _encodeMintPyFromToken(
        address receiver, address yt_, uint256 netTokenIn
    ) internal pure returns (bytes memory) {
        TokenInput memory input = _emptyTokenInput(netTokenIn);
        return abi.encodeWithSelector(SEL_MINT_PY_FROM_TOK, receiver, yt_, uint256(0), input);
    }

    function _encodeMintPyFromSy(
        address receiver, address yt_, uint256 netSyIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_MINT_PY_FROM_SY, receiver, yt_, netSyIn, uint256(0));
    }

    function _encodeRedeemPyToToken(
        address receiver, address yt_, uint256 netPyIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_REDEEM_PY_TO_TOK, receiver, yt_, netPyIn, _emptyTokenOutput()
        );
    }

    function _encodeRedeemPyToSy(
        address receiver, address yt_, uint256 netPyIn
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_REDEEM_PY_TO_SY, receiver, yt_, netPyIn, uint256(0));
    }

    // --- claim ---

    function _encodeClaimYield(address user) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_CLAIM_YIELD,
            user,
            new address[](0),
            new address[](0),
            new address[](0)
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // GOLDEN PATHS
    // ─────────────────────────────────────────────────────────────────────────

    /// 1. addLiquidityDualSyAndPt to allowed market
    function test_AddLiquidityDual_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 2. removeLiquiditySinglePt
    function test_RemoveLiquiditySinglePt_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeRemoveLiquiditySinglePt(address(safe), MARKET, 5 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_REMOVE_SINGLE_PT)));
    }

    /// 3. swapExactTokenForPt
    function test_SwapExactTokenForPt_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactTokenForPt(address(safe), MARKET, 10 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_PT)));
    }

    /// 4. swapExactPtForToken
    function test_SwapExactPtForToken_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactPtForToken(address(safe), MARKET, 50 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_PT_FOR_TOK)));
    }

    /// 5. swapExactTokenForYt — when allowYtSwaps=true
    function test_SwapExactTokenForYt_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactTokenForYt(address(safe), MARKET, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_YT)));
    }

    /// 6. mintPyFromToken — when allowMintRedeem=true
    function test_MintPyFromToken_Permitted() public {
        // YT must be in the market allowlist
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeMintPyFromToken(address(safe), YT, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_MINT_PY_FROM_TOK)));
    }

    /// 7. redeemPyToToken
    function test_RedeemPyToToken_Permitted() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeRedeemPyToToken(address(safe), YT, 5 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_REDEEM_PY_TO_TOK)));
    }

    /// 8. redeemDueInterestAndRewards (claim yield)
    function test_ClaimYield_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeClaimYield(address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_CLAIM_YIELD)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE PATHS
    // ─────────────────────────────────────────────────────────────────────────

    /// 9. target != pendleRouter → denied
    function test_WrongTarget_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), STRANGER, SEL_ADD_DUAL_SY_PT)));
    }

    /// 10. market not in allowlist → denied
    function test_DisallowedMarket_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET2, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 11. amount > maxAmountPerTx → denied
    function test_OverAmountCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 12. allowLiquidityOps = false → denied even for allowed market
    function test_LiquidityOpsDisabled_Denied() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, false, true, true, true, true);
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 13. allowPtSwaps = false → PT swap denied
    function test_PtSwapsDisabled_Denied() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, true, false, true, true, true);
        bytes memory data = _encodeSwapExactTokenForPt(address(safe), MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_PT)));
    }

    /// 14. allowYtSwaps = false → YT swap denied
    function test_YtSwapsDisabled_Denied() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, true, true, false, true, true);
        bytes memory data = _encodeSwapExactTokenForYt(address(safe), MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_YT)));
    }

    /// 15. allowMintRedeem = false → denied
    function test_MintRedeemDisabled_Denied() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, true, true, true, false, true);
        bytes memory data = _encodeMintPyFromSy(address(safe), YT, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_MINT_PY_FROM_SY)));
    }

    /// 16. allowClaimYield = false → denied
    function test_ClaimDisabled_Denied() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, true, true, true, true, false);
        bytes memory data = _encodeClaimYield(address(safe));
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_CLAIM_YIELD)));
    }

    /// 17. receiver != ctx.account → denied
    function test_WrongReceiver_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(STRANGER, MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 18. unknown selector → denied
    function test_UnknownSelector_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = abi.encodeWithSelector(bytes4(0xdeadbeef), address(safe), MARKET, uint256(1));
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), bytes4(0xdeadbeef))));
    }

    /// 19. pendleRouter = address(0) → deny everything
    function test_ZeroRouter_Denied() public {
        // L-9 fix: ZeroRouter now reverts at configure time, not silently at evaluate time.
        bytes memory params = abi.encode(address(0), _arr1(MARKET), MAX_AMOUNT, true, true, true, true, true);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce = perm.configNonces(address(safe));
        bytes32 paramsHash = keccak256(params);
        bytes32 structHash = keccak256(abi.encode(perm.CONFIGURE_TYPEHASH(), address(safe), paramsHash, nonce, deadline));
        bytes32 digest = perm.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s_) = vm.sign(PERM_SIGNER_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s_, v);
        vm.expectRevert(SharedPendlePermission.ZeroRouter.selector);
        perm.configure(address(safe), params, deadline, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATION
    // ─────────────────────────────────────────────────────────────────────────

    /// 20. getConfig returns the stored slot
    function test_Configure_StoresSlot() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, true, false, true, false, true);
        SharedPendlePermission.Slot memory s = perm.getConfig(address(safe));
        assertEq(s.pendleRouter, address(router));
        assertEq(s.maxAmountPerTx, MAX_AMOUNT);
        assertTrue(s.allowLiquidityOps);
        assertFalse(s.allowPtSwaps);
        assertTrue(s.allowYtSwaps);
        assertFalse(s.allowMintRedeem);
        assertTrue(s.allowClaimYield);
        assertTrue(perm.isAllowedMarket(address(safe), MARKET));
        assertFalse(perm.isAllowedMarket(address(safe), MARKET2));
    }

    /// 21. Reconfiguring clears the old market from the allowlist
    function test_Configure_ClearsOldMarkets() public {
        _configure(address(safe), address(router), _arr1(MARKET), MAX_AMOUNT, true, true, true, true, true);
        assertTrue(perm.isAllowedMarket(address(safe), MARKET));

        // Reconfigure with MARKET2 only
        _configure(address(safe), address(router), _arr1(MARKET2), MAX_AMOUNT, true, true, true, true, true);
        assertFalse(perm.isAllowedMarket(address(safe), MARKET),  "old market still set");
        assertTrue(perm.isAllowedMarket(address(safe), MARKET2), "new market not set");
    }

    /// 22. Safe A config does not bleed into Safe B
    function test_MultiAccount_Isolation() public {
        _configureDefault(address(safe));
        // safe2 has no config — everything should be denied
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe2), MARKET, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe2), address(router), SEL_ADD_DUAL_SY_PT)));

        // safe still passes
        bytes memory data2 = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, 1 ether);
        assertTrue(perm.evaluate(data2, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADDITIONAL COVERAGE
    // ─────────────────────────────────────────────────────────────────────────

    /// 23. addLiquidityDualTokenAndPt with TokenInput struct — checks netTokenIn
    function test_AddLiquidityDualTokenAndPt_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualTokenAndPt(address(safe), MARKET, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_TOK_PT)));
    }

    function test_AddLiquidityDualTokenAndPt_OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualTokenAndPt(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_TOK_PT)));
    }

    /// 24. swapExactSyForPt — plain SY-in path
    function test_SwapExactSyForPt_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactSyForPt(address(safe), MARKET, 10 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_SY_FOR_PT)));
    }

    function test_SwapExactSyForPt_OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactSyForPt(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_SY_FOR_PT)));
    }

    /// 25. swapExactYtForToken — YT-in amount check
    function test_SwapExactYtForToken_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactYtForToken(address(safe), MARKET, 5 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_YT_FOR_TOK)));
    }

    function test_SwapExactYtForToken_OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactYtForToken(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_YT_FOR_TOK)));
    }

    /// 26. mintPyFromSy — basic SY-in path
    function test_MintPyFromSy_Permitted() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeMintPyFromSy(address(safe), YT, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_MINT_PY_FROM_SY)));
    }

    /// 27. redeemPyToSy — amount check
    function test_RedeemPyToSy_Permitted() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeRedeemPyToSy(address(safe), YT, 3 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_REDEEM_PY_TO_SY)));
    }

    function test_RedeemPyToSy_OverCap_Denied() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeRedeemPyToSy(address(safe), YT, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_REDEEM_PY_TO_SY)));
    }

    /// 28. claimYield with wrong user address
    function test_ClaimYield_WrongUser_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeClaimYield(STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_CLAIM_YIELD)));
    }

    /// 29. discriminator returns expected hash
    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("SharedPendlePermission"));
    }

    /// 30. isConfigured flag set after configure
    function test_IsConfiguredFlag() public {
        assertFalse(perm.isConfigured(address(safe)));
        _configureDefault(address(safe));
        assertTrue(perm.isConfigured(address(safe)));
    }

    /// 31. swapExactTokenForPt over cap → denied
    function test_SwapExactTokenForPt_OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactTokenForPt(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_PT)));
    }

    /// 32. swapExactTokenForYt over cap → denied
    function test_SwapExactTokenForYt_OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeSwapExactTokenForYt(address(safe), MARKET, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_SWAP_TOK_FOR_YT)));
    }

    /// 33. exact amount at cap boundary → permitted
    function test_AmountAtCap_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, uint256(MAX_AMOUNT));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));
    }

    /// 34. mintPyFromToken over cap → denied
    function test_MintPyFromToken_OverCap_Denied() public {
        address[] memory markets = new address[](2);
        markets[0] = MARKET;
        markets[1] = YT;
        _configure(address(safe), address(router), markets, MAX_AMOUNT, false, false, false, true, false);
        bytes memory data = _encodeMintPyFromToken(address(safe), YT, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(router), SEL_MINT_PY_FROM_TOK)));
    }

    /// 35. safe2 gets its own independent config (different router + market)
    function test_MultiAccount_IndependentConfig() public {
        MockPendleRouter router2 = new MockPendleRouter();
        _configureDefault(address(safe));
        _configure(address(safe2), address(router2), _arr1(MARKET2), MAX_AMOUNT / 2, true, true, true, true, true);

        // safe uses router, MARKET → pass
        bytes memory d1 = _encodeAddLiquidityDualSyAndPt(address(safe), MARKET, 1 ether);
        assertTrue(perm.evaluate(d1, _ctx(address(safe), address(router), SEL_ADD_DUAL_SY_PT)));

        // safe2 uses router2, MARKET2 → pass
        bytes memory d2 = _encodeAddLiquidityDualSyAndPt(address(safe2), MARKET2, 1 ether);
        assertTrue(perm.evaluate(d2, _ctx(address(safe2), address(router2), SEL_ADD_DUAL_SY_PT)));

        // safe2 cannot use safe's router
        assertFalse(perm.evaluate(d1, _ctx(address(safe2), address(router), SEL_ADD_DUAL_SY_PT)));
    }
}
