// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "../contracts/templates/shared/SharedAMMLiquidityPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Structs used by mock contracts
// ─────────────────────────────────────────────────────────────────────────────

struct UniV3MintParams {
    address token0;
    address token1;
    uint24  fee;
    int24   tickLower;
    int24   tickUpper;
    uint256 amount0Desired;
    uint256 amount1Desired;
    uint256 amount0Min;
    uint256 amount1Min;
    address recipient;
    uint256 deadline;
}

struct IncreaseLiqParams {
    uint256 tokenId;
    uint256 amount0Desired;
    uint256 amount1Desired;
    uint256 amount0Min;
    uint256 amount1Min;
    uint256 deadline;
}

struct DecreaseLiqParams {
    uint256 tokenId;
    uint128 liquidity;
    uint256 amount0Min;
    uint256 amount1Min;
    uint256 deadline;
}

struct CollectParams {
    uint256 tokenId;
    address recipient;
    uint128 amount0Max;
    uint128 amount1Max;
}

struct SlipstreamMintParams {
    address token0;
    address token1;
    int24   tickSpacing;
    int24   tickLower;
    int24   tickUpper;
    uint256 amount0Desired;
    uint256 amount1Desired;
    uint256 amount0Min;
    uint256 amount1Min;
    address recipient;
    uint256 deadline;
    uint160 sqrtPriceX96;
}

// ─────────────────────────────────────────────────────────────────────────────
// Mock contracts — stubs with correct signatures, no real logic
// ─────────────────────────────────────────────────────────────────────────────

contract MockUniV3NPM {
    function mint(UniV3MintParams calldata)
        external pure returns (uint256, uint128, uint256, uint256) { return (0, 0, 0, 0); }

    function increaseLiquidity(IncreaseLiqParams calldata)
        external pure returns (uint128, uint256, uint256) { return (0, 0, 0); }

    function decreaseLiquidity(DecreaseLiqParams calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function collect(CollectParams calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function burn(uint256) external pure {}
}

contract MockAerodromeRouter {
    function addLiquidity(address, address, bool, uint256, uint256, uint256, uint256, address, uint256)
        external pure returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function addLiquidityETH(address, bool, uint256, uint256, uint256, address, uint256)
        external payable returns (uint256, uint256, uint256) { return (0, 0, 0); }

    function removeLiquidity(address, address, bool, uint256, uint256, uint256, address, uint256)
        external pure returns (uint256, uint256) { return (0, 0); }

    function removeLiquidityETH(address, bool, uint256, uint256, uint256, address, uint256)
        external pure returns (uint256, uint256) { return (0, 0); }
}

contract MockAeroSlipstreamNPM {
    function mint(SlipstreamMintParams calldata)
        external pure returns (uint256, uint128, uint256, uint256) { return (0, 0, 0, 0); }

    function increaseLiquidity(IncreaseLiqParams calldata)
        external pure returns (uint128, uint256, uint256) { return (0, 0, 0); }

    function decreaseLiquidity(DecreaseLiqParams calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function collect(CollectParams calldata)
        external pure returns (uint256, uint256) { return (0, 0); }

    function burn(uint256) external pure {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────

contract SharedAMMLiquidityPermissionTest is FactoryTestBase {
    SharedAMMLiquidityPermission internal perm;
    MockUniV3NPM                 internal mockUniV3Npm;
    MockAerodromeRouter          internal mockAeroRouter;
    MockAeroSlipstreamNPM        internal mockSlipstreamNpm;

    // A second Safe for isolation tests
    MockSafe internal safe2;

    // Addresses
    address constant TOKEN_A   = address(0xAA01);
    address constant TOKEN_B   = address(0xAA02);
    address constant TOKEN_C   = address(0xAA03); // not in allowlist
    address constant STRANGER  = address(0x9999);

    uint128 constant MAX_AMOUNT = 100 ether;

    // ── Selector constants (must match contract) ──────────────────────────────
    bytes4 constant SEL_MINT          = bytes4(keccak256("mint((address,address,uint24,int24,int24,uint256,uint256,uint256,uint256,address,uint256))"));
    bytes4 constant SEL_INCREASE_LIQ  = bytes4(keccak256("increaseLiquidity((uint256,uint256,uint256,uint256,uint256,uint256))"));
    bytes4 constant SEL_DECREASE_LIQ  = bytes4(keccak256("decreaseLiquidity((uint256,uint128,uint256,uint256,uint256))"));
    bytes4 constant SEL_COLLECT       = bytes4(keccak256("collect((uint256,address,uint128,uint128))"));
    bytes4 constant SEL_BURN          = bytes4(keccak256("burn(uint256)"));
    bytes4 constant SEL_SLIPSTREAM    = bytes4(keccak256("mint((address,address,int24,int24,int24,uint256,uint256,uint256,uint256,address,uint256,uint160))"));
    bytes4 constant SEL_AERO_ADD      = bytes4(keccak256("addLiquidity(address,address,bool,uint256,uint256,uint256,uint256,address,uint256)"));
    bytes4 constant SEL_AERO_ADD_ETH  = bytes4(keccak256("addLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256)"));
    bytes4 constant SEL_AERO_REM      = bytes4(keccak256("removeLiquidity(address,address,bool,uint256,uint256,uint256,address,uint256)"));
    bytes4 constant SEL_AERO_REM_ETH  = bytes4(keccak256("removeLiquidityETH(address,bool,uint256,uint256,uint256,address,uint256)"));

    function setUp() public override {
        super.setUp();
        perm              = new SharedAMMLiquidityPermission(address(kernel));
        mockUniV3Npm      = new MockUniV3NPM();
        mockAeroRouter    = new MockAerodromeRouter();
        mockSlipstreamNpm = new MockAeroSlipstreamNPM();

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

    function _arr2(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2); r[0] = a; r[1] = b;
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

    function _configure(
        address account,
        address[] memory allowedTargets,
        address[] memory allowedTokens,
        uint128 maxAmt,
        bool mint_,
        bool increase,
        bool decrease,
        bool collect_,
        bool burn_
    ) internal {
        bytes memory params = abi.encode(
            allowedTargets, allowedTokens, maxAmt, mint_, increase, decrease, collect_, burn_
        );
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory sig = _signConfigure(perm, account, params, deadline, PERM_SIGNER_KEY);
        perm.configure(account, params, deadline, sig);
    }

    /// @dev Default config: UniV3 NPM as target, TOKEN_A + TOKEN_B allowed, all ops on.
    function _configureDefault(address account) internal {
        _configure(
            account,
            _arr1(address(mockUniV3Npm)),
            _arr2(TOKEN_A, TOKEN_B),
            MAX_AMOUNT,
            true, true, true, true, true
        );
    }

    /// @dev Config for Aerodrome Router tests.
    function _configureAero(address account) internal {
        _configure(
            account,
            _arr1(address(mockAeroRouter)),
            _arr2(TOKEN_A, TOKEN_B),
            MAX_AMOUNT,
            true, true, true, true, true
        );
    }

    /// @dev Config for Slipstream tests.
    function _configureSlipstream(address account) internal {
        _configure(
            account,
            _arr1(address(mockSlipstreamNpm)),
            _arr2(TOKEN_A, TOKEN_B),
            MAX_AMOUNT,
            true, true, true, true, true
        );
    }

    // ── Calldata encoders ─────────────────────────────────────────────────────

    function _encodeMint(
        address token0,
        address token1,
        uint24 fee,
        address recipient,
        uint256 amt0,
        uint256 amt1
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_MINT,
            token0, token1, fee,
            int24(0), int24(0),            // tickLower, tickUpper
            amt0, amt1,
            uint256(0), uint256(0),        // amount0Min, amount1Min
            recipient,
            block.timestamp + 300          // deadline
        );
    }

    function _encodeIncreaseLiquidity(
        uint256 tokenId,
        uint256 amt0,
        uint256 amt1
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_INCREASE_LIQ,
            tokenId, amt0, amt1, uint256(0), uint256(0), block.timestamp + 300
        );
    }

    function _encodeDecreaseLiquidity(
        uint256 tokenId,
        uint128 liquidity
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_DECREASE_LIQ,
            tokenId, liquidity, uint256(0), uint256(0), block.timestamp + 300
        );
    }

    function _encodeCollect(
        uint256 tokenId,
        address recipient
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_COLLECT,
            tokenId, recipient, uint128(type(uint128).max), uint128(type(uint128).max)
        );
    }

    function _encodeBurn(uint256 tokenId) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_BURN, tokenId);
    }

    function _encodeAeroAdd(
        address tokenA,
        address tokenB,
        bool stable,
        uint256 amtA,
        uint256 amtB,
        address to
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_AERO_ADD,
            tokenA, tokenB, stable, amtA, amtB, uint256(0), uint256(0), to, block.timestamp + 300
        );
    }

    function _encodeAeroAddETH(
        address token,
        bool stable,
        uint256 amtToken,
        address to
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_AERO_ADD_ETH,
            token, stable, amtToken, uint256(0), uint256(0), to, block.timestamp + 300
        );
    }

    function _encodeAeroRemove(
        address tokenA,
        address tokenB,
        bool stable,
        uint256 liquidity,
        address to
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_AERO_REM,
            tokenA, tokenB, stable, liquidity, uint256(0), uint256(0), to, block.timestamp + 300
        );
    }

    function _encodeAeroRemoveETH(
        address token,
        bool stable,
        uint256 liquidity,
        address to
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_AERO_REM_ETH,
            token, stable, liquidity, uint256(0), uint256(0), to, block.timestamp + 300
        );
    }

    function _encodeSlipstreamMint(
        address token0,
        address token1,
        int24 tickSpacing,
        address recipient,
        uint256 amt0,
        uint256 amt1
    ) internal view returns (bytes memory) {
        return abi.encodeWithSelector(
            SEL_SLIPSTREAM,
            token0, token1, tickSpacing,
            int24(0), int24(0),            // tickLower, tickUpper
            amt0, amt1,
            uint256(0), uint256(0),        // amount0Min, amount1Min
            recipient,
            block.timestamp + 300,         // deadline
            uint160(0)                     // sqrtPriceX96
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // UNISWAP V3 GOLDEN PATHS
    // ─────────────────────────────────────────────────────────────────────────

    /// 1. UniV3 mint — all checks pass
    function test_UniV3_Mint_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), 1 ether, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 2. UniV3 increaseLiquidity — amounts within cap
    function test_UniV3_IncreaseLiquidity_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeIncreaseLiquidity(1, 10 ether, 10 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_INCREASE_LIQ)));
    }

    /// 3. UniV3 decreaseLiquidity — flag on
    function test_UniV3_DecreaseLiquidity_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeDecreaseLiquidity(1, 1e18);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_DECREASE_LIQ)));
    }

    /// 4. UniV3 collect — recipient matches account
    function test_UniV3_Collect_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeCollect(1, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_COLLECT)));
    }

    /// 5. UniV3 burn — flag on
    function test_UniV3_Burn_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeBurn(1);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_BURN)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AERODROME ROUTER GOLDEN PATHS
    // ─────────────────────────────────────────────────────────────────────────

    /// 6. Aerodrome addLiquidity stable pool
    function test_Aero_AddLiquidity_Stable_Permitted() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAdd(TOKEN_A, TOKEN_B, true, 5 ether, 5 ether, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD)));
    }

    /// 7. Aerodrome addLiquidity volatile pool
    function test_Aero_AddLiquidity_Volatile_Permitted() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAdd(TOKEN_A, TOKEN_B, false, 5 ether, 5 ether, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD)));
    }

    /// 8. Aerodrome addLiquidityETH
    function test_Aero_AddLiquidityETH_Permitted() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAddETH(TOKEN_A, false, 3 ether, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD_ETH)));
    }

    /// 9. Aerodrome removeLiquidity
    function test_Aero_RemoveLiquidity_Permitted() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroRemove(TOKEN_A, TOKEN_B, false, 1 ether, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_REM)));
    }

    /// 10. Aerodrome removeLiquidityETH
    function test_Aero_RemoveLiquidityETH_Permitted() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroRemoveETH(TOKEN_A, false, 1 ether, address(safe));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_REM_ETH)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // AERODROME SLIPSTREAM GOLDEN PATHS
    // ─────────────────────────────────────────────────────────────────────────

    /// 11. Slipstream mint — uses different selector and 12-field struct
    function test_AeroSlipstream_Mint_Permitted() public {
        _configureSlipstream(address(safe));
        bytes memory data = _encodeSlipstreamMint(TOKEN_A, TOKEN_B, int24(100), address(safe), 1 ether, 1 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockSlipstreamNpm), SEL_SLIPSTREAM)));
    }

    /// 12. Slipstream increaseLiquidity — same selector as UniV3
    function test_AeroSlipstream_IncreaseLiquidity_Permitted() public {
        _configureSlipstream(address(safe));
        bytes memory data = _encodeIncreaseLiquidity(42, 5 ether, 5 ether);
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockSlipstreamNpm), SEL_INCREASE_LIQ)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: TARGET
    // ─────────────────────────────────────────────────────────────────────────

    /// 13. Call to non-allowlisted target → denied
    function test_WrongTarget_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), STRANGER, SEL_MINT)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: TOKENS
    // ─────────────────────────────────────────────────────────────────────────

    /// 14. token0 not in allowlist → denied
    function test_Mint_Token0NotAllowed_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_C, TOKEN_B, 3000, address(safe), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 15. token1 not in allowlist → denied
    function test_Mint_Token1NotAllowed_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_C, 3000, address(safe), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: AMOUNTS
    // ─────────────────────────────────────────────────────────────────────────

    /// 16. mint amount0 over cap → denied
    function test_Mint_Amount0OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), uint256(MAX_AMOUNT) + 1, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 17. mint amount1 over cap → denied
    function test_Mint_Amount1OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), 1 ether, uint256(MAX_AMOUNT) + 1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 18. Aerodrome addLiquidity amountA over cap → denied
    function test_AeroAdd_AmountAOverCap_Denied() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAdd(TOKEN_A, TOKEN_B, false, uint256(MAX_AMOUNT) + 1, 1 ether, address(safe));
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD)));
    }

    /// 19. increaseLiquidity amount0 over cap → denied
    function test_Increase_Amount0OverCap_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeIncreaseLiquidity(1, uint256(MAX_AMOUNT) + 1, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_INCREASE_LIQ)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: OP FLAGS
    // ─────────────────────────────────────────────────────────────────────────

    /// 20. allowMint = false → mint denied
    function test_MintDisabled_Denied() public {
        _configure(address(safe), _arr1(address(mockUniV3Npm)), _arr2(TOKEN_A, TOKEN_B), MAX_AMOUNT,
                   false, true, true, true, true);
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 21. allowIncrease = false → increaseLiquidity denied
    function test_IncreaseDisabled_Denied() public {
        _configure(address(safe), _arr1(address(mockUniV3Npm)), _arr2(TOKEN_A, TOKEN_B), MAX_AMOUNT,
                   true, false, true, true, true);
        bytes memory data = _encodeIncreaseLiquidity(1, 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_INCREASE_LIQ)));
    }

    /// 22. allowDecrease = false → decreaseLiquidity denied
    function test_DecreaseDisabled_Denied() public {
        _configure(address(safe), _arr1(address(mockUniV3Npm)), _arr2(TOKEN_A, TOKEN_B), MAX_AMOUNT,
                   true, true, false, true, true);
        bytes memory data = _encodeDecreaseLiquidity(1, 1e18);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_DECREASE_LIQ)));
    }

    /// 23. allowCollect = false → collect denied
    function test_CollectDisabled_Denied() public {
        _configure(address(safe), _arr1(address(mockUniV3Npm)), _arr2(TOKEN_A, TOKEN_B), MAX_AMOUNT,
                   true, true, true, false, true);
        bytes memory data = _encodeCollect(1, address(safe));
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_COLLECT)));
    }

    /// 24. allowBurn = false → burn denied
    function test_BurnDisabled_Denied() public {
        _configure(address(safe), _arr1(address(mockUniV3Npm)), _arr2(TOKEN_A, TOKEN_B), MAX_AMOUNT,
                   true, true, true, true, false);
        bytes memory data = _encodeBurn(1);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_BURN)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: RECIPIENT / RECIPIENT
    // ─────────────────────────────────────────────────────────────────────────

    /// 25. mint with wrong recipient → denied
    function test_Mint_WrongRecipient_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, STRANGER, 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 26. collect with wrong recipient → denied
    function test_Collect_WrongRecipient_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeCollect(1, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_COLLECT)));
    }

    /// 27. Aerodrome addLiquidity with wrong `to` → denied
    function test_AeroAdd_WrongRecipient_Denied() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAdd(TOKEN_A, TOKEN_B, false, 1 ether, 1 ether, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD)));
    }

    /// 28. Aerodrome removeLiquidity with wrong `to` → denied
    function test_AeroRemove_WrongRecipient_Denied() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroRemove(TOKEN_A, TOKEN_B, false, 1 ether, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_REM)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // NEGATIVE: OTHER
    // ─────────────────────────────────────────────────────────────────────────

    /// 29. Unrecognised selector → denied
    function test_UnknownSelector_Denied() public {
        _configureDefault(address(safe));
        bytes memory data = abi.encodeWithSelector(bytes4(0xdeadbeef), TOKEN_A, TOKEN_B, uint256(1));
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), bytes4(0xdeadbeef))));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // CONFIGURATION
    // ─────────────────────────────────────────────────────────────────────────

    /// 30. getConfig returns the stored slot after configure
    function test_Configure_StoresSlot() public {
        _configure(
            address(safe),
            _arr1(address(mockUniV3Npm)),
            _arr2(TOKEN_A, TOKEN_B),
            MAX_AMOUNT,
            true, false, true, false, true
        );
        SharedAMMLiquidityPermission.Slot memory s = perm.getConfig(address(safe));
        assertEq(s.maxAmountPerTokenPerTx, MAX_AMOUNT);
        assertTrue(s.allowMint);
        assertFalse(s.allowIncrease);
        assertTrue(s.allowDecrease);
        assertFalse(s.allowCollect);
        assertTrue(s.allowBurn);
        assertTrue(perm.isAllowedTarget(address(safe), address(mockUniV3Npm)));
        assertTrue(perm.isAllowedToken(address(safe), TOKEN_A));
        assertTrue(perm.isAllowedToken(address(safe), TOKEN_B));
        assertFalse(perm.isAllowedToken(address(safe), TOKEN_C));
    }

    /// 31. Reconfiguring clears old target and token allowlists
    function test_Reconfigure_ClearsOldAllowlists() public {
        _configure(
            address(safe),
            _arr1(address(mockUniV3Npm)),
            _arr2(TOKEN_A, TOKEN_B),
            MAX_AMOUNT,
            true, true, true, true, true
        );
        assertTrue(perm.isAllowedTarget(address(safe), address(mockUniV3Npm)));
        assertTrue(perm.isAllowedToken(address(safe), TOKEN_A));
        assertTrue(perm.isAllowedToken(address(safe), TOKEN_B));

        // Reconfigure: different target, only TOKEN_C
        _configure(
            address(safe),
            _arr1(address(mockAeroRouter)),
            _arr1(TOKEN_C),
            MAX_AMOUNT,
            true, true, true, true, true
        );
        assertFalse(perm.isAllowedTarget(address(safe), address(mockUniV3Npm)), "old target still set");
        assertTrue(perm.isAllowedTarget(address(safe), address(mockAeroRouter)), "new target not set");
        assertFalse(perm.isAllowedToken(address(safe), TOKEN_A), "old token A still set");
        assertFalse(perm.isAllowedToken(address(safe), TOKEN_B), "old token B still set");
        assertTrue(perm.isAllowedToken(address(safe), TOKEN_C), "new token C not set");
    }

    /// 32. safe2 config is independent of safe config
    function test_MultiAccount_Isolation() public {
        _configureDefault(address(safe));
        // safe2 has no config — denied
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe2), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe2), address(mockUniV3Npm), SEL_MINT)));

        // safe still passes
        bytes memory data2 = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), 1 ether, 1 ether);
        assertTrue(perm.evaluate(data2, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // ADDITIONAL COVERAGE
    // ─────────────────────────────────────────────────────────────────────────

    /// 33. Amount exactly at cap → permitted (boundary)
    function test_Mint_AmountAtCap_Permitted() public {
        _configureDefault(address(safe));
        bytes memory data = _encodeMint(TOKEN_A, TOKEN_B, 3000, address(safe), uint256(MAX_AMOUNT), uint256(MAX_AMOUNT));
        assertTrue(perm.evaluate(data, _ctx(address(safe), address(mockUniV3Npm), SEL_MINT)));
    }

    /// 34. Aerodrome addLiquidityETH with wrong recipient → denied
    function test_AeroAddETH_WrongRecipient_Denied() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroAddETH(TOKEN_A, false, 1 ether, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_ADD_ETH)));
    }

    /// 35. Aerodrome removeLiquidityETH with wrong recipient → denied
    function test_AeroRemoveETH_WrongRecipient_Denied() public {
        _configureAero(address(safe));
        bytes memory data = _encodeAeroRemoveETH(TOKEN_A, false, 1 ether, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockAeroRouter), SEL_AERO_REM_ETH)));
    }

    /// 36. Slipstream mint — token not allowed → denied
    function test_Slipstream_Mint_TokenNotAllowed_Denied() public {
        _configureSlipstream(address(safe));
        bytes memory data = _encodeSlipstreamMint(TOKEN_C, TOKEN_B, int24(100), address(safe), 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockSlipstreamNpm), SEL_SLIPSTREAM)));
    }

    /// 37. Slipstream mint — wrong recipient → denied
    function test_Slipstream_Mint_WrongRecipient_Denied() public {
        _configureSlipstream(address(safe));
        bytes memory data = _encodeSlipstreamMint(TOKEN_A, TOKEN_B, int24(100), STRANGER, 1 ether, 1 ether);
        assertFalse(perm.evaluate(data, _ctx(address(safe), address(mockSlipstreamNpm), SEL_SLIPSTREAM)));
    }

    /// 38. discriminator returns expected hash
    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("SharedAMMLiquidityPermission"));
    }

    /// 39. isConfigured flag set after configure
    function test_IsConfiguredFlag() public {
        assertFalse(perm.isConfigured(address(safe)));
        _configureDefault(address(safe));
        assertTrue(perm.isConfigured(address(safe)));
    }
}
