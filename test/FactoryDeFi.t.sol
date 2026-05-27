// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "../contracts/templates/shared/SharedBoundedSwapPermission.sol";
import "../contracts/templates/shared/SharedTransferTargetPermission.sol";
import "../contracts/templates/shared/SharedBoundedBorrowPermission.sol";
import "../contracts/interfaces/IOracle.sol";

/// @notice DeFi end-to-end scenarios exercising:
///         - Single template deployment shared across multiple Safes with different configs
///         - Uniswap V3 swap routing via factory.attach + kernel.dispatch
///         - Aave V3 borrow routing with LTV-bounded oracle check
///         - Token transfer allowlists
///         - Reconfigure → behaviour changes for one account only, others unaffected
///         - Per-account isolation: User B's config is invisible to User A's evaluate()
contract FactoryDeFiTest is FactoryTestBase {
    // ── DeFi addresses (mock identities — calldata-routing tests only) ───────
    address constant UNI_V3_ROUTER = address(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    address constant UNI_V2_ROUTER = address(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
    address constant AAVE_V3_POOL  = address(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address constant MORPHO        = address(0xBBBBBbbBBb9cC5e90e3b3Af64bdAF62C37EEFFCb);

    address constant WETH = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address constant USDC = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant DAI  = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    address constant WBTC = address(0x2260FAC5E5542a773Aa44fBCfeDf7C193bc2C599);

    address constant BENEFICIARY = address(0xBEE0);

    // ── stack components ─────────────────────────────────────────────────────
    SharedBoundedSwapPermission     internal swapTemplate;
    SharedTransferTargetPermission  internal transferTemplate;
    SharedBoundedBorrowPermission   internal borrowTemplate;

    // Second Safe — shares same template deployments
    MockSafe internal safeB;

    function setUp() public override {
        super.setUp();
        swapTemplate     = new SharedBoundedSwapPermission(address(kernel));
        transferTemplate = new SharedTransferTargetPermission(address(kernel));
        borrowTemplate   = new SharedBoundedBorrowPermission(address(kernel));

        safeB = new MockSafe();
        vm.deal(address(safeB), 100 ether);
        vm.prank(address(safeB));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 1 — DeFi: Uniswap V3 swap (WETH→USDC) through factory.attach
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeFi_UniswapV3_AttachAndSwap() public {
        // Permission Signer authorises: ROUTER + WETH→USDC, 10 ETH cap, no oracle
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(10 ether), uint256(0), address(0)
            )
        );

        // Agent dispatches swap
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 5 ether, 4_900e6);
        _dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData);

        // Safe must have received exactly one execTransactionFromModule call
        assertEq(safe.callCount(), 1);
        (address to,, bytes memory data,) = safe.getCall(0);
        assertEq(to, UNI_V3_ROUTER);
        assertEq(data, swapData);
    }

    function test_DeFi_UniswapV3_DisallowedRouter_Blocked() public {
        // Only UNI_V3_ROUTER allowed, but agent tries the V2 router
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(10 ether), uint256(0), address(0)
            )
        );

        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 5 ether, 4_900e6);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(swapTemplate), UNI_V2_ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapTemplate))
        );
        kernel.dispatch(address(safe), address(swapTemplate), UNI_V2_ROUTER, 0, swapData, sig, deadline);
    }

    function test_DeFi_UniswapV3_OverCap_Blocked() public {
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(1 ether), uint256(0), address(0)
            )
        );

        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 5 ether, 4_900e6);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapTemplate))
        );
        kernel.dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 2 — DeFi: Uniswap V3 swap with oracle-bounded slippage
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeFi_UniswapV3_OracleSlippage_PassesAtFairPrice() public {
        MockOracle oracle = new MockOracle();
        oracle.set(WETH, USDC, 1_000e6, 18); // 1 WETH = 1000 USDC

        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(10 ether), uint256(200), address(oracle) // 2% slippage
            )
        );

        // 1 WETH in, min 990 USDC out — within 2% of fair 1000
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 1 ether, 990e6);
        _dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData);
        assertEq(safe.callCount(), 1);
    }

    function test_DeFi_UniswapV3_OracleSlippage_BlocksLowMinOut() public {
        MockOracle oracle = new MockOracle();
        oracle.set(WETH, USDC, 1_000e6, 18);

        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(10 ether), uint256(200), address(oracle)
            )
        );

        // 1 WETH in, min 900 USDC out — 10% below fair, exceeds 2% slippage
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 1 ether, 900e6);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapTemplate))
        );
        kernel.dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, swapData, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 3 — DeFi: Aave V3 borrow with LTV bound
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeFi_AaveV3_BorrowWithinLtv() public {
        // LTV math (template): ltvBps = amount × borPrice × 10_000 / colValue.
        // Convention from existing tests: oracle values are unitless; pick numbers
        // such that the bps ratio is what you want.
        // colValue=10_000, borPrice=1, amount=5_000 → ltv = 50% < 75% cap.
        MockOracle colOracle = new MockOracle();
        MockOracle borOracle = new MockOracle();
        colOracle.set(address(safe), address(0), 10_000, 0);
        borOracle.set(USDC, address(0), 1, 0);

        _attach(
            address(safe),
            borrowTemplate,
            abi.encode(
                _one(AAVE_V3_POOL), _one(USDC),
                uint256(10_000), uint256(7_500),
                address(colOracle), address(borOracle)
            )
        );

        bytes memory data = _aaveBorrow(USDC, 5_000, address(safe));
        _dispatch(address(safe), address(borrowTemplate), AAVE_V3_POOL, 0, data);

        assertEq(safe.callCount(), 1);
        (address to,, bytes memory d,) = safe.getCall(0);
        assertEq(to, AAVE_V3_POOL);
        assertEq(d, data);
    }

    function test_DeFi_AaveV3_BorrowOverLtv_Blocked() public {
        MockOracle colOracle = new MockOracle();
        MockOracle borOracle = new MockOracle();
        colOracle.set(address(safe), address(0), 10_000, 0);
        borOracle.set(USDC, address(0), 1, 0);

        _attach(
            address(safe),
            borrowTemplate,
            abi.encode(
                _one(AAVE_V3_POOL), _one(USDC),
                uint256(10_000), uint256(5_000), // 50% LTV cap
                address(colOracle), address(borOracle)
            )
        );

        // amount=8_000 → ltv=80% > 50% cap
        bytes memory data = _aaveBorrow(USDC, 8_000, address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(borrowTemplate), AAVE_V3_POOL, 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(borrowTemplate))
        );
        kernel.dispatch(address(safe), address(borrowTemplate), AAVE_V3_POOL, 0, data, sig, deadline);
    }

    function test_DeFi_AaveV3_BorrowOnBehalfOfWrongAccount_Blocked() public {
        _attach(
            address(safe),
            borrowTemplate,
            abi.encode(
                _one(AAVE_V3_POOL), _one(USDC),
                uint256(5_000e18), uint256(7_500),
                address(0), address(0) // no LTV check
            )
        );

        // onBehalfOf is some attacker address — borrow doesn't belong to our Safe
        bytes memory data = _aaveBorrow(USDC, 1_000e18, address(0xDEAD));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(borrowTemplate), AAVE_V3_POOL, 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(borrowTemplate))
        );
        kernel.dispatch(address(safe), address(borrowTemplate), AAVE_V3_POOL, 0, data, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 4 — DeFi: ERC-20 transfer with recipient allowlist
    // ─────────────────────────────────────────────────────────────────────────

    function test_DeFi_TransferToAllowedRecipient() public {
        _attach(
            address(safe),
            transferTemplate,
            abi.encode(_one(BENEFICIARY), _one(USDC), type(uint256).max)
        );

        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)", BENEFICIARY, uint256(1_000e6)
        );
        _dispatch(address(safe), address(transferTemplate), USDC, 0, data);
        assertEq(safe.callCount(), 1);
    }

    function test_DeFi_TransferToWrongRecipient_Blocked() public {
        _attach(
            address(safe),
            transferTemplate,
            abi.encode(_one(BENEFICIARY), _one(USDC), type(uint256).max)
        );

        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)", address(0xBAD), uint256(1_000e6)
        );
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(transferTemplate), USDC, 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(transferTemplate))
        );
        kernel.dispatch(address(safe), address(transferTemplate), USDC, 0, data, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 5 — Shared template across two Safes with different configs
    //              (the headline test for the multi-account architecture)
    // ─────────────────────────────────────────────────────────────────────────

    function test_MultiUser_SameTemplate_DifferentConfigs() public {
        // Safe A: WETH→USDC only, 5 ETH cap
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                uint256(5 ether), uint256(0), address(0)
            )
        );

        // Safe B: WETH→DAI only, 20 ETH cap — same template address
        _attach(
            address(safeB),
            swapTemplate,
            abi.encode(
                _one(UNI_V3_ROUTER), _one(WETH), _one(DAI),
                uint256(20 ether), uint256(0), address(0)
            )
        );

        // Configs are isolated
        assertTrue(swapTemplate.isAllowedTokenOut(address(safe),  USDC));
        assertFalse(swapTemplate.isAllowedTokenOut(address(safe),  DAI));
        assertFalse(swapTemplate.isAllowedTokenOut(address(safeB), USDC));
        assertTrue(swapTemplate.isAllowedTokenOut(address(safeB), DAI));

        // A's agent can swap WETH→USDC
        bytes memory dataA = _v3Swap(WETH, USDC, address(safe), 4 ether, 0);
        _dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, dataA);

        // B's agent can swap WETH→DAI
        bytes memory dataB = _v3Swap(WETH, DAI, address(safeB), 15 ether, 0);
        _dispatch(address(safeB), address(swapTemplate), UNI_V3_ROUTER, 0, dataB);

        assertEq(safe.callCount(),  1);
        assertEq(safeB.callCount(), 1);
    }

    function test_MultiUser_BConfigDoesNotLeakToA() public {
        // A: WETH→USDC, B: WETH→DAI
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                      uint256(5 ether), uint256(0), address(0))
        );
        _attach(
            address(safeB),
            swapTemplate,
            abi.encode(_one(UNI_V3_ROUTER), _one(WETH), _one(DAI),
                      uint256(5 ether), uint256(0), address(0))
        );

        // A tries WETH→DAI — should fail because DAI is not in A's tokensOut
        bytes memory dataA = _v3Swap(WETH, DAI, address(safe), 1 ether, 0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, dataA, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapTemplate))
        );
        kernel.dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, dataA, sig, deadline);
    }

    function test_MultiUser_ReconfigureOnlyAffectsOneAccount() public {
        _attach(
            address(safe),
            swapTemplate,
            abi.encode(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                      uint256(5 ether), uint256(0), address(0))
        );
        _attach(
            address(safeB),
            swapTemplate,
            abi.encode(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                      uint256(5 ether), uint256(0), address(0))
        );

        // Reconfigure A's cap to 100 ETH; B should stay at 5 ETH
        bytes memory newParams = abi.encode(
            _one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
            uint256(100 ether), uint256(0), address(0)
        );
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swapTemplate, address(safe), newParams, deadline, PERM_SIGNER_KEY);
        factory.reconfigure(address(safe), address(swapTemplate), newParams, deadline, cfgSig);

        (,,,uint256 capA,,,) = swapTemplate.getConfig(address(safe));
        (,,,uint256 capB,,,) = swapTemplate.getConfig(address(safeB));
        assertEq(capA, 100 ether);
        assertEq(capB,   5 ether);

        // Verify dispatch behaviour matches the new caps
        // A: 50 ETH passes
        bytes memory dataA = _v3Swap(WETH, USDC, address(safe), 50 ether, 0);
        _dispatch(address(safe), address(swapTemplate), UNI_V3_ROUTER, 0, dataA);

        // B: 50 ETH fails (over its 5 ETH cap)
        bytes memory dataB = _v3Swap(WETH, USDC, address(safeB), 50 ether, 0);
        uint256 nonce    = kernel.managerNonces(address(safeB));
        bytes memory sig = _signDispatch(address(safeB), address(swapTemplate), UNI_V3_ROUTER, 0, dataB, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(swapTemplate))
        );
        kernel.dispatch(address(safeB), address(swapTemplate), UNI_V3_ROUTER, 0, dataB, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Scenario 6 — Multi-template attach: one Safe with swap + transfer + borrow
    //
    // The kernel evaluates ALL registered permissions with AND semantics — every
    // template must return true for dispatch to succeed. This test verifies that
    // attachBatch correctly configures and registers all three templates; dispatch
    // semantics across templates are exercised in the individual scenarios above.
    // ─────────────────────────────────────────────────────────────────────────

    function test_MultiTemplate_BatchAttach() public {
        bytes memory swapParams =
            abi.encode(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC),
                      uint256(10 ether), uint256(0), address(0));
        bytes memory transferParams = abi.encode(_one(BENEFICIARY), _one(USDC), type(uint256).max);
        bytes memory borrowParams   = abi.encode(
            _one(AAVE_V3_POOL), _one(USDC),
            uint256(1_000), uint256(7_500),
            address(0), address(0)
        );

        address[] memory templates = new address[](3);
        templates[0] = address(swapTemplate);
        templates[1] = address(transferTemplate);
        templates[2] = address(borrowTemplate);

        bytes[] memory params = new bytes[](3);
        params[0] = swapParams;
        params[1] = transferParams;
        params[2] = borrowParams;

        uint256 deadline = block.timestamp + 1 hours;
        uint256[] memory deadlines = new uint256[](3);
        for (uint256 i; i < 3; i++) deadlines[i] = deadline;

        bytes[] memory cfgSigs = new bytes[](3);
        cfgSigs[0] = _signConfigure(swapTemplate,     address(safe), swapParams,     deadline, PERM_SIGNER_KEY);
        cfgSigs[1] = _signConfigure(transferTemplate, address(safe), transferParams, deadline, PERM_SIGNER_KEY);
        cfgSigs[2] = _signConfigure(borrowTemplate,   address(safe), borrowParams,   deadline, PERM_SIGNER_KEY);

        bytes memory kSig = _signRegisterPermissions(address(safe), templates, 0, deadline);
        uint256 fee = _calcFee(address(swapTemplate)) + _calcFee(address(transferTemplate)) + _calcFee(address(borrowTemplate));

        factory.attachBatch{value: fee}(
            address(safe), templates, params, deadlines, cfgSigs, deadline, kSig
        );

        assertEq(kernel.getPermissions(address(safe)).length, 3);
        assertTrue(swapTemplate.isConfigured(address(safe)));
        assertTrue(transferTemplate.isConfigured(address(safe)));
        assertTrue(borrowTemplate.isConfigured(address(safe)));
        // Per-template configs are independent
        assertTrue(swapTemplate.isAllowedRouter(address(safe), UNI_V3_ROUTER));
        assertTrue(transferTemplate.isAllowedRecipient(address(safe), BENEFICIARY));
        assertTrue(borrowTemplate.isAllowedProtocol(address(safe), AAVE_V3_POOL));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _attach(address account, BaseSharedPermission template, bytes memory params) internal {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(template, account, params, deadline, PERM_SIGNER_KEY);
        uint256 sigNonce = kernel.signerNonces(account);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kSig = _signRegisterPermission(account, address(template), sigNonce);
        uint256 fee = _calcFee(address(template));
        factory.attach{value: fee}(account, address(template), params, deadline, cfgSig, kDeadline, kSig);
    }

    function _dispatch(address account, address permission, address target, uint256 value, bytes memory data) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(account);
        bytes memory sig = _signDispatch(account, permission, target, value, data, nonce, deadline);
        kernel.dispatch(account, permission, target, value, data, sig, deadline);
    }

    function _v3Swap(
        address tokenIn,
        address tokenOut,
        address recipient,
        uint256 amountIn,
        uint256 amountOutMin
    ) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(
            bytes4(0x414bf389),
            tokenIn, tokenOut, uint24(3000), recipient, type(uint256).max,
            amountIn, amountOutMin, uint160(0)
        );
    }

    function _aaveBorrow(address asset, uint256 amount, address onBehalfOf)
        internal pure returns (bytes memory)
    {
        return abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)",
            asset, amount, uint256(2), uint16(0), onBehalfOf
        );
    }

    function _one(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }
}

/// @dev IOracle stub: returns a price scaled by the configured decimals.
contract MockOracle is IOracle {
    mapping(bytes32 => uint256) private _price;
    mapping(bytes32 => uint8)   private _dec;

    function set(address a, address b, uint256 p, uint8 d) external {
        _price[keccak256(abi.encode(a, b))] = p;
        _dec[keccak256(abi.encode(a, b))]   = d;
    }

    function getPrice(address a, address b) external view returns (uint256, uint8, uint256) {
        bytes32 k = keccak256(abi.encode(a, b));
        return (_price[k], _dec[k], block.timestamp);
    }
}
