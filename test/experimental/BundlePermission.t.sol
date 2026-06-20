// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "../support/FactoryTestBase.sol";
import "../../contracts/experimental/SharedDeFiBundlePermission.sol";
import "../../contracts/interfaces/IOracle.sol";

/// @notice Demonstrates the composite template pattern: ONE permission registered on
///         a Safe, capable of authorising swaps + borrows + transfers, all routed by
///         selector inside the single template. No multi-permission AND-semantics issue.
contract BundlePermissionTest is FactoryTestBase {
    SharedDeFiBundlePermission internal bundle;

    // DeFi addresses
    address constant UNI_V3_ROUTER = address(0xE592427A0AEce92De3Edee1F18E0157C05861564);
    address constant AAVE_V3_POOL  = address(0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2);
    address constant WETH = address(0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2);
    address constant USDC = address(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);
    address constant DAI  = address(0x6B175474E89094C44Da98b954EedeAC495271d0F);
    address constant BENEFICIARY = address(0xBEE0);

    MockOracle internal colOracle;
    MockOracle internal borOracle;

    // Second Safe for multi-account scenarios
    MockSafe internal safeB;

    function setUp() public override {
        super.setUp();
        bundle    = new SharedDeFiBundlePermission(address(kernel));
        colOracle = new MockOracle();
        borOracle = new MockOracle();

        safeB = new MockSafe();
        vm.deal(address(safeB), 100 ether);
        vm.prank(address(safeB));
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Headline scenario: ONE template, ALL DeFi operations
    // ─────────────────────────────────────────────────────────────────────────

    function test_Bundle_AllThreeDomainsDispatch_SinglePermission() public {
        _attachActiveTradingBundle(address(safe));

        // Sanity: exactly one permission registered
        assertEq(kernel.getPermissions(address(safe)).length, 1);
        assertEq(kernel.getPermissions(address(safe))[0], address(bundle));

        // 1. Swap WETH→USDC
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 2 ether, 0);
        _dispatch(address(safe), UNI_V3_ROUTER, 0, swapData);

        // 2. Borrow USDC from Aave (within LTV)
        bytes memory borrowData = _aaveBorrow(USDC, 3_000, address(safe));
        _dispatch(address(safe), AAVE_V3_POOL, 0, borrowData);

        // 3. Transfer USDC to a whitelisted beneficiary
        bytes memory transferData = abi.encodeWithSignature(
            "transfer(address,uint256)", BENEFICIARY, uint256(500e6)
        );
        _dispatch(address(safe), USDC, 0, transferData);

        // All three calls landed on the Safe
        assertEq(safe.callCount(), 3);
    }

    function test_Bundle_UnknownSelector_Rejected() public {
        _attachActiveTradingBundle(address(safe));

        // Some random unrelated call — bundle returns false → PermissionDenied
        bytes memory data = abi.encodeWithSignature("setOwner(address)", address(0xBAD));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), address(0xCAFE), 0, data, nonce, deadline);

        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), address(0xCAFE), 0, data, sig, deadline);
    }

    function test_Bundle_DisabledDomain_RejectsThatDomain() public {
        // "Conservative Yield Bundle": transfers enabled, swaps + borrows disabled
        // (empty allowlists for swap routers and borrow protocols → both reject)
        _attachConservativeYieldBundle(address(safe));

        // Transfer should pass
        bytes memory transferData = abi.encodeWithSignature(
            "transfer(address,uint256)", BENEFICIARY, uint256(500e6)
        );
        _dispatch(address(safe), USDC, 0, transferData);
        assertEq(safe.callCount(), 1);

        // Swap should fail — empty router allowlist
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 1 ether, 0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, swapData, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, swapData, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Per-domain bounds enforcement
    // ─────────────────────────────────────────────────────────────────────────

    function test_Bundle_Swap_OverCap_Blocked() public {
        _attachActiveTradingBundle(address(safe));

        // active bundle swap cap is 5 ETH
        bytes memory data = _v3Swap(WETH, USDC, address(safe), 10 ether, 0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, data, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, data, sig, deadline);
    }

    function test_Bundle_Borrow_OverLtv_Blocked() public {
        _attachActiveTradingBundle(address(safe));
        // ltvBps = 8_000 * 1 * 10_000 / 10_000 = 8_000 bps > 7_500 cap
        bytes memory data = _aaveBorrow(USDC, 8_000, address(safe));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), AAVE_V3_POOL, 0, data, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), AAVE_V3_POOL, 0, data, sig, deadline);
    }

    function test_Bundle_Transfer_NonWhitelistedRecipient_Blocked() public {
        _attachActiveTradingBundle(address(safe));
        bytes memory data = abi.encodeWithSignature(
            "transfer(address,uint256)", address(0xBADD00D), uint256(100e6)
        );
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), USDC, 0, data, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), USDC, 0, data, sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Multi-account: same bundle deployment, different configs per Safe
    // ─────────────────────────────────────────────────────────────────────────

    function test_Bundle_MultiAccount_DifferentBundlesPerSafe() public {
        // Safe A: Active Trading Bundle — swap + borrow + transfer all open
        _attachActiveTradingBundle(address(safe));
        // Safe B: Conservative Yield Bundle — only transfers
        _attachConservativeYieldBundle(address(safeB));

        // Safe A can swap
        _dispatch(address(safe), UNI_V3_ROUTER, 0, _v3Swap(WETH, USDC, address(safe), 2 ether, 0));

        // Safe B cannot swap (no routers in its config)
        bytes memory dataB = _v3Swap(WETH, USDC, address(safeB), 1 ether, 0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(address(safeB));
        bytes memory sig = _signDispatch(address(safeB), address(bundle), UNI_V3_ROUTER, 0, dataB, nonce, deadline);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safeB), address(bundle), UNI_V3_ROUTER, 0, dataB, sig, deadline);

        // But Safe B can still transfer
        _dispatch(address(safeB), USDC, 0,
            abi.encodeWithSignature("transfer(address,uint256)", BENEFICIARY, uint256(100e6)));
    }

    function test_Bundle_Reconfigure_TightensOneDomain() public {
        _attachActiveTradingBundle(address(safe));

        // Initially swap of 4 ETH works
        _dispatch(address(safe), UNI_V3_ROUTER, 0,
            _v3Swap(WETH, USDC, address(safe), 4 ether, 0));

        // Reconfigure: tighten swap cap to 1 ETH, leave borrow & transfer untouched
        bytes memory newParams = _bundleParams(
            _swapCfg(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC), 1 ether, 0, address(0)),
            _borrowCfg(_one(AAVE_V3_POOL), _one(USDC), 10_000, 7_500, address(colOracle), address(borOracle)),
            _transferCfg(_one(BENEFICIARY), _one(USDC))
        );
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(bundle, address(safe), newParams, deadline, PERM_SIGNER_KEY);
        factory.reconfigure(address(safe), address(bundle), newParams, deadline, cfgSig);

        // 4 ETH swap now blocked
        bytes memory data = _v3Swap(WETH, USDC, address(safe), 4 ether, 0);
        uint256 dl = block.timestamp + 1 hours;
        uint256 nonce = kernel.managerNonces(address(safe));
        bytes memory sig = _signDispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, data, nonce, dl);
        vm.expectRevert(
            abi.encodeWithSelector(SailKernel.PermissionDenied.selector, address(bundle))
        );
        kernel.dispatch(address(safe), address(bundle), UNI_V3_ROUTER, 0, data, sig, dl);

        // But transfer still works (untouched config)
        _dispatch(address(safe), USDC, 0,
            abi.encodeWithSignature("transfer(address,uint256)", BENEFICIARY, uint256(100e6)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Gas check: evaluate() must fit under the kernel's 100k staticcall cap
    // ─────────────────────────────────────────────────────────────────────────

    function test_Bundle_EvaluateGas_UnderCap() public {
        _attachActiveTradingBundle(address(safe));

        // Measure evaluate() gas for each domain.
        Context memory ctxSwap = Context({
            account: address(safe), manager: manager, submitter: manager, target: UNI_V3_ROUTER,
            selector: 0x414bf389, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number
        });
        bytes memory swapData = _v3Swap(WETH, USDC, address(safe), 1 ether, 0);

        uint256 g0 = gasleft();
        bool okSwap = bundle.evaluate(swapData, ctxSwap);
        uint256 swapGas = g0 - gasleft();

        Context memory ctxBorrow = Context({
            account: address(safe), manager: manager, submitter: manager, target: AAVE_V3_POOL,
            selector: bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)")), value: 0,
            blockTimestamp: block.timestamp, blockNumber: block.number
        });
        bytes memory borrowData = _aaveBorrow(USDC, 1_000, address(safe));
        g0 = gasleft();
        bool okBorrow = bundle.evaluate(borrowData, ctxBorrow);
        uint256 borrowGas = g0 - gasleft();

        Context memory ctxTransfer = Context({
            account: address(safe), manager: manager, submitter: manager, target: USDC,
            selector: 0xa9059cbb, value: 0, blockTimestamp: block.timestamp, blockNumber: block.number
        });
        bytes memory transferData = abi.encodeWithSignature(
            "transfer(address,uint256)", BENEFICIARY, uint256(100e6)
        );
        g0 = gasleft();
        bool okTransfer = bundle.evaluate(transferData, ctxTransfer);
        uint256 transferGas = g0 - gasleft();

        emit log_named_uint("swap evaluate gas",     swapGas);
        emit log_named_uint("borrow evaluate gas",   borrowGas);
        emit log_named_uint("transfer evaluate gas", transferGas);

        assertTrue(okSwap     && swapGas     < 100_000, "swap eval over cap");
        assertTrue(okBorrow   && borrowGas   < 100_000, "borrow eval over cap");
        assertTrue(okTransfer && transferGas < 100_000, "transfer eval over cap");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Bundle profiles (would be canonical curated configurations off-chain)
    // ─────────────────────────────────────────────────────────────────────────

    function _attachActiveTradingBundle(address account) internal {
        // Oracle setup so LTV math is well-formed: colValue=10_000, borPrice=1
        colOracle.set(account, address(0), 10_000, 0);
        borOracle.set(USDC,    address(0), 1, 0);

        bytes memory params = _bundleParams(
            _swapCfg(_one(UNI_V3_ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0)),
            _borrowCfg(_one(AAVE_V3_POOL), _one(USDC), 10_000, 7_500, address(colOracle), address(borOracle)),
            _transferCfg(_one(BENEFICIARY), _one(USDC))
        );
        _attachBundle(account, params);
    }

    function _attachConservativeYieldBundle(address account) internal {
        // Only transfers permitted. Swap and borrow allowlists empty.
        bytes memory params = _bundleParams(
            _swapCfg(_empty(), _empty(), _empty(), 0, 0, address(0)),
            _borrowCfg(_empty(), _empty(), 0, 0, address(0), address(0)),
            _transferCfg(_one(BENEFICIARY), _one(USDC))
        );
        _attachBundle(account, params);
    }

    function _attachBundle(address account, bytes memory params) internal {
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(bundle, account, params, deadline, PERM_SIGNER_KEY);
        uint256 sigNonce = kernel.signerNonces(account);
        uint256 kDeadline = block.timestamp + 1 days;
        bytes memory kSig = _signRegisterPermission(account, address(bundle), sigNonce);
        uint256 fee = _calcFee(address(bundle));
        factory.attach{value: fee}(account, address(bundle), params, deadline, cfgSig, kDeadline, kSig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Encoding helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _bundleParams(
        SharedDeFiBundlePermission.SwapConfig memory swap,
        SharedDeFiBundlePermission.BorrowConfig memory borrow,
        SharedDeFiBundlePermission.TransferConfig memory transfer
    ) internal pure returns (bytes memory) {
        return abi.encode(swap, borrow, transfer);
    }

    function _swapCfg(
        address[] memory routers,
        address[] memory tokensIn,
        address[] memory tokensOut,
        uint256 cap,
        uint256 slippageBps,
        address oracle
    ) internal pure returns (SharedDeFiBundlePermission.SwapConfig memory) {
        return SharedDeFiBundlePermission.SwapConfig({
            routers: routers,
            tokensIn: tokensIn,
            tokensOut: tokensOut,
            maxAmountPerTx: cap,
            maxSlippageBps: slippageBps,
            priceOracle: oracle,
            maxPriceAgeSec: 3600
        });
    }

    function _borrowCfg(
        address[] memory protocols,
        address[] memory assets,
        uint256 cap,
        uint256 maxLtvBps,
        address col,
        address bor
    ) internal pure returns (SharedDeFiBundlePermission.BorrowConfig memory) {
        return SharedDeFiBundlePermission.BorrowConfig({
            protocols: protocols,
            assets: assets,
            maxAmountPerTx: cap,
            maxLtvBps: maxLtvBps,
            collateralOracle: col,
            borrowOracle: bor,
            maxPriceAgeSec: 3600
        });
    }

    function _transferCfg(
        address[] memory recipients,
        address[] memory tokens
    ) internal pure returns (SharedDeFiBundlePermission.TransferConfig memory) {
        return SharedDeFiBundlePermission.TransferConfig({
            recipients: recipients,
            tokens: tokens,
            maxAmountPerTx: type(uint256).max
        });
    }

    function _dispatch(address account, address target, uint256 value, bytes memory data) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.managerNonces(account);
        bytes memory sig = _signDispatch(account, address(bundle), target, value, data, nonce, deadline);
        kernel.dispatch(account, address(bundle), target, value, data, sig, deadline);
    }

    function _v3Swap(
        address tokenIn, address tokenOut, address recipient,
        uint256 amountIn, uint256 amountOutMin
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

    function _empty() internal pure returns (address[] memory) {
        return new address[](0);
    }
}

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
