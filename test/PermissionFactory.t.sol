// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "./support/FactoryTestBase.sol";
import "../contracts/templates/shared/SharedBoundedSwapPermission.sol";
import "../contracts/templates/shared/SharedTransferTargetPermission.sol";

contract PermissionFactoryTest is FactoryTestBase {
    SharedBoundedSwapPermission         internal swap;
    SharedTransferTargetPermission       internal transfer;

    address constant ROUTER = address(0xCC01);
    address constant WETH   = address(0xCC02);
    address constant USDC   = address(0xCC03);
    address constant RECIPIENT = address(0xDEAD);

    function setUp() public override {
        super.setUp();
        swap     = new SharedBoundedSwapPermission(address(kernel));
        transfer = new SharedTransferTargetPermission(address(kernel));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // attach: configure + register, one tx
    // ─────────────────────────────────────────────────────────────────────────

    function test_Attach_GoldenPath() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;

        bytes memory cfgSig = _signConfigure(swap, address(safe), params, deadline, PERM_SIGNER_KEY);
        bytes memory kSig   = _signRegisterPermission(address(safe), address(swap), 0);

        uint256 fee = _calcFee(address(swap));
        factory.attach{value: fee}(
            address(safe), address(swap), params, deadline, cfgSig, kSig
        );

        assertTrue(kernel.isPermissionRegistered(address(safe), address(swap)));
        assertTrue(swap.isConfigured(address(safe)));
        assertEq(swap.configNonces(address(safe)), 1);
        assertTrue(swap.isAllowedRouter(address(safe), ROUTER));
        assertTrue(swap.isAllowedTokenIn(address(safe), WETH));
        assertTrue(swap.isAllowedTokenOut(address(safe), USDC));
    }

    function test_Attach_ExcessRefunded() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params, deadline, PERM_SIGNER_KEY);
        bytes memory kSig   = _signRegisterPermission(address(safe), address(swap), 0);

        uint256 fee = _calcFee(address(swap));
        uint256 overpay = fee + 1 ether;
        uint256 before_ = address(this).balance;

        factory.attach{value: overpay}(
            address(safe), address(swap), params, deadline, cfgSig, kSig
        );

        assertEq(before_ - address(this).balance, fee, "net cost should equal fee");
    }

    function test_Attach_BadConfigSig_Reverts() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        // Sign with the manager key instead of permSigner key — invalid for configure
        bytes memory badCfgSig = _signConfigure(swap, address(safe), params, deadline, MANAGER_KEY);
        bytes memory kSig     = _signRegisterPermission(address(safe), address(swap), 0);

        uint256 fee = _calcFee(address(swap));
        vm.expectRevert(BaseSharedPermission.InvalidSignature.selector);
        factory.attach{value: fee}(
            address(safe), address(swap), params, deadline, badCfgSig, kSig
        );
    }

    function test_Attach_ExpiredDeadline_Reverts() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params, deadline, PERM_SIGNER_KEY);
        bytes memory kSig   = _signRegisterPermission(address(safe), address(swap), 0);

        vm.warp(deadline + 1);
        uint256 fee = _calcFee(address(swap));
        vm.expectRevert(
            abi.encodeWithSelector(BaseSharedPermission.DeadlineExpired.selector, deadline, block.timestamp)
        );
        factory.attach{value: fee}(
            address(safe), address(swap), params, deadline, cfgSig, kSig
        );
    }

    function test_Attach_ReplayConfigureSig_Reverts() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params, deadline, PERM_SIGNER_KEY);
        bytes memory kSig   = _signRegisterPermission(address(safe), address(swap), 0);

        uint256 fee = _calcFee(address(swap));
        factory.attach{value: fee}(address(safe), address(swap), params, deadline, cfgSig, kSig);

        // Replay with same configure sig — template's nonce has advanced, so sig is stale
        bytes memory kSig2 = _signRegisterPermission(address(safe), address(swap), 1);
        vm.expectRevert(BaseSharedPermission.InvalidSignature.selector);
        factory.attach{value: fee}(address(safe), address(swap), params, deadline, cfgSig, kSig2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // reconfigure: update params without re-registering
    // ─────────────────────────────────────────────────────────────────────────

    function test_Reconfigure_UpdatesParams() public {
        // Initial attach
        _attachSwap(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));

        // Reconfigure with new cap + add a token
        address WBTC = address(0xCC04);
        address[] memory tokensOut = new address[](2);
        tokensOut[0] = USDC;
        tokensOut[1] = WBTC;

        bytes memory params2 = _swapParams(_one(ROUTER), _one(WETH), tokensOut, 20 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params2, deadline, PERM_SIGNER_KEY);

        factory.reconfigure(address(safe), address(swap), params2, deadline, cfgSig);

        assertTrue(swap.isAllowedTokenOut(address(safe), WBTC), "new token should be allowed");
        assertTrue(swap.isAllowedTokenOut(address(safe), USDC), "old token still allowed");
        (,,,uint256 cap,,) = swap.getConfig(address(safe));
        assertEq(cap, 20 ether);
    }

    function test_Reconfigure_ClearsRemovedRouter() public {
        address ROUTER2 = address(0xCCAA);
        // First config: ROUTER
        _attachSwap(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        // Reconfigure: ROUTER2 only
        bytes memory params2 = _swapParams(_one(ROUTER2), _one(WETH), _one(USDC), 5 ether, 100, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params2, deadline, PERM_SIGNER_KEY);
        factory.reconfigure(address(safe), address(swap), params2, deadline, cfgSig);

        assertFalse(swap.isAllowedRouter(address(safe), ROUTER), "old router should be removed");
        assertTrue(swap.isAllowedRouter(address(safe), ROUTER2), "new router should be allowed");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // attachBatch: multiple templates in one tx, single kernel sig
    // ─────────────────────────────────────────────────────────────────────────

    function test_AttachBatch_TwoTemplates() public {
        bytes memory swapParams =
            _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0));
        bytes memory transferParams =
            abi.encode(_one(RECIPIENT), _one(USDC));

        uint256 deadline = block.timestamp + 1 hours;

        address[] memory templates = new address[](2);
        templates[0] = address(swap);
        templates[1] = address(transfer);

        bytes[] memory params = new bytes[](2);
        params[0] = swapParams;
        params[1] = transferParams;

        uint256[] memory deadlines = new uint256[](2);
        deadlines[0] = deadline;
        deadlines[1] = deadline;

        bytes[] memory cfgSigs = new bytes[](2);
        cfgSigs[0] = _signConfigure(swap, address(safe), swapParams, deadline, PERM_SIGNER_KEY);
        cfgSigs[1] = _signConfigure(transfer, address(safe), transferParams, deadline, PERM_SIGNER_KEY);

        bytes memory kSig = _signRegisterPermissions(address(safe), templates, 0, deadline);

        uint256 fee = _calcFee(address(swap)) + _calcFee(address(transfer));
        factory.attachBatch{value: fee}(
            address(safe), templates, params, deadlines, cfgSigs, deadline, kSig
        );

        assertTrue(kernel.isPermissionRegistered(address(safe), address(swap)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(transfer)));
        assertTrue(swap.isConfigured(address(safe)));
        assertTrue(transfer.isConfigured(address(safe)));
    }

    function test_AttachBatch_LengthMismatch_Reverts() public {
        address[] memory templates = new address[](2);
        bytes[] memory params      = new bytes[](1); // mismatch
        uint256[] memory deadlines = new uint256[](2);
        bytes[] memory cfgSigs     = new bytes[](2);

        vm.expectRevert(PermissionFactory.LengthMismatch.selector);
        factory.attachBatch{value: 0}(
            address(safe), templates, params, deadlines, cfgSigs, 0, ""
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // replace: swap one template for another atomically
    // ─────────────────────────────────────────────────────────────────────────

    function test_Replace_OldRemovedNewActive() public {
        _attachSwap(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(swap)));

        // Deploy a second swap permission (different bytecode address) and replace
        SharedBoundedSwapPermission swap2 = new SharedBoundedSwapPermission(address(kernel));
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 10 ether, 0, address(0));
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap2, address(safe), params, deadline, PERM_SIGNER_KEY);
        uint256 sigNonce = kernel.signerNonces(address(safe));
        bytes memory kSig = _signReplacePermission(address(safe), address(swap), address(swap2), sigNonce);

        uint256 fee = _calcFee(address(swap2));
        factory.replace{value: fee}(
            address(safe), address(swap), address(swap2), params, deadline, cfgSig, kSig
        );

        assertFalse(kernel.isPermissionRegistered(address(safe), address(swap)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(swap2)));
        assertTrue(swap2.isConfigured(address(safe)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // detach: revoke from kernel; config slot stays in template
    // ─────────────────────────────────────────────────────────────────────────

    function test_Detach_RemovesFromKernel_PreservesConfig() public {
        _attachSwap(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0));
        uint256 sigNonce = kernel.signerNonces(address(safe));
        bytes memory kSig = _signRevokePermission(address(safe), address(swap), sigNonce);

        factory.detach(address(safe), address(swap), kSig);

        assertFalse(kernel.isPermissionRegistered(address(safe), address(swap)));
        // Config slot remains
        assertTrue(swap.isConfigured(address(safe)));
        assertTrue(swap.isAllowedRouter(address(safe), ROUTER));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // configureDirect: permSigner is the caller (no factory, no sig)
    // ─────────────────────────────────────────────────────────────────────────

    function test_ConfigureDirect_FromPermissionSigner() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0));

        vm.prank(permSigner);
        swap.configureDirect(address(safe), params);

        assertTrue(swap.isConfigured(address(safe)));
        assertEq(swap.configNonces(address(safe)), 1);
    }

    function test_ConfigureDirect_NotPermissionSigner_Reverts() public {
        bytes memory params = _swapParams(_one(ROUTER), _one(WETH), _one(USDC), 5 ether, 0, address(0));
        vm.prank(address(0xBAD));
        vm.expectRevert();
        swap.configureDirect(address(safe), params);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _attachSwap(
        address[] memory routers,
        address[] memory tokensIn,
        address[] memory tokensOut,
        uint256 cap,
        uint256 slippageBps,
        address oracle
    ) internal {
        bytes memory params = _swapParams(routers, tokensIn, tokensOut, cap, slippageBps, oracle);
        uint256 deadline = block.timestamp + 1 hours;
        bytes memory cfgSig = _signConfigure(swap, address(safe), params, deadline, PERM_SIGNER_KEY);
        uint256 sigNonce = kernel.signerNonces(address(safe));
        bytes memory kSig = _signRegisterPermission(address(safe), address(swap), sigNonce);
        uint256 fee = _calcFee(address(swap));
        factory.attach{value: fee}(
            address(safe), address(swap), params, deadline, cfgSig, kSig
        );
    }

    function _swapParams(
        address[] memory routers,
        address[] memory tokensIn,
        address[] memory tokensOut,
        uint256 cap,
        uint256 slippageBps,
        address oracle
    ) internal pure returns (bytes memory) {
        return abi.encode(routers, tokensIn, tokensOut, cap, slippageBps, oracle);
    }

    function _one(address a) internal pure returns (address[] memory arr) {
        arr = new address[](1);
        arr[0] = a;
    }
}
