// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import {BoundedApprovePermission} from "../contracts/templates/BoundedApprovePermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";
import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

contract BoundedApprovePermissionTest is Test {
    BoundedApprovePermission internal perm;

    address constant SAFE         = address(0xA11);
    address constant MANAGER      = address(0xB22);
    address constant PERM_SIGNER  = address(0xC33);

    address constant USDC          = address(0x1111);
    address constant WETH          = address(0x2222);
    address constant DAI           = address(0x3333);

    address constant UNI_ROUTER    = address(0x4001);
    address constant AAVE_POOL     = address(0x4002);
    address constant ATTACKER      = address(0xDEAD);

    uint256 constant CAP           = 1_000_000e6; // 1M USDC

    function setUp() public {
        address[] memory tokens   = new address[](2);
        tokens[0] = USDC;  tokens[1] = WETH;
        address[] memory spenders = new address[](2);
        spenders[0] = UNI_ROUTER; spenders[1] = AAVE_POOL;
        perm = BoundedApprovePermission(Clones.clone(address(new BoundedApprovePermission())));
        perm.initialize(tokens, spenders, CAP, PERM_SIGNER);
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    function _approve(address spender, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("approve(address,uint256)", spender, amount);
    }

    function _ctx(address target, bytes memory data) internal pure returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        MANAGER,
            submitter:      MANAGER,
            target:         target,
            selector:       data.length >= 4 ? bytes4(data) : bytes4(0),
            value:          0,
            blockTimestamp: 1,
            blockNumber:    1
        });
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_Constructor_RegistersAllowlists() public view {
        assertTrue(perm.isAllowedToken(USDC));
        assertTrue(perm.isAllowedToken(WETH));
        assertFalse(perm.isAllowedToken(DAI));
        assertTrue(perm.isAllowedSpender(UNI_ROUTER));
        assertTrue(perm.isAllowedSpender(AAVE_POOL));
        assertFalse(perm.isAllowedSpender(ATTACKER));
        assertEq(perm.maxAmountPerTx(), CAP);
        assertEq(perm.permissionSigner(), PERM_SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory empty;
        BoundedApprovePermission _tmp = BoundedApprovePermission(Clones.clone(address(new BoundedApprovePermission())));
        vm.expectRevert(BoundedApprovePermission.ZeroAddress.selector);
        _tmp.initialize(empty, empty, 0, address(0));
    }

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedApprovePermission"));
    }

    // -------------------------------------------------------------------------
    // Happy paths
    // -------------------------------------------------------------------------

    function test_Allowed_USDC_To_UniRouter_AtCap() public view {
        bytes memory data = _approve(UNI_ROUTER, CAP);
        assertTrue(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Allowed_WETH_To_AavePool() public view {
        // CAP is in USDC units (6 decimals); use a WETH amount well below 1e12 wei.
        bytes memory data = _approve(AAVE_POOL, 1_000_000);
        assertTrue(perm.evaluate(data, _ctx(WETH, data)));
    }

    function test_Allowed_Revoke_AmountZero() public view {
        bytes memory data = _approve(UNI_ROUTER, 0);
        assertTrue(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Allowed_InfiniteApproval_WhenCapIsMax() public {
        // Reset perm with infinite cap.
        address[] memory tokens   = new address[](1); tokens[0]   = USDC;
        address[] memory spenders = new address[](1); spenders[0] = UNI_ROUTER;
        BoundedApprovePermission infinitePerm = BoundedApprovePermission(Clones.clone(address(new BoundedApprovePermission())));
        infinitePerm.initialize(tokens, spenders, type(uint256).max, PERM_SIGNER);
        bytes memory data = _approve(UNI_ROUTER, type(uint256).max);
        assertTrue(infinitePerm.evaluate(data, _ctx(USDC, data)));
    }

    // -------------------------------------------------------------------------
    // Custody-relevant denials (these are the real-money safety properties)
    // -------------------------------------------------------------------------

    function test_Denied_ApproveAttackerSpender() public view {
        bytes memory data = _approve(ATTACKER, 1e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Denied_NonAllowlistedToken() public view {
        bytes memory data = _approve(UNI_ROUTER, 1e6);
        assertFalse(perm.evaluate(data, _ctx(DAI, data)));
    }

    function test_Denied_AmountAboveCap() public view {
        bytes memory data = _approve(UNI_ROUTER, CAP + 1);
        assertFalse(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Denied_WrongSelector_Transfer() public view {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", UNI_ROUTER, 1e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Denied_WrongSelector_TransferFrom() public view {
        bytes memory data = abi.encodeWithSignature(
            "transferFrom(address,address,uint256)", SAFE, ATTACKER, 1e6
        );
        assertFalse(perm.evaluate(data, _ctx(USDC, data)));
    }

    function test_Denied_ApproveAttackerSpender_OnAllowedToken() public view {
        // Combined attack: allowed token, attacker spender. Must deny on spender alone.
        bytes memory data = _approve(ATTACKER, 1e6);
        assertFalse(perm.evaluate(data, _ctx(WETH, data)));
    }

    function test_Denied_AllowedSpender_OnDisallowedToken() public view {
        // Combined attack: disallowed token, allowed spender. Must deny on token alone.
        bytes memory data = _approve(UNI_ROUTER, 1e6);
        assertFalse(perm.evaluate(data, _ctx(DAI, data)));
    }

    function test_Denied_TruncatedCalldata() public view {
        bytes memory full = _approve(UNI_ROUTER, 1e6);
        bytes memory shortBuf = new bytes(67);
        for (uint256 i; i < 67; i++) shortBuf[i] = full[i];
        assertFalse(perm.evaluate(shortBuf, _ctx(USDC, full)));
    }

    function test_CapZero_StillAllowsRevocation() public {
        // Setting cap to 0 stops new (non-zero) approvals but keeps amount=0
        // revocations working — a useful safety knob for operators who want to
        // freeze further authorisations without losing the ability to revoke.
        vm.prank(PERM_SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory revoke = _approve(UNI_ROUTER, 0);
        assertTrue(perm.evaluate(revoke, _ctx(USDC, revoke)));

        bytes memory nonZero = _approve(UNI_ROUTER, 1);
        assertFalse(perm.evaluate(nonZero, _ctx(USDC, nonZero)));
    }

    // -------------------------------------------------------------------------
    // Setters
    // -------------------------------------------------------------------------

    function test_SetMaxAmount_OnlySigner() public {
        vm.expectRevert(BoundedApprovePermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);

        vm.prank(PERM_SIGNER);
        perm.setMaxAmountPerTx(42);
        assertEq(perm.maxAmountPerTx(), 42);
    }

    function test_SetMaxAmount_EmitsEvent() public {
        vm.expectEmit(true, true, true, true);
        emit BoundedApprovePermission.MaxAmountUpdated(CAP, 7);
        vm.prank(PERM_SIGNER);
        perm.setMaxAmountPerTx(7);
    }

    // -------------------------------------------------------------------------
    // Fuzz
    // -------------------------------------------------------------------------

    function testFuzz_DenyUnknownSelectors(bytes4 sel) public view {
        vm.assume(sel != 0x095ea7b3);
        bytes memory data = abi.encodePacked(sel, abi.encode(UNI_ROUTER, uint256(1)));
        Context memory ctx = _ctx(USDC, data);
        assertFalse(perm.evaluate(data, ctx));
    }

    function testFuzz_RandomSpenderDenied(address randomSpender) public view {
        vm.assume(randomSpender != UNI_ROUTER && randomSpender != AAVE_POOL);
        bytes memory data = _approve(randomSpender, 1);
        assertFalse(perm.evaluate(data, _ctx(USDC, data)));
    }

    function testFuzz_RandomTokenDenied(address randomToken) public view {
        vm.assume(randomToken != USDC && randomToken != WETH);
        bytes memory data = _approve(UNI_ROUTER, 1);
        assertFalse(perm.evaluate(data, _ctx(randomToken, data)));
    }

    function testFuzz_AmountBoundary(uint256 amount) public view {
        bytes memory data = _approve(UNI_ROUTER, amount);
        bool expected = amount <= CAP;
        assertEq(perm.evaluate(data, _ctx(USDC, data)), expected);
    }
}
