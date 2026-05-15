// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                   from "forge-std/Test.sol";
import {BoundedBorrowPermission} from "../contracts/templates/BoundedBorrowPermission.sol";
import {Context}                from "../contracts/interfaces/IPermission.sol";

contract BoundedBorrowPermissionTest is Test {
    BoundedBorrowPermission perm;

    address constant SAFE     = address(0x5AFE);
    address constant POOL     = address(0xA11E);
    address constant VAULT    = address(0xBA17);
    address constant TOKEN_A  = address(0xAAAA);
    address constant TOKEN_B  = address(0xBBBB);
    address constant SIGNER   = address(0x5161);
    address constant STRANGER = address(0x9999);

    uint256 constant MAX_AMOUNT = 1_000e18;

    bytes4 constant BORROW_AAVE   = bytes4(keccak256("borrow(address,uint256,uint256,uint16,address)"));
    bytes4 constant BORROW_SIMPLE = bytes4(keccak256("borrow(uint256,address)"));

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory targets = new address[](2);
        targets[0] = POOL;
        targets[1] = VAULT;

        address[] memory tokens = new address[](2);
        tokens[0] = TOKEN_A;
        tokens[1] = TOKEN_B;

        perm = new BoundedBorrowPermission(targets, tokens, MAX_AMOUNT, SIGNER);
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _sel(bytes memory data) internal pure returns (bytes4 s) {
        assembly { s := mload(add(data, 32)) }
    }

    function _ctx(address target, bytes memory data) internal view returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         target,
            selector:       _sel(data),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    function _ctxWithValue(address target, bytes memory data, uint256 val) internal view returns (Context memory) {
        Context memory c = _ctx(target, data);
        c.value = val;
        return c;
    }

    function _borrowAave(address asset, uint256 amount, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)", asset, amount, uint256(1), uint16(0), onBehalfOf
        );
    }

    function _borrowSimple(uint256 amount, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("borrow(uint256,address)", amount, receiver);
    }

    // ── constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsPermissionSigner() public view {
        assertEq(perm.permissionSigner(), SIGNER);
    }

    function test_Constructor_SetsMaxAmount() public view {
        assertEq(perm.maxAmountPerTx(), MAX_AMOUNT);
    }

    function test_Constructor_RegistersTargets() public view {
        assertTrue(perm.isAllowedTarget(POOL));
        assertTrue(perm.isAllowedTarget(VAULT));
        assertFalse(perm.isAllowedTarget(address(0xDEAD)));
    }

    function test_Constructor_RegistersTokens() public view {
        assertTrue(perm.isAllowedToken(TOKEN_A));
        assertTrue(perm.isAllowedToken(TOKEN_B));
        assertFalse(perm.isAllowedToken(address(0xDEAD)));
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory empty = new address[](0);
        vm.expectRevert(BoundedBorrowPermission.ZeroAddress.selector);
        new BoundedBorrowPermission(empty, empty, MAX_AMOUNT, address(0));
    }

    // ── discriminator ─────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedBorrowPermission"));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Golden paths — one per supported selector
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_GoldenPath() public view {
        bytes memory data = _borrowAave(TOKEN_A, 500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowAave_ExactlyAtCap() public view {
        bytes memory data = _borrowAave(TOKEN_A, MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowAave_ZeroAmount() public view {
        bytes memory data = _borrowAave(TOKEN_A, 0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowAave_TokenB() public view {
        bytes memory data = _borrowAave(TOKEN_B, 200e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowAave_AnyInterestRateMode() public view {
        bytes memory stable   = abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)", TOKEN_A, 1e18, uint256(1), uint16(0), SAFE
        );
        bytes memory variable = abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)", TOKEN_A, 1e18, uint256(2), uint16(0), SAFE
        );
        assertTrue(perm.evaluate(stable,   _ctx(POOL, stable)));
        assertTrue(perm.evaluate(variable, _ctx(POOL, variable)));
    }

    function test_BorrowAave_AnyReferralCode() public view {
        bytes memory code0 = abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)", TOKEN_A, 1e18, uint256(1), uint16(0),     SAFE
        );
        bytes memory code1 = abi.encodeWithSignature(
            "borrow(address,uint256,uint256,uint16,address)", TOKEN_A, 1e18, uint256(1), uint16(65535), SAFE
        );
        assertTrue(perm.evaluate(code0, _ctx(POOL, code0)));
        assertTrue(perm.evaluate(code1, _ctx(POOL, code1)));
    }

    function test_BorrowAave_WorksForBothAllowedTargets() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL,  data)));
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_BorrowSimple_GoldenPath() public view {
        bytes memory data = _borrowSimple(500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_BorrowSimple_ExactlyAtCap() public view {
        bytes memory data = _borrowSimple(MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_BorrowSimple_ZeroAmount() public view {
        bytes memory data = _borrowSimple(0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ETH value rejected
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_EthValueRejected() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctxWithValue(POOL, data, 1)));
    }

    function test_BorrowSimple_EthValueRejected() public view {
        bytes memory data = _borrowSimple(1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctxWithValue(VAULT, data, 1)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Wrong target blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_WrongTarget() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_BorrowSimple_WrongTarget() public view {
        bytes memory data = _borrowSimple(1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function testFuzz_WrongTarget_BothSelectors(address target) public view {
        vm.assume(target != POOL && target != VAULT);
        bytes memory d1 = _borrowAave(TOKEN_A, 1e18, SAFE);
        bytes memory d2 = _borrowSimple(1e18, SAFE);
        assertFalse(perm.evaluate(d1, _ctx(target, d1)));
        assertFalse(perm.evaluate(d2, _ctx(target, d2)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Non-allowlisted token blocked (Aave path only)
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_UnknownToken() public view {
        bytes memory data = _borrowAave(address(0xDEAD), 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function testFuzz_BorrowAave_UnknownToken(address token) public view {
        vm.assume(token != TOKEN_A && token != TOKEN_B);
        bytes memory data = _borrowAave(token, 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowSimple_NoTokenCheckNeeded() public view {
        // Token not in calldata — safety via allowedTargets trust model.
        bytes memory data = _borrowSimple(1e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Amount over cap blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_AmountOverCap() public view {
        bytes memory data = _borrowAave(TOKEN_A, MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowSimple_AmountOverCap() public view {
        bytes memory data = _borrowSimple(MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function testFuzz_BorrowAave_AmountOverCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _borrowAave(TOKEN_A, MAX_AMOUNT + excess, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function testFuzz_BorrowSimple_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, MAX_AMOUNT);
        bytes memory data = _borrowSimple(amount, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Wrong onBehalfOf / receiver blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_BorrowAave_WrongOnBehalfOf() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowSimple_WrongReceiver() public view {
        bytes memory data = _borrowSimple(1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function testFuzz_BorrowAave_WrongOnBehalfOf(address onBehalfOf) public view {
        vm.assume(onBehalfOf != SAFE);
        bytes memory data = _borrowAave(TOKEN_A, 1e18, onBehalfOf);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function testFuzz_BorrowSimple_WrongReceiver(address receiver) public view {
        vm.assume(receiver != SAFE);
        bytes memory data = _borrowSimple(1e18, receiver);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Calldata edge cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_EmptyCalldata() public view {
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         POOL,
            selector:       bytes4(0),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate("", ctx));
    }

    function test_BorrowAave_TooShort_163Bytes() public view {
        bytes memory full   = _borrowAave(TOKEN_A, 1e18, SAFE);
        bytes memory short_ = new bytes(163);
        for (uint256 i; i < 163; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(POOL, full)));
    }

    function test_BorrowAave_ExactlyMinLength_164Bytes() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, SAFE);
        assertEq(data.length, 164);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_BorrowSimple_TooShort_67Bytes() public view {
        bytes memory full   = _borrowSimple(1e18, SAFE);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(VAULT, full)));
    }

    function test_BorrowSimple_ExactlyMinLength_68Bytes() public view {
        bytes memory data = _borrowSimple(1e18, SAFE);
        assertEq(data.length, 68);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_UnknownSelector_Withdraw() public view {
        bytes memory data = abi.encodeWithSignature("withdraw(uint256,address,address)", 1e18, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_UnknownSelector_Repay() public view {
        bytes memory data = abi.encodeWithSignature("repay(address,uint256,uint256,address)", TOKEN_A, 1e18, 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != BORROW_AAVE && sel != BORROW_SIMPLE);
        bytes memory data = abi.encodePacked(sel, abi.encode(TOKEN_A, MAX_AMOUNT, SAFE, uint256(0)));
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
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
        emit BoundedBorrowPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function testFuzz_SetMaxAmountPerTx_RevertsForNonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedBorrowPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    function test_SetMaxAmountPerTx_TakesEffect_BorrowAave() public {
        bytes memory data = _borrowAave(TOKEN_A, 500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(POOL, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_SetMaxAmountPerTx_TakesEffect_BorrowSimple() public {
        bytes memory data = _borrowSimple(500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_SetMaxAmountPerTx_ToZero_BlocksAllNonZero() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        assertFalse(perm.evaluate(_borrowAave(TOKEN_A, 1, SAFE),   _ctx(POOL,  _borrowAave(TOKEN_A, 1, SAFE))));
        assertFalse(perm.evaluate(_borrowSimple(1, SAFE),           _ctx(VAULT, _borrowSimple(1, SAFE))));
    }

    function test_SetMaxAmountPerTx_ToZero_AllowsZeroAmount() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory data = _borrowSimple(0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Combined failures
    // ═════════════════════════════════════════════════════════════════════════

    function test_AllViolated_BorrowAave() public view {
        bytes memory data = _borrowAave(address(0xDEAD), MAX_AMOUNT + 1, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_CorrectTarget_WrongToken_CorrectOnBehalfOf() public view {
        bytes memory data = _borrowAave(address(0xDEAD), 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_CorrectTarget_CorrectToken_WrongOnBehalfOf() public view {
        bytes memory data = _borrowAave(TOKEN_A, 1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }

    function test_CorrectTarget_CorrectToken_OverCap_CorrectOnBehalfOf() public view {
        bytes memory data = _borrowAave(TOKEN_A, MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(POOL, data)));
    }
}
