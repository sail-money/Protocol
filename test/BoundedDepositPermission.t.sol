// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                    from "forge-std/Test.sol";
import {BoundedDepositPermission} from "../contracts/templates/BoundedDepositPermission.sol";
import {Context}                 from "../contracts/interfaces/IPermission.sol";

contract BoundedDepositPermissionTest is Test {
    BoundedDepositPermission perm;

    address constant SAFE     = address(0x5AFE);
    address constant PROTOCOL = address(0xA11E);
    address constant VAULT    = address(0xBA17);
    address constant TOKEN_A  = address(0xAAAA);
    address constant TOKEN_B  = address(0xBBBB);
    address constant SIGNER   = address(0x5161);
    address constant STRANGER = address(0x9999);

    uint256 constant MAX_AMOUNT = 1_000e18;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory targets = new address[](2);
        targets[0] = PROTOCOL;
        targets[1] = VAULT;

        address[] memory tokens = new address[](2);
        tokens[0] = TOKEN_A;
        tokens[1] = TOKEN_B;

        perm = new BoundedDepositPermission();
        perm.initialize(targets, tokens, MAX_AMOUNT, SIGNER);
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

    function _depositSimple(uint256 amount, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("deposit(uint256,address)", amount, receiver);
    }

    function _depositAave(address asset, uint256 amount, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "deposit(address,uint256,address,uint16)", asset, amount, onBehalfOf, uint16(0)
        );
    }

    function _mint(uint256 shares, address receiver) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("mint(uint256,address)", shares, receiver);
    }

    function _supply(address asset, uint256 amount, address onBehalfOf) internal pure returns (bytes memory) {
        return abi.encodeWithSignature(
            "supply(address,uint256,address,uint16)", asset, amount, onBehalfOf, uint16(0)
        );
    }

    // ── constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsPermissionSigner() public view {
        assertEq(perm.permissionSigner(), SIGNER);
    }

    function test_Constructor_SetsMaxAmount() public view {
        assertEq(perm.maxAmountPerTx(), MAX_AMOUNT);
    }

    function test_Constructor_RegistersTargets() public view {
        assertTrue(perm.isAllowedTarget(PROTOCOL));
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
        BoundedDepositPermission _tmp = new BoundedDepositPermission();
        vm.expectRevert(BoundedDepositPermission.ZeroAddress.selector);
        _tmp.initialize(empty, empty, MAX_AMOUNT, address(0));
    }

    // ── discriminator ─────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedDepositPermission"));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Golden paths — one per supported selector
    // ═════════════════════════════════════════════════════════════════════════

    function test_DepositSimple_GoldenPath() public view {
        bytes memory data = _depositSimple(100e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositSimple_ExactlyAtCap() public view {
        bytes memory data = _depositSimple(MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositSimple_ZeroAmount() public view {
        bytes memory data = _depositSimple(0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositSimple_WorksForBothAllowedTargets() public view {
        bytes memory data = _depositSimple(1e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
        assertTrue(perm.evaluate(data, _ctx(VAULT,    data)));
    }

    function test_DepositAave_GoldenPath() public view {
        bytes memory data = _depositAave(TOKEN_A, 500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_DepositAave_ExactlyAtCap() public view {
        bytes memory data = _depositAave(TOKEN_A, MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_DepositAave_TokenB() public view {
        bytes memory data = _depositAave(TOKEN_B, 200e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_DepositAave_AnyReferralCode() public view {
        bytes memory data0 = abi.encodeWithSignature(
            "deposit(address,uint256,address,uint16)", TOKEN_A, 1e18, SAFE, uint16(0)
        );
        bytes memory data1 = abi.encodeWithSignature(
            "deposit(address,uint256,address,uint16)", TOKEN_A, 1e18, SAFE, uint16(65535)
        );
        assertTrue(perm.evaluate(data0, _ctx(PROTOCOL, data0)));
        assertTrue(perm.evaluate(data1, _ctx(PROTOCOL, data1)));
    }

    function test_Mint_GoldenPath() public view {
        bytes memory data = _mint(300e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Mint_ExactlyAtCap() public view {
        bytes memory data = _mint(MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Mint_ZeroShares() public view {
        bytes memory data = _mint(0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Supply_GoldenPath() public view {
        bytes memory data = _supply(TOKEN_A, 750e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_Supply_ExactlyAtCap() public view {
        bytes memory data = _supply(TOKEN_B, MAX_AMOUNT, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Wrong target blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_DepositSimple_WrongTarget() public view {
        bytes memory data = _depositSimple(100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_DepositAave_WrongTarget() public view {
        bytes memory data = _depositAave(TOKEN_A, 100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_Mint_WrongTarget() public view {
        bytes memory data = _mint(100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_Supply_WrongTarget() public view {
        bytes memory data = _supply(TOKEN_A, 100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function testFuzz_WrongTarget_AllSelectors(address target) public view {
        vm.assume(target != PROTOCOL && target != VAULT);
        bytes memory d1 = _depositSimple(1e18, SAFE);
        bytes memory d2 = _depositAave(TOKEN_A, 1e18, SAFE);
        bytes memory d3 = _mint(1e18, SAFE);
        bytes memory d4 = _supply(TOKEN_A, 1e18, SAFE);
        assertFalse(perm.evaluate(d1, _ctx(target, d1)));
        assertFalse(perm.evaluate(d2, _ctx(target, d2)));
        assertFalse(perm.evaluate(d3, _ctx(target, d3)));
        assertFalse(perm.evaluate(d4, _ctx(target, d4)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Non-allowlisted token blocked (Aave-style selectors only)
    // ═════════════════════════════════════════════════════════════════════════

    function test_DepositAave_UnknownToken() public view {
        bytes memory data = _depositAave(address(0xDEAD), 100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_Supply_UnknownToken() public view {
        bytes memory data = _supply(address(0xDEAD), 100e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function testFuzz_DepositAave_UnknownToken(address token) public view {
        vm.assume(token != TOKEN_A && token != TOKEN_B);
        bytes memory data = _depositAave(token, 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function testFuzz_Supply_UnknownToken(address token) public view {
        vm.assume(token != TOKEN_A && token != TOKEN_B);
        bytes memory data = _supply(token, 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_DepositSimple_NoTokenCheckNeeded() public view {
        bytes memory data = _depositSimple(1e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Mint_NoTokenCheckNeeded() public view {
        bytes memory data = _mint(1e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Amount over cap blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_DepositSimple_AmountOverCap() public view {
        bytes memory data = _depositSimple(MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositAave_AmountOverCap() public view {
        bytes memory data = _depositAave(TOKEN_A, MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_Mint_SharesOverCap() public view {
        bytes memory data = _mint(MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Supply_AmountOverCap() public view {
        bytes memory data = _supply(TOKEN_A, MAX_AMOUNT + 1, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function testFuzz_DepositSimple_AmountOverCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _depositSimple(MAX_AMOUNT + excess, SAFE);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function testFuzz_DepositSimple_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, MAX_AMOUNT);
        bytes memory data = _depositSimple(amount, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Wrong receiver blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_DepositSimple_WrongReceiver() public view {
        bytes memory data = _depositSimple(1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositAave_WrongOnBehalfOf() public view {
        bytes memory data = _depositAave(TOKEN_A, 1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_Mint_WrongReceiver() public view {
        bytes memory data = _mint(1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_Supply_WrongOnBehalfOf() public view {
        bytes memory data = _supply(TOKEN_A, 1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_DepositSimple_ReceiverIsZeroAddress() public view {
        bytes memory data = _depositSimple(1e18, address(0));
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function testFuzz_DepositSimple_WrongReceiver(address receiver) public view {
        vm.assume(receiver != SAFE);
        bytes memory data = _depositSimple(1e18, receiver);
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function testFuzz_DepositAave_WrongOnBehalfOf(address onBehalfOf) public view {
        vm.assume(onBehalfOf != SAFE);
        bytes memory data = _depositAave(TOKEN_A, 1e18, onBehalfOf);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Calldata edge cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_EmptyCalldata() public view {
        Context memory ctx = Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         VAULT,
            selector:       bytes4(0),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate("", ctx));
    }

    function test_SelectorOnly_NoArgs() public view {
        bytes memory data = abi.encodePacked(bytes4(keccak256("deposit(uint256,address)")));
        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositSimple_TooShort_67Bytes() public view {
        bytes memory full  = _depositSimple(1e18, SAFE);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(VAULT, full)));
    }

    function test_DepositSimple_ExactlyMinLength_68Bytes() public view {
        bytes memory data = _depositSimple(1e18, SAFE);
        assertEq(data.length, 68);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_DepositAave_TooShort_131Bytes() public view {
        bytes memory full  = _depositAave(TOKEN_A, 1e18, SAFE);
        bytes memory short_ = new bytes(131);
        for (uint256 i; i < 131; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(PROTOCOL, full)));
    }

    function test_DepositAave_ExactlyMinLength_132Bytes() public view {
        bytes memory data = _depositAave(TOKEN_A, 1e18, SAFE);
        assertEq(data.length, 132);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_Mint_TooShort_67Bytes() public view {
        bytes memory full  = _mint(1e18, SAFE);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(VAULT, full)));
    }

    function test_Supply_TooShort_131Bytes() public view {
        bytes memory full  = _supply(TOKEN_A, 1e18, SAFE);
        bytes memory short_ = new bytes(131);
        for (uint256 i; i < 131; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(PROTOCOL, full)));
    }

    function test_UnknownSelector_Approve() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", PROTOCOL, MAX_AMOUNT);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_UnknownSelector_Withdraw() public view {
        bytes memory data = abi.encodeWithSignature("withdraw(uint256,address,address)", 1e18, SAFE, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(
            sel != bytes4(keccak256("deposit(uint256,address)")) &&
            sel != bytes4(keccak256("deposit(address,uint256,address,uint16)")) &&
            sel != bytes4(keccak256("mint(uint256,address)")) &&
            sel != bytes4(keccak256("supply(address,uint256,address,uint16)"))
        );
        bytes memory data = abi.encodePacked(sel, abi.encode(TOKEN_A, MAX_AMOUNT, SAFE, uint256(0)));
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
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
        emit BoundedDepositPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedDepositPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function testFuzz_SetMaxAmountPerTx_RevertsForNonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedDepositPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    function test_SetMaxAmountPerTx_TakesEffectOnEvaluate_DepositSimple() public {
        bytes memory data = _depositSimple(500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(VAULT, data)));
    }

    function test_SetMaxAmountPerTx_TakesEffectOnEvaluate_DepositAave() public {
        bytes memory data = _depositAave(TOKEN_A, 500e18, SAFE);
        assertTrue(perm.evaluate(data, _ctx(PROTOCOL, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_SetMaxAmountPerTx_ToZero_BlocksAllNonZero() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        assertFalse(perm.evaluate(_depositSimple(1, SAFE),        _ctx(VAULT,    _depositSimple(1, SAFE))));
        assertFalse(perm.evaluate(_depositAave(TOKEN_A, 1, SAFE), _ctx(PROTOCOL, _depositAave(TOKEN_A, 1, SAFE))));
        assertFalse(perm.evaluate(_mint(1, SAFE),                 _ctx(VAULT,    _mint(1, SAFE))));
        assertFalse(perm.evaluate(_supply(TOKEN_A, 1, SAFE),      _ctx(PROTOCOL, _supply(TOKEN_A, 1, SAFE))));
    }

    function test_SetMaxAmountPerTx_ToZero_AllowsZeroAmount() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory data = _depositSimple(0, SAFE);
        assertTrue(perm.evaluate(data, _ctx(VAULT, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Combined failures
    // ═════════════════════════════════════════════════════════════════════════

    function test_AllViolated_DepositAave() public view {
        bytes memory data = _depositAave(address(0xDEAD), MAX_AMOUNT + 1, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, data)));
    }

    function test_CorrectTarget_WrongToken_CorrectReceiver_DepositAave() public view {
        bytes memory data = _depositAave(address(0xDEAD), 1e18, SAFE);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    function test_CorrectTarget_CorrectToken_WrongReceiver_DepositAave() public view {
        bytes memory data = _depositAave(TOKEN_A, 1e18, STRANGER);
        assertFalse(perm.evaluate(data, _ctx(PROTOCOL, data)));
    }

    // ── mint: cap is on shares, not underlying assets (documented behaviour) ──
    // This demonstrates that at a high share price, the effective asset cap is
    // maxAmountPerTx × sharePrice, not maxAmountPerTx tokens.

    function test_Mint_CapIsOnSharesNotAssets() public view {
        // Cap = MAX_AMOUNT shares. If 1 share = 1000 underlying tokens, then
        // this permission allows depositing up to MAX_AMOUNT × 1000 underlying tokens.
        // The permission evaluates `shares <= maxAmountPerTx` — share price not checked.
        bytes memory dataAtCap   = _mint(MAX_AMOUNT, SAFE);
        bytes memory dataOverCap = _mint(MAX_AMOUNT + 1, SAFE);

        assertTrue(perm.evaluate(dataAtCap,   _ctx(PROTOCOL, dataAtCap)));
        assertFalse(perm.evaluate(dataOverCap, _ctx(PROTOCOL, dataOverCap)));
    }

    function testFuzz_Mint_ShareCapEnforced(uint256 shares) public view {
        // Regardless of underlying share price, the cap is strictly on the shares value.
        bool expected = shares <= MAX_AMOUNT;
        bytes memory data = _mint(shares, SAFE);
        assertEq(perm.evaluate(data, _ctx(PROTOCOL, data)), expected);
    }
}
