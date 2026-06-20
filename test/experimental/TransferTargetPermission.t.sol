// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                    from "forge-std/Test.sol";
import {TransferTargetPermission} from "../../contracts/experimental/TransferTargetPermission.sol";
import {Context}                 from "../../contracts/interfaces/IPermission.sol";
import {Clones}                  from "@openzeppelin/contracts/proxy/Clones.sol";

contract TransferTargetPermissionTest is Test {
    TransferTargetPermission perm;

    address constant SAFE      = address(0x5AFE);
    address constant PARTNER   = address(0xC0DE);
    address constant CEX       = address(0xCEEE);
    address constant TOKEN_A   = address(0xAAAA);
    address constant TOKEN_B   = address(0xBBBB);
    address constant SIGNER    = address(0x5161);
    address constant STRANGER  = address(0x9999);
    address constant BAD_TOKEN = address(0xDEAD);

    uint256 constant MAX_AMOUNT = 1_000e18;

    bytes4 constant TRANSFER_SEL     = 0xa9059cbb;
    bytes4 constant TRANSFERFROM_SEL = 0x23b872dd;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory recipients = new address[](2);
        recipients[0] = PARTNER;
        recipients[1] = CEX;

        address[] memory tokens = new address[](2);
        tokens[0] = TOKEN_A;
        tokens[1] = TOKEN_B;

        perm = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        perm.initialize(recipients, tokens, MAX_AMOUNT, SIGNER);
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

    function _ctxEth(address recipient, uint256 val) internal view returns (Context memory) {
        return Context({
            account:        SAFE,
            manager:        address(0),
            submitter:      address(0),
            target:         recipient,
            selector:       bytes4(0),
            value:          val,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    function _ctxWithValue(address target, bytes memory data, uint256 val) internal view returns (Context memory) {
        Context memory c = _ctx(target, data);
        c.value = val;
        return c;
    }

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }

    function _transferFrom(address from, address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount);
    }

    // ── constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsPermissionSigner() public view {
        assertEq(perm.permissionSigner(), SIGNER);
    }

    function test_Constructor_SetsMaxAmount() public view {
        assertEq(perm.maxAmountPerTx(), MAX_AMOUNT);
    }

    function test_Constructor_RegistersRecipients() public view {
        assertTrue(perm.isAllowedRecipient(PARTNER));
        assertTrue(perm.isAllowedRecipient(CEX));
        assertFalse(perm.isAllowedRecipient(STRANGER));
    }

    function test_Constructor_RegistersTokens() public view {
        assertTrue(perm.isAllowedToken(TOKEN_A));
        assertTrue(perm.isAllowedToken(TOKEN_B));
        assertFalse(perm.isAllowedToken(BAD_TOKEN));
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory empty = new address[](0);
        TransferTargetPermission _tmp = TransferTargetPermission(Clones.clone(address(new TransferTargetPermission())));
        vm.expectRevert(TransferTargetPermission.ZeroAddress.selector);
        _tmp.initialize(empty, empty, MAX_AMOUNT, address(0));
    }

    // ── discriminator ─────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("TransferTargetPermission"));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Golden paths — transfer
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_GoldenPath_Partner() public view {
        bytes memory data = _transfer(PARTNER, 100e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_GoldenPath_Cex() public view {
        bytes memory data = _transfer(CEX, 200e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_B, data)));
    }

    function test_Transfer_ExactlyAtCap() public view {
        bytes memory data = _transfer(PARTNER, MAX_AMOUNT);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_ZeroAmount() public view {
        bytes memory data = _transfer(PARTNER, 0);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_WorksForBothTokens() public view {
        bytes memory data = _transfer(PARTNER, 1e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
        assertTrue(perm.evaluate(data, _ctx(TOKEN_B, data)));
    }

    function test_Transfer_WorksForBothRecipients() public view {
        bytes memory dataA = _transfer(PARTNER, 1e18);
        bytes memory dataB = _transfer(CEX, 1e18);
        assertTrue(perm.evaluate(dataA, _ctx(TOKEN_A, dataA)));
        assertTrue(perm.evaluate(dataB, _ctx(TOKEN_A, dataB)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Golden paths — transferFrom
    // ═════════════════════════════════════════════════════════════════════════

    function test_TransferFrom_GoldenPath() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, 300e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_ExactlyAtCap() public view {
        bytes memory data = _transferFrom(SAFE, CEX, MAX_AMOUNT);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_ZeroAmount() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, 0);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_FromMustBeSafe_ToAllowedRecipient() public view {
        // `from` must equal ctx.account (the Safe) per M-6 security fix.
        bytes memory data = _transferFrom(SAFE, PARTNER, 100e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
        // Non-Safe `from` is rejected.
        bytes memory dataRejected = _transferFrom(STRANGER, PARTNER, 100e18);
        assertFalse(perm.evaluate(dataRejected, _ctx(TOKEN_A, dataRejected)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Golden paths — plain ETH send
    // ═════════════════════════════════════════════════════════════════════════

    function test_EthSend_GoldenPath_Partner() public view {
        assertTrue(perm.evaluate("", _ctxEth(PARTNER, 1 ether)));
    }

    function test_EthSend_GoldenPath_Cex() public view {
        assertTrue(perm.evaluate("", _ctxEth(CEX, 0.5 ether)));
    }

    function test_EthSend_ExactlyAtCap() public view {
        assertTrue(perm.evaluate("", _ctxEth(PARTNER, MAX_AMOUNT)));
    }

    function test_EthSend_ZeroValue() public view {
        assertTrue(perm.evaluate("", _ctxEth(PARTNER, 0)));
    }

    function test_EthSend_ShortCalldataIsRejected() public view {
        // Non-empty calldata shorter than 4 bytes is malformed — rejected (not ETH path).
        bytes memory tiny = new bytes(2);
        Context memory ctx = _ctxEth(PARTNER, 0.1 ether);
        ctx.selector = bytes4(0);
        assertFalse(perm.evaluate(tiny, ctx));
    }

    function test_EthSend_BlockedForUnknownRecipient() public view {
        assertFalse(perm.evaluate("", _ctxEth(STRANGER, 1 ether)));
    }

    function test_EthSend_BlockedOverCap() public view {
        assertFalse(perm.evaluate("", _ctxEth(PARTNER, MAX_AMOUNT + 1)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ERC-20: non-zero ETH value rejected
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_EthValueRejected() public view {
        bytes memory data = _transfer(PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctxWithValue(TOKEN_A, data, 1)));
    }

    function test_TransferFrom_EthValueRejected() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctxWithValue(TOKEN_A, data, 1)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Non-allowlisted token blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_UnknownToken() public view {
        bytes memory data = _transfer(PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(BAD_TOKEN, data)));
    }

    function test_TransferFrom_UnknownToken() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(BAD_TOKEN, data)));
    }

    function testFuzz_Transfer_UnknownToken(address token) public view {
        vm.assume(token != TOKEN_A && token != TOKEN_B);
        bytes memory data = _transfer(PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(token, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Non-allowlisted recipient blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_UnknownRecipient() public view {
        bytes memory data = _transfer(STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_UnknownRecipient() public view {
        bytes memory data = _transferFrom(SAFE, STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_UnknownRecipient(address to) public view {
        vm.assume(to != PARTNER && to != CEX);
        bytes memory data = _transfer(to, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Amount over cap blocked
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_AmountOverCap() public view {
        bytes memory data = _transfer(PARTNER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_AmountOverCap() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_AmountOverCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _transfer(PARTNER, MAX_AMOUNT + excess);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, MAX_AMOUNT);
        bytes memory data = _transfer(PARTNER, amount);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Calldata edge cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_Transfer_TooShort_67Bytes() public view {
        bytes memory full   = _transfer(PARTNER, 1e18);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        // 67 bytes has a selector → ERC-20 path; fails length check
        Context memory ctx = _ctx(TOKEN_A, full);
        ctx.selector = TRANSFER_SEL;
        assertFalse(perm.evaluate(short_, ctx));
    }

    function test_Transfer_ExactlyMinLength_68Bytes() public view {
        bytes memory data = _transfer(PARTNER, 1e18);
        assertEq(data.length, 68);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_TooShort_99Bytes() public view {
        bytes memory full   = _transferFrom(SAFE, PARTNER, 1e18);
        bytes memory short_ = new bytes(99);
        for (uint256 i; i < 99; i++) short_[i] = full[i];
        Context memory ctx = _ctx(TOKEN_A, full);
        ctx.selector = TRANSFERFROM_SEL;
        assertFalse(perm.evaluate(short_, ctx));
    }

    function test_TransferFrom_ExactlyMinLength_100Bytes() public view {
        bytes memory data = _transferFrom(SAFE, PARTNER, 1e18);
        assertEq(data.length, 100);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_UnknownSelector_Approve() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", PARTNER, MAX_AMOUNT);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != TRANSFER_SEL && sel != TRANSFERFROM_SEL);
        bytes memory data = abi.encodePacked(sel, abi.encode(PARTNER, MAX_AMOUNT));
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
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
        emit TransferTargetPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function testFuzz_SetMaxAmountPerTx_RevertsForNonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    function test_SetMaxAmountPerTx_TakesEffect_Transfer() public {
        bytes memory data = _transfer(PARTNER, 500e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_SetMaxAmountPerTx_ToZero_BlocksAllNonZero() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        assertFalse(perm.evaluate(_transfer(PARTNER, 1),            _ctx(TOKEN_A, _transfer(PARTNER, 1))));
        assertFalse(perm.evaluate(_transferFrom(SAFE, PARTNER, 1),  _ctx(TOKEN_A, _transferFrom(SAFE, PARTNER, 1))));
        assertFalse(perm.evaluate("", _ctxEth(PARTNER, 1)));
    }

    function test_SetMaxAmountPerTx_ToZero_AllowsZeroAmount() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory data = _transfer(PARTNER, 0);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // setAllowedRecipient
    // ═════════════════════════════════════════════════════════════════════════

    function test_SetAllowedRecipient_AddsNewRecipient() public {
        assertFalse(perm.isAllowedRecipient(STRANGER));

        vm.prank(SIGNER);
        perm.setAllowedRecipient(STRANGER, true);

        assertTrue(perm.isAllowedRecipient(STRANGER));
        bytes memory data = _transfer(STRANGER, 1e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_SetAllowedRecipient_RemovesExistingRecipient() public {
        assertTrue(perm.isAllowedRecipient(PARTNER));

        vm.prank(SIGNER);
        perm.setAllowedRecipient(PARTNER, false);

        assertFalse(perm.isAllowedRecipient(PARTNER));
        bytes memory data = _transfer(PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_SetAllowedRecipient_EmitsEvent_OnAdd() public {
        vm.expectEmit(true, false, false, true);
        emit TransferTargetPermission.RecipientAllowlistUpdated(STRANGER, true);
        vm.prank(SIGNER);
        perm.setAllowedRecipient(STRANGER, true);
    }

    function test_SetAllowedRecipient_EmitsEvent_OnRemove() public {
        vm.expectEmit(true, false, false, true);
        emit TransferTargetPermission.RecipientAllowlistUpdated(PARTNER, false);
        vm.prank(SIGNER);
        perm.setAllowedRecipient(PARTNER, false);
    }

    function test_SetAllowedRecipient_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.setAllowedRecipient(STRANGER, true);
    }

    function test_SetAllowedRecipient_RevertsForZeroAddress() public {
        vm.prank(SIGNER);
        vm.expectRevert(TransferTargetPermission.ZeroAddress.selector);
        perm.setAllowedRecipient(address(0), true);
    }

    function testFuzz_SetAllowedRecipient_RevertsForNonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.setAllowedRecipient(PARTNER, false);
    }

    function test_SetAllowedRecipient_EthPathHonoursUpdatedAllowlist() public {
        vm.prank(SIGNER);
        perm.setAllowedRecipient(PARTNER, false);

        assertFalse(perm.evaluate("", _ctxEth(PARTNER, 1 ether)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Combined failures
    // ═════════════════════════════════════════════════════════════════════════

    function test_AllViolated_Transfer() public view {
        bytes memory data = _transfer(STRANGER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(BAD_TOKEN, data)));
    }

    function test_CorrectToken_WrongRecipient_WithinCap() public view {
        bytes memory data = _transfer(STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_CorrectToken_CorrectRecipient_OverCap() public view {
        bytes memory data = _transfer(PARTNER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_WrongToken_CorrectRecipient_WithinCap() public view {
        bytes memory data = _transfer(PARTNER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(BAD_TOKEN, data)));
    }
}
