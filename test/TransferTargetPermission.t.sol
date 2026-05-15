// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {TransferTargetPermission} from "../contracts/templates/TransferTargetPermission.sol";
import {Context} from "../contracts/interfaces/IPermission.sol";

contract TransferTargetPermissionTest is Test {
    TransferTargetPermission perm;

    address constant SAFE      = address(0x5AFE);
    address constant RECIPIENT = address(0xBEEF); // allowlisted
    address constant RECIPIENT2 = address(0xCAFE); // second allowlisted recipient
    address constant USDC      = address(0xDC01); // allowlisted token
    address constant WETH      = address(0xE711); // allowlisted token
    address constant STRANGER  = address(0x9999);
    address constant SIGNER    = address(0x5161);

    bytes4 constant SEL_TRANSFER     = 0xa9059cbb;
    bytes4 constant SEL_TRANSFERFROM = 0x23b872dd;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory recipients = new address[](2);
        recipients[0] = RECIPIENT;
        recipients[1] = RECIPIENT2;

        address[] memory tokens = new address[](2);
        tokens[0] = USDC;
        tokens[1] = WETH;

        perm = new TransferTargetPermission(recipients, tokens, SIGNER);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_TRANSFER, to, amount);
    }

    function _transferFrom(address from, address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(SEL_TRANSFERFROM, from, to, amount);
    }

    function _ctx(address token, bytes4 sel) internal pure returns (Context memory) {
        return Context({account: SAFE, manager: address(0), target: token, selector: sel, value: 0});
    }

    function _ctxValue(address token, bytes4 sel, uint256 value) internal pure returns (Context memory) {
        return Context({account: SAFE, manager: address(0), target: token, selector: sel, value: value});
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsPermissionSigner() public view {
        assertEq(perm.permissionSigner(), SIGNER);
    }

    function test_Constructor_RegistersRecipients() public view {
        assertTrue(perm.isAllowedRecipient(RECIPIENT));
        assertTrue(perm.isAllowedRecipient(RECIPIENT2));
        assertFalse(perm.isAllowedRecipient(STRANGER));
    }

    function test_Constructor_RegistersTokens() public view {
        assertTrue(perm.isAllowedToken(USDC));
        assertTrue(perm.isAllowedToken(WETH));
        assertFalse(perm.isAllowedToken(STRANGER));
    }

    function test_Constructor_EmitsRecipientAddedPerEntry() public {
        address[] memory recipients = new address[](2);
        recipients[0] = RECIPIENT;
        recipients[1] = RECIPIENT2;
        address[] memory tokens = new address[](0);

        vm.expectEmit(true, false, false, false);
        emit TransferTargetPermission.RecipientAdded(RECIPIENT);
        vm.expectEmit(true, false, false, false);
        emit TransferTargetPermission.RecipientAdded(RECIPIENT2);
        new TransferTargetPermission(recipients, tokens, SIGNER);
    }

    function test_Constructor_RevertsZeroSigner() public {
        address[] memory e = new address[](0);
        vm.expectRevert(TransferTargetPermission.ZeroAddress.selector);
        new TransferTargetPermission(e, e, address(0));
    }

    function test_Constructor_EmptyArraysSucceeds() public {
        address[] memory e = new address[](0);
        TransferTargetPermission p = new TransferTargetPermission(e, e, SIGNER);
        assertEq(p.permissionSigner(), SIGNER);
    }

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("TransferTargetPermission"));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // transfer() — golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_Transfer_GoldenPath_USDC() public view {
        bytes memory data = _transfer(RECIPIENT, 1_000e6);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_GoldenPath_WETH() public view {
        bytes memory data = _transfer(RECIPIENT, 1e18);
        assertTrue(perm.evaluate(data, _ctx(WETH, SEL_TRANSFER)));
    }

    function test_Transfer_SecondRecipient_Passes() public view {
        bytes memory data = _transfer(RECIPIENT2, 500e6);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_ZeroAmount_Passes() public view {
        bytes memory data = _transfer(RECIPIENT, 0);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_MaxUint_Passes() public view {
        bytes memory data = _transfer(RECIPIENT, type(uint256).max);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_ExactlyMinLength_68Bytes() public view {
        bytes memory data = _transfer(RECIPIENT, 1e18);
        assertEq(data.length, 68);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // transfer() — blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_Transfer_WrongRecipient_Blocked() public view {
        bytes memory data = _transfer(STRANGER, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_ZeroRecipient_Blocked() public view {
        bytes memory data = _transfer(address(0), 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Transfer_WrongToken_Blocked() public view {
        bytes memory data = _transfer(RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_TRANSFER)));
    }

    function test_Transfer_NonZeroValue_Blocked() public view {
        bytes memory data = _transfer(RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctxValue(USDC, SEL_TRANSFER, 1)));
    }

    function test_Transfer_TooShort_67Bytes() public view {
        bytes memory full  = _transfer(RECIPIENT, 1e18);
        bytes memory short_ = new bytes(67);
        for (uint256 i; i < 67; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(USDC, SEL_TRANSFER)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // transferFrom() — golden paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_TransferFrom_GoldenPath_USDC() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1_000e6);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_GoldenPath_WETH() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1e18);
        assertTrue(perm.evaluate(data, _ctx(WETH, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_SecondRecipient_Passes() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT2, 500e6);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_FromAddressIrrelevant() public view {
        // The 'from' address is not checked — only 'to' matters
        bytes memory data = _transferFrom(STRANGER, RECIPIENT, 1_000e6);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_ZeroAmount_Passes() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 0);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_ExactlyMinLength_100Bytes() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1e18);
        assertEq(data.length, 100);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // transferFrom() — blocked cases
    // ─────────────────────────────────────────────────────────────────────────

    function test_TransferFrom_WrongRecipient_Blocked() public view {
        bytes memory data = _transferFrom(SAFE, STRANGER, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_ZeroRecipient_Blocked() public view {
        bytes memory data = _transferFrom(SAFE, address(0), 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_WrongToken_Blocked() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_TRANSFERFROM)));
    }

    function test_TransferFrom_NonZeroValue_Blocked() public view {
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctxValue(USDC, SEL_TRANSFERFROM, 1)));
    }

    function test_TransferFrom_TooShort_99Bytes() public view {
        bytes memory full  = _transferFrom(SAFE, RECIPIENT, 1e18);
        bytes memory short_ = new bytes(99);
        for (uint256 i; i < 99; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Unknown calldata
    // ─────────────────────────────────────────────────────────────────────────

    function test_EmptyCalldata() public view {
        assertFalse(perm.evaluate("", _ctx(USDC, bytes4(0))));
    }

    function test_UnknownSelector_Approve() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", RECIPIENT, 1e18);
        bytes4 sel = bytes4(keccak256("approve(address,uint256)"));
        assertFalse(perm.evaluate(data, _ctx(USDC, sel)));
    }

    function test_UnknownSelector_Mint() public view {
        bytes memory data = abi.encodeWithSignature("mint(address,uint256)", RECIPIENT, 1e18);
        bytes4 sel = bytes4(keccak256("mint(address,uint256)"));
        assertFalse(perm.evaluate(data, _ctx(USDC, sel)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != SEL_TRANSFER && sel != SEL_TRANSFERFROM);
        bytes memory data = abi.encodePacked(sel, abi.encode(RECIPIENT, uint256(1e18)));
        assertFalse(perm.evaluate(data, _ctx(USDC, sel)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Fuzz: access control on recipients and tokens
    // ─────────────────────────────────────────────────────────────────────────

    function testFuzz_Transfer_NonAllowlistedRecipient(address to) public view {
        vm.assume(to != RECIPIENT && to != RECIPIENT2);
        bytes memory data = _transfer(to, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function testFuzz_TransferFrom_NonAllowlistedRecipient(address to) public view {
        vm.assume(to != RECIPIENT && to != RECIPIENT2);
        bytes memory data = _transferFrom(SAFE, to, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFERFROM)));
    }

    function testFuzz_Transfer_NonAllowlistedToken(address token) public view {
        vm.assume(token != USDC && token != WETH);
        bytes memory data = _transfer(RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(token, SEL_TRANSFER)));
    }

    function testFuzz_TransferFrom_NonAllowlistedToken(address token) public view {
        vm.assume(token != USDC && token != WETH);
        bytes memory data = _transferFrom(SAFE, RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctx(token, SEL_TRANSFERFROM)));
    }

    function testFuzz_NonZeroValue_AlwaysBlocked(uint256 value) public view {
        vm.assume(value > 0);
        bytes memory data = _transfer(RECIPIENT, 1_000e6);
        assertFalse(perm.evaluate(data, _ctxValue(USDC, SEL_TRANSFER, value)));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // addRecipient
    // ─────────────────────────────────────────────────────────────────────────

    function test_AddRecipient_Succeeds() public {
        assertFalse(perm.isAllowedRecipient(STRANGER));
        vm.prank(SIGNER);
        perm.addRecipient(STRANGER);
        assertTrue(perm.isAllowedRecipient(STRANGER));
    }

    function test_AddRecipient_EmitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit TransferTargetPermission.RecipientAdded(STRANGER);
        vm.prank(SIGNER);
        perm.addRecipient(STRANGER);
    }

    function test_AddRecipient_TakesEffectOnEvaluate() public {
        // STRANGER not in list → blocked
        bytes memory data = _transfer(STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));

        vm.prank(SIGNER);
        perm.addRecipient(STRANGER);

        // Now passes
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_AddRecipient_Idempotent() public {
        // Adding already-allowlisted recipient is silent success (no revert)
        vm.prank(SIGNER);
        perm.addRecipient(RECIPIENT); // already in list
        assertTrue(perm.isAllowedRecipient(RECIPIENT));
    }

    function test_AddRecipient_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.addRecipient(address(0xDEAD));
    }

    function testFuzz_AddRecipient_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.addRecipient(STRANGER);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // removeRecipient
    // ─────────────────────────────────────────────────────────────────────────

    function test_RemoveRecipient_Succeeds() public {
        assertTrue(perm.isAllowedRecipient(RECIPIENT));
        vm.prank(SIGNER);
        perm.removeRecipient(RECIPIENT);
        assertFalse(perm.isAllowedRecipient(RECIPIENT));
    }

    function test_RemoveRecipient_EmitsEvent() public {
        vm.expectEmit(true, false, false, false);
        emit TransferTargetPermission.RecipientRemoved(RECIPIENT);
        vm.prank(SIGNER);
        perm.removeRecipient(RECIPIENT);
    }

    function test_RemoveRecipient_TakesEffectOnEvaluate() public {
        // RECIPIENT in list → passes
        bytes memory data = _transfer(RECIPIENT, 1e18);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));

        vm.prank(SIGNER);
        perm.removeRecipient(RECIPIENT);

        // Now blocked
        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_RemoveRecipient_RevertsIfNotInList() public {
        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(TransferTargetPermission.RecipientNotInAllowlist.selector, STRANGER)
        );
        perm.removeRecipient(STRANGER);
    }

    function test_RemoveRecipient_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.removeRecipient(RECIPIENT);
    }

    function testFuzz_RemoveRecipient_NonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(TransferTargetPermission.NotPermissionSigner.selector);
        perm.removeRecipient(RECIPIENT);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Add then remove round-trip
    // ─────────────────────────────────────────────────────────────────────────

    function test_AddThenRemove_RoundTrip() public {
        // Add STRANGER
        vm.prank(SIGNER);
        perm.addRecipient(STRANGER);
        assertTrue(perm.isAllowedRecipient(STRANGER));

        bytes memory data = _transfer(STRANGER, 1e18);
        assertTrue(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));

        // Remove STRANGER
        vm.prank(SIGNER);
        perm.removeRecipient(STRANGER);
        assertFalse(perm.isAllowedRecipient(STRANGER));

        assertFalse(perm.evaluate(data, _ctx(USDC, SEL_TRANSFER)));
    }

    function test_Remove_CannotRemoveTwice() public {
        vm.prank(SIGNER);
        perm.removeRecipient(RECIPIENT);

        vm.prank(SIGNER);
        vm.expectRevert(
            abi.encodeWithSelector(TransferTargetPermission.RecipientNotInAllowlist.selector, RECIPIENT)
        );
        perm.removeRecipient(RECIPIENT);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Multiple recipients independence
    // ─────────────────────────────────────────────────────────────────────────

    function test_MultipleRecipients_IndependentlyControlled() public {
        // Both initially pass
        assertTrue(perm.evaluate(_transfer(RECIPIENT,  1e18), _ctx(USDC, SEL_TRANSFER)));
        assertTrue(perm.evaluate(_transfer(RECIPIENT2, 1e18), _ctx(USDC, SEL_TRANSFER)));

        // Remove one; other still passes
        vm.prank(SIGNER);
        perm.removeRecipient(RECIPIENT);

        assertFalse(perm.evaluate(_transfer(RECIPIENT,  1e18), _ctx(USDC, SEL_TRANSFER)));
        assertTrue(perm.evaluate( _transfer(RECIPIENT2, 1e18), _ctx(USDC, SEL_TRANSFER)));
    }

    function test_BothTokens_BothRecipients_AllCombinations() public view {
        address[2] memory tokens     = [USDC, WETH];
        address[2] memory recipients = [RECIPIENT, RECIPIENT2];

        for (uint256 t; t < 2; t++) {
            for (uint256 r; r < 2; r++) {
                bytes memory d1 = _transfer(recipients[r], 1e18);
                bytes memory d2 = _transferFrom(SAFE, recipients[r], 1e18);
                assertTrue(perm.evaluate(d1, _ctx(tokens[t], SEL_TRANSFER)));
                assertTrue(perm.evaluate(d2, _ctx(tokens[t], SEL_TRANSFERFROM)));
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Both checks must pass simultaneously
    // ─────────────────────────────────────────────────────────────────────────

    function test_WrongTokenAndWrongRecipient_Blocked() public view {
        bytes memory data = _transfer(STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_TRANSFER)));
    }

    function test_WrongTokenAndWrongRecipient_TransferFrom() public view {
        bytes memory data = _transferFrom(SAFE, STRANGER, 1e18);
        assertFalse(perm.evaluate(data, _ctx(STRANGER, SEL_TRANSFERFROM)));
    }
}
