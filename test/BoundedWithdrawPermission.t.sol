// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                     from "forge-std/Test.sol";
import {BoundedWithdrawPermission} from "../contracts/templates/BoundedWithdrawPermission.sol";
import {Context}                  from "../contracts/interfaces/IPermission.sol";

contract BoundedWithdrawPermissionTest is Test {
    BoundedWithdrawPermission perm;

    address constant SAFE     = address(0x5AFE);
    address constant TOKEN_A  = address(0xAAAA);
    address constant TOKEN_B  = address(0xBBBB);
    address constant SIGNER   = address(0x5161);
    address constant STRANGER = address(0x9999);

    uint256 constant MAX_AMOUNT = 1_000e18;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        address[] memory tokens = new address[](2);
        tokens[0] = TOKEN_A;
        tokens[1] = TOKEN_B;
        perm = new BoundedWithdrawPermission(SAFE, tokens, MAX_AMOUNT, SIGNER);
    }

    // ── calldata helpers ──────────────────────────────────────────────────────

    function _transfer(address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transfer(address,uint256)", to, amount);
    }

    function _transferFrom(address from, address to, uint256 amount) internal pure returns (bytes memory) {
        return abi.encodeWithSignature("transferFrom(address,address,uint256)", from, to, amount);
    }

    function _ctx(address token, bytes memory data) internal view returns (Context memory) {
        bytes4 sel;
        if (data.length >= 4) {
            assembly { sel := mload(add(data, 32)) }
        }
        return Context({
            account:        address(0),
            manager:        address(0),
            submitter:      address(0),
            target:         token,
            selector:       sel,
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    function _ctxWithValue(address token, bytes memory data, uint256 ethValue)
        internal view returns (Context memory c)
    {
        c = _ctx(token, data);
        c.value = ethValue;
    }

    // ── constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsAllowedRecipient() public view {
        assertEq(perm.allowedRecipient(), SAFE);
    }

    function test_Constructor_SetsMaxAmount() public view {
        assertEq(perm.maxAmountPerTx(), MAX_AMOUNT);
    }

    function test_Constructor_SetsPermissionSigner() public view {
        assertEq(perm.permissionSigner(), SIGNER);
    }

    function test_Constructor_RegistersAllowedTokens() public view {
        assertTrue(perm.isAllowedToken(TOKEN_A));
        assertTrue(perm.isAllowedToken(TOKEN_B));
    }

    function test_Constructor_UnknownTokenNotAllowed() public view {
        assertFalse(perm.isAllowedToken(address(0xDEAD)));
    }

    function test_Constructor_RevertsOnZeroSafe() public {
        address[] memory tokens = new address[](0);
        vm.expectRevert(BoundedWithdrawPermission.ZeroAddress.selector);
        new BoundedWithdrawPermission(address(0), tokens, MAX_AMOUNT, SIGNER);
    }

    function test_Constructor_RevertsOnZeroSigner() public {
        address[] memory tokens = new address[](0);
        vm.expectRevert(BoundedWithdrawPermission.ZeroAddress.selector);
        new BoundedWithdrawPermission(SAFE, tokens, MAX_AMOUNT, address(0));
    }

    // ── discriminator ─────────────────────────────────────────────────────────

    function test_Discriminator() public view {
        assertEq(perm.discriminator(), keccak256("BoundedWithdrawPermission"));
    }

    // ── golden path: transfer() ───────────────────────────────────────────────

    function test_Transfer_GoldenPath() public view {
        bytes memory data = _transfer(SAFE, 100e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_TokenB_GoldenPath() public view {
        bytes memory data = _transfer(SAFE, 1e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_B, data)));
    }

    function test_Transfer_ExactlyAtCap() public view {
        bytes memory data = _transfer(SAFE, MAX_AMOUNT);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_ZeroAmount() public view {
        bytes memory data = _transfer(SAFE, 0);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── golden path: transferFrom() ───────────────────────────────────────────

    function test_TransferFrom_GoldenPath() public view {
        bytes memory data = _transferFrom(address(0x1234), SAFE, 500e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_ExactlyAtCap() public view {
        bytes memory data = _transferFrom(address(0x1234), SAFE, MAX_AMOUNT);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_FromAddressIrrelevant() public view {
        bytes memory dataA = _transferFrom(address(0x1111), SAFE, 1e18);
        bytes memory dataB = _transferFrom(address(0x9999), SAFE, 1e18);
        assertTrue(perm.evaluate(dataA, _ctx(TOKEN_A, dataA)));
        assertTrue(perm.evaluate(dataB, _ctx(TOKEN_A, dataB)));
    }

    // ── wrong recipient ───────────────────────────────────────────────────────

    function test_Transfer_WrongRecipient() public view {
        bytes memory data = _transfer(STRANGER, 100e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_Transfer_RecipientIsZeroAddress() public view {
        bytes memory data = _transfer(address(0), 100e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_WrongRecipient() public view {
        bytes memory data = _transferFrom(address(0x1234), STRANGER, 100e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_WrongRecipient(address recipient) public view {
        vm.assume(recipient != SAFE);
        bytes memory data = _transfer(recipient, 1e18);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── non-allowlisted token ─────────────────────────────────────────────────

    function test_Transfer_UnknownToken() public view {
        bytes memory data = _transfer(SAFE, 100e18);
        assertFalse(perm.evaluate(data, _ctx(address(0xDEAD), data)));
    }

    function test_TransferFrom_UnknownToken() public view {
        bytes memory data = _transferFrom(address(0x1234), SAFE, 100e18);
        assertFalse(perm.evaluate(data, _ctx(address(0xDEAD), data)));
    }

    function testFuzz_Transfer_UnknownToken(address token) public view {
        vm.assume(token != TOKEN_A && token != TOKEN_B);
        bytes memory data = _transfer(SAFE, 1e18);
        assertFalse(perm.evaluate(data, _ctx(token, data)));
    }

    // ── amount over cap ───────────────────────────────────────────────────────

    function test_Transfer_AmountOverCap() public view {
        bytes memory data = _transfer(SAFE, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_AmountOverCap() public view {
        bytes memory data = _transferFrom(address(0x1234), SAFE, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_AmountOverCap(uint256 excess) public view {
        excess = bound(excess, 1, type(uint256).max - MAX_AMOUNT);
        bytes memory data = _transfer(SAFE, MAX_AMOUNT + excess);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_Transfer_AmountWithinCap(uint256 amount) public view {
        amount = bound(amount, 0, MAX_AMOUNT);
        bytes memory data = _transfer(SAFE, amount);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── non-zero ETH value ────────────────────────────────────────────────────

    function test_Transfer_NonZeroValue() public view {
        bytes memory data = _transfer(SAFE, 100e18);
        assertFalse(perm.evaluate(data, _ctxWithValue(TOKEN_A, data, 1)));
    }

    function test_TransferFrom_NonZeroValue() public view {
        bytes memory data = _transferFrom(address(0x1234), SAFE, 100e18);
        assertFalse(perm.evaluate(data, _ctxWithValue(TOKEN_A, data, 1 ether)));
    }

    // ── calldata parsing edge cases ───────────────────────────────────────────

    function test_EmptyCalldata() public view {
        Context memory ctx = Context({
            account:        address(0),
            manager:        address(0),
            submitter:      address(0),
            target:         TOKEN_A,
            selector:       bytes4(0),
            value:          0,
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
        assertFalse(perm.evaluate("", ctx));
    }

    function test_SelectorOnly_NoArgs() public view {
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)");
        data = bytes(abi.encodePacked(bytes4(data)));
        Context memory ctx = _ctx(TOKEN_A, data);
        assertFalse(perm.evaluate(data, ctx));
    }

    function test_Transfer_TooShort_67Bytes() public view {
        bytes memory full = _transfer(SAFE, MAX_AMOUNT);
        bytes memory short_ = new bytes(67);
        for (uint256 i = 0; i < 67; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(TOKEN_A, full)));
    }

    function test_TransferFrom_TooShort_99Bytes() public view {
        bytes memory full = _transferFrom(STRANGER, SAFE, MAX_AMOUNT);
        bytes memory short_ = new bytes(99);
        for (uint256 i = 0; i < 99; i++) short_[i] = full[i];
        assertFalse(perm.evaluate(short_, _ctx(TOKEN_A, full)));
    }

    function test_UnknownSelector() public view {
        bytes memory data = abi.encodeWithSignature("approve(address,uint256)", SAFE, MAX_AMOUNT);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_UnknownSelector_Mint() public view {
        bytes memory data = abi.encodeWithSignature("mint(address,uint256)", SAFE, MAX_AMOUNT);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function testFuzz_UnknownSelector(bytes4 sel) public view {
        vm.assume(sel != bytes4(0xa9059cbb) && sel != bytes4(0x23b872dd));
        bytes memory data = abi.encodePacked(sel, abi.encode(SAFE, SAFE, MAX_AMOUNT));
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── setMaxAmountPerTx ─────────────────────────────────────────────────────

    function test_SetMaxAmountPerTx_Succeeds() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(500e18);
        assertEq(perm.maxAmountPerTx(), 500e18);
    }

    function test_SetMaxAmountPerTx_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BoundedWithdrawPermission.MaxAmountUpdated(MAX_AMOUNT, 200e18);
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(200e18);
    }

    function test_SetMaxAmountPerTx_RevertsForStranger() public {
        vm.prank(STRANGER);
        vm.expectRevert(BoundedWithdrawPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(500e18);
    }

    function testFuzz_SetMaxAmountPerTx_RevertsForNonSigner(address caller) public {
        vm.assume(caller != SIGNER);
        vm.prank(caller);
        vm.expectRevert(BoundedWithdrawPermission.NotPermissionSigner.selector);
        perm.setMaxAmountPerTx(1);
    }

    function test_SetMaxAmountPerTx_TakesEffectOnEvaluate() public {
        bytes memory data = _transfer(SAFE, 500e18);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));

        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(100e18);

        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_SetMaxAmountPerTx_ToZero_BlocksAll() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory data = _transfer(SAFE, 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_SetMaxAmountPerTx_ToZero_AllowsZeroAmount() public {
        vm.prank(SIGNER);
        perm.setMaxAmountPerTx(0);

        bytes memory data = _transfer(SAFE, 0);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── combined failures ─────────────────────────────────────────────────────

    function test_AllThreeChecksMustPass_WrongToken_WrongRecipient_OverCap() public view {
        bytes memory data = _transfer(STRANGER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(address(0xDEAD), data)));
    }

    function test_Transfer_AllowedToken_But_WrongRecipient_And_OverCap() public view {
        bytes memory data = _transfer(STRANGER, MAX_AMOUNT + 1);
        assertFalse(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    // ── transferFrom `from` field is unchecked (documented behaviour) ─────────
    // The permission allows the manager to pull from ANY address that has
    // approved the Safe. Operators must understand this when using transferFrom.

    function test_TransferFrom_ExternalApprover_Passes() public view {
        // `from` = an external DeFi protocol that has approved the Safe.
        // The permission evaluates true because only `to` and `amount` are checked.
        address externalProtocol = address(0xEEEE);
        bytes memory data = _transferFrom(externalProtocol, SAFE, MAX_AMOUNT);
        assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
    }

    function test_TransferFrom_AnyFrom_SameToAndAmount_Passes() public view {
        // Confirm the `from` field never causes denial — only `to` and `amount` matter.
        for (uint160 i = 1; i < 5; i++) {
            bytes memory data = _transferFrom(address(i), SAFE, 1e18);
            assertTrue(perm.evaluate(data, _ctx(TOKEN_A, data)));
        }
    }
}
