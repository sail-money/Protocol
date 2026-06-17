// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test}                                 from "forge-std/Test.sol";
import {WeeklyDistributionPermission}         from "../contracts/token/WeeklyDistributionPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../contracts/interfaces/IBatchPermission.sol";
import {Context}                              from "../contracts/interfaces/IPermission.sol";
import {SailCapabilities}                     from "../contracts/interfaces/SailCapabilities.sol";
import {SailKernel}                           from "../contracts/core/SailKernel.sol";
import {SailGovernance}                       from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}                     from "./support/TimelockDeployer.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mocks (local to this file)
// ─────────────────────────────────────────────────────────────────────────────

/// @dev Minimal real ERC-20: `transfer` (selector 0xa9059cbb) actually moves balances, so the
///      live-balance bound and end-to-end drains are exercised against real state.
contract MockSAIL {
    mapping(address => uint256) public balanceOf;
    function mint(address to, uint256 amt) external { balanceOf[to] += amt; }
    function transfer(address to, uint256 amt) external returns (bool) {
        require(balanceOf[msg.sender] >= amt, "INSUFFICIENT");
        balanceOf[msg.sender] -= amt;
        balanceOf[to] += amt;
        return true;
    }
}

/// @dev Safe mock that ACTUALLY executes module calls, so dispatched transfers move tokens.
contract ExecutingMockSafe {
    receive() external payable {}
    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8)
        external returns (bool)
    {
        (bool ok, ) = to.call{value: value}(data);
        return ok;
    }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
//
// Highest-priority security tests are tagged `test_P0_*`: they cover the classes of malicious
// batch a compromised manager/agent could construct (wrong target/selector, over-budget, lost
// funds, wrong account, oversized) — each MUST be rejected.
// ─────────────────────────────────────────────────────────────────────────────

contract WeeklyDistributionPermissionTest is Test {
    WeeklyDistributionPermission perm;
    MockSAIL          sail;
    ExecutingMockSafe safe;        // == REWARDS_SMA == ctx.account
    SailGovernance    gov;
    SailKernel        kernel;

    address sma;                    // address(safe)

    bytes4  constant TRANSFER_SEL    = 0xa9059cbb;
    bytes4  constant APPROVE_SEL     = 0x095ea7b3;
    bytes4  constant TRANSFERFROM_SEL = 0x23b872dd;

    uint256 constant MAX_PER_RECIPIENT = 1_000_000e18;
    uint256 constant MAX_PER_BATCH     = 5_000_000e18; // one weekly tranche
    uint256 constant SMA_FUNDING       = 1_000_000_000e18;

    address constant TEAM            = address(0x1111);
    address constant TREASURY        = address(0x2222);
    address constant EMERGENCY_ADMIN = address(0xEEEE);

    uint256 constant SIGNER_KEY  = 0xA11CE;
    uint256 constant MANAGER_KEY = 0xBEEF;

    address permSigner;
    address manager;

    function setUp() public {
        vm.warp(1_000_000);

        gov    = new SailGovernance(TEAM, 0.001 ether, EMERGENCY_ADMIN, 0, TimelockDeployer.deploy(TEAM));
        kernel = new SailKernel(address(gov), TREASURY);

        safe = new ExecutingMockSafe();
        sma  = address(safe);
        sail = new MockSAIL();

        perm = new WeeklyDistributionPermission(address(sail), sma, MAX_PER_RECIPIENT, MAX_PER_BATCH);

        sail.mint(sma, SMA_FUNDING);

        // signers
        permSigner = vm.addr(0xA11CE);
        manager    = vm.addr(MANAGER_KEY);

        // trust the safe's codehash, register the account + permission for E2E tests
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(sma.codehash, true);

        vm.prank(sma);
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        _registerPermission();
    }

    receive() external payable {}

    // ─────────────────────────────────────────────────────────────────────────
    // Builders
    // ─────────────────────────────────────────────────────────────────────────

    function _transferData(address to, uint256 amt) internal pure returns (bytes memory) {
        return abi.encodeWithSelector(TRANSFER_SEL, to, amt);
    }

    function _call(address target, uint256 value, bytes memory data) internal pure returns (Call memory) {
        return Call({target: target, value: value, data: data});
    }

    /// @dev A valid n-recipient transfer batch, `amt` each, distinct non-reserved recipients.
    function _validBatch(uint256 n, uint256 amt) internal view returns (Call[] memory calls) {
        calls = new Call[](n);
        for (uint256 i; i < n; i++) {
            calls[i] = _call(address(sail), 0, _transferData(_recipient(i), amt));
        }
    }

    function _recipient(uint256 i) internal pure returns (address) {
        return address(uint160(0xC0FFEE0000 + i + 1)); // never 0, never sail/sma in tests
    }

    function _ctx(address account) internal view returns (BatchContext memory) {
        return BatchContext({
            account:        account,
            manager:        manager,
            submitter:      manager,
            permission:     address(perm),
            batchHash:      bytes32(0),
            blockTimestamp: block.timestamp,
            blockNumber:    block.number
        });
    }

    function _eval(Call[] memory calls) internal view returns (bool) {
        return perm.evaluateBatch(calls, _ctx(sma));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Happy paths
    // ═════════════════════════════════════════════════════════════════════════

    function test_ValidSingleRecipient() public view {
        assertTrue(_eval(_validBatch(1, 1_000e18)));
    }

    function test_ValidSixteenRecipients() public view {
        assertTrue(_eval(_validBatch(16, 100_000e18))); // 1.6M <= 5M batch cap, <= balance
    }

    function test_ValidAtPerRecipientCap() public view {
        assertTrue(_eval(_validBatch(1, MAX_PER_RECIPIENT)));
    }

    function test_ValidAtBatchCapBoundary() public view {
        // 5 * 1M = 5M == MAX_PER_BATCH (not over) => allowed
        assertTrue(_eval(_validBatch(5, MAX_PER_RECIPIENT)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Rejections — P0 adversarial cases
    // ═════════════════════════════════════════════════════════════════════════

    function test_P0_WrongTargetAnywhereRejected() public {
        Call[] memory calls = _validBatch(3, 1_000e18);
        calls[1].target = address(0xBAD); // not SAIL
        assertFalse(_eval(calls));
    }

    function test_P0_WrongSelectorApproveRejected() public view {
        Call[] memory calls = _validBatch(2, 1_000e18);
        calls[0].data = abi.encodeWithSelector(APPROVE_SEL, address(0xBAD), uint256(1_000e18)); // 68 bytes
        assertFalse(_eval(calls));
    }

    function test_P0_WrongSelectorTransferFromRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        // transferFrom is 100 bytes (3 args) — rejected on both length and selector
        calls[0].data = abi.encodeWithSelector(TRANSFERFROM_SEL, sma, address(0xBAD), uint256(1_000e18));
        assertFalse(_eval(calls));
    }

    function test_P0_RandomSelectorRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = abi.encodeWithSelector(bytes4(0xdeadbeef), _recipient(0), uint256(1_000e18));
        assertFalse(_eval(calls));
    }

    function test_P0_OverPerRecipientCapRejected() public view {
        assertFalse(_eval(_validBatch(1, MAX_PER_RECIPIENT + 1)));
    }

    function test_P0_OverBatchCapRejected() public view {
        // 6 * 1M = 6M > 5M batch cap
        assertFalse(_eval(_validBatch(6, MAX_PER_RECIPIENT)));
    }

    function test_P0_OverSMABalanceRejected() public {
        // Fresh isolated setup with a tiny balance so the live-balance bound is the binding limit.
        MockSAIL t = new MockSAIL();
        address  poorSma = address(0x9A9A);
        WeeklyDistributionPermission p =
            new WeeklyDistributionPermission(address(t), poorSma, MAX_PER_RECIPIENT, MAX_PER_BATCH);
        t.mint(poorSma, 1_500e18); // only 1,500 available

        Call[] memory calls = new Call[](2);
        calls[0] = _call(address(t), 0, _transferData(_recipient(0), 1_000e18));
        calls[1] = _call(address(t), 0, _transferData(_recipient(1), 1_000e18)); // sum 2,000 > 1,500
        BatchContext memory ctx = _ctx(poorSma);
        assertFalse(p.evaluateBatch(calls, ctx));

        // exactly at balance is fine
        calls[1].data = _transferData(_recipient(1), 500e18); // sum 1,500 == balance
        assertTrue(p.evaluateBatch(calls, ctx));
    }

    function test_P0_OversizedBatchRejected() public view {
        assertFalse(_eval(_validBatch(17, 1e18))); // > MAX_RECIPIENTS (16)
    }

    function test_EmptyBatchRejected() public view {
        Call[] memory calls = new Call[](0);
        assertFalse(_eval(calls));
    }

    function test_P0_NonZeroValueRejected() public {
        Call[] memory calls = _validBatch(2, 1_000e18);
        calls[1].value = 1 wei;
        assertFalse(_eval(calls));
    }

    function test_P0_MalformedCalldataTooShortRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = hex"a9059cbb0000"; // 6 bytes, selector ok, body truncated
        assertFalse(_eval(calls));
    }

    function test_P0_MalformedCalldataTooLongRejected() public {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = abi.encodePacked(_transferData(_recipient(0), 1_000e18), bytes32(0)); // 100 bytes
        assertFalse(_eval(calls));
    }

    function test_P0_ToZeroRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = _transferData(address(0), 1_000e18);
        assertFalse(_eval(calls));
    }

    function test_P0_ToSailRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = _transferData(address(sail), 1_000e18);
        assertFalse(_eval(calls));
    }

    function test_P0_ToRewardsSMARejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        calls[0].data = _transferData(sma, 1_000e18);
        assertFalse(_eval(calls));
    }

    function test_AmtZeroRejected() public view {
        Call[] memory calls = _validBatch(1, 0);
        assertFalse(_eval(calls));
    }

    function test_P0_WrongAccountRejected() public view {
        Call[] memory calls = _validBatch(1, 1_000e18);
        // ctx.account != REWARDS_SMA
        BatchContext memory ctx = _ctx(address(0xDEAD));
        assertFalse(perm.evaluateBatch(calls, ctx));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Interface / introspection / view-safety
    // ═════════════════════════════════════════════════════════════════════════

    function test_IsBatchPermission() public view {
        assertTrue(perm.isBatchPermission());
    }

    function test_EvaluateAlwaysFalse() public view {
        Context memory c;
        assertFalse(perm.evaluate("", c));
    }

    function test_Introspection() public view {
        assertEq(perm.permissionId(), keccak256("sail.permission.WeeklyDistributionPermission.v1"));
        assertEq(perm.permissionVersion(), keccak256("v1"));
        assertEq(perm.discriminator(), keccak256("WeeklyDistributionPermission"));
        bytes32[] memory ids = perm.capabilityIds();
        assertEq(ids.length, 1);
        assertEq(ids[0], SailCapabilities.BATCH_DISPATCH);
    }

    function test_P0_StaticcallSafe() public view {
        // Confirms evaluateBatch is side-effect-free: a staticcall must succeed and return true.
        Call[] memory calls = _validBatch(2, 1_000e18);
        BatchContext memory ctx = _ctx(sma);
        (bool ok, bytes memory ret) =
            address(perm).staticcall(abi.encodeCall(IBatchPermission.evaluateBatch, (calls, ctx)));
        assertTrue(ok);
        assertTrue(abi.decode(ret, (bool)));
    }

    function test_ConstructorRejectsBadArgs() public {
        vm.expectRevert(WeeklyDistributionPermission.ZeroAddress.selector);
        new WeeklyDistributionPermission(address(0), sma, 1, 2);
        vm.expectRevert(WeeklyDistributionPermission.TokenIsRewardsSMA.selector);
        new WeeklyDistributionPermission(address(sail), address(sail), 1, 2);
        vm.expectRevert(WeeklyDistributionPermission.ZeroCap.selector);
        new WeeklyDistributionPermission(address(sail), sma, 0, 2);
        vm.expectRevert(WeeklyDistributionPermission.PerRecipientExceedsBatch.selector);
        new WeeklyDistributionPermission(address(sail), sma, 3, 2);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // End-to-end through the kernel (real dispatchBatch path)
    // ═════════════════════════════════════════════════════════════════════════

    function test_P0_E2E_ValidBatchDispatches() public {
        Call[] memory calls = _validBatch(3, 10_000e18);
        _dispatch(calls);
        assertEq(sail.balanceOf(_recipient(0)), 10_000e18);
        assertEq(sail.balanceOf(_recipient(1)), 10_000e18);
        assertEq(sail.balanceOf(_recipient(2)), 10_000e18);
        assertEq(sail.balanceOf(sma), SMA_FUNDING - 30_000e18);
    }

    function test_P0_E2E_BadBatchReverts() public {
        Call[] memory calls = _validBatch(2, 10_000e18);
        calls[1].target = address(0xBAD);
        (bytes memory sig, uint256 deadline) = _signBatch(perm, safe, calls);
        vm.expectRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(sma, address(perm), calls, sig, deadline);
    }

    function test_P0_E2E_SequentialDrainBoundByBalance() public {
        // Re-fund: give the SMA exactly 25k so the second 15k batch would exceed the remaining 10k.
        // (Reset by using a fresh perm/safe/token to control the balance precisely.)
        (WeeklyDistributionPermission p, MockSAIL t, ExecutingMockSafe s) = _freshKernelWiredPerm(25_000e18);

        Call[] memory b1 = new Call[](1);
        b1[0] = _call(address(t), 0, _transferData(_recipient(0), 15_000e18));
        _dispatchVia(p, s, b1); // ok: 15k <= 25k
        assertEq(t.balanceOf(address(s)), 10_000e18);

        Call[] memory b2 = new Call[](1);
        b2[0] = _call(address(t), 0, _transferData(_recipient(1), 15_000e18)); // 15k > remaining 10k
        (bytes memory sig, uint256 deadline) = _signBatch(p, s, b2);
        vm.expectRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(address(s), address(p), b2, sig, deadline);
    }

    function test_GenesisFourBatchSplit() public {
        // ~50 recipients across 16+16+16+2 batches, each independently validated, draining the SMA.
        uint256 amt = 1_000e18;
        uint256[4] memory sizes = [uint256(16), 16, 16, 2];
        uint256 idx;
        uint256 totalOut;
        for (uint256 b; b < 4; b++) {
            Call[] memory calls = new Call[](sizes[b]);
            for (uint256 i; i < sizes[b]; i++) {
                calls[i] = _call(address(sail), 0, _transferData(_recipient(idx), amt));
                idx++;
            }
            _dispatch(calls);
            totalOut += sizes[b] * amt;
        }
        assertEq(idx, 50);
        assertEq(sail.balanceOf(sma), SMA_FUNDING - totalOut);
        assertEq(sail.balanceOf(_recipient(0)), amt);
        assertEq(sail.balanceOf(_recipient(49)), amt);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Fuzz
    // ═════════════════════════════════════════════════════════════════════════

    function testFuzz_SingleRecipientCapHolds(uint256 amt) public view {
        amt = bound(amt, 0, MAX_PER_RECIPIENT * 2);
        Call[] memory calls = new Call[](1);
        calls[0] = _call(address(sail), 0, _transferData(_recipient(0), amt));
        bool expected = (amt > 0 && amt <= MAX_PER_RECIPIENT); // batch cap & balance never bind here
        assertEq(_eval(calls), expected);
    }

    function testFuzz_RecipientCountAndBatchCapHold(uint8 n, uint256 amt) public view {
        uint256 count = bound(uint256(n), 0, 20);
        amt = bound(amt, 1, MAX_PER_RECIPIENT);
        Call[] memory calls = new Call[](count);
        for (uint256 i; i < count; i++) {
            calls[i] = _call(address(sail), 0, _transferData(_recipient(i), amt));
        }
        bool sizeOk   = (count >= 1 && count <= 16);
        bool budgetOk = (count * amt <= MAX_PER_BATCH); // SMA balance is huge, never binds
        assertEq(_eval(calls), sizeOk && budgetOk);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Gas
    // ═════════════════════════════════════════════════════════════════════════

    function test_GasEvaluateBatchUnderCap() public {
        _gas(1);
        _gas(8);
        _gas(16);
    }

    function _gas(uint256 n) internal {
        Call[] memory calls = _validBatch(n, 100_000e18);
        BatchContext memory ctx = _ctx(sma);
        uint256 g = gasleft();
        bool ok = perm.evaluateBatch(calls, ctx);
        uint256 used = g - gasleft();
        assertTrue(ok);
        assertLt(used, 1_000_000); // BATCH_EVAL_GAS_CAP
        emit log_named_uint(string.concat("evaluateBatch gas @ recipients=", vm.toString(n)), used);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // E2E signing helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _registerPermission() internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = kernel.signerNonces(sma);
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), sma, address(perm), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xA11CE, kernel.hashTypedDataV4(sh));
        kernel.registerPermission(sma, address(perm), deadline, abi.encodePacked(r, s, v));
    }

    function _dispatch(Call[] memory calls) internal {
        _dispatchVia(perm, safe, calls);
    }

    /// @dev Sign + dispatch a batch through the kernel for an arbitrary (perm, safe) pair.
    function _dispatchVia(WeeklyDistributionPermission p, ExecutingMockSafe s, Call[] memory calls) internal {
        (bytes memory sig, uint256 deadline) = _signBatch(p, s, calls);
        kernel.dispatchBatch(address(s), address(p), calls, sig, deadline);
    }

    /// @dev Produce a manager signature over a batch at the current batchNonce. Returned (not
    ///      dispatched) so callers can arm `vm.expectRevert` immediately before `dispatchBatch`.
    function _signBatch(WeeklyDistributionPermission p, ExecutingMockSafe s, Call[] memory calls)
        internal view returns (bytes memory sig, uint256 deadline)
    {
        address account = address(s);
        deadline = block.timestamp + 1 days;
        uint256 nonce = kernel.batchNonces(account);
        bytes32 callsHash = keccak256(abi.encode(calls));
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_BATCH_TYPEHASH(), account, address(p), callsHash, nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 sg) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        sig = abi.encodePacked(r, sg, v);
    }

    /// @dev Build a fully kernel-wired perm with a controlled SMA balance (for the drain test).
    function _freshKernelWiredPerm(uint256 funding)
        internal
        returns (WeeklyDistributionPermission p, MockSAIL t, ExecutingMockSafe s)
    {
        s = new ExecutingMockSafe();
        t = new MockSAIL();
        p = new WeeklyDistributionPermission(address(t), address(s), MAX_PER_RECIPIENT, MAX_PER_BATCH);
        t.mint(address(s), funding);

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(s).codehash, true); // same codehash, idempotent

        vm.prank(address(s));
        kernel.registerAccount(permSigner, manager, address(0), address(0));

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce = kernel.signerNonces(address(s));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(s), address(p), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 sig) = vm.sign(0xA11CE, kernel.hashTypedDataV4(sh));
        kernel.registerPermission(address(s), address(p), deadline, abi.encodePacked(r, sig, v));
    }
}
