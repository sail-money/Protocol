// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel}        from "../contracts/core/SailKernel.sol";
import {SailGovernance}    from "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer}  from "./support/TimelockDeployer.sol";
import {Call}              from "../contracts/interfaces/IBatchPermission.sol";
import {MockSafe}          from "./mocks/MockSafe.sol";
import {MockPermissionAlwaysTrue} from "./mocks/MockPermissions.sol";
import {
    MockBatchAlwaysTrue,
    MockBatchAlwaysFalse,
    MockBatchReverts,
    MockBatchGasBomb
} from "./mocks/MockBatchPermissions.sol";

/// @title  KernelGuaranteesBatchTest
/// @notice Proves the SailKernel's dispatchBatch guarantees DIRECTLY, using only mock batch
///         permissions — no example template is imported. With every template deleted, this
///         suite still exercises the batch path (separate nonce namespace, MAX_BATCH_LENGTH,
///         batch-aware requirement, whole-batch single-permission evaluation, atomic rollback,
///         and failed-attempt-does-not-consume-nonce).
contract KernelGuaranteesBatchTest is Test {
    uint256 internal constant SIGNER_KEY  = 0x5161;
    uint256 internal constant MANAGER_KEY = 0x6262;

    address internal constant TEAM      = address(0x7EA8);
    address internal constant EMERGENCY = address(0xE);
    address internal constant TREASURY  = address(0x77);
    address internal constant TARGET    = address(0xCAFE);

    SailGovernance internal gov;
    SailKernel     internal kernel;
    MockSafe       internal safe;
    address        internal account;
    address        internal manager;
    address        internal permSigner;

    function setUp() public {
        manager    = vm.addr(MANAGER_KEY);
        permSigner = vm.addr(SIGNER_KEY);

        TimelockController tl = TimelockDeployer.deploy(TEAM);
        gov    = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0, tl);
        kernel = new SailKernel(address(gov), TREASURY);
        safe   = new MockSafe();
        account = address(safe);

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);

        vm.prank(account);
        kernel.registerAccount(permSigner, manager, address(0), address(0));
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _registerPerm(address perm) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(account);
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), account, perm, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.registerPermission(account, perm, deadline, abi.encodePacked(r, s, v));
    }

    function _calls(uint256 n) internal pure returns (Call[] memory calls) {
        calls = new Call[](n);
        for (uint256 i; i < n; i++) {
            calls[i] = Call({target: TARGET, value: 0, data: hex"deadbeef"});
        }
    }

    function _mb(address perm, Call[] memory calls)
        internal view returns (bytes memory sig, uint256 deadline)
    {
        deadline = block.timestamp + 1 hours;
        uint256 nonce = kernel.batchNonces(account);
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_BATCH_TYPEHASH(), account, perm, keccak256(abi.encode(calls)), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
        sig = abi.encodePacked(r, s, v);
    }

    // ── happy path / whole-batch evaluation ─────────────────────────────────────

    function test_B_HappyBatch_ExecutesAllSubcalls() public {
        MockBatchAlwaysTrue perm = new MockBatchAlwaysTrue();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(3);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
        assertEq(safe.callCount(), 3, "all subcalls execute under one named batch permission");
    }

    // ── fail-closed batch evaluation ─────────────────────────────────────────────

    function test_B_FalseEval_RevertsWholeBatch() public {
        MockBatchAlwaysFalse perm = new MockBatchAlwaysFalse();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(3);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
        assertEq(safe.callCount(), 0);
    }

    function test_B_RevertingEval_RevertsWholeBatch() public {
        MockBatchReverts perm = new MockBatchReverts();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(2);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
        assertEq(safe.callCount(), 0);
    }

    function test_B_GasBombEval_Denied() public {
        MockBatchGasBomb perm = new MockBatchGasBomb();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(2);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
        assertEq(safe.callCount(), 0);
    }

    // ── batch-aware requirement ──────────────────────────────────────────────────

    /// @notice A named permission that is not batch-aware (no isBatchPermission) is rejected.
    function test_B_NonBatchPermission_Rejected() public {
        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue(); // single IPermission, not batch-aware
        _registerPerm(address(perm));
        Call[] memory calls = _calls(1);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.PermissionNotBatchAware.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
    }

    // ── length bounds ─────────────────────────────────────────────────────────────

    function test_B_EmptyBatch_Reverts() public {
        MockBatchAlwaysTrue perm = new MockBatchAlwaysTrue();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(0);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.EmptyBatch.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
    }

    function test_B_BatchTooLong_Reverts() public {
        MockBatchAlwaysTrue perm = new MockBatchAlwaysTrue();
        _registerPerm(address(perm));
        Call[] memory calls = _calls(17); // MAX_BATCH_LENGTH == 16
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.BatchTooLong.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
    }

    // ── atomic rollback ───────────────────────────────────────────────────────────

    /// @notice If any subcall fails, the entire batch reverts and all prior subcalls roll back.
    function test_B_SubcallFailure_AtomicRollback() public {
        MockBatchAlwaysTrue perm = new MockBatchAlwaysTrue();
        _registerPerm(address(perm));
        safe.setFailOnCall(2); // 2nd execTransactionFromModule returns false
        Call[] memory calls = _calls(3);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.BatchSubcallFailed.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
        assertEq(safe.callCount(), 0, "the whole batch reverted; the first subcall's effect rolled back");
    }

    // ── nonce namespaces ──────────────────────────────────────────────────────────

    /// @notice dispatch and dispatchBatch use independent nonce namespaces.
    function test_B_NonceNamespacesIndependent() public {
        MockPermissionAlwaysTrue single = new MockPermissionAlwaysTrue();
        MockBatchAlwaysTrue      batch  = new MockBatchAlwaysTrue();
        _registerPerm(address(single));
        _registerPerm(address(batch));

        // single dispatch advances managerNonces, not batchNonces
        {
            uint256 deadline = block.timestamp + 1 hours;
            uint256 nonce = kernel.managerNonces(account);
            bytes32 sh = keccak256(abi.encode(
                kernel.DISPATCH_TYPEHASH(), account, address(single), TARGET, uint256(0), keccak256(hex"deadbeef"), nonce, deadline
            ));
            (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh));
            kernel.dispatch(account, address(single), TARGET, 0, hex"deadbeef", abi.encodePacked(r, s, v), deadline);
        }
        assertEq(kernel.managerNonces(account), 1);
        assertEq(kernel.batchNonces(account), 0);

        // batch dispatch advances batchNonces, not managerNonces
        Call[] memory calls = _calls(1);
        (bytes memory sig, uint256 dl) = _mb(address(batch), calls);
        kernel.dispatchBatch(account, address(batch), calls, sig, dl);
        assertEq(kernel.batchNonces(account), 1);
        assertEq(kernel.managerNonces(account), 1);
    }

    /// @notice A batch attempt that reverts in evaluation does NOT consume the batch nonce — a
    ///         later valid batch reuses the same nonce and succeeds. (documented kernel behaviour)
    function test_B_FailedBatch_DoesNotConsumeNonce() public {
        MockBatchReverts    bad  = new MockBatchReverts();
        MockBatchAlwaysTrue good = new MockBatchAlwaysTrue();
        _registerPerm(address(bad));
        _registerPerm(address(good));
        assertEq(kernel.batchNonces(account), 0);

        // failed attempt at nonce 0
        Call[] memory calls = _calls(2);
        (bytes memory badSig, uint256 badDl) = _mb(address(bad), calls);
        vm.expectPartialRevert(SailKernel.BatchPermissionDenied.selector);
        kernel.dispatchBatch(account, address(bad), calls, badSig, badDl);
        assertEq(kernel.batchNonces(account), 0, "failed batch must not consume the nonce");

        // valid attempt reuses nonce 0 and succeeds
        Call[] memory ok = _calls(2);
        (bytes memory okSig, uint256 okDl) = _mb(address(good), ok);
        kernel.dispatchBatch(account, address(good), ok, okSig, okDl);
        assertEq(kernel.batchNonces(account), 1);
        assertEq(safe.callCount(), 2);
    }

    // ── registration requirement ────────────────────────────────────────────────

    function test_B_UnregisteredPermission_Rejected() public {
        MockBatchAlwaysTrue perm = new MockBatchAlwaysTrue(); // deployed, not registered
        Call[] memory calls = _calls(1);
        (bytes memory sig, uint256 dl) = _mb(address(perm), calls);
        vm.expectPartialRevert(SailKernel.PermissionNotRegistered.selector);
        kernel.dispatchBatch(account, address(perm), calls, sig, dl);
    }
}
