// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                 from "forge-std/Test.sol";
import {SafeModuleEnabler} from "../contracts/safe/SafeModuleEnabler.sol";
import {SailKernel}           from "../contracts/core/SailKernel.sol";
import {SailGovernance}       from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}     from "./support/TimelockDeployer.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";
import {IBatchPermission, Call, BatchContext} from "../contracts/interfaces/IBatchPermission.sol";
import {IFeePolicy}           from "../contracts/interfaces/IFeePolicy.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mocks — self-contained, no dependency on other test helpers
// ─────────────────────────────────────────────────────────────────────────────

contract _SessPerm is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

contract _SessBatchPerm is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) { return true; }
    function isBatchPermission() external pure returns (bool) { return true; }
}

contract _SessSafe {
    // Test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external pure returns (bool) { return true; }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}
}

contract _SessFeePolicy is IFeePolicy {
    address public immutable recipient;
    constructor(address r) { recipient = r; }
    function feeRecipient() external view returns (address) { return recipient; }
    function computeFee(address, uint256 nav) external pure returns (uint256, address, uint256) {
        // gross fee = 1% of nav, no distributor
        return (nav / 100, address(0), 0);
    }
    function recordCollection(address, uint256, uint256) external {}
    function onAttach(address) external {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Session lifecycle regression tests.
///         Covers:
///           #5  — sessionActive gate on collectFees
///           #6  — atomic replacePermissions (plural)
contract SessionLifecycleTest is Test {

    // ── Keys ──────────────────────────────────────────────────────────────────
    uint256 constant SIGNER_KEY  = 0xDEAD;
    uint256 constant MANAGER_KEY = 0xBEEF;
    uint256 constant BAD_KEY     = 0xBAD;

    // ── Protocol fixtures ─────────────────────────────────────────────────────
    SailGovernance gov;
    SailKernel     kernel;
    _SessSafe        safe;
    _SessFeePolicy   feePolicy;

    address permSigner;
    address manager;
    address feeRecipient;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        permSigner   = vm.addr(SIGNER_KEY);
        manager      = vm.addr(MANAGER_KEY);
        feeRecipient = address(0xFEE1);

        gov      = new SailGovernance(address(0x1111), 0 /* fee */, address(0xEEEE), 0, TimelockDeployer.deploy(address(0x1111)));
        kernel   = new SailKernel(address(gov), address(0x2222), address(new SafeModuleEnabler()));
        safe     = new _SessSafe();
        feePolicy = new _SessFeePolicy(feeRecipient);
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(address(feePolicy), true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // trust the mock singleton

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0), block.timestamp + 1 days, "");

        // Fund the safe with ETH so fee transfers can execute
        vm.deal(address(safe), 100 ether);
    }

    // ── Signature helpers ─────────────────────────────────────────────────────

    function _signerSig(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _badSig(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(BAD_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _revokeSession() internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce, deadline
        ));
        kernel.revokeSession(address(safe), deadline, _signerSig(sh));
    }

    function _activateSession() internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonce, deadline
        ));
        kernel.activateSession(address(safe), deadline, _signerSig(sh));
    }

    /// Build a manager signature over a single Dispatch using the account's CURRENT managerNonce.
    function _managerDispatchSig(address perm, address target, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            address(safe), perm, target, uint256(0), keccak256(""),
            kernel.managerNonces(address(safe)), deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Build a manager signature over a DispatchBatch using the account's CURRENT batchNonce.
    function _managerBatchSig(address perm, Call[] memory calls, uint256 deadline)
        internal view returns (bytes memory)
    {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_BATCH_TYPEHASH(),
            address(safe), perm, keccak256(abi.encode(calls)),
            kernel.batchNonces(address(safe)), deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    function _registerPerm(address p) internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), p, nonce, deadline
        ));
        kernel.registerPermission(address(safe), p, deadline, _signerSig(sh));
    }

    /// Build a permissionSigner sig for replacePermissions.
    function _replacePermsSig(
        address[] memory oldPerms,
        address[] memory newPerms,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSIONS_TYPEHASH(),
            address(safe),
            _hashAddrArray(oldPerms),
            _hashAddrArray(newPerms),
            nonce,
            deadline
        ));
        return _signerSig(sh);
    }

    /// Mirror of SailKernel._hashAddressArray — pads addresses to bytes32, then keccak256.
    function _hashAddrArray(address[] memory arr) internal pure returns (bytes32) {
        bytes32[] memory buf = new bytes32[](arr.length);
        for (uint256 i; i < arr.length; i++) {
            buf[i] = bytes32(uint256(uint160(arr[i])));
        }
        return keccak256(abi.encodePacked(buf));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // sessionActive gate on collectFees
    // ─────────────────────────────────────────────────────────────────────────

    /// After revokeSession, collectFees must revert with SessionInactive.
    function test_CollectFees_BlockedAfterRevokeSession() public {
        _revokeSession();

        vm.prank(manager);
        vm.expectRevert(abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(safe)));
        kernel.collectFees(address(safe), 1 ether, 100 ether, address(0));
    }

    /// With session active, collectFees proceeds normally (no revert from session gate).
    function test_CollectFees_AllowedWhenSessionActive() public {
        // Session is active by default after registerAccount.
        // The safe holds 100 ether; collectFees with grossFee=1 ether, nav=100 ether
        // → maxFee = 1 ether (1% of 100 ether), grossFee = 1 ether → OK.
        vm.prank(manager);
        kernel.collectFees(address(safe), 1 ether, 100 ether, address(0));
    }

    /// dispatch is still blocked after revokeSession — no regression.
    function test_Dispatch_StillBlockedAfterRevokeSession() public {
        _SessPerm perm = new _SessPerm();
        _registerPerm(address(perm));
        _revokeSession();

        uint256 mNonce   = kernel.managerNonces(address(safe));
        uint256 deadline = block.timestamp + 1 days;
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            address(safe), address(perm), address(0xCAFE), uint256(0), keccak256(""), mNonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        bytes memory sig = abi.encodePacked(r, s, v);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.SessionInactive.selector, address(safe)));
        kernel.dispatch(address(safe), address(perm), address(0xCAFE), 0, "", sig, deadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // replacePermissions (plural)
    // ─────────────────────────────────────────────────────────────────────────

    /// Happy path: replace [A, B] with [C, D] atomically.
    function test_ReplacePermissions_HappyPath() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permB = new _SessPerm();
        _SessPerm permC = new _SessPerm();
        _SessPerm permD = new _SessPerm();

        _registerPerm(address(permA));
        _registerPerm(address(permB));

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));

        address[] memory olds = new address[](2);
        address[] memory news = new address[](2);
        olds[0] = address(permA); olds[1] = address(permB);
        news[0] = address(permC); news[1] = address(permD);

        bytes memory sig = _replacePermsSig(olds, news, nonce, deadline);
        kernel.replacePermissions(address(safe), olds, news, deadline, sig);

        assertFalse(kernel.isPermissionRegistered(address(safe), address(permA)), "A still registered");
        assertFalse(kernel.isPermissionRegistered(address(safe), address(permB)), "B still registered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(permC)),  "C not registered");
        assertTrue(kernel.isPermissionRegistered(address(safe), address(permD)),  "D not registered");

        // nonce must have advanced by exactly 1
        assertEq(kernel.signerNonces(address(safe)), nonce + 1, "signer nonce not advanced");
    }

    /// Wrong signer → InvalidSignerSignature.
    function test_ReplacePermissions_WrongSigner_Reverts() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permC = new _SessPerm();
        _registerPerm(address(permA));

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));

        address[] memory olds = new address[](1);
        address[] memory news = new address[](1);
        olds[0] = address(permA);
        news[0] = address(permC);

        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSIONS_TYPEHASH(),
            address(safe),
            _hashAddrArray(olds),
            _hashAddrArray(news),
            nonce,
            deadline
        ));
        bytes memory badSig = _badSig(sh);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.replacePermissions(address(safe), olds, news, deadline, badSig);
    }

    /// Expired deadline → DeadlineExpired.
    function test_ReplacePermissions_ExpiredDeadline_Reverts() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permC = new _SessPerm();
        _registerPerm(address(permA));

        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));

        address[] memory olds = new address[](1);
        address[] memory news = new address[](1);
        olds[0] = address(permA);
        news[0] = address(permC);

        bytes memory sig = _replacePermsSig(olds, news, nonce, past);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.replacePermissions(address(safe), olds, news, past, sig);
    }

    /// Mismatched array lengths → ArrayLengthMismatch.
    function test_ReplacePermissions_ArrayLengthMismatch_Reverts() public {
        address[] memory olds = new address[](2);
        address[] memory news = new address[](1);
        olds[0] = address(0x1); olds[1] = address(0x2);
        news[0] = address(0x3);

        vm.expectRevert(SailKernel.ArrayLengthMismatch.selector);
        kernel.replacePermissions(address(safe), olds, news, block.timestamp + 1, "");
    }

    /// Unregistered old permission → PermissionNotRegistered.
    function test_ReplacePermissions_UnregisteredOld_Reverts() public {
        _SessPerm permA = new _SessPerm(); // NOT registered
        _SessPerm permC = new _SessPerm();

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));

        address[] memory olds = new address[](1);
        address[] memory news = new address[](1);
        olds[0] = address(permA);
        news[0] = address(permC);

        bytes memory sig = _replacePermsSig(olds, news, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionNotRegistered.selector, address(permA)));
        kernel.replacePermissions(address(safe), olds, news, deadline, sig);
    }

    /// New permission already registered → PermissionAlreadyRegistered.
    function test_ReplacePermissions_AlreadyRegisteredNew_Reverts() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permB = new _SessPerm(); // already registered; used as newPermission
        _registerPerm(address(permA));
        _registerPerm(address(permB));

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));

        address[] memory olds = new address[](1);
        address[] memory news = new address[](1);
        olds[0] = address(permA);
        news[0] = address(permB); // already registered

        bytes memory sig = _replacePermsSig(olds, news, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(SailKernel.PermissionAlreadyRegistered.selector, address(permB)));
        kernel.replacePermissions(address(safe), olds, news, deadline, sig);
    }

    /// Empty arrays → refund msg.value, no nonce consumed, no revert.
    function test_ReplacePermissions_EmptyArrays_RefundsAndReturns() public {
        uint256 nonceBefore = kernel.signerNonces(address(safe));
        address[] memory empty = new address[](0);

        uint256 balBefore = address(this).balance;
        // send 1 wei with empty call — should be refunded
        kernel.replacePermissions{value: 1}(address(safe), empty, empty, block.timestamp + 1, "");

        assertEq(kernel.signerNonces(address(safe)), nonceBefore, "nonce must not advance for empty call");
        assertEq(address(this).balance, balBefore, "msg.value not refunded");
    }

    /// After replacePermissions, previously valid manager dispatch signatures are invalidated.
    function test_ReplacePermissions_NonceEpochBump_InvalidatesManagerSigs() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permC = new _SessPerm();
        _registerPerm(address(permA));

        // Capture manager nonce BEFORE the replace
        uint256 mNonceBefore = kernel.managerNonces(address(safe));
        uint256 bNonceBefore = kernel.batchNonces(address(safe));

        uint256 deadline = block.timestamp + 1 days;
        uint256 sNonce   = kernel.signerNonces(address(safe));
        address[] memory olds = new address[](1);
        address[] memory news = new address[](1);
        olds[0] = address(permA);
        news[0] = address(permC);

        bytes memory sig = _replacePermsSig(olds, news, sNonce, deadline);
        kernel.replacePermissions(address(safe), olds, news, deadline, sig);

        // Both nonce counters must have advanced by NONCE_EPOCH_INCREMENT (1 << 128)
        uint256 epochInc = 1 << 128;
        assertEq(kernel.managerNonces(address(safe)), mNonceBefore + epochInc, "managerNonces not bumped");
        assertEq(kernel.batchNonces(address(safe)),   bNonceBefore + epochInc, "batchNonces not bumped");
    }

    /// Fee collection: N swaps → N × permissionRegistrationFee collected; excess refunded.
    function test_ReplacePermissions_FeeCollection() public {
        _SessPerm permA = new _SessPerm();
        _SessPerm permB = new _SessPerm();
        _SessPerm permC = new _SessPerm();
        _SessPerm permD = new _SessPerm();
        _registerPerm(address(permA));
        _registerPerm(address(permB));

        uint256 feePerPerm = gov.permissionRegistrationFee();
        uint256 totalFee   = feePerPerm * 2; // 2 swaps
        uint256 excess     = 0.5 ether;

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        address[] memory olds = new address[](2);
        address[] memory news = new address[](2);
        olds[0] = address(permA); olds[1] = address(permB);
        news[0] = address(permC); news[1] = address(permD);

        bytes memory sig = _replacePermsSig(olds, news, nonce, deadline);

        uint256 callerBefore = address(this).balance;
        kernel.replacePermissions{value: totalFee + excess}(address(safe), olds, news, deadline, sig);

        // Caller should have received back the excess
        assertEq(address(this).balance, callerBefore - totalFee, "excess ETH not refunded");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // nonce epochs rotate on session reactivation
    // ─────────────────────────────────────────────────────────────────────────

    /// activateSession bumps BOTH manager and batch nonce epochs (mirrors revokeSession).
    function test_ActivateSession_BumpsNonceEpochs() public {
        _revokeSession();
        uint256 mBefore = kernel.managerNonces(address(safe));
        uint256 bBefore = kernel.batchNonces(address(safe));

        _activateSession();

        uint256 epochInc = 1 << 128;
        assertEq(kernel.managerNonces(address(safe)), mBefore + epochInc, "managerNonces not bumped on activate");
        assertEq(kernel.batchNonces(address(safe)),   bBefore + epochInc, "batchNonces not bumped on activate");
        (, , , , bool active) = kernel.configs(address(safe));
        assertTrue(active, "session not active after activate");
    }

    /// A dispatch the manager pre-signs DURING suspension must NOT execute after reactivation:
    /// the epoch bump on activate invalidates the stale signature.
    function test_Dispatch_PreSignedDuringSuspension_RejectedAfterActivate() public {
        _SessPerm perm = new _SessPerm();
        _registerPerm(address(perm));

        // Operator suspends the session (epoch bump #1, session inactive).
        _revokeSession();

        // Adversarial manager pre-signs a dispatch in the suspension epoch.
        uint256 deadline = block.timestamp + 7 days;
        bytes memory preSig = _managerDispatchSig(address(perm), address(0xCAFE), deadline);

        // Operator reactivates — fix rotates the epoch again, invalidating preSig.
        _activateSession();

        // The pre-signed message no longer verifies against the live nonce.
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(perm), address(0xCAFE), 0, "", preSig, deadline);
    }

    /// Same property for dispatchBatch / batchNonces.
    function test_DispatchBatch_PreSignedDuringSuspension_RejectedAfterActivate() public {
        _SessBatchPerm perm = new _SessBatchPerm();
        _registerPerm(address(perm));

        _revokeSession();

        uint256 deadline = block.timestamp + 7 days;
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0xCAFE), value: 0, data: ""});
        bytes memory preSig = _managerBatchSig(address(perm), calls, deadline);

        _activateSession();

        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatchBatch(address(safe), address(perm), calls, preSig, deadline);
    }

    /// Legitimate flow is unaffected: revoke → activate → manager signs FRESH (new epoch)
    /// → dispatch succeeds.
    function test_Dispatch_FreshSignAfterActivate_Succeeds() public {
        _SessPerm perm = new _SessPerm();
        _registerPerm(address(perm));

        _revokeSession();
        _activateSession();

        // Manager signs AFTER activation, against the rotated nonce.
        uint256 deadline = block.timestamp + 1 days;
        bytes memory sig = _managerDispatchSig(address(perm), address(0xCAFE), deadline);

        uint256 mNonceBefore = kernel.managerNonces(address(safe));
        kernel.dispatch(address(safe), address(perm), address(0xCAFE), 0, "", sig, deadline);
        assertEq(kernel.managerNonces(address(safe)), mNonceBefore + 1, "manager nonce not consumed on success");
    }

    /// Legitimate batch flow likewise succeeds after a revoke/activate cycle.
    function test_DispatchBatch_FreshSignAfterActivate_Succeeds() public {
        _SessBatchPerm perm = new _SessBatchPerm();
        _registerPerm(address(perm));

        _revokeSession();
        _activateSession();

        uint256 deadline = block.timestamp + 1 days;
        Call[] memory calls = new Call[](1);
        calls[0] = Call({target: address(0xCAFE), value: 0, data: ""});
        bytes memory sig = _managerBatchSig(address(perm), calls, deadline);

        uint256 bNonceBefore = kernel.batchNonces(address(safe));
        kernel.dispatchBatch(address(safe), address(perm), calls, sig, deadline);
        assertEq(kernel.batchNonces(address(safe)), bNonceBefore + 1, "batch nonce not consumed on success");
    }

    // ── Allow receiving ETH refunds ───────────────────────────────────────────
    receive() external payable {}
}
