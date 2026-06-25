// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                 from "forge-std/Test.sol";
import {SailKernel}           from "../contracts/core/SailKernel.sol";
import {SailGovernance}       from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}     from "./support/TimelockDeployer.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";
import {IFeePolicy}           from "../contracts/interfaces/IFeePolicy.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mocks — self-contained, no dependency on other test helpers
// ─────────────────────────────────────────────────────────────────────────────

contract _O3Perm is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

contract _O3Safe {
    // Octane group 1a test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external pure returns (bool) { return true; }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}
}

contract _O3FeePolicy is IFeePolicy {
    function feeRecipient() external pure returns (address) { return address(0xFEE1); }
    function computeFee(address, uint256) external pure returns (uint256, address, uint256) {
        return (0, address(0), 0);
    }
    function recordCollection(address, uint256, uint256) external {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Octane audit cluster-03 regression tests.
///         Covers EIP-712 deadline enforcement (#7), nonce epoch invalidation (#7 related),
///         empty-array ETH refund (#8), and permission registration validation (#11 related).
contract Octane03_Signatures is Test {

    // ── Keys ──────────────────────────────────────────────────────────────────
    uint256 constant SIGNER_KEY  = 0xDEAD;
    uint256 constant MANAGER_KEY = 0xBEEF;

    // ── Protocol fixtures ─────────────────────────────────────────────────────
    SailGovernance gov;
    SailKernel     kernel;
    _O3Safe        safe;
    _O3Perm        perm;
    _O3FeePolicy   feePolicy;

    address permSigner;
    address manager;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        permSigner = vm.addr(SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        gov      = new SailGovernance(address(0x1111), 0 /* fee */, address(0xEEEE), 0, TimelockDeployer.deploy(address(0x1111)));
        kernel   = new SailKernel(address(gov), address(0x2222));
        safe     = new _O3Safe();
        perm     = new _O3Perm();
        feePolicy = new _O3FeePolicy();
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(address(feePolicy), true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true); // Octane #9: trust the mock singleton

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0), block.timestamp + 1 days, "");
    }

    // ── Signature helpers ─────────────────────────────────────────────────────

    /// Build a permissionSigner EIP-712 sig over an already-built struct hash.
    function _signerSig(bytes32 structHash) internal view returns (bytes memory) {
        bytes32 digest = kernel.hashTypedDataV4(structHash);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Build a manager EIP-712 sig for a dispatch call.
    function _managerSig(
        address account,
        address permission,
        address target,
        uint256 value,
        bytes memory data,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(),
            account, permission, target, value, keccak256(data), nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, digest);
        return abi.encodePacked(r, s, v);
    }

    /// Register perm on safe using a valid future deadline.
    function _registerPerm(address p) internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), p, nonce, deadline
        ));
        kernel.registerPermission(address(safe), p, deadline, _signerSig(sh));
    }

    /// Revoke session on safe using a valid future deadline.
    function _revokeSession() internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce, deadline
        ));
        kernel.revokeSession(address(safe), deadline, _signerSig(sh));
    }

    /// Activate session on safe using a valid future deadline.
    function _activateSession() internal {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonce, deadline
        ));
        kernel.activateSession(address(safe), deadline, _signerSig(sh));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 1. Deadline enforcement — all 6 single-op signer functions (#7)
    //    Each function must revert DeadlineExpired when deadline < block.timestamp.
    // ─────────────────────────────────────────────────────────────────────────

    function test_Deadline_RegisterPermission_ExpiredReverts() public {
        uint256 past     = block.timestamp - 1;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.registerPermission(address(safe), address(perm), past, sig);
    }

    function test_Deadline_RevokePermission_ExpiredReverts() public {
        _registerPerm(address(perm));
        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.revokePermission(address(safe), address(perm), past, sig);
    }

    function test_Deadline_ReplacePermission_ExpiredReverts() public {
        _registerPerm(address(perm));
        _O3Perm perm2 = new _O3Perm();
        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REPLACE_PERMISSION_TYPEHASH(), address(safe), address(perm), address(perm2), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.replacePermission(address(safe), address(perm), address(perm2), past, sig);
    }

    function test_Deadline_RevokeSession_ExpiredReverts() public {
        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.revokeSession(address(safe), past, sig);
    }

    function test_Deadline_ActivateSession_ExpiredReverts() public {
        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.activateSession(address(safe), past, sig);
    }

    function test_Deadline_SetFeePolicy_ExpiredReverts() public {
        uint256 past  = block.timestamp - 1;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(feePolicy), address(0), nonce, past
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.DeadlineExpired.selector, past, block.timestamp));
        kernel.setFeePolicy(address(safe), address(feePolicy), address(0), past, sig);
    }

    function test_Deadline_SetFeePolicy_BadSigReverts() public {
        // Verify that a wrong-key sig is still rejected (sig invalid).
        uint256 future = type(uint256).max;
        uint256 nonce  = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.SET_FEE_POLICY_TYPEHASH(), address(safe), address(feePolicy), address(0), nonce, future
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, digest);
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.setFeePolicy(address(safe), address(feePolicy), address(0), future, abi.encodePacked(r, s, v));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 2. Stale-signature replay blocked (#7)
    //    A valid activateSession sig issued with a short deadline cannot be
    //    submitted after that deadline elapses.
    // ─────────────────────────────────────────────────────────────────────────

    function test_StaleSignatureReplay_ActivateSession_Blocked() public {
        // Issue a sig that expires in 60 seconds.
        uint256 shortDeadline = block.timestamp + 60;
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonce, shortDeadline
        ));
        bytes memory sig = _signerSig(sh);

        // Fast-forward past the deadline.
        vm.warp(shortDeadline + 1);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.DeadlineExpired.selector, shortDeadline, block.timestamp
        ));
        kernel.activateSession(address(safe), shortDeadline, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 3. Nonce epoch bump — revokeSession (#7 related)
    //    A dispatch sig valid before revokeSession cannot be used after the
    //    session is re-activated, because revokeSession advances managerNonces
    //    by NONCE_EPOCH_INCREMENT (2^128).
    // ─────────────────────────────────────────────────────────────────────────

    function test_EpochBump_RevokeSession_InvalidatesManagerSig() public {
        _registerPerm(address(perm));

        // Build a dispatch sig against the current manager nonce.
        uint256 staleNonce   = kernel.managerNonces(address(safe));
        uint256 dispDeadline = block.timestamp + 1 hours;
        bytes memory staleSig = _managerSig(
            address(safe), address(perm), address(0x1), 0, "", staleNonce, dispDeadline
        );

        // Revoke session — bumps managerNonces by 2^128.
        _revokeSession();

        // Re-activate session so dispatch gate passes.
        _activateSession();

        // The stale sig references an old nonce and must be rejected.
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(perm), address(0x1), 0, "", staleSig, dispDeadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 4. Nonce epoch bump — revokePermission (#7 related)
    //    A dispatch sig naming permission P that was valid before revokePermission
    //    cannot execute even if P is re-registered, because revokePermission
    //    bumps managerNonces.
    // ─────────────────────────────────────────────────────────────────────────

    function test_EpochBump_RevokePermission_InvalidatesManagerSig() public {
        _registerPerm(address(perm));

        // Pre-sign a dispatch naming perm at the current nonce.
        uint256 staleNonce   = kernel.managerNonces(address(safe));
        uint256 dispDeadline = block.timestamp + 1 hours;
        bytes memory staleSig = _managerSig(
            address(safe), address(perm), address(0x1), 0, "", staleNonce, dispDeadline
        );

        // Revoke perm — bumps managerNonces.
        {
            uint256 deadline = block.timestamp + 1 days;
            uint256 nonce    = kernel.signerNonces(address(safe));
            bytes32 sh = keccak256(abi.encode(
                kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perm), nonce, deadline
            ));
            kernel.revokePermission(address(safe), address(perm), deadline, _signerSig(sh));
        }

        // Re-register the same permission.
        _registerPerm(address(perm));

        // Stale sig now points at a retired nonce — must be rejected.
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(perm), address(0x1), 0, "", staleSig, dispDeadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 5. Nonce epoch bump — replacePermission (#7 related)
    //    Same guarantee as #4 but via replacePermission.
    // ─────────────────────────────────────────────────────────────────────────

    function test_EpochBump_ReplacePermission_InvalidatesManagerSig() public {
        _registerPerm(address(perm));

        uint256 staleNonce   = kernel.managerNonces(address(safe));
        uint256 dispDeadline = block.timestamp + 1 hours;
        bytes memory staleSig = _managerSig(
            address(safe), address(perm), address(0x1), 0, "", staleNonce, dispDeadline
        );

        // Replace perm with perm2 — bumps managerNonces.
        _O3Perm perm2 = new _O3Perm();
        {
            uint256 deadline = block.timestamp + 1 days;
            uint256 nonce    = kernel.signerNonces(address(safe));
            bytes32 sh = keccak256(abi.encode(
                kernel.REPLACE_PERMISSION_TYPEHASH(),
                address(safe), address(perm), address(perm2), nonce, deadline
            ));
            kernel.replacePermission(address(safe), address(perm), address(perm2), deadline, _signerSig(sh));
        }

        // Re-register original perm so membership check passes.
        _registerPerm(address(perm));

        // Stale dispatch sig must be rejected.
        vm.expectRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(address(safe), address(perm), address(0x1), 0, "", staleSig, dispDeadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 6. No epoch bump on activateSession or registerPermission (#7 related)
    //    activateSession (a re-enabling op) must NOT advance managerNonces.
    //    registerPermission (widening scope) must NOT advance managerNonces.
    //    A dispatch sig signed against the current nonce must still be valid
    //    after these operations.
    // ─────────────────────────────────────────────────────────────────────────

    function test_NoBump_ActivateSession_PreserveManagerSig() public {
        _registerPerm(address(perm));

        // Revoke session first to get a bump; then sign a dispatch against the POST-bump nonce.
        _revokeSession();
        uint256 postBumpNonce = kernel.managerNonces(address(safe));
        uint256 dispDeadline  = block.timestamp + 1 hours;
        bytes memory sig = _managerSig(
            address(safe), address(perm), address(0x1), 0, "", postBumpNonce, dispDeadline
        );

        // activateSession: session re-enabled, nonce must NOT change.
        _activateSession();
        assertEq(kernel.managerNonces(address(safe)), postBumpNonce, "managerNonce must not change on activateSession");

        // Dispatch with the pre-signed sig should succeed.
        kernel.dispatch(address(safe), address(perm), address(0x1), 0, "", sig, dispDeadline);
    }

    function test_NoBump_RegisterPermission_PreserveManagerSig() public {
        _O3Perm perm2 = new _O3Perm();
        _registerPerm(address(perm2));   // register perm2 first for a known baseline

        uint256 nonceBefore  = kernel.managerNonces(address(safe));
        uint256 dispDeadline = block.timestamp + 1 hours;
        bytes memory sig = _managerSig(
            address(safe), address(perm2), address(0x1), 0, "", nonceBefore, dispDeadline
        );

        // registerPermission: widens scope — must NOT bump managerNonces.
        _registerPerm(address(perm));
        assertEq(kernel.managerNonces(address(safe)), nonceBefore, "managerNonce must not change on registerPermission");

        // Dispatch with the pre-signed sig should succeed.
        kernel.dispatch(address(safe), address(perm2), address(0x1), 0, "", sig, dispDeadline);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 7. Empty-array ETH refund in registerPermissions (#8)
    //    Calling registerPermissions with an empty array and non-zero msg.value
    //    must refund the full amount to the caller; no ETH is trapped.
    // ─────────────────────────────────────────────────────────────────────────

    function test_EmptyArray_ETHRefunded() public {
        address caller  = address(0xCAFE);
        uint256 sendAmt = 0.05 ether;
        vm.deal(caller, sendAmt);

        // Build a valid (but unused) sig — the function returns before verifying it.
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(),
            address(safe),
            keccak256(""),   // keccak of empty array encoding
            nonce,
            deadline
        ));
        bytes memory sig = _signerSig(sh);

        address[] memory empty = new address[](0);

        uint256 kernelBalBefore = address(kernel).balance;

        vm.prank(caller);
        kernel.registerPermissions{value: sendAmt}(address(safe), empty, deadline, sig);

        // Caller receives their ETH back; kernel balance is unchanged.
        assertEq(caller.balance,              sendAmt,          "caller should be refunded");
        assertEq(address(kernel).balance,     kernelBalBefore,  "kernel must not accumulate ETH");
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 8. Zero-address permission rejected (#11 related)
    // ─────────────────────────────────────────────────────────────────────────

    function test_RegisterPermission_ZeroAddressReverts() public {
        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), address(0), nonce, deadline
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(SailKernel.ZeroAddress.selector);
        kernel.registerPermission(address(safe), address(0), deadline, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // 9. Non-contract (EOA) permission rejected (#11 related)
    // ─────────────────────────────────────────────────────────────────────────

    function test_RegisterPermission_NonContractReverts() public {
        address eoa = vm.addr(0x1234); // deterministic EOA — no code
        assertEq(eoa.code.length, 0,   "precondition: eoa has no code");

        uint256 deadline = block.timestamp + 1 days;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), eoa, nonce, deadline
        ));
        bytes memory sig = _signerSig(sh); // pre-compute before expectRevert
        vm.expectRevert(abi.encodeWithSelector(SailKernel.NotAContract.selector, eoa));
        kernel.registerPermission(address(safe), eoa, deadline, sig);
    }
}
