// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test}                 from "forge-std/Test.sol";
import {SailKernel}           from "../contracts/core/SailKernel.sol";
import {SailGovernance}       from "../contracts/governance/SailGovernance.sol";
import {TimelockDeployer}     from "./support/TimelockDeployer.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mocks — self-contained
// ─────────────────────────────────────────────────────────────────────────────

contract _ERSafe {
    // A finalized Safe reports nonce>=1 and exposes its trusted singleton via masterCopy().
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }
    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external pure returns (bool) { return true; }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Emergency-revoke kill-switch regression tests
//
// The emergency revoke must take effect in a single block: a permissionSigner
// operation signed BEFORE the revoke — in particular a queued activateSession —
// must not be able to silently re-enable the session afterwards. revokeSession
// advances the signer nonce across an epoch to enforce this, while the honest
// just-in-time reactivation (signing the new current nonce) still works.
// ─────────────────────────────────────────────────────────────────────────────

contract EmergencyRevokeTest is Test {

    uint256 constant SIGNER_KEY  = 0xDEAD;
    uint256 constant MANAGER_KEY = 0xBEEF;

    SailGovernance gov;
    SailKernel     kernel;
    _ERSafe        safe;

    address permSigner;
    address manager;

    function setUp() public {
        permSigner = vm.addr(SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        gov    = new SailGovernance(address(0x1111), 0, address(0xEEEE), 0, TimelockDeployer.deploy(address(0x1111)));
        kernel = new SailKernel(address(gov), address(0x2222), address(0));
        safe   = new _ERSafe();

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeSingleton(address(0x5AFE), true);

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(0), address(0), block.timestamp + 1 days, "");
    }

    // ── Signature helpers ──────────────────────────────────────────────────────

    function _signRevoke(uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), address(safe), nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signActivate(uint256 nonce, uint256 deadline) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(kernel.ACTIVATE_SESSION_TYPEHASH(), address(safe), nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _sessionActive() internal view returns (bool active) {
        (,,,, active) = kernel.configs(address(safe));
    }

    // ── Tests ──────────────────────────────────────────────────────────────────

    /// A permissionSigner activateSession pre-signed for the next sequential nonce
    /// before the revoke must NOT re-enable the session after the revoke.
    function test_PreSignedActivateSession_RevertsAfterRevoke() public {
        uint256 n        = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 30 days;

        // Attacker holds an activateSession signed for the value the old +1 scheme would
        // have produced right after a revoke.
        bytes memory queuedActivateSig = _signActivate(n + 1, deadline);

        // Honest emergency revoke at the current nonce.
        kernel.revokeSession(address(safe), deadline, _signRevoke(n, deadline));
        assertFalse(_sessionActive(), "session must be suspended by revoke");

        // The signer nonce advanced across an epoch, not merely +1.
        assertEq(
            kernel.signerNonces(address(safe)),
            n + 1 + (uint256(1) << 128),
            "signer nonce must advance across an epoch on revoke"
        );

        // The queued activate (signed over n+1) is now stale and cannot re-enable the session.
        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.activateSession(address(safe), deadline, queuedActivateSig);

        assertFalse(_sessionActive(), "kill switch must hold against a pre-signed activate");
    }

    /// The honest reactivation — signing the NEW current nonce after a revoke — still works.
    function test_FreshActivateSession_SucceedsAfterRevoke() public {
        uint256 n        = kernel.signerNonces(address(safe));
        uint256 deadline = block.timestamp + 30 days;

        kernel.revokeSession(address(safe), deadline, _signRevoke(n, deadline));
        assertFalse(_sessionActive(), "session must be suspended by revoke");

        // Sign a fresh activate over the current (epoch-advanced) nonce.
        uint256 current = kernel.signerNonces(address(safe));
        kernel.activateSession(address(safe), deadline, _signActivate(current, deadline));

        assertTrue(_sessionActive(), "fresh just-in-time reactivation must succeed");
    }
}
