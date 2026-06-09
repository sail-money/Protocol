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

contract _O4Perm is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

contract _O4Safe {
    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external pure returns (bool) { return true; }
    function isModuleEnabled(address) external pure returns (bool) { return true; }
    receive() external payable {}
}

contract _O4FeePolicy is IFeePolicy {
    address public immutable recipient;
    constructor(address r) { recipient = r; }
    function feeRecipient() external view returns (address) { return recipient; }
    function computeFee(address, uint256 nav) external pure returns (uint256, address, uint256) {
        // gross fee = 1% of nav, no distributor
        return (nav / 100, address(0), 0);
    }
    function recordCollection(address, uint256, uint256) external {}
}

// ─────────────────────────────────────────────────────────────────────────────
// Test contract
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Octane audit cluster-04 regression tests.
///         Covers:
///           #5  — sessionActive gate on collectFees
///           #6  — atomic replacePermissions (plural)
contract Octane04_Session is Test {

    // ── Keys ──────────────────────────────────────────────────────────────────
    uint256 constant SIGNER_KEY  = 0xDEAD;
    uint256 constant MANAGER_KEY = 0xBEEF;
    uint256 constant BAD_KEY     = 0xBAD;

    // ── Protocol fixtures ─────────────────────────────────────────────────────
    SailGovernance gov;
    SailKernel     kernel;
    _O4Safe        safe;
    _O4FeePolicy   feePolicy;

    address permSigner;
    address manager;
    address feeRecipient;

    // ── Setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        permSigner   = vm.addr(SIGNER_KEY);
        manager      = vm.addr(MANAGER_KEY);
        feeRecipient = address(0xFEE1);

        gov      = new SailGovernance(address(0x1111), 0 /* fee */, address(0xEEEE), 0, TimelockDeployer.deploy(address(0x1111)));
        kernel   = new SailKernel(address(gov), address(0x2222));
        safe     = new _O4Safe();
        feePolicy = new _O4FeePolicy(feeRecipient);
        vm.prank(address(gov.timelock()));
        gov.setTrustedFeePolicy(address(feePolicy), true);
        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);

        vm.prank(address(safe));
        kernel.registerAccount(permSigner, manager, address(feePolicy), address(0));

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
    // Finding #5 — sessionActive gate on collectFees
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
        _O4Perm perm = new _O4Perm();
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
    // Finding #6 — replacePermissions (plural)
    // ─────────────────────────────────────────────────────────────────────────

    /// Happy path: replace [A, B] with [C, D] atomically.
    function test_ReplacePermissions_HappyPath() public {
        _O4Perm permA = new _O4Perm();
        _O4Perm permB = new _O4Perm();
        _O4Perm permC = new _O4Perm();
        _O4Perm permD = new _O4Perm();

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
        _O4Perm permA = new _O4Perm();
        _O4Perm permC = new _O4Perm();
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
        _O4Perm permA = new _O4Perm();
        _O4Perm permC = new _O4Perm();
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
        _O4Perm permA = new _O4Perm(); // NOT registered
        _O4Perm permC = new _O4Perm();

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
        _O4Perm permA = new _O4Perm();
        _O4Perm permB = new _O4Perm(); // already registered; used as newPermission
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
        _O4Perm permA = new _O4Perm();
        _O4Perm permC = new _O4Perm();
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
        _O4Perm permA = new _O4Perm();
        _O4Perm permB = new _O4Perm();
        _O4Perm permC = new _O4Perm();
        _O4Perm permD = new _O4Perm();
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

    // ── Allow receiving ETH refunds ───────────────────────────────────────────
    receive() external payable {}
}
