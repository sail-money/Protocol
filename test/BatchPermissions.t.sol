// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel} from "../contracts/core/SailKernel.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";
import {IPermission, Context} from "../contracts/interfaces/IPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal mocks (local to this file to avoid cross-file dependencies)
// ─────────────────────────────────────────────────────────────────────────────

contract BatchMockSafe {
    receive() external payable {}
    function execTransactionFromModule(address, uint256, bytes calldata, uint8)
        external pure returns (bool) { return true; }
}

contract BatchMockPermission is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return bytes32(0); }
}

// ─────────────────────────────────────────────────────────────────────────────
// Test harness
// ─────────────────────────────────────────────────────────────────────────────

contract BatchPermissionsTest is Test {
    SailGovernance gov;
    SailKernel     kernel;
    BatchMockSafe  safe;

    // Three independent permission contracts for batch tests
    BatchMockPermission perm1;
    BatchMockPermission perm2;
    BatchMockPermission perm3;

    address constant TEAM     = address(0x1111);
    address constant TREASURY = address(0x2222);

    uint256 constant SIGNER_KEY  = 0xDEAD;
    uint256 constant MANAGER_KEY = 0xBEEF;
    address permSigner;
    address manager;

    // ── setup ─────────────────────────────────────────────────────────────────

    function setUp() public {
        permSigner = vm.addr(SIGNER_KEY);
        manager    = vm.addr(MANAGER_KEY);

        gov    = new SailGovernance(TEAM, 1 ether);
        kernel = new SailKernel(address(gov), TREASURY);
        safe   = new BatchMockSafe();

        perm1  = new BatchMockPermission();
        perm2  = new BatchMockPermission();
        perm3  = new BatchMockPermission();

        kernel.registerAccount(address(safe), permSigner, manager, address(0));
    }

    receive() external payable {} // accept refunds

    // ─────────────────────────────────────────────────────────────────────────
    // Signature helpers
    // ─────────────────────────────────────────────────────────────────────────

    /// @dev EIP-712-compliant hash of address[]: mirrors _hashAddressArray in the kernel.
    function _hashPerms(address[] memory perms) internal pure returns (bytes32) {
        bytes32[] memory buf = new bytes32[](perms.length);
        for (uint256 i; i < perms.length; i++) {
            buf[i] = bytes32(uint256(uint160(perms[i])));
        }
        return keccak256(abi.encodePacked(buf));
    }

    function _signRegisterBatch(
        address account,
        address[] memory perms,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(),
            account,
            _hashPerms(perms),
            nonce,
            deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    function _signRevokeBatch(
        address account,
        address[] memory perms,
        uint256 nonce,
        uint256 deadline
    ) internal view returns (bytes memory) {
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSIONS_TYPEHASH(),
            account,
            _hashPerms(perms),
            nonce,
            deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        return abi.encodePacked(r, s, v);
    }

    /// @dev Register perm1 via the single-permission path to seed state for revoke tests.
    function _seedSinglePermission(address perm) internal {
        uint256 nonce = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSION_TYPEHASH(), address(safe), perm, nonce
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.registerPermission(address(safe), perm, abi.encodePacked(r, s, v));
    }

    function _arr(address a) internal pure returns (address[] memory r) {
        r = new address[](1); r[0] = a;
    }
    function _arr(address a, address b) internal pure returns (address[] memory r) {
        r = new address[](2); r[0] = a; r[1] = b;
    }
    function _arr(address a, address b, address c) internal pure returns (address[] memory r) {
        r = new address[](3); r[0] = a; r[1] = b; r[2] = c;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // registerPermissions — happy paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRegister_TwoPermissions_BothRegistered() public {
        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm2)));
        assertEq(kernel.getPermissions(address(safe)).length, 2);
    }

    function test_BatchRegister_ThreePermissions_AllRegistered() public {
        address[] memory perms = _arr(address(perm1), address(perm2), address(perm3));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(kernel.getPermissions(address(safe)).length, 3);
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm2)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm3)));
    }

    function test_BatchRegister_SingleElement_WorksLikeSingle() public {
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)));
        assertEq(kernel.getPermissions(address(safe)).length, 1);
    }

    function test_BatchRegister_EmptyArray_NoPermissionsAdded() public {
        address[] memory perms = new address[](0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(kernel.getPermissions(address(safe)).length, 0);
        assertEq(kernel.signerNonces(address(safe)), nonce + 1);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // registerPermissions — fee tests
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRegister_ExactFeeSucceeds() public {
        // Set BASE_FEE so the fee is non-trivial and deterministic
        vm.prank(TEAM); gov.setBaseFee(0.01 ether);

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 fee1     = _fee(address(perm1));
        uint256 fee2     = _fee(address(perm2));
        uint256 totalFee = fee1 + fee2;

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        uint256 treasuryBefore = TREASURY.balance;
        vm.deal(address(this), totalFee);
        kernel.registerPermissions{value: totalFee}(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(TREASURY.balance - treasuryBefore, totalFee, "treasury must receive total fee");
    }

    function test_BatchRegister_UnderpaymentReverts() public {
        vm.prank(TEAM); gov.setBaseFee(0.01 ether);

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 totalFee = _fee(address(perm1)) + _fee(address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterBatch(address(safe), perms, nonce, deadline);

        vm.deal(address(this), totalFee);
        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.InsufficientFee.selector, totalFee, totalFee - 1
        ));
        kernel.registerPermissions{value: totalFee - 1}(address(safe), perms, deadline, sig);
    }

    function test_BatchRegister_OverpaymentRefunded() public {
        vm.prank(TEAM); gov.setBaseFee(0.01 ether);

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 totalFee = _fee(address(perm1)) + _fee(address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        uint256 overpay = totalFee + 1 ether;
        vm.deal(address(this), overpay);
        uint256 balBefore = address(this).balance;

        kernel.registerPermissions{value: overpay}(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        // Net cost = totalFee; 1 ether refunded
        assertEq(balBefore - address(this).balance, totalFee, "excess must be refunded");
    }

    function test_BatchRegister_ZeroFeeWhenBaseFeeZero() public {
        // BASE_FEE default = 0, COMPLEXITY_RATE = 0 → totalFee = 0
        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        // No ETH sent — should succeed since totalFee = 0
        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(kernel.getPermissions(address(safe)).length, 2);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // registerPermissions — duplicate / already-registered handling
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRegister_DuplicateWithinBatch_Reverts() public {
        // [perm1, perm1] — second occurrence should trigger PermissionAlreadyRegistered
        address[] memory perms = _arr(address(perm1), address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.PermissionAlreadyRegistered.selector, address(perm1)
        ));
        kernel.registerPermissions(address(safe), perms, deadline, sig);
    }

    function test_BatchRegister_DuplicateWithinBatch_Atomic_NothingAdded() public {
        // perm1 then perm1 again — atomicity means even perm1 should NOT end up registered
        address[] memory perms = _arr(address(perm1), address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterBatch(address(safe), perms, nonce, deadline);

        try kernel.registerPermissions(address(safe), perms, deadline, sig) {} catch {}

        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm1)),
            "perm1 must not be registered after atomic revert");
        assertEq(kernel.getPermissions(address(safe)).length, 0);
    }

    function test_BatchRegister_AlreadyRegisteredPermission_Reverts() public {
        // Register perm1 first via single path, then try batch [perm1, perm2]
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.PermissionAlreadyRegistered.selector, address(perm1)
        ));
        kernel.registerPermissions(address(safe), perms, deadline, sig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // registerPermissions — access control and nonce
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRegister_UnauthorizedSig_Reverts() public {
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        // Sign with wrong key
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(),
            address(safe), _hashPerms(perms), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, kernel.hashTypedDataV4(sh));
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermissions(address(safe), perms, deadline, badSig);
    }

    function test_BatchRegister_ExpiredDeadline_Reverts() public {
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp - 1;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRegisterBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.DeadlineExpired.selector, deadline, block.timestamp
        ));
        kernel.registerPermissions(address(safe), perms, deadline, sig);
    }

    function test_BatchRegister_ConsumesSingleNonce() public {
        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonceBefore = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonceBefore, deadline)
        );

        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1,
            "exactly one nonce must be consumed for the entire batch");
    }

    function test_BatchRegister_EmitsPermissionRegisteredPerEntry() public {
        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        vm.expectEmit(true, true, false, false);
        emit SailKernel.PermissionRegistered(address(safe), address(perm1));
        vm.expectEmit(true, true, false, false);
        emit SailKernel.PermissionRegistered(address(safe), address(perm2));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );
    }

    function test_BatchRegister_UnregisteredAccount_Reverts() public {
        address unknown = address(new BatchMockSafe());
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(unknown);
        bytes memory sig = _signRegisterBatch(unknown, perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.AccountNotRegistered.selector, unknown
        ));
        kernel.registerPermissions(unknown, perms, deadline, sig);
    }

    function testFuzz_BatchRegister_NonSigner(address caller) public {
        vm.assume(caller != permSigner);
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        // Build a sig from caller's private key — but caller is not the permissionSigner
        bytes32 sh = keccak256(abi.encode(
            kernel.REGISTER_PERMISSIONS_TYPEHASH(),
            address(safe), _hashPerms(perms), nonce, deadline
        ));
        bytes32 digest = kernel.hashTypedDataV4(sh);
        // Just use an arbitrary invalid sig (65 bytes of zeros)
        bytes memory badSig = new bytes(65);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermissions(address(safe), perms, deadline, badSig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // revokePermissions — happy paths
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRevoke_TwoPermissions_BothRemoved() public {
        _seedSinglePermission(address(perm1));
        _seedSinglePermission(address(perm2));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );

        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm1)));
        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm2)));
        assertEq(kernel.getPermissions(address(safe)).length, 0);
    }

    function test_BatchRevoke_SingleElement() public {
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );

        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm1)));
    }

    function test_BatchRevoke_EmptyArray_NoPermissionsRemoved() public {
        _seedSinglePermission(address(perm1));

        address[] memory perms = new address[](0);
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );

        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)),
            "perm1 must still be registered after empty revoke batch");
        assertEq(kernel.signerNonces(address(safe)), nonce + 1);
    }

    function test_BatchRevoke_ThreePermissions_AllRemoved() public {
        _seedSinglePermission(address(perm1));
        _seedSinglePermission(address(perm2));
        _seedSinglePermission(address(perm3));

        address[] memory perms = _arr(address(perm1), address(perm2), address(perm3));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(kernel.getPermissions(address(safe)).length, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // revokePermissions — error cases and atomicity
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRevoke_NotRegistered_Reverts() public {
        address[] memory perms = _arr(address(perm1)); // perm1 never registered
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokeBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.PermissionNotRegistered.selector, address(perm1)
        ));
        kernel.revokePermissions(address(safe), perms, deadline, sig);
    }

    function test_BatchRevoke_DuplicateWithinBatch_Reverts() public {
        _seedSinglePermission(address(perm1));

        // [perm1, perm1] — second removal fails because perm1 was already removed
        address[] memory perms = _arr(address(perm1), address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokeBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.PermissionNotRegistered.selector, address(perm1)
        ));
        kernel.revokePermissions(address(safe), perms, deadline, sig);
    }

    function test_BatchRevoke_DuplicateWithinBatch_Atomic_NothingRemoved() public {
        _seedSinglePermission(address(perm1));

        // Revoke [perm1, perm1]: second removal fails → whole tx reverts → perm1 still registered
        address[] memory perms = _arr(address(perm1), address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokeBatch(address(safe), perms, nonce, deadline);

        try kernel.revokePermissions(address(safe), perms, deadline, sig) {} catch {}

        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)),
            "perm1 must still be registered after atomic revert");
    }

    function test_BatchRevoke_PartiallyUnregistered_Atomic() public {
        // perm1 registered, perm2 NOT registered → [perm1, perm2] reverts → perm1 stays
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokeBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.PermissionNotRegistered.selector, address(perm2)
        ));
        kernel.revokePermissions(address(safe), perms, deadline, sig);

        // perm1 must NOT have been removed (atomicity)
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm1)),
            "perm1 must survive the reverted batch revoke");
    }

    function test_BatchRevoke_UnauthorizedSig_Reverts() public {
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSIONS_TYPEHASH(),
            address(safe), _hashPerms(perms), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(0xBAD, kernel.hashTypedDataV4(sh));
        bytes memory badSig = abi.encodePacked(r, s, v);

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.revokePermissions(address(safe), perms, deadline, badSig);
    }

    function test_BatchRevoke_ExpiredDeadline_Reverts() public {
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp - 1;
        uint256 nonce    = kernel.signerNonces(address(safe));
        bytes memory sig = _signRevokeBatch(address(safe), perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.DeadlineExpired.selector, deadline, block.timestamp
        ));
        kernel.revokePermissions(address(safe), perms, deadline, sig);
    }

    function test_BatchRevoke_ConsumesSingleNonce() public {
        _seedSinglePermission(address(perm1));
        _seedSinglePermission(address(perm2));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline    = block.timestamp + 1 hours;
        uint256 nonceBefore = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonceBefore, deadline)
        );

        assertEq(kernel.signerNonces(address(safe)), nonceBefore + 1);
    }

    function test_BatchRevoke_EmitsPermissionRevokedPerEntry() public {
        _seedSinglePermission(address(perm1));
        _seedSinglePermission(address(perm2));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        vm.expectEmit(true, true, false, false);
        emit SailKernel.PermissionRevoked(address(safe), address(perm1));
        vm.expectEmit(true, true, false, false);
        emit SailKernel.PermissionRevoked(address(safe), address(perm2));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );
    }

    function test_BatchRevoke_UnregisteredAccount_Reverts() public {
        address unknown = address(new BatchMockSafe());
        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = 0;
        bytes memory sig = _signRevokeBatch(unknown, perms, nonce, deadline);

        vm.expectRevert(abi.encodeWithSelector(
            SailKernel.AccountNotRegistered.selector, unknown
        ));
        kernel.revokePermissions(unknown, perms, deadline, sig);
    }

    function testFuzz_BatchRevoke_NonSigner(address caller) public {
        vm.assume(caller != permSigner);
        _seedSinglePermission(address(perm1));

        address[] memory perms = _arr(address(perm1));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        bytes memory badSig = new bytes(65); // garbage sig

        vm.expectRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.revokePermissions(address(safe), perms, deadline, badSig);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Batch + single interoperability
    // ─────────────────────────────────────────────────────────────────────────

    function test_BatchRegister_ThenSingleRevoke_Works() public {
        // Register perm1+perm2 via batch, then revoke perm1 via single
        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.registerPermissions(
            address(safe), perms, deadline,
            _signRegisterBatch(address(safe), perms, nonce, deadline)
        );

        // Revoke perm1 via single path
        uint256 n2 = kernel.signerNonces(address(safe));
        bytes32 sh = keccak256(abi.encode(
            kernel.REVOKE_PERMISSION_TYPEHASH(), address(safe), address(perm1), n2
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.revokePermission(address(safe), address(perm1), abi.encodePacked(r, s, v));

        assertFalse(kernel.isPermissionRegistered(address(safe), address(perm1)));
        assertTrue(kernel.isPermissionRegistered(address(safe), address(perm2)));
    }

    function test_SingleRegister_ThenBatchRevoke_Works() public {
        // Register individually, revoke via batch
        _seedSinglePermission(address(perm1));
        _seedSinglePermission(address(perm2));

        address[] memory perms = _arr(address(perm1), address(perm2));
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(address(safe));

        kernel.revokePermissions(
            address(safe), perms, deadline,
            _signRevokeBatch(address(safe), perms, nonce, deadline)
        );

        assertEq(kernel.getPermissions(address(safe)).length, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Internal helper
    // ─────────────────────────────────────────────────────────────────────────

    function _fee(address perm) internal view returns (uint256) {
        uint256 size = perm.code.length;
        uint256 fee  = gov.BASE_FEE() + size * gov.COMPLEXITY_RATE();
        uint256 cap  = gov.MAX_PERMISSION_FEE_WEI();
        return fee > cap ? cap : fee;
    }
}
