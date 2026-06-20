// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailKernel}        from "../contracts/core/SailKernel.sol";
import {SailGovernance}    from "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer}  from "./support/TimelockDeployer.sol";
import {MockSafe}          from "./mocks/MockSafe.sol";
import {
    MockPermissionAlwaysTrue,
    MockPermissionAlwaysFalse,
    MockPermissionReverts,
    MockPermissionReturnsTwo,
    MockPermissionReturnsShort,
    MockPermissionGasBomb,
    MockPermissionStateMutator,
    MockPermissionReenters
} from "./mocks/MockPermissions.sol";

/// @title  KernelGuaranteesTest
/// @notice Proves the SailKernel's single-dispatch runtime guarantees DIRECTLY, using only
///         mock permissions — no example template is imported. If every template were deleted,
///         this suite would still exercise guarantees 1-6 (whitepaper §4.2 / §8.1).
contract KernelGuaranteesTest is Test {
    uint256 internal constant SIGNER_KEY  = 0x5161;
    uint256 internal constant MANAGER_KEY = 0x6262;

    address internal constant TEAM      = address(0x7EA8);
    address internal constant EMERGENCY = address(0xE);
    address internal constant TREASURY  = address(0x77);
    address internal constant TARGET    = address(0xCAFE); // benign call target (≠ account/kernel/0)

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
        gov    = new SailGovernance(TEAM, 0.001 ether, EMERGENCY, 0, tl); // fee 0
        kernel = new SailKernel(address(gov), TREASURY);
        safe   = new MockSafe();
        account = address(safe);

        vm.prank(address(gov.timelock()));
        gov.setTrustedSafeProxyCodehash(address(safe).codehash, true);

        vm.prank(account);
        kernel.registerAccount(permSigner, manager, address(0), address(0)); // no fee policy
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _registerPerm(address perm) internal {
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(account);
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), account, perm, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.registerPermission(account, perm, deadline, abi.encodePacked(r, s, v));
    }

    /// @dev Build a manager-signed dispatch for (perm, TARGET, data) at the current manager nonce.
    function _md(address perm, bytes memory data, uint256 key)
        internal view returns (bytes memory sig, uint256 deadline)
    {
        deadline = block.timestamp + 1 hours;
        uint256 nonce = kernel.managerNonces(account);
        bytes32 sh = keccak256(abi.encode(
            kernel.DISPATCH_TYPEHASH(), account, perm, TARGET, uint256(0), keccak256(data), nonce, deadline
        ));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, kernel.hashTypedDataV4(sh));
        sig = abi.encodePacked(r, s, v);
    }

    function _data() internal pure returns (bytes memory) { return hex"deadbeef"; }

    // ── Guarantee 1 — static evaluation / reentrancy safety ─────────────────────

    /// @notice A permission that attempts to mutate state during evaluate is blocked by the
    ///         kernel's staticcall: the mutation reverts, the dispatch is denied, and no write occurs.
    function test_G1_StateMutatingPermission_BlockedAndDenied() public {
        MockPermissionStateMutator perm = new MockPermissionStateMutator();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);

        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);

        assertEq(perm.touched(), 0, "staticcall must block the SSTORE");
        assertEq(safe.callCount(), 0, "no exec on denied dispatch");
    }

    /// @notice A permission that attempts to re-enter the kernel during evaluate cannot effect any
    ///         kernel state change (staticcall), the dispatch is denied, and the kernel records nothing.
    function test_G1_ReentrantPermission_CannotReenterKernel() public {
        MockPermissionReenters perm = new MockPermissionReenters(address(kernel));
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);

        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);

        assertFalse(kernel.registered(address(perm)), "reentry must not register the permission as an account");
        assertEq(safe.callCount(), 0);
    }

    // ── Guarantee 2 — gas isolation ─────────────────────────────────────────────

    /// @notice A permission that exceeds PERMISSION_GAS_CAP is treated as denied (the gas-capped
    ///         staticcall OOGs → false) and cannot DoS the kernel: the dispatch reverts cleanly
    ///         with PermissionDenied rather than consuming all transaction gas.
    function test_G2_GasBomb_CappedAndDenied() public {
        MockPermissionGasBomb perm = new MockPermissionGasBomb();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);

        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
        assertEq(safe.callCount(), 0);
    }

    // ── Guarantee 3 — selective authorization ───────────────────────────────────

    /// @notice Only the permission named in the manager signature is consulted; another registered
    ///         (denying) permission does not block a dispatch that names an approving permission.
    function test_G3_OnlyNamedPermissionConsulted() public {
        MockPermissionAlwaysTrue  yes = new MockPermissionAlwaysTrue();
        MockPermissionAlwaysFalse no  = new MockPermissionAlwaysFalse();
        _registerPerm(address(no));
        _registerPerm(address(yes));

        (bytes memory sig, uint256 dl) = _md(address(yes), _data(), MANAGER_KEY);
        kernel.dispatch(account, address(yes), TARGET, 0, _data(), sig, dl);
        assertEq(safe.callCount(), 1, "approving named permission authorises despite a registered denier");
    }

    /// @notice Naming a denying permission reverts, even though an approving one is also registered.
    function test_G3_NamingDenierReverts() public {
        MockPermissionAlwaysTrue  yes = new MockPermissionAlwaysTrue();
        MockPermissionAlwaysFalse no  = new MockPermissionAlwaysFalse();
        _registerPerm(address(yes));
        _registerPerm(address(no));

        (bytes memory sig, uint256 dl) = _md(address(no), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(no), TARGET, 0, _data(), sig, dl);
    }

    /// @notice Naming a permission that is not registered on the account reverts.
    function test_G3_UnregisteredPermission_Reverts() public {
        MockPermissionAlwaysTrue yes = new MockPermissionAlwaysTrue();
        (bytes memory sig, uint256 dl) = _md(address(yes), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionNotRegistered.selector);
        kernel.dispatch(account, address(yes), TARGET, 0, _data(), sig, dl);
    }

    // ── Guarantee 4 — fail-closed ───────────────────────────────────────────────

    /// @notice An account with no registered permission cannot dispatch.
    function test_G4_NoRegisteredPermission_Reverts() public {
        MockPermissionAlwaysTrue yes = new MockPermissionAlwaysTrue();
        (bytes memory sig, uint256 dl) = _md(address(yes), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionNotRegistered.selector);
        kernel.dispatch(account, address(yes), TARGET, 0, _data(), sig, dl);
    }

    function test_G4_RevertingPermission_Denied() public {
        MockPermissionReverts perm = new MockPermissionReverts();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }

    function test_G4_FalsePermission_Denied() public {
        MockPermissionAlwaysFalse perm = new MockPermissionAlwaysFalse();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }

    /// @notice A permission returning a non-canonical bool word (uint256(2)) is treated as denied.
    function test_G4_MalformedReturnTwo_Denied() public {
        MockPermissionReturnsTwo perm = new MockPermissionReturnsTwo();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
        assertEq(safe.callCount(), 0);
    }

    /// @notice A permission returning fewer than 32 bytes is treated as denied.
    function test_G4_ShortReturn_Denied() public {
        MockPermissionReturnsShort perm = new MockPermissionReturnsShort();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }

    /// @notice Dispatch against an account that was never registered reverts.
    function test_G4_UnregisteredAccount_Reverts() public {
        MockPermissionAlwaysTrue yes = new MockPermissionAlwaysTrue();
        (bytes memory sig, uint256 dl) = _md(address(yes), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.AccountNotRegistered.selector);
        kernel.dispatch(address(0xBEEF), address(yes), TARGET, 0, _data(), sig, dl);
    }

    // ── Guarantee 5 — custody isolation ─────────────────────────────────────────

    /// @notice The kernel moves account assets ONLY through a dispatch that satisfies the named
    ///         permission, and forwards exactly the requested call.
    function test_G5_AssetsMoveOnlyOnSatisfiedDispatch() public {
        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);

        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
        assertEq(safe.callCount(), 1);
        assertEq(safe.lastTo(), TARGET);
        assertEq(safe.lastData(), _data());
    }

    /// @notice A denied dispatch performs no Safe execution (no asset movement).
    function test_G5_DeniedDispatch_NoExec() public {
        MockPermissionAlwaysFalse perm = new MockPermissionAlwaysFalse();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.PermissionDenied.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
        assertEq(safe.callCount(), 0);
    }

    // ── Guarantee 6 — signer separation ─────────────────────────────────────────

    /// @notice The manager cannot register a permission: registration requires the permissionSigner's
    ///         signature, so a manager-signed registration is rejected.
    function test_G6_ManagerCannotRegisterPermission() public {
        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue();
        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(account);
        bytes32 sh = keccak256(abi.encode(kernel.REGISTER_PERMISSION_TYPEHASH(), account, address(perm), nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(MANAGER_KEY, kernel.hashTypedDataV4(sh)); // manager, not signer
        vm.expectPartialRevert(SailKernel.InvalidSignerSignature.selector);
        kernel.registerPermission(account, address(perm), deadline, abi.encodePacked(r, s, v));
    }

    /// @notice The permissionSigner cannot dispatch: dispatch requires the manager's signature.
    function test_G6_PermissionSignerCannotDispatch() public {
        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue();
        _registerPerm(address(perm));
        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), SIGNER_KEY); // signer, not manager
        vm.expectPartialRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }

    /// @notice The account (owner) can rotate the manager; the old manager can no longer dispatch.
    function test_G6_OwnerRotatesManager_OldManagerCannotDispatch() public {
        // Owner (the account) rotates the manager. setManager also clears registered mandates,
        // so re-register afterwards via the (unchanged) permissionSigner to isolate the proof
        // that the OLD manager's signature is now rejected.
        address newManager = vm.addr(0x9999);
        vm.prank(account);
        kernel.setManager(newManager);

        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue();
        _registerPerm(address(perm));

        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY); // old manager signs
        vm.expectPartialRevert(SailKernel.InvalidManagerSignature.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }

    /// @notice The permissionSigner can revoke the session, which disables dispatch.
    function test_G6_PermissionSignerCanRevokeSession() public {
        MockPermissionAlwaysTrue perm = new MockPermissionAlwaysTrue();
        _registerPerm(address(perm));

        uint256 deadline = block.timestamp + 1 hours;
        uint256 nonce    = kernel.signerNonces(account);
        bytes32 sh = keccak256(abi.encode(kernel.REVOKE_SESSION_TYPEHASH(), account, nonce, deadline));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(SIGNER_KEY, kernel.hashTypedDataV4(sh));
        kernel.revokeSession(account, deadline, abi.encodePacked(r, s, v));

        (bytes memory sig, uint256 dl) = _md(address(perm), _data(), MANAGER_KEY);
        vm.expectPartialRevert(SailKernel.SessionInactive.selector);
        kernel.dispatch(account, address(perm), TARGET, 0, _data(), sig, dl);
    }
}
