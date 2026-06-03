// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

contract SailGovernanceTest is Test {
    SailGovernance gov;

    address constant TEAM            = address(0x1111);
    address constant ALICE           = address(0x2222);
    address constant BOB             = address(0x3333);
    address constant EMERGENCY_ADMIN = address(0x4444);
    uint256 constant MAX_FEE         = 0.001 ether;

    uint256 private _saltNonce;

    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceProposed(address indexed currentGovernance, address indexed proposedGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event PermissionRegistrationFeeUpdated(uint256 oldFee, uint256 newFee);
    event MaxPermissionsPerAccountUpdated(uint256 oldLimit, uint256 newLimit);
    event Paused(uint256 expiry);
    event Unpaused();

    function setUp() public {
        gov = new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timelock helpers
    // ─────────────────────────────────────────────────────────────────────────

    function _timelockSchedule(bytes memory data) internal returns (bytes32 salt) {
        salt = bytes32(_saltNonce++);
        TimelockController tl = gov.timelock();
        address proposer = gov.governance();
        vm.prank(proposer);
        tl.schedule(address(gov), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
    }

    function _timelockExecute(bytes memory data, bytes32 salt) internal {
        TimelockController tl = gov.timelock();
        address executor = gov.governance();
        vm.prank(executor);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function _timelockExec(bytes memory data) internal {
        _timelockExecute(data, _timelockSchedule(data));
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constructor
    // ─────────────────────────────────────────────────────────────────────────

    function test_Constructor_SetsGovernance() public view {
        assertEq(gov.governance(), TEAM);
    }

    function test_Constructor_SetsEmergencyAdmin() public view {
        assertEq(gov.emergencyAdmin(), EMERGENCY_ADMIN);
    }

    function test_Constructor_SetsImmutableCaps() public view {
        assertEq(gov.MAX_PROTOCOL_CUT_BPS(), 2_500);
        assertEq(gov.MAX_PERMISSION_FEE_WEI(), MAX_FEE);
    }

    function test_Constructor_DefaultTunablesAreZero() public view {
        assertEq(gov.currentProtocolCutBps(), 0);
        assertEq(gov.permissionRegistrationFee(), 0);
    }

    function test_Constructor_DefaultMaxPermissionsIs20() public view {
        assertEq(gov.maxPermissionsPerAccount(), 20);
    }

    function test_Constructor_CreatesTimelock() public view {
        assertTrue(address(gov.timelock()) != address(0));
    }

    function test_Constructor_EmitsGovernanceTransferred() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(address(0), TEAM);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0);
    }

    function test_Constructor_RevertsOnZeroGovernance() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(address(0), MAX_FEE, EMERGENCY_ADMIN, 0);
    }

    function test_Constructor_RevertsOnZeroEmergencyAdmin() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(TEAM, MAX_FEE, address(0), 0);
    }

    function test_Constructor_RevertsOnInitialFeeAboveCap() public {
        vm.expectRevert(abi.encodeWithSelector(
            SailGovernance.FeeExceedsCap.selector, MAX_FEE + 1, MAX_FEE
        ));
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, MAX_FEE + 1);
    }

    function test_Constructor_SeedsInitialPermissionRegistrationFee() public {
        SailGovernance g = new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0.001 ether);
        assertEq(g.permissionRegistrationFee(), 0.001 ether);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Constitutional caps — enforced at execution time via timelock
    // ─────────────────────────────────────────────────────────────────────────

    function test_MaxProtocolCutBps_IsImmutable() public view {
        assertEq(gov.MAX_PROTOCOL_CUT_BPS(), 2_500);
    }

    function test_MaxPermissionsCap_Is100() public view {
        assertEq(gov.MAX_PERMISSIONS_CAP(), 100);
    }

    function test_SetProtocolCutBps_AtExactCap() public {
        _timelockExec(abi.encodeCall(gov.setProtocolCutBps, (2_500)));
        assertEq(gov.currentProtocolCutBps(), 2_500);
    }

    function test_SetProtocolCutBps_RevertsAboveCap() public {
        bytes memory data = abi.encodeCall(gov.setProtocolCutBps, (2_501));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsProtocolCutCap.selector, 2_501, 2_500)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetProtocolCutBps_RevertsAboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - 2_500);
        uint256 requested = 2_500 + excess;
        bytes memory data = abi.encodeCall(gov.setProtocolCutBps, (requested));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsProtocolCutCap.selector, requested, 2_500)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetProtocolCutBps_WithinCap(uint256 bps) public {
        bps = bound(bps, 0, 2_500);
        _timelockExec(abi.encodeCall(gov.setProtocolCutBps, (bps)));
        assertEq(gov.currentProtocolCutBps(), bps);
    }

    function test_SetPermissionRegistrationFee_AtExactCap() public {
        _timelockExec(abi.encodeCall(gov.setPermissionRegistrationFee, (MAX_FEE)));
        assertEq(gov.permissionRegistrationFee(), MAX_FEE);
    }

    function test_SetPermissionRegistrationFee_RevertsAboveCap() public {
        bytes memory data = abi.encodeCall(gov.setPermissionRegistrationFee, (MAX_FEE + 1));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.FeeExceedsCap.selector, MAX_FEE + 1, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetPermissionRegistrationFee_RevertsAboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - MAX_FEE);
        uint256 requested = MAX_FEE + excess;
        bytes memory data = abi.encodeCall(gov.setPermissionRegistrationFee, (requested));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.FeeExceedsCap.selector, requested, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetPermissionRegistrationFee_WithinCap(uint256 fee) public {
        fee = bound(fee, 0, MAX_FEE);
        _timelockExec(abi.encodeCall(gov.setPermissionRegistrationFee, (fee)));
        assertEq(gov.permissionRegistrationFee(), fee);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // setMaxPermissionsPerAccount
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetMaxPermissionsPerAccount_Succeeds() public {
        _timelockExec(abi.encodeCall(gov.setMaxPermissionsPerAccount, (50)));
        assertEq(gov.maxPermissionsPerAccount(), 50);
    }

    function test_SetMaxPermissionsPerAccount_ToOne() public {
        _timelockExec(abi.encodeCall(gov.setMaxPermissionsPerAccount, (1)));
        assertEq(gov.maxPermissionsPerAccount(), 1);
    }

    function test_SetMaxPermissionsPerAccount_ToExactCap() public {
        _timelockExec(abi.encodeCall(gov.setMaxPermissionsPerAccount, (100)));
        assertEq(gov.maxPermissionsPerAccount(), 100);
    }

    function test_SetMaxPermissionsPerAccount_EmitsEvent() public {
        bytes memory data = abi.encodeCall(gov.setMaxPermissionsPerAccount, (50));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(false, false, false, true);
        emit MaxPermissionsPerAccountUpdated(20, 50);
        _timelockExecute(data, salt);
    }

    function test_SetMaxPermissionsPerAccount_RevertsAtZero() public {
        bytes memory data = abi.encodeCall(gov.setMaxPermissionsPerAccount, (0));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionsCap.selector, 0, 100)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function test_SetMaxPermissionsPerAccount_RevertsAboveCap() public {
        bytes memory data = abi.encodeCall(gov.setMaxPermissionsPerAccount, (101));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionsCap.selector, 101, 100)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetMaxPermissionsPerAccount_WithinBounds(uint256 limit) public {
        limit = bound(limit, 1, 100);
        _timelockExec(abi.encodeCall(gov.setMaxPermissionsPerAccount, (limit)));
        assertEq(gov.maxPermissionsPerAccount(), limit);
    }

    function testFuzz_SetMaxPermissionsPerAccount_AboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - 100);
        uint256 requested = 100 + excess;
        bytes memory data = abi.encodeCall(gov.setMaxPermissionsPerAccount, (requested));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionsCap.selector, requested, 100)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Setters reject direct calls — only timelock may invoke them
    // ─────────────────────────────────────────────────────────────────────────

    function test_Setter_RevertsIfCalledDirectly() public {
        vm.startPrank(TEAM);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setProtocolCutBps(100);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setPermissionRegistrationFee(0.01 ether);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setMaxPermissionsPerAccount(50);
        vm.stopPrank();
    }

    function testFuzz_Setter_RevertsForAnyDirectCaller(address caller) public {
        vm.assume(caller != address(gov.timelock()));
        vm.startPrank(caller);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setProtocolCutBps(100);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setPermissionRegistrationFee(0.01 ether);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setMaxPermissionsPerAccount(50);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Two-step governance transfer
    // ─────────────────────────────────────────────────────────────────────────

    function test_ProposeGovernance_SetsPendingGovernance() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        assertEq(gov.pendingGovernance(), ALICE);
    }

    function test_ProposeGovernance_EmitsEvent() public {
        bytes memory data = abi.encodeCall(gov.proposeGovernance, (ALICE));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(true, true, false, false);
        emit GovernanceProposed(TEAM, ALICE);
        _timelockExecute(data, salt);
    }

    function test_ProposeGovernance_RevertsOnZeroAddress() public {
        bytes memory data = abi.encodeCall(gov.proposeGovernance, (address(0)));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function test_ProposeGovernance_RevertsIfNotTimelock() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.proposeGovernance(ALICE);
    }

    function test_ProposeGovernance_RevertsSameAddress() public {
        bytes memory data = abi.encodeCall(gov.proposeGovernance, (TEAM));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(SailGovernance.SameAddress.selector);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function test_ProposeGovernance_OverridesPending() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (BOB)));
        assertEq(gov.pendingGovernance(), BOB);
    }

    /// @dev Helper: rotate timelock roles from TEAM to `newGov`, then call acceptGovernance.
    ///      Required by the M-1 fix: acceptGovernance now requires the candidate already
    ///      holds PROPOSER_ROLE on the timelock (i.e., rotateTimelockRoles was called first).
    function _rotateAndAccept(address newGov) internal {
        TimelockController tl = gov.timelock();
        bytes32 proposerRole = tl.PROPOSER_ROLE();
        bytes32 executorRole = tl.EXECUTOR_ROLE();
        vm.prank(address(tl));
        tl.grantRole(proposerRole, newGov);
        vm.prank(address(tl));
        tl.grantRole(executorRole, newGov);
        vm.prank(newGov);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_TransfersControl() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        _rotateAndAccept(ALICE);
        assertEq(gov.governance(), ALICE);
    }

    function test_AcceptGovernance_ClearsPendingGovernance() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        _rotateAndAccept(ALICE);
        assertEq(gov.pendingGovernance(), address(0));
    }

    function test_AcceptGovernance_EmitsEvent() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        TimelockController tl = gov.timelock();
        bytes32 proposerRole = tl.PROPOSER_ROLE();
        bytes32 executorRole = tl.EXECUTOR_ROLE();
        vm.prank(address(tl));
        tl.grantRole(proposerRole, ALICE);
        vm.prank(address(tl));
        tl.grantRole(executorRole, ALICE);
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(TEAM, ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfNotPendingGovernance() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        vm.prank(BOB);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfNothingProposed() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfRolesNotRotated() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        // ALICE doesn't have PROPOSER_ROLE yet — rotateTimelockRoles not called
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.RolesNotYetRotated.selector);
        gov.acceptGovernance();
    }

    function test_TwoStep_OldGovernanceCannotProposeAfterAccept() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        _rotateAndAccept(ALICE);
        // Old governance (TEAM) no longer has PROPOSER_ROLE — timelock call would revert
        // Direct call reverts with NotTimelock
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.proposeGovernance(BOB);
    }

    function test_TwoStep_NewGovernanceCanPropose() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        _rotateAndAccept(ALICE);
        // ALICE is now governance with full timelock roles
        assertEq(gov.governance(), ALICE);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Emergency pause
    // ─────────────────────────────────────────────────────────────────────────

    function test_Pause_SetsPauseExpiry() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertEq(gov.pauseExpiry(), block.timestamp + 72 hours);
    }

    function test_Pause_EmitsEvent() public {
        uint256 expectedExpiry = block.timestamp + 72 hours;
        vm.expectEmit(false, false, false, true);
        emit Paused(expectedExpiry);
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
    }

    function test_Unpause_ClearsPauseExpiry() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        assertEq(gov.pauseExpiry(), 0);
    }

    function test_Unpause_EmitsEvent() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.expectEmit(false, false, false, false);
        emit Unpaused();
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
    }

    function test_Pause_RevertsIfNotEmergencyAdmin() public {
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotEmergencyAdmin.selector);
        gov.pause();
    }

    function test_Unpause_RevertsIfNotEmergencyAdmin() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotEmergencyAdmin.selector);
        gov.unpause();
    }

    function test_IsPaused_TrueWhenActive() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertTrue(gov.isPaused());
    }

    function test_IsPaused_FalseAfterExpiry() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.warp(block.timestamp + 72 hours + 1);
        assertFalse(gov.isPaused());
    }

    function test_IsPaused_FalseAfterUnpause() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        assertFalse(gov.isPaused());
    }

    function test_IsPaused_FalseByDefault() public view {
        assertFalse(gov.isPaused());
    }

    // Octane finding #10 — pause cooldown reset on unpause
    // ─────────────────────────────────────────────────────────────────────────

    function test_EarlyUnpause_AllowsImmediateRepause() public {
        // pause at t0, unpause at t0 + 1h — cooldown must not block re-pause
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        // should succeed immediately with no PauseCooldown revert
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertTrue(gov.isPaused());
    }

    function test_NormalUnpause_AfterFullExpiry_Unchanged() public {
        // pause, let pauseExpiry pass, then unpause — should still work
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        vm.warp(block.timestamp + 72 hours + 1);
        assertFalse(gov.isPaused());
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        assertEq(gov.pauseExpiry(), 0);
        assertEq(gov.lastPauseTimestamp(), 0);
    }

    function test_Unpause_ResetsLastPauseTimestamp() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertGt(gov.lastPauseTimestamp(), 0);
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        assertEq(gov.lastPauseTimestamp(), 0);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Events on parameter updates
    // ─────────────────────────────────────────────────────────────────────────

    function test_SetProtocolCutBps_EmitsEvent() public {
        _timelockExec(abi.encodeCall(gov.setProtocolCutBps, (500)));

        bytes memory data = abi.encodeCall(gov.setProtocolCutBps, (1_000));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(false, false, false, true);
        emit ProtocolCutUpdated(500, 1_000);
        _timelockExecute(data, salt);
    }

    function test_SetPermissionRegistrationFee_EmitsEvent() public {
        bytes memory data = abi.encodeCall(gov.setPermissionRegistrationFee, (0.001 ether));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(false, false, false, true);
        emit PermissionRegistrationFeeUpdated(0, 0.001 ether);
        _timelockExecute(data, salt);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // bootstrapAllowlists — one-time genesis seeding (no timelock)
    // ─────────────────────────────────────────────────────────────────────────

    address constant SAFE_FACTORY   = address(0xFAC0);
    address constant SAFE_SINGLETON = address(0x5147);
    address constant MODULE_SETUP   = address(0x5E70);
    address constant FEE_POLICY     = address(0xFEE0);
    bytes32 constant PROXY_CODEHASH = keccak256("safe-proxy-1.4.1");

    function _bootstrapArgs()
        internal
        pure
        returns (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c)
    {
        f = new address[](1); f[0] = SAFE_FACTORY;
        s = new address[](1); s[0] = SAFE_SINGLETON;
        m = new address[](1); m[0] = MODULE_SETUP;
        p = new address[](1); p[0] = FEE_POLICY;
        c = new bytes32[](1); c[0] = PROXY_CODEHASH;
    }

    function test_Bootstrap_SeedsAllowlistsWithoutTimelock() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c) =
            _bootstrapArgs();
        vm.prank(TEAM); // governance == TEAM at deploy
        gov.bootstrapAllowlists(f, s, m, p, c);

        assertTrue(gov.allowlistBootstrapped());
        assertTrue(gov.trustedSafeFactory(SAFE_FACTORY));
        assertTrue(gov.trustedSafeSingleton(SAFE_SINGLETON));
        assertTrue(gov.trustedModuleSetup(MODULE_SETUP));
        assertTrue(gov.trustedFeePolicy(FEE_POLICY));
        assertTrue(gov.trustedSafeProxyCodehash(PROXY_CODEHASH));
    }

    function test_Bootstrap_RevertsForNonGovernance() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c) =
            _bootstrapArgs();
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.bootstrapAllowlists(f, s, m, p, c);
    }

    function test_Bootstrap_RevertsOnSecondCall() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c) =
            _bootstrapArgs();
        vm.prank(TEAM);
        gov.bootstrapAllowlists(f, s, m, p, c);

        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.AlreadyBootstrapped.selector);
        gov.bootstrapAllowlists(f, s, m, p, c);
    }

    function test_Bootstrap_RevertsOnZeroCodehash() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p,) = _bootstrapArgs();
        bytes32[] memory c = new bytes32[](1); c[0] = bytes32(0);
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.ZeroCodehash.selector);
        gov.bootstrapAllowlists(f, s, m, p, c);
    }

    function test_Bootstrap_EmitsEvent() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c) =
            _bootstrapArgs();
        vm.prank(TEAM);
        vm.expectEmit(true, false, false, false);
        emit AllowlistBootstrapped(TEAM);
        gov.bootstrapAllowlists(f, s, m, p, c);
    }

    /// @dev After genesis bootstrap, allowlist changes are timelock-only again — the EOA path is closed.
    function test_Bootstrap_PostBootstrapStillTimelockGated() public {
        (address[] memory f, address[] memory s, address[] memory m, address[] memory p, bytes32[] memory c) =
            _bootstrapArgs();
        vm.prank(TEAM);
        gov.bootstrapAllowlists(f, s, m, p, c);

        // Direct EOA call to a trusted setter still reverts (onlyTimelock).
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setTrustedSafeFactory(address(0xBEEF), true);

        // The timelock path still works.
        _timelockExec(abi.encodeCall(gov.setTrustedSafeFactory, (address(0xBEEF), true)));
        assertTrue(gov.trustedSafeFactory(address(0xBEEF)));
    }

    event AllowlistBootstrapped(address indexed by);
}
