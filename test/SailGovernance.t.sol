// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";
import {TimelockDeployer} from "./support/TimelockDeployer.sol";

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
        gov = new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, TimelockDeployer.deploy(TEAM));
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
        // Deploy the injected timelock first, so expectEmit wraps only the SailGovernance
        // construction (which is the call that emits GovernanceTransferred).
        TimelockController tl = TimelockDeployer.deploy(TEAM);
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(address(0), TEAM);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, tl);
    }

    function test_Constructor_RevertsOnZeroGovernance() public {
        TimelockController tl = TimelockDeployer.deploy(TEAM);
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(address(0), MAX_FEE, EMERGENCY_ADMIN, 0, tl);
    }

    function test_Constructor_RevertsOnZeroEmergencyAdmin() public {
        TimelockController tl = TimelockDeployer.deploy(TEAM);
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(TEAM, MAX_FEE, address(0), 0, tl);
    }

    function test_Constructor_RevertsOnInitialFeeAboveCap() public {
        TimelockController tl = TimelockDeployer.deploy(TEAM);
        vm.expectRevert(abi.encodeWithSelector(
            SailGovernance.FeeExceedsCap.selector, MAX_FEE + 1, MAX_FEE
        ));
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, MAX_FEE + 1, tl);
    }

    function test_Constructor_SeedsInitialPermissionRegistrationFee() public {
        SailGovernance g =
            new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0.001 ether, TimelockDeployer.deploy(TEAM));
        assertEq(g.permissionRegistrationFee(), 0.001 ether);
    }

    function test_Constructor_RevertsOnZeroTimelock() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, TimelockController(payable(address(0))));
    }

    /// @dev The injected timelock must report a minimum delay of EXACTLY 48 hours. A timelock with
    ///      any other delay (here 24h) must be rejected so the specified 48h guarantee is preserved.
    function test_Constructor_RevertsOnWrongTimelockDelay() public {
        address[] memory p = new address[](1); p[0] = TEAM;
        address[] memory e = new address[](1); e[0] = TEAM;
        TimelockController badDelay = new TimelockController(24 hours, p, e, address(0));
        vm.expectRevert(SailGovernance.TimelockDelayMismatch.selector);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, badDelay);
    }

    /// @dev The injected timelock must grant PROPOSER_ROLE to `initialGovernance`. A timelock whose
    ///      sole proposer is some other address must be rejected — otherwise governance could not
    ///      schedule any parameter change.
    function test_Constructor_RevertsWhenGovernanceNotProposer() public {
        TimelockController wrongProposer = TimelockDeployer.deploy(ALICE); // proposer is ALICE, not TEAM
        vm.expectRevert(SailGovernance.GovernanceNotProposer.selector);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, wrongProposer);
    }

    /// @dev The injected timelock must grant EXECUTOR_ROLE to `initialGovernance`.
    ///      Here the timelock makes TEAM the proposer but ALICE the sole executor — TEAM is not an
    ///      executor, so construction must revert with GovernanceNotExecutor.
    function test_Constructor_RevertsWhenGovernanceNotExecutor() public {
        address[] memory proposers = new address[](1); proposers[0] = TEAM;
        address[] memory executors = new address[](1); executors[0] = ALICE; // not TEAM
        TimelockController wrongExecutor = new TimelockController(48 hours, proposers, executors, address(0));
        vm.expectRevert(SailGovernance.GovernanceNotExecutor.selector);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, wrongExecutor);
    }

    /// @dev The injected timelock must self-administer its roles — the governance
    ///      EOA must not hold admin over them. Here the timelock is deployed with the governance EOA
    ///      (TEAM = initialGovernance) as admin instead of address(0), so construction must revert
    ///      with TimelockNotSelfAdministered.
    ///
    ///      NOTE: a real OZ TimelockController always self-grants DEFAULT_ADMIN_ROLE to itself, so the
    ///      detected condition is specifically "initialGovernance also holds the admin role" — the
    ///      realistic misconfiguration. An arbitrary unrelated EOA admin is not detectable in-contract
    ///      (TimelockController is not AccessControlEnumerable); see the constructor NatSpec.
    function test_Constructor_RevertsWhenTimelockNotSelfAdministered() public {
        address[] memory roles = new address[](1); roles[0] = TEAM;
        TimelockController govAdmin = new TimelockController(48 hours, roles, roles, TEAM); // TEAM = initialGovernance as admin
        vm.expectRevert(SailGovernance.TimelockNotSelfAdministered.selector);
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN, 0, govAdmin);
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
        // acceptGovernance now requires the candidate to hold all three roles that
        // rotateTimelockRoles grants (PROPOSER + EXECUTOR + CANCELLER), so the handoff cannot
        // complete into a split-control state. Cache the role IDs BEFORE pranking — a view call
        // between vm.prank and grantRole would otherwise consume the prank.
        bytes32 proposer  = tl.PROPOSER_ROLE();
        bytes32 executor  = tl.EXECUTOR_ROLE();
        bytes32 canceller = tl.CANCELLER_ROLE();
        vm.prank(address(tl)); tl.grantRole(proposer,  newGov);
        vm.prank(address(tl)); tl.grantRole(executor,  newGov);
        vm.prank(address(tl)); tl.grantRole(canceller, newGov);
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
        bytes32 proposer  = tl.PROPOSER_ROLE();
        bytes32 executor  = tl.EXECUTOR_ROLE();
        bytes32 canceller = tl.CANCELLER_ROLE();
        vm.prank(address(tl)); tl.grantRole(proposer,  ALICE);
        vm.prank(address(tl)); tl.grantRole(executor,  ALICE);
        vm.prank(address(tl)); tl.grantRole(canceller, ALICE);
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

    /// @dev acceptGovernance requires ALL three timelock roles, so a partial rotation (e.g. PROPOSER
    ///      + EXECUTOR granted but CANCELLER withheld) cannot complete the handoff — preventing a
    ///      split-control state where the outgoing governance keeps CANCELLER.
    function test_AcceptGovernance_RevertsIfCancellerNotRotated() public {
        _timelockExec(abi.encodeCall(gov.proposeGovernance, (ALICE)));
        TimelockController tl = gov.timelock();
        bytes32 proposer = tl.PROPOSER_ROLE();
        bytes32 executor = tl.EXECUTOR_ROLE();
        vm.prank(address(tl)); tl.grantRole(proposer, ALICE);
        vm.prank(address(tl)); tl.grantRole(executor, ALICE);
        // CANCELLER_ROLE deliberately withheld.
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

    // Pause cooldown persists across an early unpause (anti-pause-griefing)
    // ─────────────────────────────────────────────────────────────────────────

    function test_EarlyUnpause_DoesNotResetCooldown() public {
        // pause at t0, unpause early at t0 + 1h. The cooldown is measured from the pause START and is
        // NOT reset by the unpause, so an immediate re-pause is blocked until PAUSE_COOLDOWN elapses —
        // a (compromised) emergency admin cannot defeat the cooldown by pause→unpause→re-pause looping.
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        uint256 pausedAt = gov.lastPauseTimestamp();
        vm.warp(block.timestamp + 1 hours);
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        // immediate re-pause reverts on the still-running cooldown. Precompute the expected revert
        // arg BEFORE pranking — a view call here would otherwise consume the prank.
        uint256 cooldownEnd = pausedAt + gov.PAUSE_COOLDOWN();
        vm.prank(EMERGENCY_ADMIN);
        vm.expectRevert(abi.encodeWithSelector(SailGovernance.PauseCooldown.selector, cooldownEnd));
        gov.pause();
        // once the cooldown fully elapses, a fresh pause succeeds
        vm.warp(cooldownEnd);
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertTrue(gov.isPaused());
    }

    function test_NormalUnpause_AfterFullExpiry_PreservesTimestamp() public {
        // pause, let pauseExpiry pass, then unpause. lastPauseTimestamp is preserved (not reset), but
        // the cooldown from the original pause has elapsed, so a fresh pause is allowed.
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        uint256 pausedAt = gov.lastPauseTimestamp();
        vm.warp(block.timestamp + 72 hours + 1);
        assertFalse(gov.isPaused());
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        assertEq(gov.pauseExpiry(), 0);
        assertEq(gov.lastPauseTimestamp(), pausedAt);
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        assertTrue(gov.isPaused());
    }

    function test_Unpause_PreservesLastPauseTimestamp() public {
        vm.prank(EMERGENCY_ADMIN);
        gov.pause();
        uint256 pausedAt = gov.lastPauseTimestamp();
        assertGt(pausedAt, 0);
        vm.prank(EMERGENCY_ADMIN);
        gov.unpause();
        // NOT reset to zero — the cooldown persists across the early unpause.
        assertEq(gov.lastPauseTimestamp(), pausedAt);
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

    // -------------------------------------------------------------------------
    // C3 — zero-value guard symmetry on steady-state setters (mirror bootstrap)
    // -------------------------------------------------------------------------

    /// @dev setTrustedSafeProxyCodehash must reject a zero codehash, matching the
    ///      `ZeroCodehash` guard bootstrapAllowlists already applies. A zero codehash
    ///      would match empty/EOA accounts and has no legitimate use.
    function test_C3_SetTrustedSafeProxyCodehash_RevertsOnZero() public {
        bytes memory data = abi.encodeCall(gov.setTrustedSafeProxyCodehash, (bytes32(0), true));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(SailGovernance.ZeroCodehash.selector);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    /// @dev A non-zero codehash still writes successfully (the guard is purely additive).
    function test_C3_SetTrustedSafeProxyCodehash_NonZeroSucceeds() public {
        bytes32 ch = keccak256("some.proxy.codehash");
        _timelockExec(abi.encodeCall(gov.setTrustedSafeProxyCodehash, (ch, true)));
        assertTrue(gov.trustedSafeProxyCodehash(ch));
    }

    /// @dev setTrustedSafeFactory must reject the zero address, matching bootstrap's ZeroAddress guard.
    function test_C3_SetTrustedSafeFactory_RevertsOnZero() public {
        bytes memory data = abi.encodeCall(gov.setTrustedSafeFactory, (address(0), true));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    /// @dev setTrustedSafeSingleton must reject the zero address, matching bootstrap's ZeroAddress guard.
    function test_C3_SetTrustedSafeSingleton_RevertsOnZero() public {
        bytes memory data = abi.encodeCall(gov.setTrustedSafeSingleton, (address(0), true));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }
}
