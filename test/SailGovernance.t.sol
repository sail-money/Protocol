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
    uint256 constant MAX_FEE         = 1 ether;

    uint256 private _saltNonce;

    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceProposed(address indexed currentGovernance, address indexed proposedGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);
    event MaxPermissionsPerAccountUpdated(uint256 oldLimit, uint256 newLimit);
    event Paused(uint256 expiry);
    event Unpaused();

    function setUp() public {
        gov = new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN);
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
        assertEq(gov.baseFee(), 0);
        assertEq(gov.complexityRate(), 0);
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
        new SailGovernance(TEAM, MAX_FEE, EMERGENCY_ADMIN);
    }

    function test_Constructor_RevertsOnZeroGovernance() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(address(0), MAX_FEE, EMERGENCY_ADMIN);
    }

    function test_Constructor_RevertsOnZeroEmergencyAdmin() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(TEAM, MAX_FEE, address(0));
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

    function test_SetBaseFee_AtExactCap() public {
        _timelockExec(abi.encodeCall(gov.setBaseFee, (MAX_FEE)));
        assertEq(gov.baseFee(), MAX_FEE);
    }

    function test_SetBaseFee_RevertsAboveCap() public {
        bytes memory data = abi.encodeCall(gov.setBaseFee, (MAX_FEE + 1));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, MAX_FEE + 1, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetBaseFee_RevertsAboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - MAX_FEE);
        uint256 requested = MAX_FEE + excess;
        bytes memory data = abi.encodeCall(gov.setBaseFee, (requested));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, requested, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetBaseFee_WithinCap(uint256 fee) public {
        fee = bound(fee, 0, MAX_FEE);
        _timelockExec(abi.encodeCall(gov.setBaseFee, (fee)));
        assertEq(gov.baseFee(), fee);
    }

    // setComplexityRate — capped at MAX_PERMISSION_FEE_WEI for overflow safety

    function test_SetComplexityRate_AtExactCap() public {
        _timelockExec(abi.encodeCall(gov.setComplexityRate, (MAX_FEE)));
        assertEq(gov.complexityRate(), MAX_FEE);
    }

    function test_SetComplexityRate_RevertsAboveCap() public {
        bytes memory data = abi.encodeCall(gov.setComplexityRate, (MAX_FEE + 1));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, MAX_FEE + 1, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
    }

    function testFuzz_SetComplexityRate_WithinCap(uint256 rate) public {
        rate = bound(rate, 0, MAX_FEE);
        _timelockExec(abi.encodeCall(gov.setComplexityRate, (rate)));
        assertEq(gov.complexityRate(), rate);
    }

    function testFuzz_SetComplexityRate_AboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - MAX_FEE);
        uint256 requested = MAX_FEE + excess;
        bytes memory data = abi.encodeCall(gov.setComplexityRate, (requested));
        bytes32 salt = _timelockSchedule(data);
        TimelockController tl = gov.timelock();
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, requested, MAX_FEE)
        );
        vm.prank(TEAM);
        tl.execute(address(gov), 0, data, bytes32(0), salt);
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
        gov.setBaseFee(0.01 ether);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setComplexityRate(1);
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
        gov.setBaseFee(0.01 ether);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setComplexityRate(1);
        vm.expectRevert(SailGovernance.NotTimelock.selector);
        gov.setMaxPermissionsPerAccount(50);
        vm.stopPrank();
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Two-step governance transfer
    // ─────────────────────────────────────────────────────────────────────────

    function test_ProposeGovernance_SetsPendingGovernance() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        assertEq(gov.pendingGovernance(), ALICE);
    }

    function test_ProposeGovernance_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceProposed(TEAM, ALICE);
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
    }

    function test_ProposeGovernance_RevertsOnZeroAddress() public {
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        gov.proposeGovernance(address(0));
    }

    function test_ProposeGovernance_RevertsIfNotGovernance() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.proposeGovernance(ALICE);
    }

    function test_ProposeGovernance_OverridesPending() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(TEAM);
        gov.proposeGovernance(BOB);
        assertEq(gov.pendingGovernance(), BOB);
    }

    function test_AcceptGovernance_TransfersControl() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        assertEq(gov.governance(), ALICE);
    }

    function test_AcceptGovernance_ClearsPendingGovernance() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        assertEq(gov.pendingGovernance(), address(0));
    }

    function test_AcceptGovernance_EmitsEvent() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(TEAM, ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfNotPendingGovernance() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(BOB);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfNothingProposed() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_TwoStep_OldGovernanceCannotProposeAfterAccept() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.proposeGovernance(BOB);
    }

    function test_TwoStep_NewGovernanceCanPropose() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        vm.prank(ALICE);
        gov.proposeGovernance(BOB);
        assertEq(gov.pendingGovernance(), BOB);
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

    function test_SetBaseFee_EmitsEvent() public {
        bytes memory data = abi.encodeCall(gov.setBaseFee, (0.1 ether));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(false, false, false, true);
        emit BaseFeeUpdated(0, 0.1 ether);
        _timelockExecute(data, salt);
    }

    function test_SetComplexityRate_EmitsEvent() public {
        bytes memory data = abi.encodeCall(gov.setComplexityRate, (7));
        bytes32 salt = _timelockSchedule(data);
        vm.expectEmit(false, false, false, true);
        emit ComplexityRateUpdated(0, 7);
        _timelockExecute(data, salt);
    }
}
