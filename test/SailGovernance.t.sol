// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {SailGovernance} from "../contracts/governance/SailGovernance.sol";

contract SailGovernanceTest is Test {
    SailGovernance gov;

    address constant TEAM    = address(0x1111);
    address constant ALICE   = address(0x2222);
    address constant BOB     = address(0x3333);
    uint256 constant MAX_FEE = 1 ether;

    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceProposed(address indexed currentGovernance, address indexed proposedGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);

    function setUp() public {
        gov = new SailGovernance(TEAM, MAX_FEE);
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    function test_Constructor_SetsGovernance() public view {
        assertEq(gov.governance(), TEAM);
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

    function test_Constructor_EmitsGovernanceTransferred() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(address(0), TEAM);
        new SailGovernance(TEAM, MAX_FEE);
    }

    function test_Constructor_RevertsOnZeroAddress() public {
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        new SailGovernance(address(0), MAX_FEE);
    }

    // -------------------------------------------------------------------------
    // Constitutional caps — cannot be exceeded under any circumstances
    // -------------------------------------------------------------------------

    function test_MaxProtocolCutBps_IsImmutable() public view {
        assertEq(gov.MAX_PROTOCOL_CUT_BPS(), 2_500);
    }

    function test_SetProtocolCutBps_AtExactCap() public {
        vm.prank(TEAM);
        gov.setProtocolCutBps(2_500);
        assertEq(gov.currentProtocolCutBps(), 2_500);
    }

    function test_SetProtocolCutBps_RevertsAboveCap() public {
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsProtocolCutCap.selector, 2_501, 2_500)
        );
        gov.setProtocolCutBps(2_501);
    }

    function testFuzz_SetProtocolCutBps_RevertsAboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - 2_500);
        uint256 requested = 2_500 + excess;
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsProtocolCutCap.selector, requested, 2_500)
        );
        gov.setProtocolCutBps(requested);
    }

    function testFuzz_SetProtocolCutBps_WithinCap(uint256 bps) public {
        bps = bound(bps, 0, 2_500);
        vm.prank(TEAM);
        gov.setProtocolCutBps(bps);
        assertEq(gov.currentProtocolCutBps(), bps);
    }

    function test_SetBaseFee_AtExactCap() public {
        vm.prank(TEAM);
        gov.setBaseFee(MAX_FEE);
        assertEq(gov.baseFee(), MAX_FEE);
    }

    function test_SetBaseFee_RevertsAboveCap() public {
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, MAX_FEE + 1, MAX_FEE)
        );
        gov.setBaseFee(MAX_FEE + 1);
    }

    function testFuzz_SetBaseFee_RevertsAboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - MAX_FEE);
        uint256 requested = MAX_FEE + excess;
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, requested, MAX_FEE)
        );
        gov.setBaseFee(requested);
    }

    function testFuzz_SetBaseFee_WithinCap(uint256 fee) public {
        fee = bound(fee, 0, MAX_FEE);
        vm.prank(TEAM);
        gov.setBaseFee(fee);
        assertEq(gov.baseFee(), fee);
    }

    // -------------------------------------------------------------------------
    // Governance transfer — two-step propose → accept
    // -------------------------------------------------------------------------

    function test_ProposeGovernance_SetsPending() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        assertEq(gov.pendingGovernance(), ALICE);
        assertEq(gov.governance(), TEAM); // not yet transferred
    }

    function test_ProposeGovernance_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceProposed(TEAM, ALICE);
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
    }

    function test_AcceptGovernance_CompletesTransfer() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        assertEq(gov.governance(), ALICE);
        assertEq(gov.pendingGovernance(), address(0));
    }

    function test_AcceptGovernance_EmitsGovernanceTransferred() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(TEAM, ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_NewGovernanceCanAct() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();

        vm.prank(ALICE);
        gov.setProtocolCutBps(1_000);
        assertEq(gov.currentProtocolCutBps(), 1_000);
    }

    function test_AcceptGovernance_OldGovernanceCanNoLongerAct() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();

        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setProtocolCutBps(1_000);
    }

    function test_AcceptGovernance_RevertsForNonPending() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);

        vm.prank(BOB);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_AcceptGovernance_RevertsIfNoPendingProposal() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    function test_ProposeGovernance_RevertsOnZeroAddress() public {
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        gov.proposeGovernance(address(0));
    }

    function test_ProposeGovernance_ChainedTransfer() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(ALICE);
        gov.acceptGovernance();
        vm.prank(ALICE);
        gov.proposeGovernance(BOB);
        vm.prank(BOB);
        gov.acceptGovernance();
        assertEq(gov.governance(), BOB);
    }

    function test_ProposeGovernance_CanOverwritePendingBeforeAccept() public {
        vm.prank(TEAM);
        gov.proposeGovernance(ALICE);
        vm.prank(TEAM);
        gov.proposeGovernance(BOB); // overwrite — ALICE can no longer accept
        assertEq(gov.pendingGovernance(), BOB);

        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotPendingGovernance.selector);
        gov.acceptGovernance();
    }

    // -------------------------------------------------------------------------
    // Unauthorized callers rejected
    // -------------------------------------------------------------------------

    function test_Unauthorized_SetProtocolCutBps() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setProtocolCutBps(100);
    }

    function test_Unauthorized_SetBaseFee() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setBaseFee(0.01 ether);
    }

    function test_Unauthorized_SetComplexityRate() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setComplexityRate(42);
    }

    function test_Unauthorized_ProposeGovernance() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.proposeGovernance(ALICE);
    }

    function testFuzz_Unauthorized_AllSetters(address caller) public {
        vm.assume(caller != TEAM);
        vm.startPrank(caller);

        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setProtocolCutBps(100);

        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setBaseFee(0.01 ether);

        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setComplexityRate(1);

        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.proposeGovernance(caller);

        vm.stopPrank();
    }

    // -------------------------------------------------------------------------
    // Events on parameter updates
    // -------------------------------------------------------------------------

    function test_SetProtocolCutBps_EmitsEvent() public {
        vm.prank(TEAM);
        gov.setProtocolCutBps(500);

        vm.expectEmit(false, false, false, true);
        emit ProtocolCutUpdated(500, 1_000);
        vm.prank(TEAM);
        gov.setProtocolCutBps(1_000);
    }

    function test_SetBaseFee_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit BaseFeeUpdated(0, 0.1 ether);
        vm.prank(TEAM);
        gov.setBaseFee(0.1 ether);
    }

    function test_SetComplexityRate_EmitsEvent() public {
        vm.expectEmit(false, false, false, true);
        emit ComplexityRateUpdated(0, 7);
        vm.prank(TEAM);
        gov.setComplexityRate(7);
    }

    // -------------------------------------------------------------------------
    // COMPLEXITY_RATE — capped at MAX_PERMISSION_FEE_WEI for consistency
    // -------------------------------------------------------------------------

    function test_SetComplexityRate_AtExactCap() public {
        vm.prank(TEAM);
        gov.setComplexityRate(MAX_FEE);
        assertEq(gov.complexityRate(), MAX_FEE);
    }

    function test_SetComplexityRate_RevertsAboveCap() public {
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, MAX_FEE + 1, MAX_FEE)
        );
        gov.setComplexityRate(MAX_FEE + 1);
    }

    function testFuzz_SetComplexityRate_WithinCap(uint256 rate) public {
        rate = bound(rate, 0, MAX_FEE);
        vm.prank(TEAM);
        gov.setComplexityRate(rate);
        assertEq(gov.complexityRate(), rate);
    }

    function testFuzz_SetComplexityRate_AboveCap(uint256 excess) public {
        excess = bound(excess, 1, type(uint256).max - MAX_FEE);
        uint256 requested = MAX_FEE + excess;
        vm.prank(TEAM);
        vm.expectRevert(
            abi.encodeWithSelector(SailGovernance.ExceedsPermissionFeeCap.selector, requested, MAX_FEE)
        );
        gov.setComplexityRate(requested);
    }
}
