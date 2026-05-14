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
        assertEq(gov.CURRENT_PROTOCOL_CUT_BPS(), 0);
        assertEq(gov.BASE_FEE(), 0);
        assertEq(gov.COMPLEXITY_RATE(), 0);
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
        assertEq(gov.CURRENT_PROTOCOL_CUT_BPS(), 2_500);
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
        assertEq(gov.CURRENT_PROTOCOL_CUT_BPS(), bps);
    }

    function test_SetBaseFee_AtExactCap() public {
        vm.prank(TEAM);
        gov.setBaseFee(MAX_FEE);
        assertEq(gov.BASE_FEE(), MAX_FEE);
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
        assertEq(gov.BASE_FEE(), fee);
    }

    // -------------------------------------------------------------------------
    // Governance transfer
    // -------------------------------------------------------------------------

    function test_TransferGovernance_UpdatesAddress() public {
        vm.prank(TEAM);
        gov.transferGovernance(ALICE);
        assertEq(gov.governance(), ALICE);
    }

    function test_TransferGovernance_EmitsEvent() public {
        vm.expectEmit(true, true, false, false);
        emit GovernanceTransferred(TEAM, ALICE);
        vm.prank(TEAM);
        gov.transferGovernance(ALICE);
    }

    function test_TransferGovernance_NewGovernanceCanAct() public {
        vm.prank(TEAM);
        gov.transferGovernance(ALICE);

        vm.prank(ALICE);
        gov.setProtocolCutBps(1_000);
        assertEq(gov.CURRENT_PROTOCOL_CUT_BPS(), 1_000);
    }

    function test_TransferGovernance_OldGovernanceCanNoLongerAct() public {
        vm.prank(TEAM);
        gov.transferGovernance(ALICE);

        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.setProtocolCutBps(1_000);
    }

    function test_TransferGovernance_RevertsOnZeroAddress() public {
        vm.prank(TEAM);
        vm.expectRevert(SailGovernance.ZeroAddress.selector);
        gov.transferGovernance(address(0));
    }

    function test_TransferGovernance_ChainedTransfer() public {
        vm.prank(TEAM);
        gov.transferGovernance(ALICE);
        vm.prank(ALICE);
        gov.transferGovernance(BOB);
        assertEq(gov.governance(), BOB);
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

    function test_Unauthorized_TransferGovernance() public {
        vm.prank(ALICE);
        vm.expectRevert(SailGovernance.NotGovernance.selector);
        gov.transferGovernance(ALICE);
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
        gov.transferGovernance(caller);

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
    // COMPLEXITY_RATE has no cap (no upper bound in the spec)
    // -------------------------------------------------------------------------

    function testFuzz_SetComplexityRate_AnyValue(uint256 rate) public {
        vm.prank(TEAM);
        gov.setComplexityRate(rate);
        assertEq(gov.COMPLEXITY_RATE(), rate);
    }
}
