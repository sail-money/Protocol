// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import "forge-std/Test.sol";
import "../contracts/policies/StandardFeePolicy.sol";

contract StandardFeePolicyTest is Test {
    StandardFeePolicy policy;

    address constant KERNEL       = address(0xA1);
    address constant FEE_MANAGER  = address(0xA2);
    address constant DISTRIBUTOR  = address(0xA3);
    address constant ACCOUNT      = address(0xB1);
    address constant ACCOUNT2     = address(0xB2);
    address constant STRANGER     = address(0xC1);

    uint256 constant MGMT_BPS  = 200;       // 2% annual
    uint256 constant PERF_BPS  = 2_000;     // 20%
    uint256 constant DIST_BPS  = 500;       // 5%
    uint256 constant NAV       = 1_000_000e18;
    uint256 constant T0        = 1_000_000;  // non-zero genesis time

    function setUp() public {
        vm.warp(T0);
        policy = new StandardFeePolicy(
            MGMT_BPS, PERF_BPS, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER
        );
    }

    // ── helpers ───────────────────────────────────────────────────────────────

    function _initAccount(address acct, uint256 nav) internal {
        // feeManager must seed HWM first (H-5 fix)
        vm.prank(FEE_MANAGER);
        policy.seedHighWaterMark(acct, nav);
        vm.prank(KERNEL);
        policy.recordCollection(acct, 0, nav);
    }

    // expected management fee for pro-rated accrual
    function _expectedMgmt(uint256 nav, uint256 bps, uint256 elapsed) internal pure returns (uint256) {
        return nav * bps * elapsed / (365 days * 10_000);
    }

    // ── constructor ───────────────────────────────────────────────────────────

    function test_Constructor_SetsValues() public view {
        assertEq(policy.managementFeeBps(),  MGMT_BPS);
        assertEq(policy.performanceFeeBps(), PERF_BPS);
        assertEq(policy.distributor(),       DISTRIBUTOR);
        assertEq(policy.distributorBps(),    DIST_BPS);
        assertEq(policy.kernel(),            KERNEL);
        assertEq(policy.feeManager(),        FEE_MANAGER);
    }

    function test_Constructor_RevertsZeroKernel() public {
        vm.expectRevert(StandardFeePolicy.ZeroAddress.selector);
        new StandardFeePolicy(MGMT_BPS, PERF_BPS, DISTRIBUTOR, DIST_BPS, address(0), FEE_MANAGER);
    }

    function test_Constructor_RevertsZeroFeeManager() public {
        vm.expectRevert(StandardFeePolicy.ZeroAddress.selector);
        new StandardFeePolicy(MGMT_BPS, PERF_BPS, DISTRIBUTOR, DIST_BPS, KERNEL, address(0));
    }

    function test_Constructor_RevertsManagementFeeAboveCap() public {
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.ManagementFeeTooHigh.selector, 1001));
        new StandardFeePolicy(1001, PERF_BPS, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
    }

    function test_Constructor_RevertsPerformanceFeeAboveCap() public {
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.PerformanceFeeTooHigh.selector, 5001));
        new StandardFeePolicy(MGMT_BPS, 5001, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
    }

    function test_Constructor_AtExactMaxManagementFee() public {
        StandardFeePolicy p = new StandardFeePolicy(1_000, PERF_BPS, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
        assertEq(p.managementFeeBps(), 1_000);
    }

    function test_Constructor_AtExactMaxPerformanceFee() public {
        StandardFeePolicy p = new StandardFeePolicy(MGMT_BPS, 5000, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
        assertEq(p.performanceFeeBps(), 5000);
    }

    function test_Constructor_NoDistributorAllowed() public {
        StandardFeePolicy p = new StandardFeePolicy(MGMT_BPS, PERF_BPS, address(0), 0, KERNEL, FEE_MANAGER);
        assertEq(p.distributor(), address(0));
        assertEq(p.distributorBps(), 0);
    }

    function test_Constructor_RevertsDistributorBpsAboveCap() public {
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.DistributorBpsTooLarge.selector, 10_001));
        new StandardFeePolicy(MGMT_BPS, PERF_BPS, DISTRIBUTOR, 10_001, KERNEL, FEE_MANAGER);
    }

    function test_Constructor_AtExactMaxDistributorBps() public {
        StandardFeePolicy p = new StandardFeePolicy(MGMT_BPS, PERF_BPS, DISTRIBUTOR, 10_000, KERNEL, FEE_MANAGER);
        assertEq(p.distributorBps(), 10_000);
    }

    // ── computeFee: uninitialised ─────────────────────────────────────────────

    function test_ComputeFee_UninitialisedReturnsZeroFee() public view {
        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);
        assertEq(grossFee, 0);
    }

    function test_ComputeFee_UninitialisedReturnsDistributor() public view {
        (, address dist, uint256 dbps) = policy.computeFee(ACCOUNT, NAV);
        assertEq(dist, DISTRIBUTOR);
        assertEq(dbps, DIST_BPS);
    }

    function test_ComputeFee_UninitialisedZeroNav() public view {
        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, 0);
        assertEq(grossFee, 0);
    }

    // ── computeFee: management fee ────────────────────────────────────────────

    function test_ComputeFee_ManagementFee_ExactlyOneYear() public {
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 365 days);

        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);

        // Exactly 2% of NAV after one year
        uint256 expected = NAV * MGMT_BPS / 10_000;
        assertEq(grossFee, expected);
    }

    function test_ComputeFee_ManagementFee_HalfYear() public {
        _initAccount(ACCOUNT, NAV);
        uint256 elapsed = 365 days / 2;
        vm.warp(T0 + elapsed);

        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);

        // Expected: 1% of NAV after half year
        uint256 expected = _expectedMgmt(NAV, MGMT_BPS, elapsed);
        assertEq(grossFee, expected);
    }

    function test_ComputeFee_ManagementFee_ZeroElapsed() public {
        _initAccount(ACCOUNT, NAV);
        // No time has passed — management fee must be 0
        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);
        assertEq(grossFee, 0);
    }

    function test_ComputeFee_ManagementFee_ZeroRate() public {
        StandardFeePolicy p = new StandardFeePolicy(0, PERF_BPS, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
        vm.prank(FEE_MANAGER); p.seedHighWaterMark(ACCOUNT, NAV);
        vm.prank(KERNEL); p.recordCollection(ACCOUNT, 0, NAV);
        vm.warp(T0 + 365 days);
        (uint256 grossFee,,) = p.computeFee(ACCOUNT, NAV);
        assertEq(grossFee, 0);
    }

    function test_ComputeFee_ManagementFee_NavIncreasedMidPeriod() public {
        // Management fee is on *current* NAV, not average
        uint256 higherNav = NAV * 2;
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 365 days);

        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, higherNav);

        // Management fee = higherNav * 2% after 1 year
        // Performance fee = (higherNav - NAV) * 20%
        uint256 expectedMgmt = higherNav * MGMT_BPS / 10_000;
        uint256 expectedPerf = (higherNav - NAV) * PERF_BPS / 10_000;
        assertEq(grossFee, expectedMgmt + expectedPerf);
    }

    // ── computeFee: performance fee ───────────────────────────────────────────

    function test_ComputeFee_PerfFee_AboveHWM() public {
        uint256 higherNav = NAV + 100_000e18;
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 1 days);

        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, higherNav);

        uint256 mgmt = _expectedMgmt(higherNav, MGMT_BPS, 1 days);
        uint256 perf = (higherNav - NAV) * PERF_BPS / 10_000;
        assertEq(grossFee, mgmt + perf);
    }

    function test_ComputeFee_PerfFee_ExactlyAtHWM() public {
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 1 days);

        // NAV exactly at HWM → no performance fee
        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);

        uint256 mgmt = _expectedMgmt(NAV, MGMT_BPS, 1 days);
        assertEq(grossFee, mgmt);
    }

    function test_ComputeFee_PerfFee_BelowHWM() public {
        uint256 lowerNav = NAV - 100_000e18;
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 1 days);

        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, lowerNav);

        // Only management fee; no performance fee when underwater
        uint256 mgmt = _expectedMgmt(lowerNav, MGMT_BPS, 1 days);
        assertEq(grossFee, mgmt);
    }

    function test_ComputeFee_PerfFee_ZeroRate() public {
        StandardFeePolicy p = new StandardFeePolicy(MGMT_BPS, 0, DISTRIBUTOR, DIST_BPS, KERNEL, FEE_MANAGER);
        vm.prank(FEE_MANAGER); p.seedHighWaterMark(ACCOUNT, NAV);
        vm.prank(KERNEL); p.recordCollection(ACCOUNT, 0, NAV);
        vm.warp(T0 + 365 days);
        uint256 higherNav = NAV * 2;
        (uint256 grossFee,,) = p.computeFee(ACCOUNT, higherNav);
        // Only management fee
        assertEq(grossFee, _expectedMgmt(higherNav, MGMT_BPS, 365 days));
    }

    function test_ComputeFee_DistributorAlwaysReturned() public view {
        (, address dist, uint256 dbps) = policy.computeFee(ACCOUNT, NAV);
        assertEq(dist, DISTRIBUTOR);
        assertEq(dbps, DIST_BPS);
    }

    function test_ComputeFee_DistributorReturnedAfterInit() public {
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 30 days);
        (, address dist, uint256 dbps) = policy.computeFee(ACCOUNT, NAV);
        assertEq(dist, DISTRIBUTOR);
        assertEq(dbps, DIST_BPS);
    }

    // ── recordCollection: initialisation ─────────────────────────────────────

    function test_RecordCollection_RevertsWhenHWMNotSeeded() public {
        // Must call seedHighWaterMark before recordCollection on a new account
        vm.prank(KERNEL);
        vm.expectRevert(StandardFeePolicy.HWMNotSeeded.selector);
        policy.recordCollection(ACCOUNT, 0, NAV);
    }

    function test_SeedHighWaterMark_RevertsOnZeroInitialNav() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(StandardFeePolicy.ZeroInitialNav.selector);
        policy.seedHighWaterMark(ACCOUNT, 0);
    }

    function test_SeedHighWaterMark_RevertsIfAlreadySeeded() public {
        vm.prank(FEE_MANAGER);
        policy.seedHighWaterMark(ACCOUNT, NAV);
        vm.prank(FEE_MANAGER);
        vm.expectRevert(StandardFeePolicy.AlreadySeeded.selector);
        policy.seedHighWaterMark(ACCOUNT, NAV);
    }

    function test_SeedHighWaterMark_RevertsNotFeeManager() public {
        vm.prank(KERNEL);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.seedHighWaterMark(ACCOUNT, NAV);
    }

    function test_SeedHighWaterMark_EmitsEvent() public {
        vm.prank(FEE_MANAGER);
        vm.expectEmit(true, false, false, true, address(policy));
        emit StandardFeePolicy.HWMSeeded(ACCOUNT, NAV);
        policy.seedHighWaterMark(ACCOUNT, NAV);
    }

    // Keep backward-compat test name pointing to new error
    function test_RecordCollection_RevertsOnZeroInitialNav() public {
        // With H-5 fix: zero nav is now rejected in seedHighWaterMark, not recordCollection.
        // Trying recordCollection without seeding gives HWMNotSeeded.
        vm.prank(KERNEL);
        vm.expectRevert(StandardFeePolicy.HWMNotSeeded.selector);
        policy.recordCollection(ACCOUNT, 0, 0);
    }

    function test_RecordCollection_ZeroNavAfterInitDoesNotRevert() public {
        // Zero nav is only forbidden on the FIRST call (init). Subsequent calls are fine.
        _initAccount(ACCOUNT, NAV);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, 0); // nav drops to 0 after init — no revert
    }

    function test_RecordCollection_InitialisesHWM() public {
        _initAccount(ACCOUNT, NAV);
        assertEq(policy.highWaterMark(ACCOUNT), NAV);
    }

    function test_RecordCollection_InitialisesTimestamp() public {
        _initAccount(ACCOUNT, NAV);
        assertEq(policy.lastCollectionTimestamp(ACCOUNT), T0);
    }

    function test_RecordCollection_InitEmitsFeesCollectedWithZeroFee() public {
        // Seed first (emits HWMSeeded), then check that recordCollection emits FeesCollected
        vm.prank(FEE_MANAGER);
        policy.seedHighWaterMark(ACCOUNT, NAV);
        vm.expectEmit(true, false, false, true, address(policy));
        emit StandardFeePolicy.FeesCollected(ACCOUNT, 0, NAV, NAV);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, NAV);
    }

    function test_RecordCollection_FirstCallReturnsFeeZeroOnNextCompute() public {
        _initAccount(ACCOUNT, NAV);
        // Immediately after init, elapsed = 0 and NAV == HWM → grossFee = 0
        (uint256 grossFee,,) = policy.computeFee(ACCOUNT, NAV);
        assertEq(grossFee, 0);
    }

    // ── recordCollection: subsequent calls ────────────────────────────────────

    function test_RecordCollection_UpdatesTimestamp() public {
        _initAccount(ACCOUNT, NAV);
        uint256 t1 = T0 + 30 days;
        vm.warp(t1);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 5_000e18, NAV);
        assertEq(policy.lastCollectionTimestamp(ACCOUNT), t1);
    }

    function test_RecordCollection_RatchetsHWMUpward() public {
        uint256 higherNav = NAV * 2;
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 365 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, higherNav);
        assertEq(policy.highWaterMark(ACCOUNT), higherNav);
    }

    function test_RecordCollection_HWMDoesNotDropBelow() public {
        uint256 lowerNav = NAV / 2;
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 30 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, lowerNav);
        // HWM stays at the original NAV
        assertEq(policy.highWaterMark(ACCOUNT), NAV);
    }

    function test_RecordCollection_EmitsFeesCollected() public {
        _initAccount(ACCOUNT, NAV);
        uint256 grossFee = 5_000e18;
        uint256 higherNav = NAV + 100_000e18;
        vm.warp(T0 + 30 days);

        vm.expectEmit(true, false, false, true);
        emit StandardFeePolicy.FeesCollected(ACCOUNT, grossFee, higherNav, higherNav);

        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, grossFee, higherNav);
    }

    function test_RecordCollection_EmitsWithOldHWMWhenNavDrops() public {
        _initAccount(ACCOUNT, NAV);
        uint256 lowerNav = NAV / 2;
        vm.warp(T0 + 30 days);

        vm.expectEmit(true, false, false, true);
        emit StandardFeePolicy.FeesCollected(ACCOUNT, 0, lowerNav, NAV); // HWM stays at NAV

        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, lowerNav);
    }

    function test_RecordCollection_RevertsNotKernel() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotKernel.selector);
        policy.recordCollection(ACCOUNT, 0, NAV);
    }

    function test_RecordCollection_RevertsNotKernel_FeeManager() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(StandardFeePolicy.NotKernel.selector);
        policy.recordCollection(ACCOUNT, 0, NAV);
    }

    // ── integration: full lifecycle ───────────────────────────────────────────

    function test_Integration_FirstThenSecondCollection() public {
        // Init at T0 with NAV = 1M
        _initAccount(ACCOUNT, NAV);

        // After 1 year, NAV = 1.2M (20% profit)
        uint256 newNav = NAV * 12 / 10;
        vm.warp(T0 + 365 days);

        (uint256 fee,,) = policy.computeFee(ACCOUNT, newNav);

        uint256 expectedMgmt = _expectedMgmt(newNav, MGMT_BPS, 365 days);
        uint256 expectedPerf = (newNav - NAV) * PERF_BPS / 10_000;
        assertEq(fee, expectedMgmt + expectedPerf);

        // Collect fees; HWM should now be newNav
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, fee, newNav);
        assertEq(policy.highWaterMark(ACCOUNT), newNav);
        assertEq(policy.lastCollectionTimestamp(ACCOUNT), T0 + 365 days);
    }

    function test_Integration_UnderwaterAccountPaysManagementFeeOnly() public {
        // Init at 1M
        _initAccount(ACCOUNT, NAV);

        // NAV drops to 0.8M after 6 months
        uint256 lowerNav = NAV * 8 / 10;
        vm.warp(T0 + 182 days);

        (uint256 fee,,) = policy.computeFee(ACCOUNT, lowerNav);

        // Only management fee; HWM is still 1M so no performance fee
        uint256 expectedMgmt = _expectedMgmt(lowerNav, MGMT_BPS, 182 days);
        assertEq(fee, expectedMgmt);
    }

    function test_Integration_HWMRatchetsUpMultipleTimes() public {
        _initAccount(ACCOUNT, NAV);

        // Collection 1: NAV 1.2M → HWM = 1.2M
        uint256 nav1 = NAV * 12 / 10;
        vm.warp(T0 + 365 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, nav1);
        assertEq(policy.highWaterMark(ACCOUNT), nav1);

        // Collection 2: NAV 1.5M → HWM = 1.5M
        uint256 nav2 = NAV * 15 / 10;
        vm.warp(T0 + 730 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, nav2);
        assertEq(policy.highWaterMark(ACCOUNT), nav2);

        // Collection 3: NAV drops to 1.3M → HWM stays at 1.5M
        uint256 nav3 = NAV * 13 / 10;
        vm.warp(T0 + 1095 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, nav3);
        assertEq(policy.highWaterMark(ACCOUNT), nav2);
    }

    function test_Integration_RecoveryAfterUnderwater() public {
        _initAccount(ACCOUNT, NAV);

        // NAV drops to 0.5M
        uint256 lowerNav = NAV / 2;
        vm.warp(T0 + 180 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, lowerNav);
        // HWM stays at NAV (1M)
        assertEq(policy.highWaterMark(ACCOUNT), NAV);

        // NAV recovers to 0.8M — still below HWM, no performance fee
        uint256 midNav = NAV * 8 / 10;
        vm.warp(T0 + 360 days);
        (uint256 fee,,) = policy.computeFee(ACCOUNT, midNav);
        uint256 mgmt = _expectedMgmt(midNav, MGMT_BPS, 180 days);
        assertEq(fee, mgmt); // no perf

        // NAV recovers to 1.2M — now above original HWM, performance fee kicks in
        uint256 highNav = NAV * 12 / 10;
        (uint256 fee2,,) = policy.computeFee(ACCOUNT, highNav);
        uint256 mgmt2 = _expectedMgmt(highNav, MGMT_BPS, 180 days);
        uint256 perf2 = (highNav - NAV) * PERF_BPS / 10_000;
        assertEq(fee2, mgmt2 + perf2);
    }

    function test_Integration_MultipleAccountsIndependent() public {
        _initAccount(ACCOUNT,  NAV);
        _initAccount(ACCOUNT2, NAV * 5);

        vm.warp(T0 + 365 days);
        uint256 nav2Higher = NAV * 6;
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT2, 0, nav2Higher);

        // ACCOUNT HWM unchanged
        assertEq(policy.highWaterMark(ACCOUNT),  NAV);
        // ACCOUNT2 HWM updated
        assertEq(policy.highWaterMark(ACCOUNT2), nav2Higher);
    }

    // ── setters: setManagementFeeBps ─────────────────────────────────────────

    function test_SetManagementFeeBps_Succeeds() public {
        vm.prank(FEE_MANAGER);
        policy.setManagementFeeBps(100);
        assertEq(policy.managementFeeBps(), 100);
    }

    function test_SetManagementFeeBps_ToZero() public {
        vm.prank(FEE_MANAGER);
        policy.setManagementFeeBps(0);
        assertEq(policy.managementFeeBps(), 0);
    }

    function test_SetManagementFeeBps_AtExactMax() public {
        vm.prank(FEE_MANAGER);
        policy.setManagementFeeBps(1_000);
        assertEq(policy.managementFeeBps(), 1_000);
    }

    function test_SetManagementFeeBps_RevertsAboveCap() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.ManagementFeeTooHigh.selector, 1001));
        policy.setManagementFeeBps(1001);
    }

    function test_SetManagementFeeBps_RevertsNotFeeManager() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setManagementFeeBps(100);
    }

    function test_SetManagementFeeBps_EmitsEvent() public {
        vm.prank(FEE_MANAGER);
        vm.expectEmit();
        emit StandardFeePolicy.ManagementFeeUpdated(MGMT_BPS, 100);
        policy.setManagementFeeBps(100);
    }

    function test_SetManagementFeeBps_TakesEffect() public {
        _initAccount(ACCOUNT, NAV);
        vm.prank(FEE_MANAGER);
        policy.setManagementFeeBps(100); // lower from 200 to 100

        vm.warp(T0 + 365 days);
        (uint256 fee,,) = policy.computeFee(ACCOUNT, NAV);
        // Only management fee at new rate
        assertEq(fee, _expectedMgmt(NAV, 100, 365 days));
    }

    // ── setters: setPerformanceFeeBps ─────────────────────────────────────────

    function test_SetPerformanceFeeBps_Succeeds() public {
        vm.prank(FEE_MANAGER);
        policy.setPerformanceFeeBps(1_000);
        assertEq(policy.performanceFeeBps(), 1_000);
    }

    function test_SetPerformanceFeeBps_ToZero() public {
        vm.prank(FEE_MANAGER);
        policy.setPerformanceFeeBps(0);
        assertEq(policy.performanceFeeBps(), 0);
    }

    function test_SetPerformanceFeeBps_AtExactMax() public {
        vm.prank(FEE_MANAGER);
        policy.setPerformanceFeeBps(5_000);
        assertEq(policy.performanceFeeBps(), 5_000);
    }

    function test_SetPerformanceFeeBps_RevertsAboveCap() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.PerformanceFeeTooHigh.selector, 5001));
        policy.setPerformanceFeeBps(5001);
    }

    function test_SetPerformanceFeeBps_RevertsNotFeeManager() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setPerformanceFeeBps(1_000);
    }

    function test_SetPerformanceFeeBps_EmitsEvent() public {
        vm.prank(FEE_MANAGER);
        vm.expectEmit();
        emit StandardFeePolicy.PerformanceFeeUpdated(PERF_BPS, 1_000);
        policy.setPerformanceFeeBps(1_000);
    }

    function test_SetPerformanceFeeBps_TakesEffect() public {
        uint256 higherNav = NAV * 2;
        _initAccount(ACCOUNT, NAV);
        vm.prank(FEE_MANAGER);
        policy.setPerformanceFeeBps(1_000); // cut from 20% to 10%

        vm.warp(T0 + 1);
        (uint256 fee,,) = policy.computeFee(ACCOUNT, higherNav);
        uint256 mgmt = _expectedMgmt(higherNav, MGMT_BPS, 1);
        uint256 perf = (higherNav - NAV) * 1_000 / 10_000;
        assertEq(fee, mgmt + perf);
    }

    // ── setters: setDistributor ───────────────────────────────────────────────

    function test_SetDistributor_Succeeds() public {
        address newDist = address(0xD1);
        vm.prank(FEE_MANAGER);
        policy.setDistributor(newDist);
        assertEq(policy.distributor(), newDist);
    }

    function test_SetDistributor_AllowsZeroAddress() public {
        vm.prank(FEE_MANAGER);
        policy.setDistributor(address(0));
        assertEq(policy.distributor(), address(0));
    }

    function test_SetDistributor_EmitsEvent() public {
        address newDist = address(0xD1);
        vm.prank(FEE_MANAGER);
        vm.expectEmit();
        emit StandardFeePolicy.DistributorUpdated(DISTRIBUTOR, newDist);
        policy.setDistributor(newDist);
    }

    function test_SetDistributor_RevertsNotFeeManager() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setDistributor(address(0xD1));
    }

    function test_SetDistributor_ReflectedInComputeFee() public {
        address newDist = address(0xD2);
        vm.prank(FEE_MANAGER);
        policy.setDistributor(newDist);
        (, address dist,) = policy.computeFee(ACCOUNT, NAV);
        assertEq(dist, newDist);
    }

    // ── setters: setDistributorBps ────────────────────────────────────────────

    function test_SetDistributorBps_Succeeds() public {
        vm.prank(FEE_MANAGER);
        policy.setDistributorBps(1_000);
        assertEq(policy.distributorBps(), 1_000);
    }

    function test_SetDistributorBps_EmitsEvent() public {
        vm.prank(FEE_MANAGER);
        vm.expectEmit();
        emit StandardFeePolicy.DistributorBpsUpdated(DIST_BPS, 1_000);
        policy.setDistributorBps(1_000);
    }

    function test_SetDistributorBps_RevertsNotFeeManager() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setDistributorBps(1_000);
    }

    function test_SetDistributorBps_ReflectedInComputeFee() public {
        vm.prank(FEE_MANAGER);
        policy.setDistributorBps(750);
        (,, uint256 dbps) = policy.computeFee(ACCOUNT, NAV);
        assertEq(dbps, 750);
    }

    function test_SetDistributorBps_RevertsAbove10000() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.DistributorBpsTooLarge.selector, 10_001));
        policy.setDistributorBps(10_001);
    }

    function test_SetDistributorBps_AtExactly10000_Passes() public {
        vm.prank(FEE_MANAGER);
        policy.setDistributorBps(10_000);
        assertEq(policy.distributorBps(), 10_000);
    }

    function testFuzz_SetDistributorBps_AboveCap(uint256 bps) public {
        bps = bound(bps, 10_001, type(uint256).max);
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.DistributorBpsTooLarge.selector, bps));
        policy.setDistributorBps(bps);
    }

    // ── setters: proposeFeeManager / acceptFeeManager (two-step) ─────────────

    function test_TransferFeeManager_Succeeds() public {
        address newFM = address(0xF1);
        vm.prank(FEE_MANAGER);
        policy.proposeFeeManager(newFM);
        vm.prank(newFM);
        policy.acceptFeeManager();
        assertEq(policy.feeManager(), newFM);
    }

    function test_TransferFeeManager_EmitsEvent() public {
        address newFM = address(0xF1);
        vm.prank(FEE_MANAGER);
        policy.proposeFeeManager(newFM);
        vm.expectEmit();
        emit StandardFeePolicy.FeeManagerTransferred(FEE_MANAGER, newFM);
        vm.prank(newFM);
        policy.acceptFeeManager();
    }

    function test_TransferFeeManager_RevertsOnZeroAddress() public {
        vm.prank(FEE_MANAGER);
        vm.expectRevert(StandardFeePolicy.ZeroAddress.selector);
        policy.proposeFeeManager(address(0));
    }

    function test_TransferFeeManager_RevertsNotFeeManager() public {
        vm.prank(STRANGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.proposeFeeManager(address(0xF1));
    }

    function test_TransferFeeManager_OldManagerLosesAccess() public {
        address newFM = address(0xF1);
        vm.prank(FEE_MANAGER);
        policy.proposeFeeManager(newFM);
        vm.prank(newFM);
        policy.acceptFeeManager();

        vm.prank(FEE_MANAGER);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setManagementFeeBps(0);
    }

    function test_TransferFeeManager_NewManagerGainsAccess() public {
        address newFM = address(0xF1);
        vm.prank(FEE_MANAGER);
        policy.proposeFeeManager(newFM);
        vm.prank(newFM);
        policy.acceptFeeManager();

        vm.prank(newFM);
        policy.setManagementFeeBps(100);
        assertEq(policy.managementFeeBps(), 100);
    }

    // ── fuzz tests ────────────────────────────────────────────────────────────

    function testFuzz_ManagementFee_TimeWeighted(uint256 elapsed, uint256 nav) public {
        // Bound to realistic ranges: elapsed up to 10 years, nav up to 1 quadrillion tokens (18 dec)
        elapsed = bound(elapsed, 0, 10 * 365 days);
        nav     = bound(nav,     0, 1e33);

        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + elapsed);

        (uint256 fee,,) = policy.computeFee(ACCOUNT, nav);

        uint256 mgmt = nav * MGMT_BPS * elapsed / (365 days * 10_000);

        // Performance fee: only if nav > NAV (initial HWM from init)
        uint256 perf = nav > NAV ? (nav - NAV) * PERF_BPS / 10_000 : 0;

        // Allow rounding tolerance of 1 wei from integer division
        assertApproxEqAbs(fee, mgmt + perf, 1);
    }

    function testFuzz_PerformanceFee_AboveHWM(uint256 profit) public {
        profit = bound(profit, 1, 1e30);
        uint256 newNav = NAV + profit;

        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 1); // 1 second elapsed

        (uint256 fee,,) = policy.computeFee(ACCOUNT, newNav);

        uint256 mgmt = _expectedMgmt(newNav, MGMT_BPS, 1);
        uint256 perf = profit * PERF_BPS / 10_000;

        assertApproxEqAbs(fee, mgmt + perf, 1);
    }

    function testFuzz_PerformanceFee_NoFeeWhenUnderwater(uint256 loss) public {
        loss = bound(loss, 1, NAV - 1);
        uint256 lowerNav = NAV - loss;

        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + 1);

        (uint256 fee,,) = policy.computeFee(ACCOUNT, lowerNav);

        // Only management fee
        uint256 mgmt = _expectedMgmt(lowerNav, MGMT_BPS, 1);
        assertApproxEqAbs(fee, mgmt, 1);
    }

    function testFuzz_RecordCollection_NotKernel(address caller) public {
        vm.assume(caller != KERNEL);
        vm.prank(caller);
        vm.expectRevert(StandardFeePolicy.NotKernel.selector);
        policy.recordCollection(ACCOUNT, 0, NAV);
    }

    function testFuzz_SetManagementFeeBps_NonFeeManager(address caller) public {
        vm.assume(caller != FEE_MANAGER);
        vm.prank(caller);
        vm.expectRevert(StandardFeePolicy.NotFeeManager.selector);
        policy.setManagementFeeBps(100);
    }

    function testFuzz_SetPerformanceFeeBps_AboveCap(uint256 bps) public {
        bps = bound(bps, 5001, type(uint256).max);
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.PerformanceFeeTooHigh.selector, bps));
        policy.setPerformanceFeeBps(bps);
    }

    function testFuzz_SetManagementFeeBps_AboveCap(uint256 bps) public {
        bps = bound(bps, 1001, type(uint256).max);
        vm.prank(FEE_MANAGER);
        vm.expectRevert(abi.encodeWithSelector(StandardFeePolicy.ManagementFeeTooHigh.selector, bps));
        policy.setManagementFeeBps(bps);
    }

    function testFuzz_HWM_NeverDecreases(uint256 nav1, uint256 nav2) public {
        nav1 = bound(nav1, 1, 1e33);
        nav2 = bound(nav2, 0, 1e33);

        _initAccount(ACCOUNT, nav1);
        vm.warp(T0 + 1 days);
        vm.prank(KERNEL);
        policy.recordCollection(ACCOUNT, 0, nav2);

        // HWM = max(nav1, nav2), never below nav1
        assertGe(policy.highWaterMark(ACCOUNT), nav1);
    }

    function testFuzz_ComputeFee_ZeroNavNoRevert(uint256 elapsed) public {
        elapsed = bound(elapsed, 0, 10 * 365 days);
        _initAccount(ACCOUNT, NAV);
        vm.warp(T0 + elapsed);
        // Should not revert
        (uint256 fee,,) = policy.computeFee(ACCOUNT, 0);
        assertEq(fee, 0); // nav=0 → both fees zero
    }
}
