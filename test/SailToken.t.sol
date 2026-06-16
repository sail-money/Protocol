// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test}                from "forge-std/Test.sol";
import {SailToken}          from "../contracts/token/SailToken.sol";
import {TimelockDeployer}   from "./support/TimelockDeployer.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title  SailTokenTest
/// @notice Unit suite for SailToken. Highest-priority security tests are tagged `test_P0_*`:
///         they cover the irreversible / catastrophic guarantees — cap can't be breached, emission
///         can't over-issue, the freeze can't be bypassed, and the flip can't be reversed or forced.
contract SailTokenTest is Test {
    SailToken          token;
    TimelockController timelock;

    // ── actors ──────────────────────────────────────────────────────────────
    address constant TEAM_GOV   = address(0x60D);        // timelock proposer/executor
    address constant INVESTORS  = address(0x1117);
    address constant TEAM       = address(0x2227);
    address constant TREASURY   = address(0x3337);       // DAO/Treasury bucket — frozen pre-flip
    address constant FOUNDATION = address(0x4447);
    address constant LIQUIDITY  = address(0x5557);
    address constant REWARDS    = address(0x9999);       // the rewards SMA (REWARDS_SOURCE)
    address constant ALICE      = address(0xA11CE);
    address constant BOB        = address(0xB0B);

    // ── season 1 constants ──────────────────────────────────────────────────
    uint128 constant WEEKLY = 5_000_000e18;
    uint32  constant WEEKS  = 12;
    uint256 constant SEASON1_BUDGET = uint256(WEEKLY) * WEEKS; // 60M

    uint256 internal _salt;
    uint64  internal s1Start; // tranche-0 unlock for the most recently opened season

    function setUp() public {
        vm.warp(1_000_000); // sane non-zero base timestamp
        timelock = TimelockDeployer.deploy(TEAM_GOV);
        token = new SailToken(
            INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY,
            REWARDS, TEAM_GOV, timelock
        );
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Timelock helpers — schedule / warp / execute (house pattern)
    // ─────────────────────────────────────────────────────────────────────────

    function _tlExec(bytes memory data) internal {
        bytes32 salt = bytes32(_salt++);
        vm.prank(TEAM_GOV);
        timelock.schedule(address(token), 0, data, bytes32(0), salt, 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(TEAM_GOV);
        timelock.execute(address(token), 0, data, bytes32(0), salt);
    }

    /// @dev Open Season 1 (12 weeks, 5M/wk) via the timelock. Records `s1Start`.
    function _openSeason1() internal {
        uint64 start = uint64(block.timestamp + 48 hours + 1 days);
        s1Start = start;
        _tlExec(abi.encodeCall(SailToken.openSeason, (start, WEEKS, WEEKLY)));
    }

    function _enableTransfers() internal {
        _tlExec(abi.encodeCall(SailToken.enablePublicTransfers, ()));
    }

    function _mintGenesis(uint256 amount) internal {
        _tlExec(abi.encodeCall(SailToken.mintGenesis, (amount)));
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Construction & allocation
    // ═════════════════════════════════════════════════════════════════════════

    function test_ConstructorMintsAllocationBuckets() public view {
        assertEq(token.balanceOf(TEAM),       token.CAP_TEAM());
        assertEq(token.balanceOf(INVESTORS),  token.CAP_INVESTORS());
        assertEq(token.balanceOf(TREASURY),   token.CAP_TREASURY());
        assertEq(token.balanceOf(FOUNDATION), token.CAP_FOUNDATION());
        assertEq(token.balanceOf(LIQUIDITY),  token.CAP_LIQUIDITY());
        assertEq(token.balanceOf(REWARDS),    0); // community bucket starts empty
    }

    function test_ConstructorMintedAccountingAndTotalSupply() public view {
        assertEq(token.mintedOf(SailToken.Bucket.TEAM),       token.CAP_TEAM());
        assertEq(token.mintedOf(SailToken.Bucket.INVESTORS),  token.CAP_INVESTORS());
        assertEq(token.mintedOf(SailToken.Bucket.TREASURY),   token.CAP_TREASURY());
        assertEq(token.mintedOf(SailToken.Bucket.FOUNDATION), token.CAP_FOUNDATION());
        assertEq(token.mintedOf(SailToken.Bucket.LIQUIDITY),  token.CAP_LIQUIDITY());
        assertEq(token.mintedOf(SailToken.Bucket.COMMUNITY),  0);
        // 60% minted at deploy; 40% community still unminted.
        assertEq(token.totalSupply(), 600_000_000e18);
    }

    function test_CapIsOneBillionAndBucketsSumToCap() public view {
        assertEq(token.cap(),      token.HARD_CAP());
        assertEq(token.HARD_CAP(), 1_000_000_000e18);
        assertEq(
            token.CAP_COMMUNITY() + token.CAP_TEAM() + token.CAP_INVESTORS() +
            token.CAP_TREASURY() + token.CAP_FOUNDATION() + token.CAP_LIQUIDITY(),
            token.HARD_CAP()
        );
    }

    function test_ConstructorRejectsZeroAddress() public {
        vm.expectRevert(SailToken.ZeroAddress.selector);
        new SailToken(address(0), TEAM, TREASURY, FOUNDATION, LIQUIDITY, REWARDS, TEAM_GOV, timelock);
        vm.expectRevert(SailToken.ZeroAddress.selector);
        new SailToken(INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY, address(0), TEAM_GOV, timelock);
    }

    // ── timelock validation (mirrors SailGovernance invariants) ───────────────

    function test_ConstructorRejectsWrongTimelockDelay() public {
        address[] memory r = new address[](1); r[0] = TEAM_GOV;
        TimelockController bad = new TimelockController(24 hours, r, r, address(0));
        vm.expectRevert(SailToken.TimelockDelayMismatch.selector);
        new SailToken(INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY, REWARDS, TEAM_GOV, bad);
    }

    function test_ConstructorRejectsGovNotProposer() public {
        address[] memory other = new address[](1); other[0] = ALICE;
        TimelockController bad = new TimelockController(48 hours, other, other, address(0));
        vm.expectRevert(SailToken.GovernanceNotProposer.selector);
        new SailToken(INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY, REWARDS, TEAM_GOV, bad);
    }

    function test_ConstructorRejectsNonSelfAdministeredTimelock() public {
        // admin == TEAM_GOV (the governance EOA) => not self-administered.
        address[] memory r = new address[](1); r[0] = TEAM_GOV;
        TimelockController bad = new TimelockController(48 hours, r, r, TEAM_GOV);
        vm.expectRevert(SailToken.TimelockNotSelfAdministered.selector);
        new SailToken(INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY, REWARDS, TEAM_GOV, bad);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Genesis distribution
    // ═════════════════════════════════════════════════════════════════════════

    function test_MintGenesisToRewardsSource() public {
        _mintGenesis(GENESIS());
        assertEq(token.balanceOf(REWARDS), GENESIS());
        assertEq(token.mintedOf(SailToken.Bucket.COMMUNITY), GENESIS());
        assertTrue(token.genesisMinted());
    }

    function test_P0_GenesisIsOneShot() public {
        _mintGenesis(GENESIS());
        // Calling directly as the timelock isolates the contract's own revert (no wrapping).
        vm.prank(address(timelock));
        vm.expectRevert(SailToken.GenesisAlreadyMinted.selector);
        token.mintGenesis(1e18);
    }

    function test_P0_GenesisCannotExceedMax() public {
        uint256 over = token.GENESIS_MAX() + 1;
        uint256 max  = token.GENESIS_MAX();
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(SailToken.ExceedsGenesisMax.selector, over, max));
        token.mintGenesis(over);
    }

    function test_GenesisOnlyViaTimelock() public {
        uint256 g = GENESIS(); // evaluate the view BEFORE arming expectRevert
        vm.prank(TEAM_GOV);
        vm.expectRevert(SailToken.NotTimelock.selector);
        token.mintGenesis(g);
    }

    function GENESIS() internal view returns (uint256) { return token.GENESIS_MAX(); }

    // ═════════════════════════════════════════════════════════════════════════
    // Seasons
    // ═════════════════════════════════════════════════════════════════════════

    function test_OpenSeason1() public {
        _openSeason1();
        (uint64 start, uint32 nw, uint32 wp, uint128 rate, uint128 budget, bool active) = token.season();
        assertEq(start, s1Start);
        assertEq(nw, WEEKS);
        assertEq(wp, 0);
        assertEq(rate, WEEKLY);
        assertEq(budget, SEASON1_BUDGET);
        assertTrue(active);
        assertEq(token.seasonCount(), 1);
    }

    function test_OpenSeasonOnlyViaTimelock() public {
        vm.expectRevert(SailToken.NotTimelock.selector);
        token.openSeason(uint64(block.timestamp + 1 days), WEEKS, WEEKLY);
    }

    function test_P0_NoOverlappingSeasons() public {
        _openSeason1();
        // Opening another season while one is active must revert (SeasonActive).
        uint64 start = uint64(block.timestamp + 30 days);
        vm.prank(address(timelock));
        vm.expectRevert(SailToken.SeasonActive.selector);
        token.openSeason(start, 4, WEEKLY);
    }

    function test_RejectsStartInPast() public {
        uint64 start = uint64(block.timestamp - 1);
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(SailToken.StartInPast.selector, start, block.timestamp));
        token.openSeason(start, WEEKS, WEEKLY);
    }

    function test_RejectsZeroRate() public {
        uint64 start = uint64(block.timestamp + 30 days);
        vm.prank(address(timelock));
        vm.expectRevert(SailToken.ZeroRate.selector);
        token.openSeason(start, WEEKS, 0);
    }

    function test_RejectsZeroWeeks() public {
        uint64 start = uint64(block.timestamp + 30 days);
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(SailToken.InvalidWeeks.selector, uint32(0)));
        token.openSeason(start, 0, WEEKLY);
    }

    function test_RejectsTooManyWeeks() public {
        uint64 start    = uint64(block.timestamp + 30 days);
        uint32 tooMany  = token.MAX_WEEKS() + 1;
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(SailToken.InvalidWeeks.selector, tooMany));
        token.openSeason(start, tooMany, WEEKLY);
    }

    function test_P0_CumulativeCannotExceedCommunityBucket() public {
        // A single season requesting more than the whole community bucket must revert.
        uint128 rate      = uint128(token.CAP_COMMUNITY()); // 400M
        uint256 attempted = uint256(rate) * 2;              // 800M
        uint256 cap       = token.CAP_COMMUNITY();
        uint64  start     = uint64(block.timestamp + 30 days);
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(SailToken.ExceedsCommunityBucket.selector, attempted, cap));
        token.openSeason(start, 2, rate);
    }

    function test_P0_CumulativeBoundaryAcrossSeasons() public {
        // Season A: 60M. Then a season that would tip community over 400M reverts; one that lands
        // exactly on 400M succeeds.
        _openSeason1();
        _runWholeSeason(s1Start, WEEKS); // mint 60M
        assertEq(token.mintedOf(SailToken.Bucket.COMMUNITY), 60_000_000e18);

        uint128 rate10m = 10_000_000e18;
        uint64  start   = uint64(block.timestamp + 30 days);
        uint256 commCap = token.CAP_COMMUNITY(); // precompute view before prank/expectRevert

        // 35 * 10M = 350M; 60M + 350M = 410M > 400M => revert
        vm.prank(address(timelock));
        vm.expectRevert(abi.encodeWithSelector(
            SailToken.ExceedsCommunityBucket.selector, uint256(410_000_000e18), commCap
        ));
        token.openSeason(start, 35, rate10m);

        // 34 * 10M = 340M; 60M + 340M = 400M == cap => OK (boundary)
        vm.prank(address(timelock));
        token.openSeason(start, 34, rate10m);
        (, , , , uint128 budgetB, bool activeB) = token.season();
        assertEq(budgetB, 340_000_000e18);
        assertTrue(activeB);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Weekly emission (highest priority)
    // ═════════════════════════════════════════════════════════════════════════

    function test_P0_PullMintsExactTrancheToRewardsSource() public {
        _openSeason1();
        vm.warp(s1Start);
        uint256 amt = token.pullWeeklyEmission();
        assertEq(amt, WEEKLY);
        assertEq(token.balanceOf(REWARDS), WEEKLY);
        assertEq(token.mintedOf(SailToken.Bucket.COMMUNITY), WEEKLY);
    }

    function test_P0_CannotDoublePullWithinWindow() public {
        _openSeason1();
        vm.warp(s1Start);
        token.pullWeeklyEmission();
        // immediate second pull: tranche 1 not yet unlocked
        vm.expectRevert(abi.encodeWithSelector(
            SailToken.TrancheNotYetUnlocked.selector, uint256(s1Start) + 1 weeks, block.timestamp
        ));
        token.pullWeeklyEmission();
        // after the week boundary it succeeds
        vm.warp(uint256(s1Start) + 1 weeks);
        assertEq(token.pullWeeklyEmission(), WEEKLY);
        assertEq(token.balanceOf(REWARDS), 2 * uint256(WEEKLY));
    }

    function test_P0_RevertsWhenNoActiveSeason() public {
        vm.expectRevert(SailToken.NoActiveSeason.selector);
        token.pullWeeklyEmission();
    }

    function test_P0_PullPermissionless() public {
        _openSeason1();
        vm.warp(s1Start);
        vm.prank(ALICE); // arbitrary caller
        assertEq(token.pullWeeklyEmission(), WEEKLY);
        assertEq(token.balanceOf(REWARDS), WEEKLY); // recipient is always the rewards source
    }

    function test_P0_EmissionStopsAfterLastWeekThenResumesWithNewSeason() public {
        _openSeason1();
        _runWholeSeason(s1Start, WEEKS);
        assertEq(token.balanceOf(REWARDS), SEASON1_BUDGET);
        // 13th pull: season is now inactive
        vm.warp(uint256(s1Start) + uint256(WEEKS) * 1 weeks);
        vm.expectRevert(SailToken.NoActiveSeason.selector);
        token.pullWeeklyEmission();

        // governance opens a new season => emission resumes
        uint64 start2 = uint64(block.timestamp + 48 hours + 1 days);
        _tlExec(abi.encodeCall(SailToken.openSeason, (start2, 4, WEEKLY)));
        vm.warp(start2);
        assertEq(token.pullWeeklyEmission(), WEEKLY);
        assertEq(token.balanceOf(REWARDS), SEASON1_BUDGET + uint256(WEEKLY));
    }

    function test_CatchUpAllowed() public {
        // D5: if several unlock times have passed, several pulls become available.
        _openSeason1();
        vm.warp(uint256(s1Start) + 3 weeks); // tranches 0,1,2,3 all unlocked
        token.pullWeeklyEmission();
        token.pullWeeklyEmission();
        token.pullWeeklyEmission();
        token.pullWeeklyEmission();
        assertEq(token.balanceOf(REWARDS), 4 * uint256(WEEKLY));
        // the 5th (tranche index 4) is NOT yet unlocked
        vm.expectRevert(abi.encodeWithSelector(
            SailToken.TrancheNotYetUnlocked.selector, uint256(s1Start) + 4 weeks, block.timestamp
        ));
        token.pullWeeklyEmission();
    }

    /// @dev Pull all `nw` tranches of a season starting at `start`.
    function _runWholeSeason(uint64 start, uint32 nw) internal {
        for (uint256 i; i < nw; i++) {
            vm.warp(uint256(start) + i * 1 weeks);
            token.pullWeeklyEmission();
        }
    }

    function testFuzz_P0_PullNeverExceedsBudgetOrCap(uint8 iters) public {
        _openSeason1();
        uint256 pulled;
        for (uint256 i; i < iters; i++) {
            vm.warp(uint256(s1Start) + i * 1 weeks);
            try token.pullWeeklyEmission() returns (uint256 a) { pulled += a; } catch {}
        }
        uint256 expected = (iters > WEEKS ? WEEKS : iters) * uint256(WEEKLY);
        assertEq(pulled, expected);
        assertEq(token.balanceOf(REWARDS), expected);
        assertLe(token.mintedOf(SailToken.Bucket.COMMUNITY), SEASON1_BUDGET);
        assertLe(token.totalSupply(), token.HARD_CAP());
    }

    // ═════════════════════════════════════════════════════════════════════════
    // Non-transferability predicate (highest priority)
    // ═════════════════════════════════════════════════════════════════════════

    function test_P0_MintAllowedPreFlip() public {
        // emission mint (from == 0) succeeds while transfers are locked
        _openSeason1();
        vm.warp(s1Start);
        token.pullWeeklyEmission();
        assertEq(token.balanceOf(REWARDS), WEEKLY);
        assertFalse(token.transfersEnabled());
    }

    function test_P0_RewardsSourceCanDistributePreFlip() public {
        _fundRewards(WEEKLY);
        vm.prank(REWARDS);
        token.transfer(ALICE, 1_000e18); // SMA -> user allowed
        assertEq(token.balanceOf(ALICE), 1_000e18);
    }

    function test_P0_UserToUserRevertsPreFlip() public {
        _fundRewards(WEEKLY);
        vm.prank(REWARDS);
        token.transfer(ALICE, 1_000e18);
        // user -> user is frozen
        vm.prank(ALICE);
        vm.expectRevert(SailToken.TransfersLocked.selector);
        token.transfer(BOB, 1e18);
    }

    function test_P0_InvestorAndTeamCannotTransferPreFlip() public {
        vm.prank(INVESTORS);
        vm.expectRevert(SailToken.TransfersLocked.selector);
        token.transfer(ALICE, 1e18);

        vm.prank(TEAM);
        vm.expectRevert(SailToken.TransfersLocked.selector);
        token.transfer(ALICE, 1e18);
    }

    function test_P0_TreasuryBucketFrozenPreFlip() public {
        // The DAO/Treasury bucket is NOT the rewards source — it cannot move pre-flip.
        vm.prank(TREASURY);
        vm.expectRevert(SailToken.TransfersLocked.selector);
        token.transfer(ALICE, 1e18);
    }

    function test_P0_UserToRewardsSourceRevertsPreFlip() public {
        _fundRewards(WEEKLY);
        vm.prank(REWARDS);
        token.transfer(ALICE, 1_000e18);
        // a user cannot even send back to the rewards source pre-flip (from is a user)
        vm.prank(ALICE);
        vm.expectRevert(SailToken.TransfersLocked.selector);
        token.transfer(REWARDS, 1e18);
    }

    /// @dev Give the rewards source a balance via emission.
    function _fundRewards(uint256 /*hint*/) internal {
        _openSeason1();
        vm.warp(s1Start);
        token.pullWeeklyEmission(); // mints WEEKLY to REWARDS
    }

    // ═════════════════════════════════════════════════════════════════════════
    // One-way transferability switch (highest priority)
    // ═════════════════════════════════════════════════════════════════════════

    function test_P0_EnableOnlyViaTimelock() public {
        vm.expectRevert(SailToken.NotTimelock.selector);
        vm.prank(TEAM_GOV);
        token.enablePublicTransfers();
    }

    function test_P0_AfterFlipTransfersAreOpen() public {
        _fundRewards(WEEKLY);
        vm.prank(REWARDS);
        token.transfer(ALICE, 1_000e18);

        _enableTransfers();
        assertTrue(token.transfersEnabled());
        assertEq(token.transfersEnabledAt(), block.timestamp);

        // now user -> user works, and frozen buckets can move too
        vm.prank(ALICE);
        token.transfer(BOB, 500e18);
        assertEq(token.balanceOf(BOB), 500e18);

        vm.prank(TREASURY);
        token.transfer(BOB, 1e18);
        assertEq(token.balanceOf(BOB), 500e18 + 1e18);
    }

    function test_P0_FlipCannotBeRelocked() public {
        _enableTransfers();
        // calling again reverts (idempotency guard); there is NO disable path anywhere.
        vm.prank(address(timelock));
        vm.expectRevert(SailToken.TransfersAlreadyEnabled.selector);
        token.enablePublicTransfers();

        // transfers remain permanently open across long time jumps
        vm.warp(block.timestamp + 3650 days);
        assertTrue(token.transfersEnabled());
        deal(address(token), ALICE, 10e18);
        vm.prank(ALICE);
        token.transfer(BOB, 10e18);
        assertEq(token.balanceOf(BOB), 10e18);
    }

    // ═════════════════════════════════════════════════════════════════════════
    // ERC20Votes scaffolding (included, nothing wired — decision D3)
    // ═════════════════════════════════════════════════════════════════════════

    function test_VotesCheckpointOnMintAfterDelegation() public {
        // voting power materializes only after self-delegation
        assertEq(token.getVotes(TEAM), 0);
        vm.prank(TEAM);
        token.delegate(TEAM);
        assertEq(token.getVotes(TEAM), token.CAP_TEAM());
    }

    function test_TokenMetadata() public view {
        assertEq(token.name(), "Sail");
        assertEq(token.symbol(), "SAIL");
        assertEq(token.decimals(), 18);
    }
}
