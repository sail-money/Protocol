// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {Test}                from "forge-std/Test.sol";
import {Vm}                  from "forge-std/Vm.sol";
import {SailToken}          from "../contracts/token/SailToken.sol";
import {TimelockDeployer}   from "./support/TimelockDeployer.sol";
import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @notice Drives permissionless emission under random time jumps. Used by the invariant suite to
///         prove the cap and the community-bucket bound hold under ANY pull cadence.
contract EmissionHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SailToken public immutable token;
    uint256 public pulls;

    constructor(SailToken _token) { token = _token; }

    /// @dev Jump a random amount of time (0..~2 weeks) then attempt a pull. Reverts are swallowed:
    ///      a denied pull (too early / season over) must never corrupt accounting.
    function pull(uint256 warpBy) external {
        vm.warp(block.timestamp + (warpBy % (14 days)) + 1);
        try token.pullWeeklyEmission() { pulls++; } catch {}
    }
}

/// @title  SailTokenInvariantTest
/// @notice P0 invariant: under arbitrary permissionless emission, total supply never exceeds the
///         hard cap and the community bucket never exceeds its 40% cap.
contract SailTokenInvariantTest is Test {
    SailToken          token;
    TimelockController timelock;
    EmissionHandler    handler;

    address constant TEAM_GOV   = address(0x60D);
    address constant INVESTORS  = address(0x1117);
    address constant TEAM       = address(0x2227);
    address constant TREASURY   = address(0x3337);
    address constant FOUNDATION = address(0x4447);
    address constant LIQUIDITY  = address(0x5557);
    address constant REWARDS    = address(0x9999);

    uint128 constant WEEKLY = 5_000_000e18;
    uint32  constant WEEKS  = 12;

    function setUp() public {
        vm.warp(1_000_000);
        timelock = TimelockDeployer.deploy(TEAM_GOV);
        token = new SailToken(
            INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY,
            REWARDS, TEAM_GOV, timelock
        );

        // Open Season 1 via the timelock so emission can flow.
        uint64 start = uint64(block.timestamp + 48 hours + 1 days);
        bytes memory data = abi.encodeCall(SailToken.openSeason, (start, WEEKS, WEEKLY));
        vm.prank(TEAM_GOV);
        timelock.schedule(address(token), 0, data, bytes32(0), bytes32(0), 48 hours);
        vm.warp(block.timestamp + 48 hours + 1);
        vm.prank(TEAM_GOV);
        timelock.execute(address(token), 0, data, bytes32(0), bytes32(0));
        vm.warp(start);

        handler = new EmissionHandler(token);
        targetContract(address(handler));
    }

    /// @notice Total supply can never exceed the immutable 1B hard cap.
    function invariant_totalSupplyWithinHardCap() public view {
        assertLe(token.totalSupply(), token.HARD_CAP());
    }

    /// @notice Cumulative community minting (genesis + all seasons) can never exceed the 40% bucket.
    function invariant_communityBucketWithinCap() public view {
        assertLe(token.mintedOf(SailToken.Bucket.COMMUNITY), token.CAP_COMMUNITY());
    }

    /// @notice A single season can never over-issue beyond its budget.
    function invariant_seasonEmissionWithinBudget() public view {
        // Community minted is exactly weeklyRate * weeksPulled for the single season opened here.
        assertLe(token.mintedOf(SailToken.Bucket.COMMUNITY), uint256(WEEKLY) * WEEKS);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi-season lifecycle (Alvaro review item 2)
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Drives the FULL season lifecycle — open -> pull across weeks -> exhaust -> reopen — under
///         fuzzed week counts, rates, and time jumps. Closes the gap where the prior handler only
///         ever opened ONE season: this proves the cumulative community bound holds across an
///         arbitrary number of open/exhaust/reopen cycles, not just within a single season.
contract SeasonLifecycleHandler {
    Vm internal constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    SailToken public immutable token;
    address  public immutable timelockAddr;
    uint256  public opens;
    uint256  public pulls;

    constructor(SailToken _token, address _timelock) {
        token = _token;
        timelockAddr = _timelock;
    }

    /// @dev Jump time then attempt a pull (permissionless). Denied pulls (too early / no active
    ///      season) are swallowed — they must never corrupt accounting.
    function pull(uint256 warpBy) external {
        vm.warp(block.timestamp + (warpBy % (10 days)) + 1);
        try token.pullWeeklyEmission() { pulls++; } catch {}
    }

    /// @dev Attempt to open a new season with a budget chosen to ALWAYS fit the remaining community
    ///      bucket (so opens are meaningful, not guaranteed reverts). `start == now` makes tranche 0
    ///      immediately pullable. Opens prank the timelock (the lifecycle is what we fuzz, not the
    ///      48h delay). Reverts (e.g. a season already active) are swallowed.
    function openNextSeason(uint256 weeksSeed, uint256 rateSeed) external {
        uint256 minted = token.mintedOf(SailToken.Bucket.COMMUNITY);
        uint256 cap    = token.CAP_COMMUNITY();
        if (minted >= cap) return;                          // bucket exhausted; nothing left to emit
        uint256 remaining = cap - minted;

        uint256 weeks_ = (weeksSeed % uint256(token.MAX_WEEKS())) + 1; // 1..MAX_WEEKS
        if (weeks_ > remaining) weeks_ = 1;                 // guarantee a >=1 wei rate is possible
        uint256 maxRate = remaining / weeks_;               // budget = rate*weeks_ <= remaining
        if (maxRate == 0) return;
        uint256 rate = (rateSeed % maxRate) + 1;            // 1..maxRate

        vm.prank(timelockAddr);
        // start == now is valid (openSeason reverts only on start < now); rate/weeks_ casts bounded
        // (rate <= maxRate <= remaining <= CAP_COMMUNITY < 2^128; weeks_ <= MAX_WEEKS < 2^32).
        try token.openSeason(uint64(block.timestamp), uint32(weeks_), uint128(rate)) { opens++; } catch {}
    }
}

/// @title  SailTokenMultiSeasonInvariantTest
/// @notice P0 invariant under ARBITRARY open/exhaust/reopen sequences: cumulative community minting
///         (every season + genesis) never exceeds the 40% bucket, and total supply never exceeds the
///         hard cap. No season is pre-opened — the handler drives the entire lifecycle.
contract SailTokenMultiSeasonInvariantTest is Test {
    SailToken              token;
    TimelockController     timelock;
    SeasonLifecycleHandler handler;

    address constant TEAM_GOV   = address(0x60D);
    address constant INVESTORS  = address(0x1117);
    address constant TEAM       = address(0x2227);
    address constant TREASURY   = address(0x3337);
    address constant FOUNDATION = address(0x4447);
    address constant LIQUIDITY  = address(0x5557);
    address constant REWARDS    = address(0x9999);

    function setUp() public {
        vm.warp(1_000_000);
        timelock = TimelockDeployer.deploy(TEAM_GOV);
        token = new SailToken(INVESTORS, TEAM, TREASURY, FOUNDATION, LIQUIDITY, REWARDS, TEAM_GOV, timelock);
        handler = new SeasonLifecycleHandler(token, address(timelock));
        targetContract(address(handler));
    }

    /// @notice Across arbitrary open/pull/exhaust/reopen sequences, cumulative community minting can
    ///         never exceed the 40% community bucket (the multi-season cumulative bound).
    function invariant_multiSeasonCommunityBucketWithinCap() public view {
        assertLe(token.mintedOf(SailToken.Bucket.COMMUNITY), token.CAP_COMMUNITY());
    }

    /// @notice Total supply can never exceed the immutable 1B hard cap, regardless of season churn.
    function invariant_multiSeasonTotalSupplyWithinHardCap() public view {
        assertLe(token.totalSupply(), token.HARD_CAP());
    }
}
