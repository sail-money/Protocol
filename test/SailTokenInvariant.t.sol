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
