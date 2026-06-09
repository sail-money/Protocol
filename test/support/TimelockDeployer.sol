// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title  TimelockDeployer
/// @notice Test-only helper that deploys a TimelockController wired exactly as SailGovernance
///         requires: a 48-hour minimum delay, with `gov` as the sole proposer / executor /
///         canceller and no external admin (self-administered, `admin == address(0)`).
///
/// @dev    SailGovernance no longer constructs its timelock inline — it accepts one as a
///         constructor argument and validates (a) the delay is exactly 48 hours and (b) `gov`
///         holds PROPOSER_ROLE. This helper produces a timelock that satisfies both checks, so
///         test setup reads as a single line:
///
///             gov = new SailGovernance(GOV, maxFee, emergency, regFee, TimelockDeployer.deploy(GOV));
///
///         The `gov` passed here MUST be the same address passed as SailGovernance's
///         `initialGovernance`, or construction reverts with `GovernanceNotProposer`.
library TimelockDeployer {
    /// @notice Deploy a 48-hour, self-administered timelock with `gov` as sole proposer/executor.
    function deploy(address gov) internal returns (TimelockController) {
        address[] memory proposers = new address[](1);
        proposers[0] = gov;
        address[] memory executors = new address[](1);
        executors[0] = gov;
        return new TimelockController(48 hours, proposers, executors, address(0));
    }
}
