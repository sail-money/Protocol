// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

contract SailGovernance {
    // -------------------------------------------------------------------------
    // Constitutional caps — immutable, no governance procedure can change these
    // -------------------------------------------------------------------------
    uint256 public constant MAX_PROTOCOL_CUT_BPS = 2_500;
    uint256 public immutable MAX_PERMISSION_FEE_WEI;

    // -------------------------------------------------------------------------
    // Governance-tunable parameters (within the caps above)
    // -------------------------------------------------------------------------
    uint256 public CURRENT_PROTOCOL_CUT_BPS;
    uint256 public BASE_FEE;
    uint256 public COMPLEXITY_RATE;

    // -------------------------------------------------------------------------
    // Access control
    // -------------------------------------------------------------------------
    address public governance;
    address public pendingGovernance;
    address public immutable emergencyAdmin;

    // -------------------------------------------------------------------------
    // Timelock — 48-hour delay on all parameter changes
    // -------------------------------------------------------------------------
    TimelockController public immutable timelock;

    // -------------------------------------------------------------------------
    // Pause — emergency admin can pause for up to 72 hours
    // -------------------------------------------------------------------------
    uint256 public pauseExpiry;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event GovernanceTransferProposed(address indexed proposedGovernance);
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);
    event Paused(uint256 expiry);
    event Unpaused();

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------
    error NotGovernance();
    error NotPendingGovernance();
    error NotEmergencyAdmin();
    error NotTimelock();
    error ExceedsProtocolCutCap(uint256 requested, uint256 cap);
    error ExceedsPermissionFeeCap(uint256 requested, uint256 cap);
    error ZeroAddress();

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    modifier onlyTimelock() {
        if (msg.sender != address(timelock)) revert NotTimelock();
        _;
    }

    modifier onlyEmergencyAdmin() {
        if (msg.sender != emergencyAdmin) revert NotEmergencyAdmin();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(address initialGovernance, uint256 maxPermissionFeeWei, address _emergencyAdmin) {
        if (initialGovernance == address(0) || _emergencyAdmin == address(0)) revert ZeroAddress();
        governance     = initialGovernance;
        emergencyAdmin = _emergencyAdmin;
        MAX_PERMISSION_FEE_WEI = maxPermissionFeeWei;

        // Governance is the sole proposer and executor; no admin (self-governing timelock)
        address[] memory proposers = new address[](1);
        proposers[0] = initialGovernance;
        address[] memory executors = new address[](1);
        executors[0] = initialGovernance;
        timelock = new TimelockController(48 hours, proposers, executors, address(0));

        emit GovernanceTransferred(address(0), initialGovernance);
    }

    // -------------------------------------------------------------------------
    // Two-step governance transfer
    // -------------------------------------------------------------------------

    /// @notice Propose a governance handoff. Pending address must call acceptGovernance().
    function proposeGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroAddress();
        pendingGovernance = newGovernance;
        emit GovernanceTransferProposed(newGovernance);
    }

    /// @notice Called by pendingGovernance to complete the handoff.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous  = governance;
        governance        = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, governance);
    }

    // -------------------------------------------------------------------------
    // Parameter setters — only callable via the timelock
    // -------------------------------------------------------------------------

    function setProtocolCutBps(uint256 newBps) external onlyTimelock {
        if (newBps > MAX_PROTOCOL_CUT_BPS) revert ExceedsProtocolCutCap(newBps, MAX_PROTOCOL_CUT_BPS);
        uint256 old = CURRENT_PROTOCOL_CUT_BPS;
        CURRENT_PROTOCOL_CUT_BPS = newBps;
        emit ProtocolCutUpdated(old, newBps);
    }

    function setBaseFee(uint256 newFee) external onlyTimelock {
        if (newFee > MAX_PERMISSION_FEE_WEI) revert ExceedsPermissionFeeCap(newFee, MAX_PERMISSION_FEE_WEI);
        uint256 old = BASE_FEE;
        BASE_FEE = newFee;
        emit BaseFeeUpdated(old, newFee);
    }

    function setComplexityRate(uint256 newRate) external onlyTimelock {
        uint256 old = COMPLEXITY_RATE;
        COMPLEXITY_RATE = newRate;
        emit ComplexityRateUpdated(old, newRate);
    }

    // -------------------------------------------------------------------------
    // Emergency pause — admin only, auto-expires after 72 hours
    // -------------------------------------------------------------------------

    function pause() external onlyEmergencyAdmin {
        pauseExpiry = block.timestamp + 72 hours;
        emit Paused(pauseExpiry);
    }

    function unpause() external onlyEmergencyAdmin {
        pauseExpiry = 0;
        emit Unpaused();
    }

    function isPaused() external view returns (bool) {
        return block.timestamp < pauseExpiry;
    }
}
