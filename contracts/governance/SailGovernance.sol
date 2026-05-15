// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

contract SailGovernance {
    // -------------------------------------------------------------------------
    // Constitutional caps — immutable; no governance procedure can raise these
    // -------------------------------------------------------------------------
    uint256 public constant MAX_PROTOCOL_CUT_BPS = 2_500;
    uint256 public immutable MAX_PERMISSION_FEE_WEI;

    // -------------------------------------------------------------------------
    // Governance-tunable parameters (within the caps above)
    // -------------------------------------------------------------------------
    /// @dev Lowercase names: these are mutable storage, not constants.
    uint256 public currentProtocolCutBps;
    uint256 public baseFee;
    uint256 public complexityRate;

    address public governance;
    /// @dev Pending successor set by proposeGovernance. Zero if no transfer in flight.
    address public pendingGovernance;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event GovernanceProposed(address indexed currentGovernance, address indexed proposedGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------
    error NotGovernance();
    error NotPendingGovernance();
    error ExceedsProtocolCutCap(uint256 requested, uint256 cap);
    error ExceedsPermissionFeeCap(uint256 requested, uint256 cap);
    error ZeroAddress();

    // -------------------------------------------------------------------------
    // Modifier
    // -------------------------------------------------------------------------
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------
    constructor(address initialGovernance, uint256 maxPermissionFeeWei) {
        if (initialGovernance == address(0)) revert ZeroAddress();
        governance = initialGovernance;
        MAX_PERMISSION_FEE_WEI = maxPermissionFeeWei;
        emit GovernanceTransferred(address(0), initialGovernance);
    }

    // -------------------------------------------------------------------------
    // Governance transfer — two-step to prevent irrecoverable transfers
    // -------------------------------------------------------------------------

    /// @notice Step 1: current governance nominates a successor. No immediate effect.
    /// @dev    The transfer is only finalised when the candidate calls acceptGovernance.
    ///         This prevents governance loss from a mistyped address.
    function proposeGovernance(address candidate) external onlyGovernance {
        if (candidate == address(0)) revert ZeroAddress();
        pendingGovernance = candidate;
        emit GovernanceProposed(governance, candidate);
    }

    /// @notice Step 2: nominated address accepts, completing the transfer.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        address previous  = governance;
        governance        = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, governance);
    }

    // -------------------------------------------------------------------------
    // Parameter setters
    // -------------------------------------------------------------------------
    function setProtocolCutBps(uint256 newBps) external onlyGovernance {
        if (newBps > MAX_PROTOCOL_CUT_BPS) revert ExceedsProtocolCutCap(newBps, MAX_PROTOCOL_CUT_BPS);
        uint256 old = currentProtocolCutBps;
        currentProtocolCutBps = newBps;
        emit ProtocolCutUpdated(old, newBps);
    }

    function setBaseFee(uint256 newFee) external onlyGovernance {
        if (newFee > MAX_PERMISSION_FEE_WEI) revert ExceedsPermissionFeeCap(newFee, MAX_PERMISSION_FEE_WEI);
        uint256 old = baseFee;
        baseFee = newFee;
        emit BaseFeeUpdated(old, newFee);
    }

    /// @notice Set the per-byte complexity contribution to the permission registration fee.
    /// @dev    The actual per-permission fee is always capped at MAX_PERMISSION_FEE_WEI by the
    ///         kernel, so an extreme rate cannot cause fees to exceed the constitutional cap.
    ///         Rate is bounded at MAX_PERMISSION_FEE_WEI for consistency with setBaseFee.
    function setComplexityRate(uint256 newRate) external onlyGovernance {
        if (newRate > MAX_PERMISSION_FEE_WEI) revert ExceedsPermissionFeeCap(newRate, MAX_PERMISSION_FEE_WEI);
        uint256 old = complexityRate;
        complexityRate = newRate;
        emit ComplexityRateUpdated(old, newRate);
    }
}
