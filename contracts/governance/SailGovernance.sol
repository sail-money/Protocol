// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

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

    address public governance;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------
    error NotGovernance();
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
    // Governance transfer
    // -------------------------------------------------------------------------
    function transferGovernance(address newGovernance) external onlyGovernance {
        if (newGovernance == address(0)) revert ZeroAddress();
        address previous = governance;
        governance = newGovernance;
        emit GovernanceTransferred(previous, newGovernance);
    }

    // -------------------------------------------------------------------------
    // Parameter setters
    // -------------------------------------------------------------------------
    function setProtocolCutBps(uint256 newBps) external onlyGovernance {
        if (newBps > MAX_PROTOCOL_CUT_BPS) revert ExceedsProtocolCutCap(newBps, MAX_PROTOCOL_CUT_BPS);
        uint256 old = CURRENT_PROTOCOL_CUT_BPS;
        CURRENT_PROTOCOL_CUT_BPS = newBps;
        emit ProtocolCutUpdated(old, newBps);
    }

    function setBaseFee(uint256 newFee) external onlyGovernance {
        if (newFee > MAX_PERMISSION_FEE_WEI) revert ExceedsPermissionFeeCap(newFee, MAX_PERMISSION_FEE_WEI);
        uint256 old = BASE_FEE;
        BASE_FEE = newFee;
        emit BaseFeeUpdated(old, newFee);
    }

    function setComplexityRate(uint256 newRate) external onlyGovernance {
        uint256 old = COMPLEXITY_RATE;
        COMPLEXITY_RATE = newRate;
        emit ComplexityRateUpdated(old, newRate);
    }
}
