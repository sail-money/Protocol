// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  SailGovernance
/// @notice Protocol-level governance and fee-parameter store for the Sail kernel.
/// @dev    Maintains two categories of settings:
///           • Constitutional caps — immutable after deployment; no governance action can
///             raise them. They bound all mutable parameters below.
///           • Tunable parameters — adjustable by the current `governance` address within
///             the caps above.
///
///         Governance transfer is two-step (propose → accept) to prevent irrecoverable
///         loss from a mistyped successor address.
/// @custom:security-contact security@sail.money
contract SailGovernance {
    // -------------------------------------------------------------------------
    // Constitutional caps — immutable; no governance procedure can raise these
    // -------------------------------------------------------------------------

    /// @notice Hard ceiling on the protocol's share of collected fees (25%).
    uint256 public constant MAX_PROTOCOL_CUT_BPS = 2_500;

    /// @notice Hard ceiling on the per-permission registration fee in wei.
    ///         Set at deployment; cannot be raised afterwards.
    uint256 public immutable MAX_PERMISSION_FEE_WEI;

    /// @notice Hard ceiling on the number of permissions an account may register.
    ///         Bounds the maximum gas cost of the kernel's dispatch loop across all future
    ///         governance decisions. No governance action can raise the live limit above this.
    ///
    ///         Gas budget at the cap: 100 × PERMISSION_GAS_CAP (100 000) = 10 000 000 gas.
    ///         Feasible on all L2s; expensive but not impossible on Ethereum mainnet for
    ///         large managed positions.
    uint256 public constant MAX_PERMISSIONS_CAP = 100;

    // -------------------------------------------------------------------------
    // Governance-tunable parameters (within the caps above)
    // -------------------------------------------------------------------------

    /// @notice Protocol's share of each fee collection, in basis points.
    ///         0 = no protocol fee. Bounded by MAX_PROTOCOL_CUT_BPS.
    /// @dev    Lowercase name signals mutable storage, not a constant.
    uint256 public currentProtocolCutBps;

    /// @notice Flat component of the permission registration fee, in wei.
    ///         Applied regardless of permission bytecode size.
    uint256 public baseFee;

    /// @notice Per-byte contribution to the permission registration fee, in wei.
    ///         Final fee = min(baseFee + complexityRate × codeSize, MAX_PERMISSION_FEE_WEI).
    uint256 public complexityRate;

    /// @notice Live limit on the number of permissions per account.
    ///         Governance may adjust this between 1 and MAX_PERMISSIONS_CAP (100).
    ///         Increasing the limit raises the maximum gas cost of every future dispatch call
    ///         by up to PERMISSION_GAS_CAP gas per additional slot — operators should account
    ///         for this when sizing positions on gas-expensive networks.
    uint256 public maxPermissionsPerAccount;

    /// @notice Address with governance rights (may set parameters and transfer governance).
    address public governance;

    /// @notice Pending successor nominated by `proposeGovernance`.
    ///         Zero address means no transfer is in flight.
    address public pendingGovernance;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when governance is successfully transferred to a new address.
    /// @param  previousGovernance The previous governance address.
    /// @param  newGovernance      The new governance address.
    event GovernanceTransferred(address indexed previousGovernance, address indexed newGovernance);

    /// @notice Emitted when a governance transfer is proposed but not yet accepted.
    /// @param  currentGovernance  Address that proposed the transfer.
    /// @param  proposedGovernance Address nominated as successor.
    event GovernanceProposed(address indexed currentGovernance, address indexed proposedGovernance);

    /// @notice Emitted when `currentProtocolCutBps` is updated.
    /// @param  oldBps Previous value.
    /// @param  newBps New value.
    event ProtocolCutUpdated(uint256 oldBps, uint256 newBps);

    /// @notice Emitted when `baseFee` is updated.
    /// @param  oldFee Previous value in wei.
    /// @param  newFee New value in wei.
    event BaseFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when `complexityRate` is updated.
    /// @param  oldRate Previous value in wei per byte.
    /// @param  newRate New value in wei per byte.
    event ComplexityRateUpdated(uint256 oldRate, uint256 newRate);

    /// @notice Emitted when `maxPermissionsPerAccount` is updated.
    /// @param  oldLimit Previous limit.
    /// @param  newLimit New limit.
    event MaxPermissionsPerAccountUpdated(uint256 oldLimit, uint256 newLimit);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown by `onlyGovernance` when caller is not the current governance address.
    error NotGovernance();

    /// @dev Thrown by `acceptGovernance` when caller is not `pendingGovernance`.
    error NotPendingGovernance();

    /// @dev Thrown when a requested `currentProtocolCutBps` exceeds `MAX_PROTOCOL_CUT_BPS`.
    error ExceedsProtocolCutCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a requested `baseFee` or `complexityRate` exceeds `MAX_PERMISSION_FEE_WEI`.
    error ExceedsPermissionFeeCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a requested `maxPermissionsPerAccount` exceeds `MAX_PERMISSIONS_CAP`
    ///      or is set to zero.
    error ExceedsPermissionsCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a governance-related address argument is the zero address.
    error ZeroAddress();

    // -------------------------------------------------------------------------
    // Modifier
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotGovernance when caller is not the current governance address.
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy the governance contract with an initial governance address and fee cap.
    /// @param  initialGovernance   Address to hold initial governance rights.
    /// @param  maxPermissionFeeWei Constitutional ceiling for the per-permission registration fee.
    constructor(address initialGovernance, uint256 maxPermissionFeeWei) {
        if (initialGovernance == address(0)) revert ZeroAddress();
        // Cap at 1e36 wei (~1e18 ETH). Values above this would allow base + sizeContrib
        // to overflow uint256 in _calcPermissionFee (sum of two values each <= cap).
        if (maxPermissionFeeWei > 1e36) revert ExceedsPermissionFeeCap(maxPermissionFeeWei, 1e36);
        governance = initialGovernance;
        MAX_PERMISSION_FEE_WEI = maxPermissionFeeWei;
        maxPermissionsPerAccount = 20;
        emit GovernanceTransferred(address(0), initialGovernance);
    }

    // -------------------------------------------------------------------------
    // Governance transfer — two-step to prevent irrecoverable transfers
    // -------------------------------------------------------------------------

    /// @notice Step 1: current governance nominates a successor. No immediate effect.
    /// @dev    The transfer is only finalised when the candidate calls `acceptGovernance`.
    ///         Calling this again before acceptance overwrites `pendingGovernance`, allowing
    ///         the current governance to cancel or redirect an in-flight nomination.
    /// @param  candidate Address being nominated as the next governance.
    function proposeGovernance(address candidate) external onlyGovernance {
        if (candidate == address(0)) revert ZeroAddress();
        pendingGovernance = candidate;
        emit GovernanceProposed(governance, candidate);
    }

    /// @notice Step 2: nominated address accepts, completing the transfer.
    /// @dev    Clears `pendingGovernance` after the transfer to signal no in-flight nomination.
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

    /// @notice Set the protocol's share of each fee collection.
    /// @param  newBps New basis-point value. Must not exceed MAX_PROTOCOL_CUT_BPS (2 500).
    function setProtocolCutBps(uint256 newBps) external onlyGovernance {
        if (newBps > MAX_PROTOCOL_CUT_BPS) revert ExceedsProtocolCutCap(newBps, MAX_PROTOCOL_CUT_BPS);
        uint256 old = currentProtocolCutBps;
        currentProtocolCutBps = newBps;
        emit ProtocolCutUpdated(old, newBps);
    }

    /// @notice Set the flat component of the permission registration fee.
    /// @param  newFee New fee in wei. Must not exceed MAX_PERMISSION_FEE_WEI.
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
    /// @param  newRate New rate in wei per byte of permission bytecode.
    ///                 Must not exceed MAX_PERMISSION_FEE_WEI.
    function setComplexityRate(uint256 newRate) external onlyGovernance {
        if (newRate > MAX_PERMISSION_FEE_WEI) revert ExceedsPermissionFeeCap(newRate, MAX_PERMISSION_FEE_WEI);
        uint256 old = complexityRate;
        complexityRate = newRate;
        emit ComplexityRateUpdated(old, newRate);
    }

    /// @notice Set the live limit on the number of permissions per account.
    /// @dev    Raising this limit increases the maximum dispatch gas cost by up to
    ///         PERMISSION_GAS_CAP gas per additional slot. Operators on gas-expensive
    ///         networks should account for this before registering up to the new limit.
    ///         Lowering the limit does NOT retroactively revoke permissions on accounts
    ///         that are already at or above the new limit — it only prevents further
    ///         registrations until those accounts fall below the live limit again.
    /// @param  newLimit New per-account permission limit.
    ///                  Must be between 1 and MAX_PERMISSIONS_CAP (100) inclusive.
    function setMaxPermissionsPerAccount(uint256 newLimit) external onlyGovernance {
        if (newLimit == 0 || newLimit > MAX_PERMISSIONS_CAP)
            revert ExceedsPermissionsCap(newLimit, MAX_PERMISSIONS_CAP);
        uint256 old = maxPermissionsPerAccount;
        maxPermissionsPerAccount = newLimit;
        emit MaxPermissionsPerAccountUpdated(old, newLimit);
    }
}
