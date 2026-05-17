// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {TimelockController} from "@openzeppelin/contracts/governance/TimelockController.sol";

/// @title  SailGovernance
/// @notice Protocol-level governance and fee-parameter store for the Sail kernel.
/// @dev    Maintains two categories of settings:
///           • Constitutional caps — immutable after deployment; no governance action can
///             raise them. They bound all mutable parameters below.
///           • Tunable parameters — adjustable by the current `governance` address (via the
///             48-hour timelock) within the caps above.
///
///         Governance transfer is two-step (propose → accept) to prevent irrecoverable
///         loss from a mistyped successor address.
///
///         All parameter changes flow through `timelock` (48-hour delay).
///         The `emergencyAdmin` may pause the kernel for up to 72 hours without a timelock.
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

    /// @notice Flat fee charged per permission registration, in wei.
    ///         Bounded by MAX_PERMISSION_FEE_WEI.
    uint256 public permissionRegistrationFee;

    /// @notice Live limit on the number of permissions per account.
    ///         Governance may adjust this between 1 and MAX_PERMISSIONS_CAP (100).
    ///         Increasing the limit raises the maximum gas cost of every future dispatch call
    ///         by up to PERMISSION_GAS_CAP gas per additional slot — operators should account
    ///         for this when sizing positions on gas-expensive networks.
    uint256 public maxPermissionsPerAccount;

    // -------------------------------------------------------------------------
    // Access control
    // -------------------------------------------------------------------------

    /// @notice Address with governance rights (may set parameters and transfer governance).
    address public governance;

    /// @notice Pending successor nominated by `proposeGovernance`.
    ///         Zero address means no transfer is in flight.
    address public pendingGovernance;

    /// @notice Address that can pause the kernel in an emergency (no timelock).
    ///         Can be rotated by the timelock via `rotateEmergencyAdmin`.
    address public emergencyAdmin;

    /// @notice Timestamp of the last successful `pause()` call; 0 = never paused.
    uint256 public lastPauseTimestamp;

    /// @dev Minimum time between consecutive `pause()` calls.
    uint256 public constant PAUSE_COOLDOWN = 72 hours;

    // -------------------------------------------------------------------------
    // Timelock — 48-hour delay on all parameter changes
    // -------------------------------------------------------------------------

    /// @notice On-chain timelock enforcing a 48-hour delay on all parameter changes.
    TimelockController public immutable timelock;

    // -------------------------------------------------------------------------
    // Trusted Safe factory and singleton allowlists
    // -------------------------------------------------------------------------

    /// @notice Allowlist of Safe proxy factory contracts trusted by the kernel.
    ///         Only factories in this mapping may be used in `createAccount`.
    mapping(address => bool) public trustedSafeFactory;

    /// @notice Allowlist of Safe singleton (implementation) contracts trusted by the kernel.
    ///         Only singletons in this mapping may be used in `createAccount`.
    mapping(address => bool) public trustedSafeSingleton;

    /// @notice Emitted when a Safe factory's trusted status changes.
    /// @param  factory  The factory address.
    /// @param  trusted  True if added to the allowlist, false if removed.
    event SafeFactoryTrusted(address indexed factory, bool trusted);

    /// @notice Emitted when a Safe singleton's trusted status changes.
    /// @param  singleton  The singleton address.
    /// @param  trusted    True if added to the allowlist, false if removed.
    event SafeSingletonTrusted(address indexed singleton, bool trusted);

    /// @notice Add or remove a Safe proxy factory from the trusted allowlist.
    /// @param  factory  Address of the factory contract.
    /// @param  trusted  True to add to allowlist, false to remove.
    function setTrustedSafeFactory(address factory, bool trusted) external onlyTimelock {
        trustedSafeFactory[factory] = trusted;
        emit SafeFactoryTrusted(factory, trusted);
    }

    /// @notice Add or remove a Safe singleton from the trusted allowlist.
    /// @param  singleton  Address of the singleton (implementation) contract.
    /// @param  trusted    True to add to allowlist, false to remove.
    function setTrustedSafeSingleton(address singleton, bool trusted) external onlyTimelock {
        trustedSafeSingleton[singleton] = trusted;
        emit SafeSingletonTrusted(singleton, trusted);
    }

    // -------------------------------------------------------------------------
    // Pause — emergency admin can pause for up to 72 hours
    // -------------------------------------------------------------------------

    /// @notice Timestamp at which the current pause expires. 0 = not paused.
    uint256 public pauseExpiry;

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

    /// @notice Emitted when `permissionRegistrationFee` is updated.
    /// @param  oldFee Previous value in wei.
    /// @param  newFee New value in wei.
    event PermissionRegistrationFeeUpdated(uint256 oldFee, uint256 newFee);

    /// @notice Emitted when `maxPermissionsPerAccount` is updated.
    /// @param  oldLimit Previous limit.
    /// @param  newLimit New limit.
    event MaxPermissionsPerAccountUpdated(uint256 oldLimit, uint256 newLimit);

    /// @notice Emitted when the kernel is paused by the emergency admin.
    /// @param  expiry Timestamp at which the pause auto-expires.
    event Paused(uint256 expiry);

    /// @notice Emitted when the emergency admin manually lifts a pause.
    event Unpaused();

    /// @notice Emitted when the emergency admin is rotated via timelock.
    event EmergencyAdminRotated(address indexed oldAdmin, address indexed newAdmin);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown by `onlyGovernance` when caller is not the current governance address.
    error NotGovernance();

    /// @dev Thrown by `acceptGovernance` when caller is not `pendingGovernance`.
    error NotPendingGovernance();

    /// @dev Thrown by `onlyTimelock` when caller is not the timelock contract.
    error NotTimelock();

    /// @dev Thrown by `onlyEmergencyAdmin` when caller is not the emergency admin.
    error NotEmergencyAdmin();

    /// @dev Thrown when a requested `currentProtocolCutBps` exceeds `MAX_PROTOCOL_CUT_BPS`.
    error ExceedsProtocolCutCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a requested `permissionRegistrationFee` exceeds `MAX_PERMISSION_FEE_WEI`.
    error FeeExceedsCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a requested `maxPermissionsPerAccount` exceeds `MAX_PERMISSIONS_CAP`
    ///      or is set to zero.
    error ExceedsPermissionsCap(uint256 requested, uint256 cap);

    /// @dev Thrown when a governance-related address argument is the zero address.
    error ZeroAddress();

    /// @dev Thrown by `proposeGovernance` when the candidate is the current governance address.
    error SameAddress();

    /// @dev Thrown by `acceptGovernance` when the candidate does not yet hold PROPOSER_ROLE
    ///      on the timelock. `rotateTimelockRoles` must be executed before `acceptGovernance`
    ///      can complete, eliminating the window where old governance retains timelock keys.
    error RolesNotYetRotated();

    /// @dev Thrown when `pause()` is called before PAUSE_COOLDOWN has elapsed since the last pause.
    error PauseCooldown(uint256 nextAllowed);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotGovernance when caller is not the current governance address.
    modifier onlyGovernance() {
        if (msg.sender != governance) revert NotGovernance();
        _;
    }

    /// @dev Reverts with NotTimelock when caller is not the timelock contract.
    modifier onlyTimelock() {
        if (msg.sender != address(timelock)) revert NotTimelock();
        _;
    }

    /// @dev Reverts with NotEmergencyAdmin when caller is not the emergency admin.
    modifier onlyEmergencyAdmin() {
        if (msg.sender != emergencyAdmin) revert NotEmergencyAdmin();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy the governance contract.
    /// @param  initialGovernance   Address to hold initial governance rights.
    /// @param  maxPermissionFeeWei Constitutional ceiling for the per-permission registration fee.
    /// @param  _emergencyAdmin     Address that can pause the kernel without a timelock delay.
    constructor(address initialGovernance, uint256 maxPermissionFeeWei, address _emergencyAdmin) {
        if (initialGovernance == address(0) || _emergencyAdmin == address(0)) revert ZeroAddress();
        if (maxPermissionFeeWei > 1 ether) revert FeeExceedsCap(maxPermissionFeeWei, 1 ether);

        governance     = initialGovernance;
        emergencyAdmin = _emergencyAdmin;
        MAX_PERMISSION_FEE_WEI = maxPermissionFeeWei;
        maxPermissionsPerAccount = 20;

        // Governance is the sole proposer and executor; no admin (self-governing timelock).
        address[] memory proposers = new address[](1);
        proposers[0] = initialGovernance;
        address[] memory executors = new address[](1);
        executors[0] = initialGovernance;
        timelock = new TimelockController(48 hours, proposers, executors, address(0));

        emit GovernanceTransferred(address(0), initialGovernance);
    }

    // -------------------------------------------------------------------------
    // Governance transfer — two-step to prevent irrecoverable transfers
    // -------------------------------------------------------------------------

    /// @notice Step 1: current governance nominates a successor. No immediate effect.
    /// @dev    The transfer is only finalised when the candidate calls `acceptGovernance`.
    ///         Calling this again before acceptance overwrites `pendingGovernance`, allowing
    ///         the current governance to cancel or redirect an in-flight nomination.
    ///
    ///         **IMPORTANT — timelock role rotation required:**
    ///         After `acceptGovernance` completes, the new governance holds the `governance`
    ///         storage variable but does NOT yet hold `PROPOSER_ROLE` or `EXECUTOR_ROLE` on
    ///         the TimelockController (those roles remain with the old governance).
    ///         Before or concurrent with the two-step transfer, the current governance MUST
    ///         schedule and execute a `rotateTimelockRoles(newGovernance)` call via the
    ///         timelock to hand over scheduling and execution rights. Failure to do so leaves
    ///         the new governance unable to enact any timelocked parameter changes.
    ///
    ///         Recommended sequence:
    ///           1. Current governance calls `proposeGovernance(candidate)`.
    ///           2. Current governance schedules `rotateTimelockRoles(candidate)` via the
    ///              timelock (48-hour delay).
    ///           3. After 48 hours, current governance executes `rotateTimelockRoles`.
    ///           4. Candidate calls `acceptGovernance()` to finalise the transfer.
    ///
    /// @param  candidate Address being nominated as the next governance.
    /// @dev    Must be called via the 48-hour timelock (`onlyTimelock`). Schedule via
    ///         `governance.timelock()` with the standard 48-hour delay.
    function proposeGovernance(address candidate) external onlyTimelock {
        if (candidate == address(0)) revert ZeroAddress();
        if (candidate == governance) revert SameAddress();
        pendingGovernance = candidate;
        emit GovernanceProposed(governance, candidate);
    }

    /// @notice Step 2: nominated address accepts, completing the transfer.
    /// @dev    Clears `pendingGovernance` after the transfer. See `proposeGovernance` for the
    ///         required timelock role rotation procedure that must precede this call.
    ///         Requires that `rotateTimelockRoles` has already been executed — i.e., the
    ///         candidate already holds PROPOSER_ROLE on the timelock. This eliminates the
    ///         window where old governance retains timelock scheduling rights after handoff.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        // Enforce that rotateTimelockRoles was called before acceptGovernance, preventing
        // a governance handoff window where the old governance still holds timelock roles.
        if (!timelock.hasRole(timelock.PROPOSER_ROLE(), msg.sender)) revert RolesNotYetRotated();
        address previous  = governance;
        governance        = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, governance);
    }

    /// @notice Rotate PROPOSER_ROLE and EXECUTOR_ROLE on the timelock from `oldGov` to `newGov`.
    /// @dev    Must be called via the 48-hour timelock (scheduled by the current PROPOSER).
    ///         Intended to be executed as part of a governance handoff — grants roles to the
    ///         incoming governance and revokes them from the outgoing governance in one atomic
    ///         operation.
    ///
    ///         The timelock holds its own DEFAULT_ADMIN_ROLE (admin=address(0) in constructor),
    ///         so only the timelock itself can grant or revoke roles. This function provides a
    ///         safe entry point for that operation.
    ///
    /// @param  oldGov Address to revoke PROPOSER_ROLE and EXECUTOR_ROLE from.
    /// @param  newGov Address to grant PROPOSER_ROLE and EXECUTOR_ROLE to.
    function rotateTimelockRoles(address oldGov, address newGov) external onlyTimelock {
        if (newGov == address(0)) revert ZeroAddress();
        bytes32 proposer  = timelock.PROPOSER_ROLE();
        bytes32 executor  = timelock.EXECUTOR_ROLE();
        bytes32 canceller = timelock.CANCELLER_ROLE();
        timelock.grantRole(proposer,  newGov);
        timelock.grantRole(executor,  newGov);
        timelock.grantRole(canceller, newGov);
        timelock.revokeRole(proposer,  oldGov);
        timelock.revokeRole(executor,  oldGov);
        timelock.revokeRole(canceller, oldGov);
    }

    // -------------------------------------------------------------------------
    // Parameter setters — only callable via the 48-hour timelock
    // -------------------------------------------------------------------------

    /// @notice Set the protocol's share of each fee collection.
    /// @param  newBps New basis-point value. Must not exceed MAX_PROTOCOL_CUT_BPS (2 500).
    function setProtocolCutBps(uint256 newBps) external onlyTimelock {
        if (newBps > MAX_PROTOCOL_CUT_BPS) revert ExceedsProtocolCutCap(newBps, MAX_PROTOCOL_CUT_BPS);
        uint256 old = currentProtocolCutBps;
        currentProtocolCutBps = newBps;
        emit ProtocolCutUpdated(old, newBps);
    }

    /// @notice Set the flat fee charged per permission registration.
    /// @param  newFee New fee in wei. Must not exceed MAX_PERMISSION_FEE_WEI.
    function setPermissionRegistrationFee(uint256 newFee) external onlyTimelock {
        if (newFee > MAX_PERMISSION_FEE_WEI) revert FeeExceedsCap(newFee, MAX_PERMISSION_FEE_WEI);
        uint256 oldFee = permissionRegistrationFee;
        permissionRegistrationFee = newFee;
        emit PermissionRegistrationFeeUpdated(oldFee, newFee);
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
    function setMaxPermissionsPerAccount(uint256 newLimit) external onlyTimelock {
        if (newLimit == 0 || newLimit > MAX_PERMISSIONS_CAP)
            revert ExceedsPermissionsCap(newLimit, MAX_PERMISSIONS_CAP);
        uint256 old = maxPermissionsPerAccount;
        maxPermissionsPerAccount = newLimit;
        emit MaxPermissionsPerAccountUpdated(old, newLimit);
    }

    // -------------------------------------------------------------------------
    // Emergency pause — admin only, auto-expires after 72 hours
    // -------------------------------------------------------------------------

    /// @notice Pause the kernel for up to 72 hours. Can be called without a timelock delay.
    ///         Subject to a PAUSE_COOLDOWN between consecutive calls to prevent spam.
    function pause() external onlyEmergencyAdmin {
        if (lastPauseTimestamp != 0 && block.timestamp < lastPauseTimestamp + PAUSE_COOLDOWN)
            revert PauseCooldown(lastPauseTimestamp + PAUSE_COOLDOWN);
        lastPauseTimestamp = block.timestamp;
        pauseExpiry = block.timestamp + 72 hours;
        emit Paused(pauseExpiry);
    }

    /// @notice Lift the pause early.
    function unpause() external onlyEmergencyAdmin {
        pauseExpiry = 0;
        emit Unpaused();
    }

    /// @notice Rotate the emergency admin address. Only callable by the timelock.
    /// @param  newAdmin New emergency admin address. Must not be zero.
    function rotateEmergencyAdmin(address newAdmin) external onlyTimelock {
        if (newAdmin == address(0)) revert ZeroAddress();
        address old = emergencyAdmin;
        emergencyAdmin = newAdmin;
        emit EmergencyAdminRotated(old, newAdmin);
    }

    /// @notice Returns true if the kernel is currently paused.
    function isPaused() external view returns (bool) {
        return block.timestamp < pauseExpiry;
    }
}
