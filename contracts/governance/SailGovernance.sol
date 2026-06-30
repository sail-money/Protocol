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
/// @custom:security-contact hello@sail.money
contract SailGovernance {
    // -------------------------------------------------------------------------
    // Constitutional caps — immutable; no governance procedure can raise these
    // -------------------------------------------------------------------------

    /// @notice Hard ceiling on the protocol's share of collected fees (25%).
    uint256 public constant MAX_PROTOCOL_CUT_BPS = 2_500;

    /// @notice Hard ceiling on the per-permission registration fee in wei.
    ///         Set at deployment via the constructor and bounded by an immutable
    ///         bytecode ceiling of 0.01 ether; cannot be raised afterwards.
    uint256 public immutable MAX_PERMISSION_FEE_WEI;

    /// @notice Hard ceiling on the number of permissions an account may register.
    ///         Bounds account registry size (and its per-account storage), not per-dispatch gas.
    ///         No governance action can raise the live limit above this.
    ///
    ///         Under selective authorization the kernel never loops over an account's registered
    ///         permissions: each dispatch evaluates exactly the one permission named in the manager's
    ///         signature under PERMISSION_GAS_CAP = 150_000 (a batch evaluates one batch-aware
    ///         permission under BATCH_EVAL_GAS_CAP = 1_000_000). So per-dispatch evaluation gas is
    ///         bounded by the cap regardless of how many permissions an account has registered.
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
    ///         Under selective authorization this bounds how many permissions an account can attach,
    ///         not per-dispatch gas: each dispatch evaluates only the one named permission under
    ///         PERMISSION_GAS_CAP, so registering more permissions does not raise per-dispatch cost.
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
    /// @dev    Deployed separately and injected via the constructor (not constructed inline), so
    ///         that this contract's deployment bytecode and constructor arguments are identical
    ///         across chains — a prerequisite for the deterministic CREATE2 same-address deployment.
    ///         The constructor validates that the injected timelock has a 48-hour minimum delay and
    ///         grants PROPOSER_ROLE to the initial governance address.
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

    /// @notice Allowlist of fee policy contracts trusted by the kernel.
    ///         Only policies in this mapping may be set via `_registerAccount` or `setFeePolicy`.
    ///         Prevents upgradeable/metamorphic policies from being used to redirect or inflate fees.
    mapping(address => bool) public trustedFeePolicy;

    /// @notice Allowlist of Safe `SafeModuleSetup`-style helpers trusted by the kernel.
    ///         Only helpers in this mapping may be used as the `to` target of Safe.setup's
    ///         internal delegatecall during `createAccount`. This is the structural defense
    ///         against attacker-controlled setup delegatecalls overwriting the proxy slot 0.
    mapping(address => bool) public trustedModuleSetup;

    /// @notice Allowlist of Safe proxy runtime codehashes trusted by the kernel.
    ///         A freshly deployed proxy (in `createAccount`) or a self-registering Safe
    ///         (in `registerAccount`) must match one of these codehashes, proving it is a
    ///         genuine Safe proxy rather than arbitrary attacker bytecode.
    mapping(bytes32 => bool) public trustedSafeProxyCodehash;

    /// @notice True once the one-time genesis allowlist seeding (`bootstrapAllowlists`) has run.
    ///         Latches true forever; afterwards every allowlist change MUST go through the
    ///         48-hour timelock. Starts false so a fresh deployment can seed its initial
    ///         onboarding allowlists in the deployment transaction without the timelock delay.
    bool public allowlistBootstrapped;

    /// @notice Emitted when a Safe factory's trusted status changes.
    /// @param  factory  The factory address.
    /// @param  trusted  True if added to the allowlist, false if removed.
    event SafeFactoryTrusted(address indexed factory, bool trusted);

    /// @notice Emitted when a Safe singleton's trusted status changes.
    /// @param  singleton  The singleton address.
    /// @param  trusted    True if added to the allowlist, false if removed.
    event SafeSingletonTrusted(address indexed singleton, bool trusted);

    /// @notice Emitted when a fee policy's trusted status changes.
    /// @param  policy   The fee policy address.
    /// @param  trusted  True if added to the allowlist, false if removed.
    event FeePolicyTrusted(address indexed policy, bool trusted);

    /// @notice Emitted when a module-setup helper's trusted status changes.
    /// @param  setup    The helper address.
    /// @param  trusted  True if added to the allowlist, false if removed.
    event ModuleSetupTrusted(address indexed setup, bool trusted);

    /// @notice Emitted when a Safe proxy codehash's trusted status changes.
    /// @param  codehash The proxy runtime codehash.
    /// @param  trusted  True if added to the allowlist, false if removed.
    event SafeProxyCodehashTrusted(bytes32 indexed codehash, bool trusted);

    /// @notice Emitted once, when the one-time genesis allowlist bootstrap runs.
    /// @param  by The governance address that performed the bootstrap.
    event AllowlistBootstrapped(address indexed by);

    /// @notice Add or remove a Safe proxy factory from the trusted allowlist.
    /// @param  factory  Address of the factory contract.
    /// @param  trusted  True to add to allowlist, false to remove.
    function setTrustedSafeFactory(address factory, bool trusted) external onlyTimelock {
        if (factory == address(0)) revert ZeroAddress();
        trustedSafeFactory[factory] = trusted;
        emit SafeFactoryTrusted(factory, trusted);
    }

    /// @notice Add or remove a Safe singleton from the trusted allowlist.
    /// @param  singleton  Address of the singleton (implementation) contract.
    /// @param  trusted    True to add to allowlist, false to remove.
    function setTrustedSafeSingleton(address singleton, bool trusted) external onlyTimelock {
        if (singleton == address(0)) revert ZeroAddress();
        trustedSafeSingleton[singleton] = trusted;
        emit SafeSingletonTrusted(singleton, trusted);
    }

    /// @notice Add or remove a fee policy contract from the trusted allowlist.
    /// @param  policy   Address of the fee policy contract.
    /// @param  trusted  True to add to allowlist, false to remove.
    function setTrustedFeePolicy(address policy, bool trusted) external onlyTimelock {
        if (policy == address(0)) revert ZeroAddress();
        trustedFeePolicy[policy] = trusted;
        emit FeePolicyTrusted(policy, trusted);
    }

    /// @notice Add or remove a `SafeModuleSetup`-style helper from the trusted allowlist.
    /// @dev    Only helpers in this allowlist may be used as the `to` target of the Safe
    ///         setup delegatecall constructed by `SailKernel.createAccount`.
    /// @param  setup    Address of the module-setup helper contract.
    /// @param  trusted  True to add to allowlist, false to remove.
    function setTrustedModuleSetup(address setup, bool trusted) external onlyTimelock {
        if (setup == address(0)) revert ZeroAddress();
        trustedModuleSetup[setup] = trusted;
        emit ModuleSetupTrusted(setup, trusted);
    }

    /// @notice Add or remove a Safe proxy runtime codehash from the trusted allowlist.
    /// @dev    Used by the kernel to confirm a deployed or self-registering account is a
    ///         genuine Safe proxy rather than attacker bytecode.
    /// @param  codehash The proxy runtime codehash (keccak256 of the proxy's deployed code).
    /// @param  trusted  True to add to allowlist, false to remove.
    function setTrustedSafeProxyCodehash(bytes32 codehash, bool trusted) external onlyTimelock {
        if (codehash == bytes32(0)) revert ZeroCodehash();
        trustedSafeProxyCodehash[codehash] = trusted;
        emit SafeProxyCodehashTrusted(codehash, trusted);
    }

    /// @notice One-time genesis seeding of the onboarding allowlists, callable by the initial
    ///         governance address WITHOUT the 48-hour timelock — and only before any other
    ///         allowlist entry has been set.
    /// @dev    The `trusted*` setters are `onlyTimelock` so that every change during normal
    ///         operation is delayed and publicly visible. That delay serves no purpose at
    ///         genesis: the deployer already chooses the entire bytecode and initial config, so
    ///         seeding the canonical Safe v1.4.1 factory/singleton/module-setup, the deployed fee
    ///         policy, and the SafeProxy codehash within the deployment transaction grants no
    ///         capability the deployer did not already hold. This function therefore bypasses the
    ///         timelock exactly once: `allowlistBootstrapped` latches true on first call, after
    ///         which it always reverts and EVERY further allowlist change must go through the
    ///         48-hour timelock. Intended to be invoked from the deploy script in the same
    ///         broadcast as the core deployment, while `governance` is still the deployer.
    /// @param  safeFactories        Safe proxy factories to trust (e.g. Safe v1.4.1 ProxyFactory).
    /// @param  safeSingletons       Safe singletons (implementations) to trust.
    /// @param  moduleSetups         `SafeModuleSetup`-style helpers to trust (the Sail SafeModuleEnabler).
    /// @param  feePolicies          Fee policy contracts to trust (the deployed StandardFeePolicy).
    /// @param  safeProxyCodehashes  SafeProxy runtime codehashes to trust.
    function bootstrapAllowlists(
        address[] calldata safeFactories,
        address[] calldata safeSingletons,
        address[] calldata moduleSetups,
        address[] calldata feePolicies,
        bytes32[] calldata safeProxyCodehashes
    ) external onlyGovernance {
        if (allowlistBootstrapped) revert AlreadyBootstrapped();
        allowlistBootstrapped = true;

        for (uint256 i; i < safeFactories.length; ++i) {
            address factory = safeFactories[i];
            if (factory == address(0)) revert ZeroAddress();
            trustedSafeFactory[factory] = true;
            emit SafeFactoryTrusted(factory, true);
        }
        for (uint256 i; i < safeSingletons.length; ++i) {
            address singleton = safeSingletons[i];
            if (singleton == address(0)) revert ZeroAddress();
            trustedSafeSingleton[singleton] = true;
            emit SafeSingletonTrusted(singleton, true);
        }
        for (uint256 i; i < moduleSetups.length; ++i) {
            address setup = moduleSetups[i];
            if (setup == address(0)) revert ZeroAddress();
            trustedModuleSetup[setup] = true;
            emit ModuleSetupTrusted(setup, true);
        }
        for (uint256 i; i < feePolicies.length; ++i) {
            address policy = feePolicies[i];
            if (policy == address(0)) revert ZeroAddress();
            trustedFeePolicy[policy] = true;
            emit FeePolicyTrusted(policy, true);
        }
        for (uint256 i; i < safeProxyCodehashes.length; ++i) {
            bytes32 codehash = safeProxyCodehashes[i];
            if (codehash == bytes32(0)) revert ZeroCodehash();
            trustedSafeProxyCodehash[codehash] = true;
            emit SafeProxyCodehashTrusted(codehash, true);
        }

        emit AllowlistBootstrapped(msg.sender);
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

    /// @dev Thrown by `bootstrapAllowlists` when a supplied SafeProxy codehash is zero.
    error ZeroCodehash();

    /// @dev Thrown by `bootstrapAllowlists` after the one-time genesis seeding has already run.
    ///      All subsequent allowlist changes must go through the 48-hour timelock.
    error AlreadyBootstrapped();

    /// @dev Thrown by `proposeGovernance` when the candidate is the current governance address.
    error SameAddress();

    /// @dev Thrown by `acceptGovernance` when the candidate does not yet hold PROPOSER_ROLE
    ///      on the timelock. The candidate's three timelock roles must be rotated to it (via
    ///      scheduled timelock self-calls — see `rotateTimelockRoles` NatSpec) before
    ///      `acceptGovernance` can complete, eliminating the window where old governance retains
    ///      timelock keys.
    error RolesNotYetRotated();

    /// @dev Thrown when `pause()` is called before PAUSE_COOLDOWN has elapsed since the last pause.
    error PauseCooldown(uint256 nextAllowed);

    /// @dev Thrown by the constructor when the injected timelock's minimum delay is not exactly
    ///      REQUIRED_TIMELOCK_DELAY (48 hours). An exact match — not a lower bound — is required so
    ///      the injected timelock reproduces the specified inline timelock's behaviour precisely.
    error TimelockDelayMismatch();

    /// @dev Thrown by the constructor when `initialGovernance` does not hold PROPOSER_ROLE on the
    ///      injected timelock. The inline timelock granted `initialGovernance` the proposer role by
    ///      construction; an injected timelock must do the same or governance could not schedule
    ///      any parameter change.
    error GovernanceNotProposer();

    /// @dev Thrown by the constructor when `initialGovernance` does not hold EXECUTOR_ROLE on the
    ///      injected timelock. The inline timelock made `initialGovernance` the sole executor. An
    ///      injected timelock that omits this (e.g. `address(0)` as executor, OZ's "open executor"
    ///      mode where anyone may execute after the delay) deviates from the intended model and is
    ///      rejected.
    error GovernanceNotExecutor();

    /// @dev Thrown by the constructor when the injected timelock is not self-administered — i.e. the
    ///      timelock does not hold the admin role over its own PROPOSER_ROLE, OR `initialGovernance`
    ///      holds that admin role. The inline timelock was deployed with `admin == address(0)`, so
    ///      only the timelock holds its own admin role and every role change must pass through the
    ///      48-hour timelock. A timelock where the governance EOA holds the admin role could re-grant
    ///      roles or alter the delay outside the timelock process, so it is rejected.
    ///      See the constructor NatSpec for the detection limitation.
    error TimelockNotSelfAdministered();

    /// @dev Thrown by `pause`/`unpause` when msg.data is not the exact selector-only length (4).
    ///      Both are zero-argument; a Safe FallbackManager relay appends the caller's 20 bytes, so
    ///      any length other than 4 flags a fallback-relayed call (which a relay can never shrink
    ///      back to 4, since the relayed payload is at least selector + 20 bytes).
    error UnexpectedCalldataLength();

    /// @dev Thrown by `rotateTimelockRoles`, which is non-functional under a self-administered
    ///      timelock: the inner grant/revoke calls are made by this contract, but only the timelock
    ///      holds DEFAULT_ADMIN_ROLE over the roles. Roles are rotated by scheduling timelock
    ///      self-calls instead — see the function NatSpec.
    error TimelockMustSelfAdministerRoles();

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

    /// @notice The exact timelock delay this contract requires (48 hours).
    /// @dev    The TimelockController is now deployed separately and injected via the
    ///         constructor (see `_timelock` below). To preserve the intended governance
    ///         behaviour byte-for-byte, the constructor REQUIRES the injected timelock to
    ///         have a minimum delay of exactly this value — not merely at least this value.
    ///         An exact match prevents a misconfigured timelock (faster OR slower) from
    ///         silently weakening or altering the 48-hour guarantee that the rest of the
    ///         protocol's security analysis assumes.
    uint256 public constant REQUIRED_TIMELOCK_DELAY = 48 hours;

    /// @notice Deploy the governance contract.
    /// @dev    The `TimelockController` is deployed SEPARATELY and injected here, rather than
    ///         constructed inline. This makes every SailGovernance constructor argument identical
    ///         across chains (the timelock is itself deployed deterministically via CREATE2 with a
    ///         global salt and chain-independent constructor args), which yields an identical
    ///         SailGovernance address — and therefore an identical kernel / Safe-initializer /
    ///         SMA address — on every chain. The injected timelock MUST be configured exactly as
    ///         the previously-inlined timelock was: a 48-hour minimum delay, `initialGovernance`
    ///         as the sole proposer/executor/canceller, and no external admin (self-administered).
    ///         The constructor validates the injected timelock for ALL of the following and reverts
    ///         if any differs:
    ///           • non-zero address (`ZeroAddress`),
    ///           • minimum delay of exactly REQUIRED_TIMELOCK_DELAY / 48 hours (`TimelockDelayMismatch`),
    ///           • `initialGovernance` holds PROPOSER_ROLE (`GovernanceNotProposer`),
    ///           • `initialGovernance` holds EXECUTOR_ROLE (`GovernanceNotExecutor`),
    ///           • the timelock self-administers its roles — the admin role of PROPOSER_ROLE is held
    ///             by the timelock itself AND is NOT held by `initialGovernance`
    ///             (`TimelockNotSelfAdministered`).
    ///
    ///         Self-administration detection limitation: a real OpenZeppelin `TimelockController` ALWAYS self-grants
    ///         `DEFAULT_ADMIN_ROLE` to itself in its constructor, so the "timelock holds its own admin
    ///         role" half of the check is a no-op for genuine timelocks. The operative half rejects
    ///         the realistic misconfiguration — deploying the timelock with `admin == initialGovernance`
    ///         (the governance EOA holding timelock admin). Because `TimelockController` is not
    ///         `AccessControlEnumerable`, neither this constructor nor the deploy-script assertion can
    ///         detect an arbitrary UNRELATED EOA admin (one this contract has no reference to); both
    ///         can only check known addresses. This is an accepted, documented limitation.
    /// @param  initialGovernance                Address to hold initial governance rights. MUST also be
    ///                                          the sole proposer AND executor configured on `_timelock`.
    /// @param  maxPermissionFeeWei              Constitutional ceiling for the per-permission registration fee.
    /// @param  _emergencyAdmin                  Address that can pause the kernel without a timelock delay.
    /// @param  initialPermissionRegistrationFee Initial flat permission-registration fee in wei.
    ///                                          Must not exceed maxPermissionFeeWei. Pass 0 to leave
    ///                                          registration free until governance raises it via the
    ///                                          48-hour timelock.
    /// @param  _timelock                        Pre-deployed TimelockController enforcing the 48-hour
    ///                                          delay on all parameter changes. Must have a minimum
    ///                                          delay of exactly REQUIRED_TIMELOCK_DELAY (48 hours),
    ///                                          grant PROPOSER_ROLE and EXECUTOR_ROLE to
    ///                                          `initialGovernance`, and self-administer its roles
    ///                                          (admin == address(0) at deployment).
    constructor(
        address initialGovernance,
        uint256 maxPermissionFeeWei,
        address _emergencyAdmin,
        uint256 initialPermissionRegistrationFee,
        TimelockController _timelock
    ) {
        if (initialGovernance == address(0) || _emergencyAdmin == address(0)) revert ZeroAddress();
        if (address(_timelock) == address(0)) revert ZeroAddress();
        if (maxPermissionFeeWei              > 0.01 ether)              revert FeeExceedsCap(maxPermissionFeeWei,             0.01 ether);
        if (initialPermissionRegistrationFee > maxPermissionFeeWei) revert FeeExceedsCap(initialPermissionRegistrationFee, maxPermissionFeeWei);

        // Preserve the intended timelock behaviour exactly. The TimelockController used to be
        // built inline as `new TimelockController(48 hours, [initialGovernance], [initialGovernance],
        // address(0))`. Now that it is injected, enforce every invariant the inline call guaranteed
        // by construction:
        //   • the minimum delay is EXACTLY 48 hours (not just "at least"),
        //   • `initialGovernance` holds PROPOSER_ROLE (it was the sole proposer inline),
        //   • `initialGovernance` holds EXECUTOR_ROLE (it was the sole executor inline — rejecting
        //     an injected timelock with an open/foreign executor), and
        //   • the timelock self-administers its roles, i.e. the admin role of PROPOSER_ROLE is held
        //     by the timelock itself and not by any EOA (the inline timelock used admin=address(0)).
        //     A self-administered timelock cannot re-grant roles or change the
        //     delay outside the 48-hour process, so these checks cannot be satisfied by a timelock
        //     that later weakens its own guarantees without a public, delayed operation.
        if (_timelock.getMinDelay() != REQUIRED_TIMELOCK_DELAY) revert TimelockDelayMismatch();
        if (!_timelock.hasRole(_timelock.PROPOSER_ROLE(), initialGovernance)) revert GovernanceNotProposer();
        if (!_timelock.hasRole(_timelock.EXECUTOR_ROLE(), initialGovernance)) revert GovernanceNotExecutor();
        // Self-administration: the timelock must hold the admin role over its own PROPOSER_ROLE, and
        // the governance EOA must NOT hold that admin role. NOTE: a real OZ TimelockController ALWAYS
        // self-grants DEFAULT_ADMIN_ROLE to itself, so the first check alone is a no-op for genuine
        // timelocks — the operative check is the second, which rejects the realistic misconfiguration
        // of deploying the timelock with `admin == initialGovernance`. See the constructor NatSpec for
        // the limitation (an arbitrary unrelated EOA admin cannot be detected without enumeration).
        bytes32 proposerAdminRole = _timelock.getRoleAdmin(_timelock.PROPOSER_ROLE());
        if (!_timelock.hasRole(proposerAdminRole, address(_timelock))) revert TimelockNotSelfAdministered();
        if (_timelock.hasRole(proposerAdminRole, initialGovernance))   revert TimelockNotSelfAdministered();

        governance                = initialGovernance;
        emergencyAdmin            = _emergencyAdmin;
        MAX_PERMISSION_FEE_WEI    = maxPermissionFeeWei;
        permissionRegistrationFee = initialPermissionRegistrationFee;
        maxPermissionsPerAccount  = 20;

        timelock = _timelock;

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
    ///         rotate the three timelock roles (`PROPOSER_ROLE` / `EXECUTOR_ROLE` /
    ///         `CANCELLER_ROLE`) to the candidate by scheduling timelock SELF-calls (target ==
    ///         the timelock), since only the timelock holds `DEFAULT_ADMIN_ROLE` over its own
    ///         roles. Failure to do so leaves the new governance unable to enact any timelocked
    ///         parameter changes.
    ///
    ///         Recommended sequence:
    ///           1. Current governance calls `proposeGovernance(candidate)`.
    ///           2. Current governance schedules timelock self-calls (48-hour delay) that grant
    ///              the three roles to the candidate and revoke them from the outgoing governance.
    ///           3. After 48 hours, current governance executes those self-calls.
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
    ///         Requires that the candidate's timelock roles have already been rotated (via the
    ///         scheduled timelock self-calls) — i.e., the candidate already holds PROPOSER_ROLE
    ///         on the timelock. This eliminates the window where old governance retains timelock
    ///         scheduling rights after handoff.
    function acceptGovernance() external {
        if (msg.sender != pendingGovernance) revert NotPendingGovernance();
        // Enforce that rotateTimelockRoles was called before acceptGovernance, preventing
        // a governance handoff window where the old governance still holds timelock roles.
        // All THREE roles that rotateTimelockRoles grants must be present on the candidate, so the
        // handoff cannot complete into a split-control state (e.g. candidate holds PROPOSER but the
        // outgoing governance retains EXECUTOR/CANCELLER and can cancel everything the new one queues).
        if (!timelock.hasRole(timelock.PROPOSER_ROLE(),  msg.sender)) revert RolesNotYetRotated();
        if (!timelock.hasRole(timelock.EXECUTOR_ROLE(),  msg.sender)) revert RolesNotYetRotated();
        if (!timelock.hasRole(timelock.CANCELLER_ROLE(), msg.sender)) revert RolesNotYetRotated();
        address previous  = governance;
        governance        = pendingGovernance;
        pendingGovernance = address(0);
        emit GovernanceTransferred(previous, governance);
    }

    /// @notice Non-functional under a self-administered timelock; always reverts. Retained only to
    ///         document the correct role-rotation procedure.
    /// @dev    The timelock holds its own DEFAULT_ADMIN_ROLE (admin == address(0) in its
    ///         constructor), so AccessControl permits role changes only when the CALLER is the
    ///         timelock. This function's inner grant/revoke calls would be made by this contract,
    ///         which does not hold that admin role — so they revert. Rather than expose a helper
    ///         that fails at handoff time, it reverts immediately.
    ///
    ///         CORRECT HANDOFF: schedule timelock SELF-calls (target == address(timelock)) that
    ///         grant PROPOSER_ROLE / EXECUTOR_ROLE / CANCELLER_ROLE to the incoming governor and
    ///         revoke them from the outgoing one; once the candidate holds all three, it calls
    ///         `acceptGovernance()`.
    function rotateTimelockRoles(address, address) external view onlyTimelock {
        revert TimelockMustSelfAdministerRoles();
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
    /// @dev    Bounds registry size only. Under selective authorization each dispatch evaluates a
    ///         single named permission under PERMISSION_GAS_CAP, so raising this limit does NOT raise
    ///         per-dispatch gas cost; it caps how many permissions an account can attach.
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
        // Reject fallback-relayed calls: pause() is zero-argument, so a direct call is exactly the
        // 4-byte selector. A Safe fallback relay appends the caller's 20 bytes (>= 24 total), which
        // can never equal 4 — so this guard cannot be bypassed by sizing the relayed payload.
        if (msg.data.length != 4) revert UnexpectedCalldataLength();
        if (lastPauseTimestamp != 0 && block.timestamp < lastPauseTimestamp + PAUSE_COOLDOWN)
            revert PauseCooldown(lastPauseTimestamp + PAUSE_COOLDOWN);
        lastPauseTimestamp = block.timestamp;
        pauseExpiry = block.timestamp + 72 hours;
        emit Paused(pauseExpiry);
    }

    /// @notice Lift the pause early.
    /// @dev    `lastPauseTimestamp` is intentionally NOT reset here. The PAUSE_COOLDOWN is measured
    ///         from the start of the most recent pause regardless of an intervening early unpause, so
    ///         a (compromised) emergency admin cannot defeat the cooldown by pausing → unpausing →
    ///         re-pausing in a tight loop. Trade-off: after an early unpause the admin must wait out
    ///         the remaining cooldown before it can pause again; recovery paths (`setManager`, the
    ///         revoke* family) are pause-exempt regardless, so this never blocks owner recovery.
    function unpause() external onlyEmergencyAdmin {
        // Reject fallback-relayed calls (see pause()): unpause() is zero-argument, so a direct call
        // is exactly the 4-byte selector and a relay (>= 24 bytes) can never match.
        if (msg.data.length != 4) revert UnexpectedCalldataLength();
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
