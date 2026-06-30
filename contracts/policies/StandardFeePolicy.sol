// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IFeePolicy} from "../interfaces/IFeePolicy.sol";
import {Math}       from "@openzeppelin/contracts/utils/math/Math.sol";

/// @title  StandardFeePolicy
/// @notice Classic 2-and-20 fee schedule: an annual management fee on AUM plus
///         a performance fee on profits above a per-account high-water mark.
///
///         Fee formula (per collection call):
///           managementFee = currentNav × managementFeeBps × elapsed
///                           ─────────────────────────────────────────
///                                 365 days × 10 000
///
///           performanceFee = max(currentNav − HWM, 0) × performanceFeeBps
///                            ─────────────────────────────────────────────
///                                          10 000
///
///           grossFee = managementFee + performanceFee
///
///         After each collection the high-water mark is updated to max(HWM, currentNav),
///         ensuring performance fees are only charged on new all-time highs.
///
/// @dev    NAV is provided by the manager — it is not independently verified on-chain.
///         The HWM seeding guard (`HWMNotSeeded`) prevents a manager from
///         claiming a performance fee on the full portfolio on the very first collection
///         by seeding HWM at 0.
/// @custom:security-contact hello@sail.money
contract StandardFeePolicy is IFeePolicy {
    // -------------------------------------------------------------------------
    // Constants
    // -------------------------------------------------------------------------

    /// @dev Minimum time between fee collections for a given account.
    ///      Prevents management fee timer resets via rapid zero-fee calls that could
    ///      manipulate the elapsed time used in the management fee calculation.
    uint256 public constant MIN_COLLECTION_INTERVAL = 1 days;

    /// @dev Hard cap on the management fee rate (10% per year).
    uint256 private constant MAX_MANAGEMENT_FEE_BPS  = 1_000;
    /// @dev Hard cap on the performance fee rate (50%).
    uint256 private constant MAX_PERFORMANCE_FEE_BPS = 5_000;
    /// @dev Hard cap on the distributor's share of the manager's net fee (100%).
    uint256 private constant MAX_DISTRIBUTOR_BPS     = 10_000;
    /// @dev Denominator for basis-point arithmetic.
    uint256 private constant BASIS_POINTS            = 10_000;
    /// @dev Seconds in a 365-day year, used in the management fee formula.
    uint256 private constant SECONDS_PER_YEAR        = 365 days;

    // -------------------------------------------------------------------------
    // Mutable parameters — adjustable by feeManager
    // -------------------------------------------------------------------------

    /// @notice Annual management fee rate in basis points. Max 1 000 (10%).
    uint256 public managementFeeBps;

    /// @notice Performance fee rate on profits above HWM, in basis points. Max 5 000 (50%).
    uint256 public performanceFeeBps;

    /// @notice Address that receives the distributor share of the manager's net fee.
    ///         address(0) means no distributor split.
    address public distributor;

    /// @notice Fraction of the manager's net fee sent to `distributor`, in basis points.
    uint256 public distributorBps;

    // -------------------------------------------------------------------------
    // Access control
    // -------------------------------------------------------------------------

    /// @notice The kernel contract that may call `recordCollection`.
    address public immutable kernel;

    /// @notice Address authorised to update fee parameters and transfer management.
    address public feeManager;

    /// @notice Pending successor nominated by `proposeFeeManager`. Zero = no transfer in flight.
    address public pendingFeeManager;

    // -------------------------------------------------------------------------
    // Per-account state
    // -------------------------------------------------------------------------

    /// @notice Per-account high-water mark: the highest NAV seen at collection time.
    ///         Performance fees are only charged on gains above this level.
    mapping(address account => uint256) public highWaterMark;

    /// @notice Timestamp of the last fee collection for each account.
    ///         Zero means the account has not been initialised yet.
    mapping(address account => uint256) public lastCollectionTimestamp;

    /// @notice Whether the HWM has been explicitly seeded for an account by the feeManager.
    ///         Prevents the manager from seeding HWM at 0 via a zero-fee first collection.
    mapping(address account => bool) public hwmSeeded;

    /// @notice Per-account applied management fee rate snapshot (updated at end of each collection).
    ///         Prevents retroactive repricing: rate changes only take effect prospectively.
    mapping(address account => uint256) public appliedManagementFeeBps;

    /// @notice Per-account applied performance fee rate snapshot (updated at end of each collection).
    ///         Prevents retroactive repricing: rate changes only take effect prospectively.
    mapping(address account => uint256) public appliedPerformanceFeeBps;

    /// @notice Set by `onAttach` when a previously-seeded account reattaches this instance, cleared
    ///         on the next `recordCollection`. While true, the first post-reattach collection charges
    ///         no performance fee and re-bases the HWM to the reattachment NAV — so no fee is billed
    ///         on gains booked while the policy was detached. (Management fees are already re-anchored
    ///         by `onAttach` resetting `lastCollectionTimestamp`.)
    mapping(address account => bool) public pendingReanchor;

    // -------------------------------------------------------------------------
    // Events
    // -------------------------------------------------------------------------

    /// @notice Emitted when the management fee rate is updated.
    /// @param  oldBps Previous rate in basis points.
    /// @param  newBps New rate in basis points.
    event ManagementFeeUpdated(uint256 oldBps, uint256 newBps);

    /// @notice Emitted when the performance fee rate is updated.
    /// @param  oldBps Previous rate in basis points.
    /// @param  newBps New rate in basis points.
    event PerformanceFeeUpdated(uint256 oldBps, uint256 newBps);

    /// @notice Emitted when the distributor address is updated.
    /// @param  oldDistributor Previous distributor address.
    /// @param  newDistributor New distributor address.
    event DistributorUpdated(address oldDistributor, address newDistributor);

    /// @notice Emitted when the distributor's fee share is updated.
    /// @param  oldBps Previous share in basis points.
    /// @param  newBps New share in basis points.
    event DistributorBpsUpdated(uint256 oldBps, uint256 newBps);

    /// @notice Emitted when a fee manager transfer is proposed (step 1).
    /// @param  currentFeeManager  The current fee manager who proposed the transfer.
    /// @param  proposedFeeManager The address nominated as successor.
    event FeeManagerProposed(address indexed currentFeeManager, address indexed proposedFeeManager);

    /// @notice Emitted when fee manager control is finalised (step 2 — accepted by pending).
    /// @param  oldFeeManager Previous fee manager address.
    /// @param  newFeeManager New fee manager address.
    event FeeManagerTransferred(address oldFeeManager, address newFeeManager);

    /// @notice Emitted on each successful fee collection.
    /// @param  account          The Safe account that was charged.
    /// @param  grossFee         Total fee collected (in fee-token units).
    /// @param  currentNav       NAV reported by the manager at collection time.
    /// @param  newHighWaterMark Updated HWM after this collection.
    event FeesCollected(address indexed account, uint256 grossFee, uint256 currentNav, uint256 newHighWaterMark);

    /// @notice Emitted when the HWM is explicitly seeded for an account.
    /// @param  account    The Safe account.
    /// @param  initialNav The initial NAV used to seed the HWM.
    event HWMSeeded(address indexed account, uint256 initialNav);

    // -------------------------------------------------------------------------
    // Errors
    // -------------------------------------------------------------------------

    /// @dev Thrown when a caller other than `kernel` invokes a kernel-only function.
    error NotKernel();

    /// @dev Thrown when a caller other than `feeManager` invokes a fee-manager-only function.
    error NotFeeManager();

    /// @dev Thrown when a required address argument is the zero address.
    error ZeroAddress();

    /// @dev Thrown by `acceptFeeManager` when caller is not `pendingFeeManager`.
    error NotPendingFeeManager();

    /// @dev Thrown when `recordCollection` is called before `seedHighWaterMark` has been called.
    error HWMNotSeeded();

    /// @dev Thrown when `seedHighWaterMark` is called for an account that already has a seeded HWM.
    error AlreadySeeded();

    /// @dev Thrown when `recordCollection` is called before MIN_COLLECTION_INTERVAL has
    ///      elapsed since the last collection. Prevents fee timer manipulation via rapid calls.
    error CollectionTooFrequent();

    /// @dev Thrown when a requested `managementFeeBps` exceeds MAX_MANAGEMENT_FEE_BPS.
    error ManagementFeeTooHigh(uint256 bps);

    /// @dev Thrown when a requested `performanceFeeBps` exceeds MAX_PERFORMANCE_FEE_BPS.
    error PerformanceFeeTooHigh(uint256 bps);

    /// @dev Thrown when a requested `distributorBps` exceeds MAX_DISTRIBUTOR_BPS.
    error DistributorBpsTooLarge(uint256 bps);

    // -------------------------------------------------------------------------
    // Modifiers
    // -------------------------------------------------------------------------

    /// @dev Reverts with NotKernel when caller is not the registered kernel address.
    modifier onlyKernel() {
        if (msg.sender != kernel) revert NotKernel();
        _;
    }

    /// @dev Reverts with NotFeeManager when caller is not the current feeManager.
    modifier onlyFeeManager() {
        if (msg.sender != feeManager) revert NotFeeManager();
        _;
    }

    // -------------------------------------------------------------------------
    // Constructor
    // -------------------------------------------------------------------------

    /// @notice Deploy a StandardFeePolicy with the given fee schedule and access control.
    /// @param  _managementFeeBps  Annual management fee in basis points. Max 1 000 (10%).
    /// @param  _performanceFeeBps Performance fee in basis points. Max 5 000 (50%).
    /// @param  _distributor       Initial distributor address; address(0) = no split.
    /// @param  _distributorBps    Distributor's share of manager's net fee in basis points.
    /// @param  _kernel            Kernel contract permitted to call `recordCollection`.
    /// @param  _feeManager        Address permitted to update fee parameters.
    constructor(
        uint256 _managementFeeBps,
        uint256 _performanceFeeBps,
        address _distributor,
        uint256 _distributorBps,
        address _kernel,
        address _feeManager
    ) {
        if (_kernel     == address(0)) revert ZeroAddress();
        if (_feeManager == address(0)) revert ZeroAddress();
        if (_managementFeeBps  > MAX_MANAGEMENT_FEE_BPS)  revert ManagementFeeTooHigh(_managementFeeBps);
        if (_performanceFeeBps > MAX_PERFORMANCE_FEE_BPS) revert PerformanceFeeTooHigh(_performanceFeeBps);
        if (_distributorBps    > MAX_DISTRIBUTOR_BPS)     revert DistributorBpsTooLarge(_distributorBps);

        managementFeeBps  = _managementFeeBps;
        performanceFeeBps = _performanceFeeBps;
        distributor       = _distributor;
        distributorBps    = _distributorBps;
        kernel            = _kernel;
        feeManager        = _feeManager;
    }

    // -------------------------------------------------------------------------
    // IFeePolicy
    // -------------------------------------------------------------------------

    /// @dev NAV TRUST MODEL: Management and performance fees are computed from
    ///      manager-supplied `currentNav`. The manager controls collection timing
    ///      and NAV reporting. This is an intentional design choice — the manager
    ///      bears responsibility for honest NAV attestation. See whitepaper §8.2.
    ///      Strategies requiring trustless fee computation should use an
    ///      oracle-backed fee policy rather than this reference implementation.
    /// @inheritdoc IFeePolicy
    function computeFee(address account, uint256 currentNav)
        external view
        returns (uint256 grossFee, address _distributor, uint256 _distributorBps)
    {
        _distributor    = distributor;
        _distributorBps = distributorBps;

        // Uninitialised: no fee accrued until the first recordCollection seeds state.
        uint256 lastTs = lastCollectionTimestamp[account];
        if (lastTs == 0) return (0, _distributor, _distributorBps);

        uint256 elapsed = block.timestamp - lastTs;

        uint256 managementFee = Math.mulDiv(
            currentNav,
            appliedManagementFeeBps[account] * elapsed,
            SECONDS_PER_YEAR * BASIS_POINTS
        );

        // On the first collection after a reattach, charge no performance fee: the HWM is about to be
        // re-anchored to max(priorHWM, currentNav) (see recordCollection), so any gain booked while
        // detached is not billed. Management fee is unaffected — it already accrues only from the
        // re-anchored lastCollectionTimestamp set by onAttach.
        uint256 performanceFee;
        uint256 hwm = highWaterMark[account];
        if (!pendingReanchor[account] && currentNav > hwm) {
            performanceFee = Math.mulDiv(currentNav - hwm, appliedPerformanceFeeBps[account], BASIS_POINTS);
        }

        // During a suppressed reattach window the performance leg is zero by construction; if the
        // management leg is also zero (a 0% management schedule, or a tiny rate that floors to 0 on
        // a small NAV) the gross fee would be zero. The kernel rejects a zero fee (ZeroFee), so no
        // collection could ever settle — and only a settled collection clears the re-anchor latch.
        // Return a minimal fee so a collection can run and clear the latch; thereafter pricing is
        // normal. The elapsed check mirrors recordCollection's MIN_COLLECTION_INTERVAL so the minimal
        // fee is only offered once a collection could actually succeed. Boundary: if the Safe holds no
        // balance of the configured fee asset, even this 1-unit transfer cannot settle and the account
        // stays stuck until it is funded.
        if (pendingReanchor[account] && managementFee == 0 && elapsed >= MIN_COLLECTION_INTERVAL) {
            return (1, _distributor, _distributorBps);
        }

        grossFee = managementFee + performanceFee;
    }

    /// @inheritdoc IFeePolicy
    function recordCollection(address account, uint256 grossFee, uint256 currentNav) external onlyKernel {
        // HWM must be explicitly seeded by feeManager before any collection is allowed.
        // This prevents the manager from seeding HWM at a low value via a first zero-fee
        // collection and subsequently claiming a performance fee on the full portfolio.
        if (!hwmSeeded[account]) revert HWMNotSeeded();

        if (lastCollectionTimestamp[account] == 0) {
            lastCollectionTimestamp[account] = block.timestamp;
            appliedManagementFeeBps[account]  = managementFeeBps;
            appliedPerformanceFeeBps[account] = performanceFeeBps;
            emit FeesCollected(account, grossFee, currentNav, highWaterMark[account]);
            return;
        }

        if (block.timestamp < lastCollectionTimestamp[account] + MIN_COLLECTION_INTERVAL)
            revert CollectionTooFrequent();

        lastCollectionTimestamp[account] = block.timestamp;
        // On the first collection after a reattach, the performance leg is suppressed (see computeFee)
        // and the HWM is re-anchored to max(priorHWM, currentNav) — the same conservative ratchet as a
        // normal collection. We deliberately NEVER lower the mark: re-basing it DOWN (when
        // currentNav < priorHWM) would let a later recovery below the prior all-time high be charged a
        // performance fee — the opposite of this fix's intent. For the gains-while-detached case
        // (currentNav > priorHWM) max picks currentNav, so the dormant gain is still not billed.
        uint256 newHwm = Math.max(highWaterMark[account], currentNav);
        if (pendingReanchor[account]) pendingReanchor[account] = false;
        highWaterMark[account] = newHwm;
        emit FeesCollected(account, grossFee, currentNav, newHwm);
        // Prospective: rate changes apply from the next period forward.
        appliedManagementFeeBps[account]  = managementFeeBps;
        appliedPerformanceFeeBps[account] = performanceFeeBps;
    }

    /// @inheritdoc IFeePolicy
    /// @dev Lifecycle hook: re-anchor an account that already has state on THIS instance (i.e. a
    ///      detach→reattach of the same policy). Resetting `lastCollectionTimestamp` to now stops the
    ///      dormant interval from being billed as management fees, and `pendingReanchor` makes the next
    ///      collection suppress its performance leg and re-anchor the HWM to max(priorHWM, currentNav)
    ///      — the mark is never ratcheted DOWN, so the re-anchor is owner-protective: it can only avoid
    ///      a charge, never create one (it skips a dormant-interval gain, and never lets a later
    ///      recovery below the prior high be billed). A never-seeded account has no anchors to reset —
    ///      the normal first-use path — so onAttach is a no-op for it. The kernel passes only
    ///      `account`; no NAV is involved.
    ///
    ///      The applied-rate snapshots are also refreshed to the current global schedule so the first
    ///      post-reattach window is priced at today's rate, not a rate captured before the detach. This
    ///      is prospective only: the dormant interval is not billed (lastCollectionTimestamp is reset)
    ///      and the performance leg is suppressed for that first window.
    function onAttach(address account) external onlyKernel {
        if (hwmSeeded[account]) {
            lastCollectionTimestamp[account] = block.timestamp;
            pendingReanchor[account]         = true;
            appliedManagementFeeBps[account]  = managementFeeBps;
            appliedPerformanceFeeBps[account] = performanceFeeBps;
        }
    }

    /// @notice Explicitly seed the high-water mark for an account before the first collection.
    /// @dev    Must be called by feeManager before any `recordCollection` call for the account.
    ///         Calling with a meaningful initial NAV prevents a zero-HWM performance fee attack.
    /// @param  account    The Safe account to seed.
    /// @param  initialNav Initial NAV to use as the HWM. Must be non-zero.
    function seedHighWaterMark(address account, uint256 initialNav) external onlyFeeManager {
        if (hwmSeeded[account]) revert AlreadySeeded();
        if (initialNav == 0) revert HWMNotSeeded(); // reuse: signals bad initial state
        hwmSeeded[account]      = true;
        highWaterMark[account]  = initialNav;
        lastCollectionTimestamp[account]  = block.timestamp;
        appliedManagementFeeBps[account]  = managementFeeBps;
        appliedPerformanceFeeBps[account] = performanceFeeBps;
        emit HWMSeeded(account, initialNav);
    }

    /// @inheritdoc IFeePolicy
    function feeRecipient() external view returns (address) {
        return feeManager;
    }

    // -------------------------------------------------------------------------
    // Fee parameter setters
    // -------------------------------------------------------------------------

    /// @notice Update the annual management fee rate.
    /// @param  newBps New rate in basis points. Must not exceed MAX_MANAGEMENT_FEE_BPS (1 000).
    function setManagementFeeBps(uint256 newBps) external onlyFeeManager {
        if (newBps > MAX_MANAGEMENT_FEE_BPS) revert ManagementFeeTooHigh(newBps);
        uint256 old = managementFeeBps;
        managementFeeBps = newBps;
        emit ManagementFeeUpdated(old, newBps);
    }

    /// @notice Update the performance fee rate.
    /// @param  newBps New rate in basis points. Must not exceed MAX_PERFORMANCE_FEE_BPS (5 000).
    function setPerformanceFeeBps(uint256 newBps) external onlyFeeManager {
        if (newBps > MAX_PERFORMANCE_FEE_BPS) revert PerformanceFeeTooHigh(newBps);
        uint256 old = performanceFeeBps;
        performanceFeeBps = newBps;
        emit PerformanceFeeUpdated(old, newBps);
    }

    /// @notice Update the distributor address.
    /// @param  newDistributor New distributor address; address(0) disables the distributor split.
    function setDistributor(address newDistributor) external onlyFeeManager {
        address old = distributor;
        distributor = newDistributor;
        emit DistributorUpdated(old, newDistributor);
    }

    /// @notice Update the distributor's share of the manager's net fee.
    /// @param  newBps New share in basis points. Must not exceed MAX_DISTRIBUTOR_BPS (10 000).
    function setDistributorBps(uint256 newBps) external onlyFeeManager {
        if (newBps > MAX_DISTRIBUTOR_BPS) revert DistributorBpsTooLarge(newBps);
        uint256 old = distributorBps;
        distributorBps = newBps;
        emit DistributorBpsUpdated(old, newBps);
    }

    /// @notice Step 1: propose a new fee manager. Only the current fee manager may call.
    /// @dev    The transfer is only finalised when the candidate calls `acceptFeeManager`.
    ///         Calling again before acceptance overwrites `pendingFeeManager`.
    /// @param  newFeeManager Address being nominated as the next fee manager. Must not be zero.
    function proposeFeeManager(address newFeeManager) external onlyFeeManager {
        if (newFeeManager == address(0)) revert ZeroAddress();
        pendingFeeManager = newFeeManager;
        emit FeeManagerProposed(feeManager, newFeeManager);
    }

    /// @notice Step 2: pending fee manager accepts, completing the transfer.
    /// @dev    Only callable by `pendingFeeManager`. Clears `pendingFeeManager` after transfer.
    function acceptFeeManager() external {
        if (msg.sender != pendingFeeManager) revert NotPendingFeeManager();
        address old = feeManager;
        feeManager = pendingFeeManager;
        pendingFeeManager = address(0);
        emit FeeManagerTransferred(old, feeManager);
    }
}
