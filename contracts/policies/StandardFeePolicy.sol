// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

import {IFeePolicy} from "../interfaces/IFeePolicy.sol";
import {Math} from "@openzeppelin/contracts/utils/math/Math.sol";

/// @notice Classic 2-and-20 fee schedule: annual management fee on AUM plus
///         performance fee on profits above a per-account high-water mark.
contract StandardFeePolicy is IFeePolicy {
    uint256 private constant MAX_MANAGEMENT_FEE_BPS  = 500;   // 5% annual
    uint256 private constant MAX_PERFORMANCE_FEE_BPS = 5_000; // 50%
    uint256 private constant BASIS_POINTS            = 10_000;
    uint256 private constant SECONDS_PER_YEAR        = 365 days;

    // ── mutable parameters ────────────────────────────────────────────────────
    uint256 public managementFeeBps;
    uint256 public performanceFeeBps;
    address public distributor;
    uint256 public distributorBps;

    // ── access control ────────────────────────────────────────────────────────
    address public immutable kernel;
    address public feeManager;

    // ── per-account state ─────────────────────────────────────────────────────
    mapping(address account => uint256) public highWaterMark;
    mapping(address account => uint256) public lastCollectionTimestamp;

    // ── events ────────────────────────────────────────────────────────────────
    event ManagementFeeUpdated(uint256 oldBps, uint256 newBps);
    event PerformanceFeeUpdated(uint256 oldBps, uint256 newBps);
    event DistributorUpdated(address oldDistributor, address newDistributor);
    event DistributorBpsUpdated(uint256 oldBps, uint256 newBps);
    event FeeManagerTransferred(address oldFeeManager, address newFeeManager);
    event FeesCollected(address indexed account, uint256 grossFee, uint256 currentNav, uint256 newHighWaterMark);

    // ── errors ────────────────────────────────────────────────────────────────
    error NotKernel();
    error NotFeeManager();
    error ZeroAddress();
    error ManagementFeeTooHigh(uint256 bps);
    error PerformanceFeeTooHigh(uint256 bps);

    modifier onlyKernel() {
        if (msg.sender != kernel) revert NotKernel();
        _;
    }

    modifier onlyFeeManager() {
        if (msg.sender != feeManager) revert NotFeeManager();
        _;
    }

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

        managementFeeBps  = _managementFeeBps;
        performanceFeeBps = _performanceFeeBps;
        distributor       = _distributor;
        distributorBps    = _distributorBps;
        kernel            = _kernel;
        feeManager        = _feeManager;
    }

    // ── IFeePolicy ────────────────────────────────────────────────────────────

    /// @inheritdoc IFeePolicy
    function computeFee(address account, uint256 currentNav)
        external view
        returns (uint256 grossFee, address _distributor, uint256 _distributorBps)
    {
        _distributor    = distributor;
        _distributorBps = distributorBps;

        // Uninitialised: no fee until first recordCollection seeds the state.
        if (lastCollectionTimestamp[account] == 0) return (0, _distributor, _distributorBps);

        uint256 elapsed = block.timestamp - lastCollectionTimestamp[account];

        // Management fee: pro-rated annual fee on currentNav.
        // grossFee += currentNav × managementFeeBps × elapsed / (365d × 10_000)
        uint256 managementFee = Math.mulDiv(
            currentNav,
            managementFeeBps * elapsed,
            SECONDS_PER_YEAR * BASIS_POINTS
        );

        // Performance fee: charged only on gains above the high-water mark.
        uint256 performanceFee;
        uint256 hwm = highWaterMark[account];
        if (currentNav > hwm) {
            performanceFee = Math.mulDiv(currentNav - hwm, performanceFeeBps, BASIS_POINTS);
        }

        grossFee = managementFee + performanceFee;
    }

    /// @inheritdoc IFeePolicy
    function recordCollection(address account, uint256 grossFee, uint256 currentNav) external onlyKernel {
        // First call: seed state, no event (fee was 0).
        if (lastCollectionTimestamp[account] == 0) {
            highWaterMark[account]            = currentNav;
            lastCollectionTimestamp[account]  = block.timestamp;
            return;
        }

        lastCollectionTimestamp[account] = block.timestamp;
        uint256 newHwm = Math.max(highWaterMark[account], currentNav);
        highWaterMark[account] = newHwm;
        emit FeesCollected(account, grossFee, currentNav, newHwm);
    }

    // ── setters ───────────────────────────────────────────────────────────────

    function setManagementFeeBps(uint256 newBps) external onlyFeeManager {
        if (newBps > MAX_MANAGEMENT_FEE_BPS) revert ManagementFeeTooHigh(newBps);
        uint256 old = managementFeeBps;
        managementFeeBps = newBps;
        emit ManagementFeeUpdated(old, newBps);
    }

    function setPerformanceFeeBps(uint256 newBps) external onlyFeeManager {
        if (newBps > MAX_PERFORMANCE_FEE_BPS) revert PerformanceFeeTooHigh(newBps);
        uint256 old = performanceFeeBps;
        performanceFeeBps = newBps;
        emit PerformanceFeeUpdated(old, newBps);
    }

    function setDistributor(address newDistributor) external onlyFeeManager {
        address old = distributor;
        distributor = newDistributor;
        emit DistributorUpdated(old, newDistributor);
    }

    function setDistributorBps(uint256 newBps) external onlyFeeManager {
        uint256 old = distributorBps;
        distributorBps = newBps;
        emit DistributorBpsUpdated(old, newBps);
    }

    function transferFeeManager(address newFeeManager) external onlyFeeManager {
        if (newFeeManager == address(0)) revert ZeroAddress();
        address old = feeManager;
        feeManager = newFeeManager;
        emit FeeManagerTransferred(old, newFeeManager);
    }
}
