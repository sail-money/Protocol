// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  IFeePolicy
/// @notice Interface for on-chain fee computation and state recording in the Sail protocol.
/// @dev    Implementations receive a manager-supplied `currentNav` value.
///         TRUST ASSUMPTION: NAV is not verified on-chain. Deployers must use a policy
///         that either validates NAV through an oracle or accepts the manager's word.
///         The kernel enforces `grossFee <= maxFee` where `maxFee` is returned by
///         `computeFee`; this bounds extraction to what the policy authorises.
interface IFeePolicy {
    /// @notice Return the address that receives the manager's net fee share.
    /// @dev    The kernel calls this to determine the fee recipient, ignoring any
    ///         caller-supplied address. Prevents a compromised manager from redirecting
    ///         fees to an arbitrary address.
    /// @return The pre-approved recipient address for manager fee proceeds.
    function feeRecipient() external view returns (address);

    /// @notice Compute the maximum collectable fee for an account at a given NAV.
    /// @dev    Pure computation — must not modify state. Called by the kernel before
    ///         transferring funds to enforce the fee ceiling. If `lastCollectionTimestamp`
    ///         is unset (first call), implementations should return `(0, ...)`.
    /// @param  account    The Safe account whose fees are being calculated.
    /// @param  currentNav Current net asset value, expressed in the same unit as fee token.
    ///                    Provided by the manager — not independently verified on-chain.
    /// @return grossFee      Maximum fee that may be collected in this call.
    /// @return distributor   Address to receive the distributor share; address(0) = no split.
    /// @return distributorBps Fraction of the post-protocol-cut remainder sent to `distributor`,
    ///                        expressed in basis points (10 000 = 100%).
    function computeFee(address account, uint256 currentNav)
        external
        view
        returns (uint256 grossFee, address distributor, uint256 distributorBps);

    /// @notice Persist state after a successful fee collection (e.g., update HWM, timestamp).
    /// @dev    Only the kernel should call this. Implementations may revert to enforce
    ///         preconditions (e.g., non-zero initial NAV).
    /// @param  account    The Safe account for which fees were collected.
    /// @param  grossFee   Actual fee amount collected in this call.
    /// @param  currentNav NAV reported by the manager at collection time.
    function recordCollection(address account, uint256 grossFee, uint256 currentNav) external;
}
