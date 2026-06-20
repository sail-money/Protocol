// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @title  SailCapabilities
/// @notice Canonical capability identifiers for the Sail template set.
///
/// @dev    Each constant is a keccak256 hash encoding a unique, versioned capability name.
///         These IDs are stable — they MUST NOT change meaning after publication.
///         For breaking changes to a capability's semantics, introduce a new constant
///         with a bumped version suffix (e.g. "sail.capability.bounded-swap.v2").
///
/// @dev    Third parties may define their own capability IDs following the same convention:
///             keccak256("sail.capability.<name>.v<n>")
///         Capability IDs from different namespaces can coexist because the hash space
///         is sufficiently collision-resistant for practical purposes.
///
/// @dev    Every constant in this file corresponds to a live Sail template in
///         contracts/templates/shared/. Retire constants (by NatSpec deprecation) only
///         when the corresponding template is permanently removed from the protocol.
library SailCapabilities {
    /// @notice Capability declared by SharedBoundedSwapPermission.
    ///         Gates token-swap operations with amount caps, slippage bounds, and oracle checks.
    bytes32 internal constant BOUNDED_SWAP =
        keccak256("sail.capability.bounded-swap.v1");

    /// @notice Capability declared by SharedBoundedBorrowPermission.
    ///         Gates borrow operations on Aave V3, Morpho, and Compound with LTV enforcement.
    bytes32 internal constant BOUNDED_BORROW =
        keccak256("sail.capability.bounded-borrow.v1");

    /// @notice Capability declared by SharedTransferTargetPermission.
    ///         Gates ERC-20 transfer / transferFrom to an allowlisted set of recipients.
    bytes32 internal constant TRANSFER_TARGET =
        keccak256("sail.capability.transfer-target.v1");

    /// @notice Capability declared by SharedDeFiBundlePermission.
    ///         Gates swap, borrow, and transfer operations through a single composite permission.
    bytes32 internal constant DEFI_BUNDLE =
        keccak256("sail.capability.defi-bundle.v1");

    /// @notice Capability declared by SharedPendlePermission.
    ///         Gates Pendle V2 Router V4 operations: liquidity, PT/YT swaps, mint/redeem, yield claim.
    bytes32 internal constant PENDLE_YIELD =
        keccak256("sail.capability.pendle-yield.v1");

    /// @notice Capability declared by SharedAMMLiquidityPermission.
    ///         Gates AMM liquidity operations on Uniswap V3, Aerodrome Slipstream, and Aerodrome Router.
    bytes32 internal constant AMM_LIQUIDITY =
        keccak256("sail.capability.amm-liquidity.v1");

    /// @notice Capability declared by SharedApproveAndCallBatchPermission.
    ///         Authorises kernel-native batch dispatch using the approve/consume/reset pattern.
    bytes32 internal constant BATCH_DISPATCH =
        keccak256("sail.capability.batch-dispatch.v1");

    /// @notice Capability declared by DepositPermission.
    ///         Gates ERC-4626 / Aave-style deposits, pinning the receiver to the account
    ///         with target + token allowlists and a per-tx amount cap.
    bytes32 internal constant DEPOSIT =
        keccak256("sail.capability.deposit.v1");

    /// @notice Capability declared by WithdrawPermission.
    ///         Gates ERC-20 transfer / transferFrom so funds only reach the account's
    ///         configured recipient, within a per-tx amount cap.
    bytes32 internal constant WITHDRAW =
        keccak256("sail.capability.withdraw.v1");

    /// @dev Declared by templates that implement IAgentIdentityResolver or
    ///      IAccountAgentIdentityResolver. Signals to consumers that this template
    ///      can surface agent identity metadata for off-chain discovery and indexing.
    ///      Presence of this capability does NOT imply any on-chain identity enforcement
    ///      — check the template's evaluate() logic for that.
    bytes32 internal constant AGENT_IDENTITY =
        keccak256("sail.capability.agent-identity.v1");
}
