// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Execution context passed to every permission on each dispatch call.
/// @dev    Permissions receive a snapshot of the transaction environment captured
///         at the moment the kernel invokes them. Fields are read-only (staticcall).
struct Context {
    /// @dev The Safe account whose assets are being moved.
    address account;
    /// @dev The delegated signer who submitted the dispatch request.
    address manager;
    /// @dev msg.sender of the dispatch call; may differ from manager when a relayer is used.
    address submitter;
    /// @dev The call target address.
    address target;
    /// @dev Leading 4 bytes of calldata; bytes4(0) if calldata is shorter than 4 bytes.
    bytes4  selector;
    /// @dev Native ETH forwarded with the call (wei).
    uint256 value;
    /// @dev block.timestamp at dispatch time — available for time-based gates.
    uint256 blockTimestamp;
    /// @dev block.number at dispatch time.
    uint256 blockNumber;
    /// @dev The kernel's current per-(account, permission) registration epoch, pushed by the
    ///      kernel at dispatch time. Configurable permissions compare it against the epoch they
    ///      stamped at configure() time and fail closed on a mismatch, so a configuration left
    ///      over from a prior registration (e.g. after a revoke → re-register cycle) can never be
    ///      honoured. Not part of any signed digest — purely a read-only freshness tag.
    uint256 configEpoch;
}

/// @title  IPermission
/// @notice Interface every Sail permission contract must implement.
/// @dev    Permissions are evaluated via staticcall with a fixed gas cap
///         (`SailKernel.PERMISSION_GAS_CAP`). A revert or gas exhaustion is treated
///         as `false` by the kernel. Permissions must never modify state (enforced by
///         staticcall), but they may read arbitrary on-chain state within the gas budget.
/// @dev    Templates MAY also implement IBatchPermission to declare whole-batch
///         validation for kernel batch dispatch.
/// @dev    Templates MAY implement IAgentIdentityResolver or
///         IAccountAgentIdentityResolver to expose the agent identity associated
///         with the manager or strategy. This is metadata only — the kernel never
///         reads or verifies agent identity.
interface IPermission {
    /// @notice Decide whether a manager-submitted transaction is permitted.
    /// @dev    Called by the kernel during dispatch to evaluate the named permission.
    ///         In `dispatch`, the manager names ONE specific registered permission to evaluate
    ///         the call. Other permissions on the account are not consulted.
    /// @param  txData  Raw calldata of the transaction being dispatched.
    /// @param  ctx     Execution context snapshot (see Context struct above).
    /// @return         True if the transaction is permitted; false to block it.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool);

    /// @notice Optional stable identifier for fast off-chain indexing and deduplication.
    /// @dev    Permissions with a fixed structure (selector + target + asset) should return
    ///         a non-zero value, typically `keccak256("<ContractName>")`. Complex or
    ///         multi-purpose permissions may return `bytes32(0)`.
    /// @return A stable identifier for this permission type, or bytes32(0) if not applicable.
    function discriminator() external view returns (bytes32);
}
