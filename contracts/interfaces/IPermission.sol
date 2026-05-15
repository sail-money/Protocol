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
}

/// @title  IPermission
/// @notice Interface every Sail permission contract must implement.
/// @dev    Permissions are evaluated via staticcall with a fixed gas cap
///         (`SailKernel.PERMISSION_GAS_CAP`). A revert or gas exhaustion is treated
///         as `false` by the kernel. Permissions must never modify state (enforced by
///         staticcall), but they may read arbitrary on-chain state within the gas budget.
interface IPermission {
    /// @notice Decide whether a manager-submitted transaction is permitted.
    /// @dev    Called by the kernel once per registered permission per dispatch.
    ///         ALL registered permissions must return true for the transaction to proceed —
    ///         the kernel uses AND-semantics across the permission set.
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
