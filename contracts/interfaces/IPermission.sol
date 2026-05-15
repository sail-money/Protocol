// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Execution context passed to every permission on each dispatch call.
/// @dev    Permissions receive a snapshot of the transaction environment captured
///         at the moment the kernel invokes them. Fields are read-only (staticcall).
struct Context {
    address account;        // the Safe whose assets are at stake
    address manager;        // the delegated signer who submitted the transaction
    address submitter;      // msg.sender of dispatch — may differ from manager (relayer)
    address target;         // the call target
    bytes4  selector;       // leading 4 bytes of calldata; bytes4(0) if calldata < 4 bytes
    uint256 value;          // native ETH forwarded with the call
    uint256 blockTimestamp; // block.timestamp at dispatch time — usable for time-based gates
    uint256 blockNumber;    // block.number at dispatch time
}

interface IPermission {
    /// @notice Decide whether a manager-submitted transaction is allowed.
    /// @dev    Called via staticcall with a per-permission gas cap. No state changes possible.
    ///         A revert or gas exhaustion is treated as a false return by the kernel.
    /// @param txData   Raw calldata of the transaction being dispatched.
    /// @param ctx      Execution context snapshot (see Context struct).
    /// @return         True if the transaction is permitted; false to block it.
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool);

    /// @notice Optional stable identifier for fast off-chain indexing.
    /// @dev    Permissions with a fixed structure (selector + target + asset) return a
    ///         non-zero discriminator. Complex or multi-purpose permissions return zero
    ///         and are always evaluated on every dispatch.
    function discriminator() external view returns (bytes32);
}
