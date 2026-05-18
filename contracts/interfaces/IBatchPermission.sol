// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice A single subcall in a batch dispatch.
/// @dev    The kernel executes every Call as `safe.execTransactionFromModule(target, value, data, 0)`
///         — operation is always CALL, never DELEGATECALL.
struct Call {
    /// @dev Subcall target. MUST NOT equal the kernel address (enforced by the kernel).
    address target;
    /// @dev Native ETH forwarded to the subcall (wei).
    uint256 value;
    /// @dev Calldata for the subcall.
    bytes   data;
}

/// @notice Execution context passed to `evaluateBatch` on each batch dispatch.
/// @dev    A snapshot of the dispatch environment. Read-only (staticcall).
struct BatchContext {
    /// @dev The Safe account whose assets are being moved.
    address account;
    /// @dev The delegated signer who authorised the batch.
    address manager;
    /// @dev msg.sender of the dispatch call; may differ from manager when a relayer is used.
    address submitter;
    /// @dev The batch-aware permission contract being consulted (this contract).
    address permission;
    /// @dev keccak256(abi.encode(calls)) — stable identifier for the exact call sequence.
    bytes32 batchHash;
    /// @dev block.timestamp at dispatch time — available for time-based gates.
    uint256 blockTimestamp;
    /// @dev block.number at dispatch time.
    uint256 blockNumber;
}

/// @title  IBatchPermission
/// @notice Interface for batch-aware Sail permissions.
///
/// @dev    BATCH DISPATCH SEMANTICS — READ THIS BEFORE IMPLEMENTING.
///
///         The kernel exposes a second dispatch entry point — `dispatchBatch` — that
///         executes a sequence of Safe module calls as a single atomic transaction.
///         A batch dispatch is gated by exactly ONE batch-aware permission, named
///         explicitly in the manager's signature.
///
///         ONLY THE NAMED PERMISSION EVALUATES. This is a deliberate divergence from
///         single dispatch. In single dispatch (`SailKernel.dispatch`), every IPermission
///         registered on the account is consulted and ALL must return true (AND-semantics).
///         In batch dispatch, the manager picks one batch-aware permission to validate
///         the entire call sequence; the other permissions registered on the account
///         are NOT consulted. The selected permission owns full responsibility for
///         validating every subcall in the batch.
///
///         The named permission MUST still be registered on the account, just like any
///         other permission. Registration is the trust anchor — the permissionSigner has
///         already approved this contract for this account by registering it. Choosing
///         it for a batch dispatch then requires only a manager signature.
///
///         The rationale: batch permissions encode whole-batch invariants that cannot
///         be enforced by per-call evaluation. The classic example is "approve, call,
///         reset-to-zero" — the approve and the reset are individually unsafe, but the
///         pair is safe iff the consuming call between them is bounded. No per-call
///         IPermission can express that. A single IBatchPermission can.
///
/// @dev    IMPLEMENTATION CONTRACT:
///         - Implementations MUST validate every subcall — target, selector, decoded
///           parameters — as well as cross-call relationships (e.g. matching amounts,
///           mandatory cleanup calls, ordering constraints).
///         - `evaluateBatch` MUST be view. The kernel calls it via staticcall under a
///           gas cap (SailKernel.BATCH_EVAL_GAS_CAP). A revert, OOG, or malformed
///           return is treated as a false return (fail-closed).
///         - `isBatchPermission()` exists for kernel type detection. Implementations
///           MUST return `true`. A non-implementing contract will fail the kernel's
///           try/catch detection and be rejected.
///         - Implementations SHOULD revert on malformed calldata in subcalls rather
///           than silently allowing them. Revert is treated as denial.
interface IBatchPermission {
    /// @notice Validate an entire batch of subcalls.
    /// @param  calls Sequence of subcalls to execute (length 1..MAX_BATCH_LENGTH).
    /// @param  ctx   Execution context for this batch dispatch.
    /// @return       True to authorise the entire batch; false to deny.
    function evaluateBatch(
        Call[] calldata calls,
        BatchContext calldata ctx
    ) external view returns (bool);

    /// @notice Marker function used by the kernel to detect IBatchPermission support.
    /// @dev    Implementations MUST return `true`. The kernel uses try/catch on this
    ///         call to distinguish batch-aware permissions from single-permission
    ///         contracts that happen to share an address slot in the registry.
    /// @return Always true.
    function isBatchPermission() external pure returns (bool);
}
