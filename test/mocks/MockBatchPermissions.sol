// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IBatchPermission, Call, BatchContext} from "../../contracts/interfaces/IBatchPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal batch-aware mock permissions for proving the kernel's batch-dispatch
// guarantees independently of any example template. Each imports only the
// IBatchPermission interface (+ Call/BatchContext) — zero template dependency.
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Authorises any batch. (happy path, atomicity, nonce-namespace tests)
contract MockBatchAlwaysTrue is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) { return true; }
    function isBatchPermission() external pure returns (bool) { return true; }
}

/// @notice Denies any batch. (fail-closed: false => whole batch reverts)
contract MockBatchAlwaysFalse is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) { return false; }
    function isBatchPermission() external pure returns (bool) { return true; }
}

/// @notice Reverts during batch evaluation. (fail-closed: revert => deny)
contract MockBatchReverts is IBatchPermission {
    error Boom();
    function evaluateBatch(Call[] calldata, BatchContext calldata) external pure returns (bool) { revert Boom(); }
    function isBatchPermission() external pure returns (bool) { return true; }
}

/// @notice Burns more than BATCH_EVAL_GAS_CAP (1,000,000) so the gas-capped staticcall runs
///         out of gas; the kernel treats that as deny. (batch gas isolation)
contract MockBatchGasBomb is IBatchPermission {
    function evaluateBatch(Call[] calldata, BatchContext calldata) external view returns (bool) {
        uint256 x;
        for (uint256 i; i < 1_000_000; i++) {
            x += uint256(keccak256(abi.encode(i, x)));
        }
        return x == type(uint256).max; // never reached: OOG under the 1M cap
    }
    function isBatchPermission() external pure returns (bool) { return true; }
}
