// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

/// @notice Minimal Safe stub for kernel guarantee tests.
///
///         Records every `execTransactionFromModule` call (count + last args) so tests can
///         prove the kernel moves account assets ONLY through a satisfied dispatch, and can be
///         toggled to fail a chosen subcall index to prove atomic batch rollback.
///
///         Self-contained — imports nothing — so the kernel-guarantee suite has zero dependency
///         on the example templates.
contract MockSafe {
    // Test support: a finalized Safe reports nonce>=1 (setup never bumps it)
    // and exposes its trusted singleton via masterCopy() (intercepted by a real SafeProxy fallback).
    function nonce() external pure returns (uint256) { return 1; }
    function checkSignatures(bytes32, bytes calldata, bytes calldata) external view {}
    function masterCopy() external pure returns (address) { return address(0x5AFE); }

    bool    public moduleEnabled = true;
    uint256 public callCount;
    address public lastTo;
    uint256 public lastValue;
    bytes   public lastData;

    /// @dev When non-zero, the `failOnCall`-th exec (1-indexed) returns false.
    uint256 public failOnCall;

    function setModuleEnabled(bool v) external { moduleEnabled = v; }
    function setFailOnCall(uint256 n) external { failOnCall = n; }

    function isModuleEnabled(address) external view returns (bool) { return moduleEnabled; }

    function execTransactionFromModule(address to, uint256 value, bytes calldata data, uint8)
        external
        returns (bool)
    {
        callCount += 1;
        lastTo    = to;
        lastValue = value;
        lastData  = data;
        if (failOnCall != 0 && callCount == failOnCall) return false;
        return true;
    }
}
