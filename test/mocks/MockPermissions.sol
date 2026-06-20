// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

import {IPermission, Context} from "../../contracts/interfaces/IPermission.sol";

// ─────────────────────────────────────────────────────────────────────────────
// Minimal single-dispatch mock permissions for proving the kernel's runtime
// guarantees independently of any example template. Each imports only the
// IPermission interface (and Context) — zero template dependency.
// ─────────────────────────────────────────────────────────────────────────────

/// @notice Always authorises. (selective-auth, custody, happy-path)
contract MockPermissionAlwaysTrue is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return true; }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionAlwaysTrue"); }
}

/// @notice Always denies. (fail-closed, selective-auth)
contract MockPermissionAlwaysFalse is IPermission {
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { return false; }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionAlwaysFalse"); }
}

/// @notice Reverts during evaluate. (fail-closed: revert => deny)
contract MockPermissionReverts is IPermission {
    error Boom();
    function evaluate(bytes calldata, Context calldata) external pure returns (bool) { revert Boom(); }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionReverts"); }
}

/// @notice Returns a non-canonical "bool" word (uint256(2)). The kernel decodes the return
///         as uint256 and requires == 1, so this is treated as deny. Does NOT inherit
///         IPermission because its return type differs; the kernel calls `evaluate` by selector.
///         (fail-closed: malformed return => deny)
contract MockPermissionReturnsTwo {
    function evaluate(bytes calldata, Context calldata) external pure returns (uint256) { return 2; }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionReturnsTwo"); }
}

/// @notice Returns fewer than 32 bytes of return data. The kernel treats `ret.length < 32`
///         as deny. Uses assembly to emit a short (4-byte) return; the kernel calls by selector.
///         (fail-closed: short return data => deny)
contract MockPermissionReturnsShort {
    function evaluate(bytes calldata, Context calldata) external pure {
        assembly { return(0, 4) }
    }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionReturnsShort"); }
}

/// @notice Burns far more than PERMISSION_GAS_CAP (150k) so the gas-capped staticcall runs
///         out of gas; the kernel treats that as deny and the outer dispatch is unaffected.
///         (gas isolation: over-cap => deny, no DoS)
contract MockPermissionGasBomb is IPermission {
    function evaluate(bytes calldata, Context calldata) external view returns (bool) {
        uint256 x;
        for (uint256 i; i < 100_000; i++) {
            x += uint256(keccak256(abi.encode(i, x)));
        }
        return x == type(uint256).max; // never reached: OOG under the 150k cap
    }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionGasBomb"); }
}

/// @notice Attempts to mutate its own storage during evaluate. Because the kernel calls
///         evaluate via staticcall, the SSTORE reverts; the kernel treats that as deny and
///         `touched` stays 0. Does NOT inherit IPermission (evaluate is non-view) — the kernel
///         calls by selector. (static evaluation: state mutation is impossible)
contract MockPermissionStateMutator {
    uint256 public touched;
    function evaluate(bytes calldata, Context calldata) external returns (bool) {
        touched = 1; // reverts under staticcall
        return true;
    }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionStateMutator"); }
}

interface IKernelReenter {
    function registerAccount(address permissionSigner, address manager, address feePolicy, address feeAsset) external;
}

/// @notice Attempts to re-enter the kernel with a state-changing call during evaluate. Under
///         staticcall the re-entrant call cannot mutate kernel state, so it reverts and the
///         dispatch is denied; the kernel records no state change for this permission.
///         Does NOT inherit IPermission (evaluate is non-view). (no re-entry via the permission surface)
contract MockPermissionReenters {
    address public immutable kernel;
    constructor(address _kernel) { kernel = _kernel; }
    function evaluate(bytes calldata, Context calldata) external returns (bool) {
        IKernelReenter(kernel).registerAccount(address(this), address(this), address(0), address(0));
        return true;
    }
    function discriminator() external pure returns (bytes32) { return keccak256("MockPermissionReenters"); }
}
