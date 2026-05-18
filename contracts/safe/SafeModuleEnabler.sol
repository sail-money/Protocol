// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface ISafeModuleEnable {
    function enableModule(address module) external;
}

/// @title  SafeModuleEnabler
/// @notice One-shot bootstrap helper invoked via Safe.setup()'s delegatecall hook to
///         enable a module on a freshly deployed Safe in the same transaction.
///
/// @dev    Background: Safe's `enableModule(address)` is gated by an `authorized`
///         modifier that requires `msg.sender == address(this)`. The only window during
///         which a freshly created Safe proxy can satisfy that check without first
///         executing a Safe-owner transaction is the `to`/`data` delegatecall in
///         `Safe.setup`. By delegatecalling this contract's `enable(module)` during
///         setup, the inner call resolves `address(this)` to the Safe itself,
///         making `Safe.enableModule(module)` a valid Safe → Safe call.
///
///         The contract is stateless and re-entrant-safe by construction. Deploy once
///         per chain at a known address; integrators reference that address as
///         `safeInitializer.to` when calling `SailKernel.createAccount`.
///
///         Out of scope:
///           - Enabling multiple modules in one shot (compose multiple Safe.setup
///             initializers, or use a MultiSend, if needed)
///           - Validating that `module` implements any particular interface
///           - Reverting on already-enabled module (Safe itself reverts in that case)
contract SafeModuleEnabler {
    /// @notice Enable `module` on the calling Safe.
    /// @dev    MUST be invoked via `delegatecall` from the Safe (via `Safe.setup`'s
    ///         `to`/`data` parameters). When called directly, the inner
    ///         `enableModule` call targets this contract — which has no such function —
    ///         and reverts.
    /// @param  module Address of the module contract to enable on the Safe.
    function enable(address module) external {
        ISafeModuleEnable(address(this)).enableModule(module);
    }
}
