// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

/// @notice Minimal initializer guard for EIP-1167 clone templates.
///
///         Each clone starts with `_initialized = false` (fresh storage).
///         The first (and only) call to a function marked `initializer` succeeds
///         and sets `_initialized = true`. All subsequent calls revert with
///         `AlreadyInitialized`.
///
///         `_disableInitializers()` is provided for logic contracts that want to
///         lock themselves so `initialize()` cannot be called directly on the
///         implementation address. For non-upgradeable, calldata-validation-only
///         templates (like the Sail permission templates) this is optional: a
///         clone `delegatecall`s the logic's bytecode but reads/writes its own
///         storage, so any state change on the logic contract address is isolated
///         and harmless. Call `_disableInitializers()` in the logic constructor
///         if you prefer belt-and-suspenders hygiene; omit it to allow the logic
///         contract to be tested directly with `new Template()` + `initialize()`.
///
///         This keeps the implementation minimal and avoids pulling in OZ Initializable
///         (which uses an upgradeable storage layout incompatible with simple clones).
abstract contract CloneInitializable {
    bool private _initialized;

    error AlreadyInitialized();

    modifier initializer() {
        if (_initialized) revert AlreadyInitialized();
        _initialized = true;
        _;
    }

    /// @dev Call in the logic contract's constructor to permanently lock it.
    ///      Clones start with `_initialized = false` and are unaffected.
    function _disableInitializers() internal {
        _initialized = true;
    }

    /// @notice Returns true once `initialize()` has been called on this instance.
    function initialized() external view returns (bool) {
        return _initialized;
    }
}
