// SPDX-License-Identifier: GPL-2.0-or-later
pragma solidity 0.8.26;

/// @notice Minimal initializer guard for EIP-1167 clone templates.
///
///         Each clone starts with `_initialized = false` (fresh storage).
///         The first (and only) call to a function marked `initializer` succeeds
///         and sets `_initialized = true`. All subsequent calls revert with
///         `AlreadyInitialized`.
///
///         Logic (implementation) contracts MUST call `_disableInitializers()` in
///         their constructor to permanently lock the implementation address. Without
///         this, an attacker can call `initialize()` directly on the logic contract,
///         setting arbitrary state on its storage (storage layout conflicts aside,
///         this is a hygiene hazard and a footgun for off-chain tooling that reads
///         the logic address as a canonical reference).
///
///         This keeps the implementation minimal and avoids pulling in OZ Initializable
///         (which uses an upgradeable storage layout incompatible with simple clones).
///
/// @dev    Storage layout: `_initialized` is `bool` at slot 0. Inheriting contracts
///         must account for this — their first declared `bool` field will pack into
///         the same slot as `_initialized`. To avoid accidental aliasing, place the
///         first storage variable on a type boundary that does not pack with `bool`
///         (e.g., start with `address`, `uint256`, or an explicit gap).
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
