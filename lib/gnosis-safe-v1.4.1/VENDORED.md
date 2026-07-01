# Gnosis Safe v1.4.1 — vendored source (offline review only)

Vendored copy of the Safe smart-account contracts, included so the exact Safe v1.4.1
Solidity source travels with the repository for offline inspection.

- Upstream: https://github.com/safe-global/safe-smart-account
- Tag: `v1.4.1`
- Commit: `bf943f80fec5ac647159d26161446ac5d716a294`
- Version: `1.4.1` (see `package.json` and `contracts/Safe.sol` `VERSION` constant)

Corresponds to the canonical Safe v1.4.1 deterministic deployments pinned in
`script/SafeConstants.sol` (SafeProxyFactory, Safe L1 singleton, SafeL2).

This tree is **inspection context only**. It is NOT part of the Sail compile set:
nothing under `contracts/`, `script/`, or `test/` imports it, and Sail interacts with
Safe exclusively through the inline `ISafe` / `ISafeFactory` interfaces declared in
`contracts/core/SailKernel.sol`. The Safe sources are not compiled into any Sail
artifact and do not affect any deployed address or bytecode.
