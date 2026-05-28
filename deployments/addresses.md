# Sail Protocol — Deployed Addresses

> **⚠️ Important: Use the Previous Kernels for Now**
>
> The addresses in this directory come from the post-Octane audit remediation redeploy (May 2026).
>
> **The new kernels are not yet usable for onboarding.**
>
> `createAccount()` and `registerAccount()` will revert on these new deployments until the four `onlyTimelock` allowlists are populated via the 48-hour timelock on each chain:
>
> - `setTrustedSafeFactory`
> - `setTrustedSafeSingleton`
> - `setTrustedModuleSetup` (the new `SafeModuleEnabler`)
> - `setTrustedSafeProxyCodehash`
>
> **Recommendation:**
> - On **Arbitrum** and **Base**: Continue using the *previous* kernel deployments for creating/registering accounts and attaching permissions.
> - On **Base Sepolia**: There is no previous kernel. You must complete the timelock allowlisting steps before you can use this deployment.
>
> Once the timelock proposals are executed, the new kernels (with hardened onboarding logic) will become active.

This directory contains the canonical deployment manifests for the Sail protocol.

**All deployments below use zero fees** (`managementFeeBps: 0`, `performanceFeeBps: 0`).

---

## Arbitrum (Chain ID 42161)

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `0xA3ee24e4fB7800c4f4c1481Bd920A4034Dfc34cf` |
| TimelockController    | `0xD6cBDe852186b5b51b01950bB45399A9768acb76` |
| SailKernel            | `0x7542c3BCEd0014C14d79dA9A98Ec043F1ceC63E2` |
| MandateFactory        | `0x19BD2629790e602aF22840b37208e44e4F9B0aaE` |
| StandardFeePolicy     | `0x0Da0fc382E0F990bB08Bf9868fa469904D4E1cdF` |
| SafeModuleEnabler     | `0x9FCaEfc7791cE24dF88804655916E0Ef91c94DeC` |

**Manifests**
- `core.json`
- `templates.shared.json`
- `templates.standalone.json`

**Deployed at block** `25193607` (git commit `a40fc0bc...`)

---

## Base (Chain ID 8453)

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `0xe88668dEd183ef283A606b0D7f6Dbcc4D3f4639B` |
| TimelockController    | `0x4f19ea113c92711166FA423d859c0d099Dd8bA00` |
| SailKernel            | `0x852553c5ceb0B2c4c429F355fFBB719ECeF6d0d4` |
| MandateFactory        | `0x0402b812cCD90608Ca91AdE265082aCa0b8780C8` |
| StandardFeePolicy     | `0xa4d4F6A0Ebfe1c0798371f897Da85126d6722534` |
| SafeModuleEnabler     | `0xc7Ad7e2Cfe71050bd905aa6a67b3056730E5017a` |

**Manifests**
- `core.json`
- `templates.shared.json`
- `templates.standalone.json`

**Deployed at block** `46589301` (git commit `a40fc0bc...`)

---

## Base Sepolia (Chain ID 84532)

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `0x2287e52c7fDb5748bB05a857c026D732D1634707` |
| TimelockController    | `0xFcB810e1127f40266d70DfB8f74320c3F7a14695` |
| SailKernel            | `0x2e22Cc96F5C069C9eC8B9310E1BbF08C41Ae613E` |
| MandateFactory        | `0x19650F55577242953Cea668D59F5049a6faf3480` |
| StandardFeePolicy     | `0xf47689F681a8bEb4595DB51AE7d464D03CbC8b63` |
| SafeModuleEnabler     | `0x6B05cD59e748364a3dB8f7A3005AA0979859321B` |

**Manifests**
- `core.json`
- `templates.shared.json`
- `templates.standalone.json`

**Deployed at block** `42099572` (git commit `a40fc0bc...`)

---

## Notes

- All three deployments were performed with **zero fees** (`MGMT_FEE_BPS=0`, `PERF_FEE_BPS=0`).
- `initialPermissionRegistrationFee` is set to `0` on all chains.
- `maxPermissionFeeWei` is set to the constitutional cap (`0.001 ETH`).
- The `StandardFeePolicy` on each chain can be updated later by the `feeManager` (currently the deployer EOA).
- After each core deployment, the four allowlist entries must be configured via the 48-hour timelock before accounts can be created:
  - `setTrustedSafeFactory`
  - `setTrustedSafeSingleton`
  - `setTrustedModuleSetup` (points to the chain-specific `SafeModuleEnabler`)
  - `setTrustedSafeProxyCodehash` (capture `extcodehash` of any SafeProxy deployed by the v1.4.1 factory)

**Template contracts** (shared + standalone) are listed in the respective `templates.*.json` files in each chain directory. They are bound to the kernel address shown above.

Last updated: 2026-05-28 (post-Octane audit remediation redeploy)