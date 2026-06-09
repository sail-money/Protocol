# Sail Protocol — Deployed Addresses

> **✅ Deployed — CREATE2 deterministic scheme (deployed 2026-06-09, commit `1199b33`)**
>
> Every core contract is deployed via **deterministic CREATE2 with a global (chain-independent)
> salt per contract**, through the standard CREATE2 factory
> `0x4e59b44847b379578588920cA78FbF26c0B4956C`.
>
> The practical consequence: **each core contract has the SAME address on every chain**, and so
> does the resulting Safe initializer — giving users the **same Separately-Managed-Account (SMA)
> address on every supported chain**. This is enabled by extracting the `TimelockController` from
> `SailGovernance`'s constructor (it is now deployed separately and injected), which makes every
> constructor argument chain-independent.
>
> The addresses below are **live** on all six chains (Ethereum, Base, Arbitrum, Unichain, Base
> Sepolia, Eth Sepolia), and the onboarding allowlists were seeded at genesis (`bootstrapAllowlists`).

This directory contains the canonical deployment manifests for the Sail protocol. Per-chain
manifests are written to `deployments/<chainId>/core.json` by `script/core/DeployCore.s.sol`.

---

## Core addresses (identical on every chain)

Under the CREATE2 global-salt scheme, the following addresses are the same on Ethereum, Base,
Arbitrum, Unichain, Base Sepolia, and Eth Sepolia, provided the deployment uses identical
configuration across chains.

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `0x7A478118715791728BDE3bc7A4D7ECfdEB89C6EC` |
| TimelockController    | `0xE48Ba8DB6d748adafD13155c3590f62e58a77f56` |
| SailKernel            | `0x02ABC18B65A328de2e749F56ba79ACF2718a6659` |
| MandateFactory        | `0x14EDd6c2a56EfC0d71E215ab13094B9AF90543d2` |
| StandardFeePolicy     | `0xe7B5901b839cFFDEd9D4108A22712C8BfdA1D80D` |
| SafeModuleEnabler     | `0x7897Cb53a4be4a2eaAf46D60573C4Fd83b33fE1F` |

## Supported chains

| Chain        | Chain ID  | Status                       |
|--------------|-----------|------------------------------|
| Ethereum     | 1         | live (CREATE2, bootstrapped) |
| Base         | 8453      | live (CREATE2, bootstrapped) |
| Arbitrum     | 42161     | live (CREATE2, bootstrapped) |
| Unichain     | 130       | live (CREATE2, bootstrapped) |
| Base Sepolia | 84532     | live (CREATE2, bootstrapped) |
| Eth Sepolia  | 11155111  | live (CREATE2, bootstrapped) |

The CREATE2 factory (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) and the Safe v1.4.1 proxy
factory (`0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`) are both present at their canonical
addresses on all six chains, so the same-address property is achievable on each.

---

## Notes

- Deployments are intended to use **zero fees** (`MGMT_FEE_BPS=0`, `PERF_FEE_BPS=0`),
  `initialPermissionRegistrationFee = 0`, and `maxPermissionFeeWei` at the constitutional cap
  (`0.001 ETH`) — and these values **must be identical across chains** for the addresses to match.
- The `TimelockController` is deployed first, with the governance wallet (`INITIAL_GOVERNANCE`) as
  its sole proposer/executor/canceller and `address(0)` as admin (self-administered, 48h delay).
  Its address is injected into `SailGovernance`, whose constructor re-verifies the 48h delay and
  the proposer role.
- After each core deployment, the onboarding allowlists must be configured before accounts can be
  created — either seeded at genesis via `bootstrapAllowlists` (the `SAIL_BOOTSTRAP_ALLOWLISTS`
  path in `DeployCore`) or, in normal operation, via the 48-hour timelock:
  - `setTrustedSafeFactory`
  - `setTrustedSafeSingleton`
  - `setTrustedModuleSetup` (points to the deployed `SafeModuleEnabler`)
  - `setTrustedSafeProxyCodehash` (capture `extcodehash` of any SafeProxy deployed by the v1.4.1 factory)
- **Template contracts** (shared + standalone) are deployed separately, bind to the kernel address,
  and will be republished after the core redeploy.

Last updated: 2026-06-09 — CREATE2 deterministic deploy (commit `1199b33`) live on chains 1, 8453, 42161, 130, 84532, 11155111; bootstrapped at genesis.
