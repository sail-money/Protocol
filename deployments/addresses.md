# Sail Protocol — Deployed Addresses

> **⚠️ Redeploy in progress — CREATE2 deterministic scheme**
>
> The protocol is being redeployed so that every core contract is deployed via **deterministic
> CREATE2 with a global (chain-independent) salt per contract**, through the standard CREATE2
> factory `0x4e59b44847b379578588920cA78FbF26c0B4956C`.
>
> The practical consequence: **each core contract has the SAME address on every chain**, and so
> does the resulting Safe initializer — giving users the **same Separately-Managed-Account (SMA)
> address on every supported chain**. This is enabled by extracting the `TimelockController` from
> `SailGovernance`'s constructor (it is now deployed separately and injected), which makes every
> constructor argument chain-independent.
>
> **Addresses below are placeholders** until the redeploy completes. Do not treat them as live.
> Once published, the address for a given contract will be identical across all six chains.

This directory contains the canonical deployment manifests for the Sail protocol. Per-chain
manifests are written to `deployments/<chainId>/core.json` by `script/core/DeployCore.s.sol`.

---

## Core addresses (identical on every chain)

Under the CREATE2 global-salt scheme, the following addresses are the same on Ethereum, Base,
Arbitrum, Unichain, Base Sepolia, and Eth Sepolia, provided the deployment uses identical
configuration across chains.

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `<to be populated on CREATE2 redeploy>`      |
| TimelockController    | `<to be populated on CREATE2 redeploy>`      |
| SailKernel            | `<to be populated on CREATE2 redeploy>`      |
| MandateFactory        | `<to be populated on CREATE2 redeploy>`      |
| StandardFeePolicy     | `<to be populated on CREATE2 redeploy>`      |
| SafeModuleEnabler     | `<to be populated on CREATE2 redeploy>`      |

## Supported chains

| Chain        | Chain ID  | Status                    |
|--------------|-----------|---------------------------|
| Ethereum     | 1         | pending CREATE2 redeploy  |
| Base         | 8453      | pending CREATE2 redeploy  |
| Arbitrum     | 42161     | pending CREATE2 redeploy  |
| Unichain     | 130       | pending CREATE2 redeploy  |
| Base Sepolia | 84532     | pending CREATE2 redeploy  |
| Eth Sepolia  | 11155111  | pending CREATE2 redeploy  |

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

Last updated: pending CREATE2 redeploy (deterministic same-address scheme).
