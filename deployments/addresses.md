# Sail Protocol — Deployed Addresses

> **✅ Deployed — CREATE2 deterministic scheme, Safe-governed config (core: commit `1dc1960` /
> `f2e1bdc`; templates: commit `0316883`)**
>
> Both the trusted core and the 7 shared permission templates deploy via **deterministic CREATE2
> with a global (chain-independent) salt per contract**, through the standard CREATE2 factory
> `0x4e59b44847b379578588920cA78FbF26c0B4956C`.
>
> The practical consequence: **every core contract and every template has the SAME address on
> every chain**, and so does the resulting Safe initializer — giving users the **same
> Separately-Managed-Account (SMA) address on every supported chain**.
>
> This deploy supersedes the prior EOA-governed 2026-06-09 addresses (commit `1199b33`): governance
> is now the admin Safe, and onboarding allowlists were seeded post-deploy via
> `SailGovernance.bootstrapAllowlists()` rather than at genesis. Bootstrap has been confirmed live
> (`allowlistBootstrapped() == true`) on all 11 chains below.

This directory contains the canonical deployment manifests for the Sail protocol. Per-chain
manifests are written to `deployments/<chainId>/core.json` (by `script/core/DeployCore.s.sol`) and
`deployments/<chainId>/templates.shared.json` (by `script/templates/DeploySharedTemplates.s.sol`).

Machine-readable index: [`deployments/deployments.json`](./deployments.json) — a tooling-grade
summary of the addresses, governance, fees, and per-chain metadata below, validated by
`scripts/validate-deployments.mjs`.

---

## Core addresses (identical on every chain)

| Contract              | Address                                      |
|-----------------------|----------------------------------------------|
| SailGovernance        | `0x4315B37cA4A315A7042af1Fcb37F8436f4D24356` |
| TimelockController    | `0xC1E5F9A581D4100Aa949f80204540a33aD97A7b6` |
| SailKernel            | `0x38b508756c976e876EFF05a29E731A4d348BA6ED` |
| MandateFactory        | `0x6d2C802ffa0d9A8Ed69A5Bf22c1b63ccB566B8Fc` |
| StandardFeePolicy     | `0x1087312447C8a2BfA15EB9cE23590E3502DBA04b` |
| SafeModuleEnabler     | `0x7897Cb53a4be4a2eaAf46D60573C4Fd83b33fE1F` |

### Config (identical on every chain)

| Parameter                          | Value                                          |
|-------------------------------------|------------------------------------------------|
| Admin Safe (3/5)                    | `0x152a32c851d317Cd54F1E6423377d7D58Dd3DE8C` — parameter governance behind the 48h timelock |
| Treasury Safe (3/5)                 | `0x7b37F85575F1568a37dBA342BC5FE6d393F0872f` — protocol fee recipient |
| Emergency Safe (2/3)                | `0xFf02DE6630F192Bc6d14608f5C52a9f1ae478961` — emergency pause (auto-expiry + cooldown) |
| Deployer EOA                        | `0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` — deployment only; holds no protocol authority |
| `maxPermissionFeeWei` (cap)         | `0.01` native-unit ceiling — immutable, applies per 18-decimal native token |
| `initialPermissionRegistrationFee`  | `0.00015` in each chain's native unit (ETH; BNB on BSC; HYPE on HyperEVM) |
| Management / performance / distributor fees | `0` at launch (protocol-cut cap 2500 bps = 25%) |

## Shared permission template addresses (identical on every chain)

Multi-tenant templates — one deployment per chain serves every account, bound to the canonical
core `kernel` above (constructor is `(kernel, author)`, `author` = deployer EOA
`0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6`).

| Template                     | Address                                      |
|-------------------------------|----------------------------------------------|
| SwapPermission                 | `0x35cEEa0db96997Cc3CF3beB42FFa36A499342F7C` |
| SwapPermissionNoOracle          | `0x34Ba96CbEd1f46c88A5265E645DC5fe41662b519` |
| BorrowPermission                | `0x3e2666051599223cEAb10De55C89A0842857d8AF` |
| DepositPermission               | `0xBfB5e13a97b12Ee89d2F2b9B65eCf7e0E371911f` |
| WithdrawPermission              | `0xF5eF5dda450a130e3020d54f565E830e4a7531f8` |
| TransferPermission              | `0xda909a1CC584fb7559Ce4A828b008B473Da095e1` |
| ApproveAndCallBatchPermission   | `0x0535A4D51333484ef583103DAB1a9449756ab732` |

## Supported chains

| Chain        | Chain ID  | Status                        | Core verified | Templates verified |
|--------------|-----------|--------------------------------|:---:|:---:|
| Ethereum     | 1         | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Base         | 8453      | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Arbitrum     | 42161     | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Optimism     | 10        | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Unichain     | 130       | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| BSC          | 56        | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| World        | 480       | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| HyperEVM     | 999       | live (CREATE2, bootstrapped)   | ⬜ no explorer | ⬜ no explorer |
| MegaETH      | 4326      | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Base Sepolia | 84532     | live (CREATE2, bootstrapped)   | ✅ | ✅ |
| Eth Sepolia  | 11155111  | live (CREATE2, bootstrapped)   | ✅ | ✅ |

The CREATE2 factory (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) and the Safe v1.4.1 proxy
factory (`0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`) are both present at their canonical
addresses on all eleven chains, so the same-address property is achievable on each.

---

## Notes

- The `TimelockController` is deployed first, with the governance wallet as its sole
  proposer/executor/canceller and `address(0)` as admin (self-administered, 48h delay). Its
  address is injected into `SailGovernance`, whose constructor re-verifies the 48h delay and the
  proposer role.
- This deploy intentionally does **not** use the `SAIL_BOOTSTRAP_ALLOWLISTS` genesis path (that
  path requires `governance() == deployer`, which doesn't hold when governance is the admin Safe).
  Instead, the admin Safe (`0x152a32c851d317Cd54F1E6423377d7D58Dd3DE8C`) submits one
  `SailGovernance.bootstrapAllowlists(...)` transaction per chain — `onlyGovernance`, **not**
  timelocked (one-shot latch `allowlistBootstrapped`), seeding:
  - `trustedSafeFactory = [0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67]`
  - `trustedSafeSingleton = [0x41675C099F32341bf84BFc5382aF534df5C7461a, 0x29fcB43b46531BcA003ddC8FCB67FFE91900C762]` (Safe 1.4.1 / SafeL2 1.4.1)
  - `trustedModuleSetup = [0x7897Cb53a4be4a2eaAf46D60573C4Fd83b33fE1F]` (SafeModuleEnabler)
  - `trustedFeePolicy = [0x1087312447C8a2BfA15EB9cE23590E3502DBA04b]` (StandardFeePolicy)
  - `trustedSafeProxyCodehash = [0xd7d408ebcd99b2b70be43e20253d6d92a8ea8fab29bd3be7f55b10032331fb4c]`
  Confirmed live on all 11 chains via `allowlistBootstrapped() == true`.
- HyperEVM (999) has no available block explorer/verifier, so core and templates are deployed but
  unverified there; addresses are identical to every other chain regardless.
- MegaETH (4326) core required a deferred follow-up deploy (`f2e1bdc`) after an initial RPC
  failure; it now matches the canonical addresses and is fully verified (core + templates).

Last updated: 2026-07-01 — Safe-governed CREATE2 core (commits `1dc1960`, `f2e1bdc`) and shared
templates (commit `0316883`) live and bootstrapped on all 11 chains: Ethereum, Base, Arbitrum,
Optimism, Unichain, BSC, World, HyperEVM, MegaETH, Base Sepolia, Eth Sepolia.
