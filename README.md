# Sail Protocol

> Onchain Separately Managed Accounts Run By Agents

<p align="center">
  <img src="./docs/brand/protocol-banner.jpg" alt="Sail Protocol Banner" width="100%" />
</p>

[![license](https://img.shields.io/badge/license-GPL--2.0--or--later-blue)](./LICENSE)

Sail is a minimal account-abstraction primitive for Separately Managed Accounts (SMAs). Capital is held in a self-custodial [Safe](https://safe.global/) the owner controls; a designated manager — typically an autonomous agent — executes only within a mandate enforced by smart contracts on every dispatch. The mandate is a set of user-deployed contracts implementing `IPermission`. On each dispatch the manager names one registered permission, and the kernel evaluates it via `staticcall` under a gas cap, forwarding the call to the Safe only if it returns `true`. Because a permission is arbitrary Solidity, any DeFi primitive can be expressed as one — adding an integration is a contract deployment, not a protocol upgrade.

[Whitepaper](./docs/whitepaper/Sail_Protocol_Whitepaper.pdf) · [sail.money](https://sail.money) · [Documentation](./docs/README.md)

The trusted core and shared permission templates were reviewed by Octane, an AI source-code security scanner, across three analyses. See [docs/security/](./docs/security/).

## How it works

```mermaid
flowchart TD
    Owner["`**Owner**
holds the Safe ·
signs the mandate`"]
    Manager["`**Manager**
agent · signs dispatches`"]
    Mandate["`**Mandate**
set of permission contracts`"]
    Kernel["`**Sail Kernel**
evaluates permission · trusted core
dispatches to Safe on success`"]
    SMA["`**SMA**
holds assets · executes`"]

    Owner -- "03 appoints · instant revocation" --> Manager
    Owner -- "02 signs mandate · EIP-712" --> Mandate
    Owner -. "01 deploys & owns" .-> SMA
    Manager -- "04 signs dispatch · EIP-712" --> Kernel
    Mandate -- "05 defines bounds" --> Kernel
    Kernel -- "06 executes on SMA · reverts outside mandate" --> SMA

    classDef default fill:none,stroke:#999
    classDef kernelNode fill:none,stroke:#555,stroke-width:2px
    class Kernel kernelNode
```

Sail separates three roles. The **Owner** holds the Safe and custodies the SMA's capital — always self-custodial. The **Permission Signer** authorizes the mandate, signing registration, configuration, and revocation of permissions over EIP-712; in retail setups it collapses to the Owner, and for institutional setups it is a separate key or multisig. The **Manager** executes transactions within bounds and can never exceed what the registered permissions allow; its signing key may be an EOA, multisig, or MPC wallet, and it may be an autonomous agent or a human. The address that submits a signed dispatch and pays gas is not an authority role — authority derives from the manager's signature and the registered permissions — which makes Sail natively compatible with relayers, paymasters, and ERC-4337 bundlers.

The kernel enforces four properties on every dispatch: permissions are called via **`staticcall`** (state mutation and reentrancy are structurally impossible); under a fixed **gas cap** (150,000 for a single `evaluate`, 1,000,000 for a batch `evaluateBatch`), where exceeding the cap is treated as a `false`; under **selective authorization**, where only the one permission named in the manager's signature is consulted, so unrelated templates coexist on one account without falsely denying each other; and **fail-closed**, where any revert, out-of-gas, malformed return, or `false` denies the dispatch. A second entry point, `dispatchBatch`, executes a sequence of Safe module calls atomically, gated by one `IBatchPermission` that owns all cross-call invariants.

See [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) for the data flow and diagrams, and [docs/spec.md](./docs/spec.md) for the normative specification.

## Trust boundary

**The trusted core** is the code every account must trust to use Sail at all: `SailKernel`, `SailGovernance`, its `TimelockController`, `MandateFactory`, `StandardFeePolicy`, and `SafeModuleEnabler`. It is roughly **1,022 nSLOC** (the kernel itself ~791) — logical SLOC via `solidity-code-metrics`, comments and blanks excluded — small enough to review in isolation.

**The permission templates and the reference fee policy are not "the protocol."** The seven shared templates and `StandardFeePolicy` are demonstrations of the pattern, deployable and forkable by anyone; the kernel registers and dispatches through any contract implementing `IPermission`, and any account may register a different `IFeePolicy`. Trust them only if you choose to register them.

**Non-guarantees.** A security review is not a guarantee of correctness. The kernel verifies that a permission is a contract and respects its `true`/`false` answer — it does not verify that the permission's logic enforces what its author claims; permission correctness is the author's responsibility. The reference fee policy uses a manager-attested NAV, appropriate when the manager and owner are the same party. Venues with off-chain components (order books, off-chain matching) can only be constrained at their on-chain boundary. See the [Known Limitations](./docs/SECURITY_MODEL.md#known-limitations-and-operator-responsibilities) in the security model.

Repository layout:

```
contracts/
  core/         SailKernel — execution engine, dispatch, fee accounting        [trusted core]
  governance/   SailGovernance — parameters, timelock, allowlists              [trusted core]
  factory/      MandateFactory — UX orchestrator, holds no privileges          [trusted core]
  safe/         SafeModuleEnabler — stateless module-enable helper              [trusted core]
  policies/     StandardFeePolicy — reference IFeePolicy (swappable per account)
  templates/    the 7 shared permission templates + ConfigurablePermission base [not the protocol]
  interfaces/   IPermission, IFeePolicy, IOracle, … (MIT import surface)
  utils/        supporting implementation (e.g. CloneInitializable)
test/           test suite (not deployed)
script/         deployment scripts (not deployed as protocol)
```

## Permission templates

A reference set of multi-tenant templates ships with the protocol as swappable defaults. All inherit a shared base, `ConfigurablePermission`, which provides per-account configuration (EIP-712 domain, per-account nonces, ECDSA and ERC-1271 verification) and is not deployed on its own. In brief: **SwapPermission** (oracle-gated DEX swaps), **SwapPermissionNoOracle** (swaps sanity-banded against a reference pool's live price), **BorrowPermission** (bounded lending borrows with an optional LTV ceiling), **DepositPermission** (deposits into allowlisted vaults/pools, credited to the account), **WithdrawPermission** (ERC-20 moves pinned to one recipient), **TransferPermission** (ERC-20 sends to an allowlisted recipient set), and **ApproveAndCallBatchPermission** (an atomic approve / call / reset-to-zero batch). Each template documents the exact boundary of what it enforces — and what it does not — in [docs/TEMPLATES.md](./docs/TEMPLATES.md).

## Fee model

Two independent fee mechanisms, each capped by an immutable constitutional limit and tunable within it by governance. The **permission registration fee** is a flat native-token amount paid to the treasury per permission registered; excess `msg.value` is refunded. The **protocol cut** on manager-collected fees is `managerGrossFee × currentProtocolCutBps / 10,000`, bounded above by an immutable cap of **25%** (`MAX_PROTOCOL_CUT_BPS = 2,500`) and set to **0 at launch**. The fee computation itself lives in the registered `IFeePolicy`; `StandardFeePolicy` provides a management fee on AUM and a performance fee above a per-account high-water mark. See [docs/FEE_POLICIES.md](./docs/FEE_POLICIES.md).

## Deployments

The trusted core and the shared templates are deployed at **identical CREATE2 addresses on 9 mainnets and 2 testnets (11 chains total)**, through the standard CREATE2 factory `0x4e59b44847b379578588920cA78FbF26c0B4956C` with chain-independent salts and byte-for-byte identical constructor arguments — so every core contract and every template has the same address on every chain. Addresses are shown once below; per-chain manifests are under [`deployments/`](./deployments/). The machine-readable, validated index is [`deployments/deployments.json`](./deployments/deployments.json); the human-readable version is [`deployments/addresses.md`](./deployments/addresses.md).

**Core (identical on every chain):**

| Contract | Address |
|---|---|
| SailKernel | `0x38b508756c976e876EFF05a29E731A4d348BA6ED` |
| SailGovernance | `0x4315B37cA4A315A7042af1Fcb37F8436f4D24356` |
| TimelockController | `0xC1E5F9A581D4100Aa949f80204540a33aD97A7b6` |
| MandateFactory | `0x6d2C802ffa0d9A8Ed69A5Bf22c1b63ccB566B8Fc` |
| StandardFeePolicy | `0x1087312447C8a2BfA15EB9cE23590E3502DBA04b` |
| SafeModuleEnabler | `0x7897Cb53a4be4a2eaAf46D60573C4Fd83b33fE1F` |

**Shared permission templates (identical on every chain):**

| Template | Address |
|---|---|
| SwapPermission | `0x35cEEa0db96997Cc3CF3beB42FFa36A499342F7C` |
| SwapPermissionNoOracle | `0x34Ba96CbEd1f46c88A5265E645DC5fe41662b519` |
| BorrowPermission | `0x3e2666051599223cEAb10De55C89A0842857d8AF` |
| DepositPermission | `0xBfB5e13a97b12Ee89d2F2b9B65eCf7e0E371911f` |
| WithdrawPermission | `0xF5eF5dda450a130e3020d54f565E830e4a7531f8` |
| TransferPermission | `0xda909a1CC584fb7559Ce4A828b008B473Da095e1` |
| ApproveAndCallBatchPermission | `0x0535A4D51333484ef583103DAB1a9449756ab732` |

**Chains:**

| Chain | Chain ID | Native |
|---|---|---|
| Ethereum | 1 | ETH |
| Optimism | 10 | ETH |
| Unichain | 130 | ETH |
| Arbitrum | 42161 | ETH |
| MegaETH | 4326 | ETH |
| World | 480 | ETH |
| BSC | 56 | BNB |
| Base | 8453 | ETH |
| HyperEVM | 999 | HYPE |
| Ethereum Sepolia | 11155111 | ETH |
| Base Sepolia | 84532 | ETH |

**Governance** (identical on every chain; Safe threshold m/n):

| Role | Threshold | Address |
|---|---|---|
| Admin Safe — parameter governance behind the 48h timelock | 3/5 | `0x152a32c851d317Cd54F1E6423377d7D58Dd3DE8C` |
| Treasury Safe — protocol fee recipient | 3/5 | `0x7b37F85575F1568a37dBA342BC5FE6d393F0872f` |
| Emergency Safe — pause (auto-expiry + cooldown) | 2/3 | `0xFf02DE6630F192Bc6d14608f5C52a9f1ae478961` |

The deployer EOA `0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` was used for deployment only and holds no protocol authority.

**Fees** (native units):

| Parameter | Value |
|---|---|
| Registration fee cap (immutable ceiling) | `0.01` native token (`10000000000000000` wei) |
| Registration fee — deploy-time (all chains) | `0.00015` native token |
| Registration fee — live | `0.00015 ETH` (nine ETH-gas chains) · `0.005 HYPE` (HyperEVM) · `0.00045 BNB` (BSC) |
| Manager fee cut | `0` at launch; immutable cap `25%` |

The registration fee is set immutably at construction to the same value on every chain — a prerequisite for the identical CREATE2 address — and then tuned per chain post-deploy by governance through the 48h timelock, which does not affect the already-locked addresses. The live per-chain values differ for that reason.

## Build and test

Sail is a [Foundry](https://book.getfoundry.sh/) project (solc `0.8.26`, EVM `cancun`, `via_ir = true`, optimizer runs `200`).

```bash
forge install    # install submodule dependencies
forge build      # compile all contracts
forge test       # run the test suite — 923 tests across 47 suites
forge snapshot    # regenerate the committed gas snapshot
```

The contracts target the **Cancun** EVM and their bytecode uses `MCOPY`; deploy only to chains that support Cancun or later.

## Security

Sail's trusted core and its seven shared permission templates underwent an AI security review by Octane ([octane.security](https://www.octane.security)), an AI source-code security scanner, across three successive analyses (2026-06-24, 2026-06-26, 2026-06-29). The third and final analysis (2026-06-29) identified no critical- or high-severity findings; all reported vulnerabilities were resolved or acknowledged, and the remaining lower-severity warnings are documented, accepted by design, or out of scope. Reports are in [docs/security/](./docs/security/). A security review is not a guarantee of correctness — see the [Known Limitations](./docs/SECURITY_MODEL.md#known-limitations-and-operator-responsibilities) in the security model.

To report a vulnerability, do not open a public issue — see the [Security Policy](./SECURITY.md) and report privately to hello@sail.money.

## Documentation

Start with the [documentation index](./docs/README.md). Key documents:

- [spec.md](./docs/spec.md) — normative protocol specification
- [ARCHITECTURE.md](./docs/ARCHITECTURE.md) — narrative + diagram overview
- [KERNEL.md](./docs/KERNEL.md) — `SailKernel` reference
- [GOVERNANCE.md](./docs/GOVERNANCE.md) — `SailGovernance` reference
- [FEE_POLICIES.md](./docs/FEE_POLICIES.md) — fee policies and `StandardFeePolicy`
- [TEMPLATES.md](./docs/TEMPLATES.md) — the seven permission templates and their boundaries
- [INTEGRATION.md](./docs/INTEGRATION.md) — operator and permission/fee-policy author guide
- [DEPLOYMENT.md](./docs/DEPLOYMENT.md) — CREATE2 deployment runbook
- [SECURITY_MODEL.md](./docs/SECURITY_MODEL.md) — trust model, properties, and known limitations
- [oracle-adapters.md](./docs/oracle-adapters.md) — `IOracle` adapter specification
- [agent-identity.md](./docs/agent-identity.md) · [off-chain-attribution.md](./docs/off-chain-attribution.md) — advanced topics

The off-chain SDK, CLI, and local dashboard for building and operating mandated agents — **Sailor** — is a separate, open-source project ([sail-money/Sailor](https://github.com/sail-money/Sailor)), not part of this repository or the trusted core.

## Contributing

Contributions are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). Permission templates, docs, tooling, and bug fixes are especially welcome; trusted-core changes carry a higher bar. Security issues must be reported privately via [SECURITY.md](./SECURITY.md), never as public issues.

## License

GPL-2.0-or-later for the trusted core and the shared permission templates; MIT for the interface/import-surface files. Per-file SPDX headers are authoritative. See [LICENSE](./LICENSE).

Built on [Gnosis Safe v1.4.1](https://github.com/safe-global/safe-smart-account) and [OpenZeppelin Contracts v5](https://github.com/OpenZeppelin/openzeppelin-contracts).
