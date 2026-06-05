# Sail Protocol

> A protocol for onchain Separately Managed Accounts run by agents.

Sail is a protocol for onchain Separately Managed Accounts (SMAs). An SMA is an account where capital sits under the LP's custody and a designated manager — typically an autonomous agent, but optionally a human, multisig, or MPC wallet — executes transactions within bounds approved by the account's permission signer. Sail provides the kernel that mediates this relationship: it instantiates the account, registers permissions, gates manager dispatch through those permissions, accounts for fees, and tracks principal. Because each SMA is a separate account with its own permission set, an agent can run an individually calibrated strategy for each owner — sensitive to their balance, risk profile, and preferences — rather than applying a single algorithm across all accounts.

The protocol is positioned for developers and crypto-native builders deploying autonomous agents on top of Safe accounts. Sail provides the custody layer agents need to act on-chain without being given private keys, and the permission infrastructure that LPs need to bound what an agent can do.

The trusted kernel is 804 source lines of Solidity. All permission logic, valuation math, fee schedules, and venue-specific gating lives in user-deployed contracts the kernel reads via `staticcall` under a gas cap. Adding a new permission pattern means deploying a new contract — not extending a grammar, not upgrading the kernel.

The trusted core is deployed on Base, Base Sepolia, and Arbitrum as staging deployments for testing and integration ahead of a formal launch. These deployments run the selective dispatch model, are under an ongoing external audit by [Octane Security](https://octane.security), and are not final. They should not be used with funds you are not prepared to lose. Permission templates are not yet deployed against these kernels; mainnet launch will follow audit completion.

---

## Documentation

- **[Whitepaper (PDF)](./docs/whitepaper/Sail_Protocol_Whitepaper.pdf)** — full design rationale, roles, permission model, fee mechanics, governance, security properties
- **[Specification](./docs/spec.md)** — single source of truth for protocol design decisions
- **[Architecture](./docs/ARCHITECTURE.md)** — component diagram, data flow, trust boundaries
- **[Kernel](./docs/KERNEL.md)** — SailKernel internals, dispatch flow, storage layout
- **[Permission templates](./docs/TEMPLATES.md)** — template authoring guide, shared vs per-instance patterns
- **[Fee policies](./docs/FEE_POLICIES.md)** — IFeePolicy interface, StandardFeePolicy, NAV trust model
- **[Governance](./docs/GOVERNANCE.md)** — parameter governance, timelock, constitutional caps
- **[Security](./docs/SECURITY.md)** — threat model, invariants, known limitations
- **[Integration guide](./docs/INTEGRATION.md)** — Safe setup, permission registration, manager signing flow
- **[Agent identity](./docs/agent-identity.md)** — IAgentIdentityResolver, off-chain discovery patterns
- **[Off-chain attribution](./docs/off-chain-attribution.md)** — deriving metrics from kernel events

---

## Summary

The core does five things:

1. **Instantiates SMAs** from any signer setup that Safe supports (EOA, multisig, MPC).
2. **Registers permission modules** deployed by users, on a per-account list.
3. **Gates a delegated manager's transactions** through those permissions, evaluated via `staticcall` with a gas cap.
4. **Tracks principal** — cumulative deposits, cumulative withdrawals, and (when relevant) high-water mark.
5. **Routes manager-collected fees** through a protocol-enforced split with a constitutional 25% cap.

Three roles are separated explicitly:

| Role | Authority | Held by |
|---|---|---|
| **Owner** | Holds the Safe. Custody anchor. Self-custodial. | The LP (Safe owner) |
| **Permission Signer** | Authorizes the mandate — decides which permissions apply to the account. Signs registration, revocation, and configuration via EIP-712. | Same as Owner, or a separate signing key/multisig |
| **Manager** | Executes within bounds. Cannot exceed what the registered permissions allow. | EOA, multisig, MPC wallet, or autonomous agent |

The structure these roles operate on:

- **SMA** — the account. A Safe holds the custody.
- **Mandate** — the set of Permissions registered for an SMA. Defines what the Manager is authorized to do.
- **Permission** — an individual rule. A deployed Solidity contract implementing `IPermission`.
- **Template** — an example or reusable pattern for building a Permission. Sail ships a starter set; anyone may deploy more.

Governance is a contract initially held by the team multisig, transferable to a DAO, token, or other mechanism over time. Constitutional caps (the 25% protocol cut, the registration fee ceiling) are immutable in source code and cannot be raised by any governance procedure.

---

## Architecture

```
   ┌────────────────────┐                          ┌────────────────────┐
   │  Permission Signer │                          │       Manager      │
   │                    │                          │ agent/human/msig   │
   └─────────┬──────────┘                          └─────────┬──────────┘
             │                                               │
             │ EIP-712 mandate                               │ dispatch
             ▼                                               ▼
   ┌─────────────────────────────────────────────────────────────────────┐
   │                            SailKernel                               │
   │                          (trusted core)                             │
   │                                                                     │
   │      · account registration        · manager dispatch               │
   │      · permission registry         · fee collection                 │
   └─────────┬───────────────────────┬───────────────────────┬───────────┘
             │                       │                       │
             │ staticcall            │ execModule            │ collectFees
             ▼                       ▼                       ▼
   ┌────────────────────┐  ┌────────────────────┐  ┌────────────────────┐
   │     Permissions    │  │         Safe       │  │     Fee Policy     │
   │   (user-deployed)  │  │      (custody)     │  │   (user-deployed)  │
   └────────────────────┘  └────────────────────┘  └────────────────────┘
```

### Components

**Trusted core** — every account on the protocol depends on this surface.

| Component | Role | SLOC |
|---|---|---|
| `SailKernel` | Account registration, permission registry, EIP-712 signature verification, selective and batch manager dispatch via Safe modules, fee collection, principal tracking. | 804 |
| `SailGovernance` | Protocol parameter governance with 48h timelock, two-step transfer, emergency pause with 72h auto-expiry, trusted Safe factory/singleton allowlists. | 212 |
| Interfaces | `IPermission`, `IConfigurablePermission`, `IFeePolicy`, `IOracle`, `IBatchPermission`, `IPermissionIntrospection`, `IAgentIdentityResolver`, `SailCapabilities` | 113 |
| **Total** | | **1,129** |

**Template layer** — independently deployable and auditable; a bug affects only registered accounts.

| Component | Role | SLOC |
|---|---|---|
| `BaseSharedPermission` | Abstract base for shared multi-tenant templates. EIP-712 domain, per-account nonces, ECDSA + ERC-1271 signature verification. | 123 |
| `StandardFeePolicy` | Reference fee policy. Management fee on AUM, performance fee above high-water mark. Manager-attested NAV model. | 156 |
| `SharedBoundedSwapPermission` | AMM swaps. Router allowlist, token allowlist, amount cap, optional oracle slippage. | 165 |
| `SharedBoundedBorrowPermission` | Aave V3, Morpho, Compound borrows. Protocol allowlist, asset allowlist, LTV check. | 140 |
| `SharedTransferTargetPermission` | ERC-20 transfers. Recipient allowlist, token allowlist. | 77 |
| `SharedDeFiBundlePermission` | Composite — swap + borrow + transfer in one registered permission. Selector-routed evaluation. | 284 |
| `SharedPendlePermission` | Pendle V2 router: liquidity, PT swaps, YT swaps, mint/redeem, claim rewards. | 262 |
| `SharedAMMLiquidityPermission` | Uniswap V3 NPM and Aerodrome (legacy router + Slipstream NPM) liquidity operations. | 197 |
| `SharedApproveAndCallBatchPermission` | Batch dispatch: atomic approve / protocol call / reset sequence. Token allowlist, spender allowlist, amount cap, mandatory reset to zero. | 142 |
| `MandateFactory` | UX orchestrator. Bundles configuration and registration into single transactions. Holds no protocol-level privileges. | 185 |
| **Total** | | **1,731** |

---

## Permission system

A permission is a contract implementing `IPermission`:

```solidity
interface IPermission {
    function evaluate(bytes calldata txData, Context calldata ctx) 
        external view returns (bool);
    function discriminator() external view returns (bytes32);
}

struct Context {
    address account;        // the Safe
    address manager;        // the delegated signer
    address submitter;      // msg.sender of dispatch (may be a relayer)
    address target;         // call target
    bytes4  selector;       // call selector
    uint256 value;          // msg.value
    uint256 blockTimestamp;
    uint256 blockNumber;
}
```

Permissions are called via `staticcall` with a per-permission gas cap. Reentrancy is structurally impossible — `staticcall` prohibits state changes. A permission that exceeds its gas cap or reverts is treated as a `false` result. Each dispatch names one registered permission as the authorizer; the kernel evaluates that permission alone. Dispatch succeeds only if that permission returns `true`.

A second dispatch path, `dispatchBatch()`, accepts an ordered array of calls and a single batch permission (implementing `IBatchPermission`) that validates the entire sequence before execution. Any subcall failure reverts the whole batch atomically. This covers strategies requiring temporary ERC20 approvals — the batch permission enforces the approve/execute/reset shape as a unit — and any other multi-step workflow requiring atomicity.

Templates may optionally implement `IPermissionIntrospection` to expose a stable `permissionId`, version, metadata URI, and capability identifiers from the `SailCapabilities` library. This allows indexers, UIs, and the Sail Marketplace to discover template types and capabilities without maintaining a separate registry of known addresses.

Templates operating under a known agent identity may optionally implement `IAgentIdentityResolver` to associate the manager with an external identity registry, chain, agent ID, and signing wallet. This is metadata only — the kernel does not read or verify agent identity.

### Shared multi-tenant templates (recommended)

One deployed contract serves all accounts. Per-account configuration is stored in mappings keyed by account address. Configuration happens through `IConfigurablePermission`:

```solidity
interface IConfigurablePermission is IPermission {
    function configure(
        address account, 
        bytes calldata params, 
        uint256 deadline, 
        bytes calldata sig
    ) external;
    function configureDirect(address account, bytes calldata params) external;
    function configNonces(address account) external view returns (uint256);
    function isConfigured(address account) external view returns (bool);
}
```

The `params` field is opaque template-specific calldata, decoded inside the template's `_applyConfig` hook. New template shapes need zero changes to the factory.

| Template | Gates |
|---|---|
| `SharedBoundedSwapPermission` | Uniswap V2/V3 swaps. Router allowlist, token allowlist, amount cap, optional oracle slippage. |
| `SharedBoundedBorrowPermission` | Aave V3, Morpho, Compound borrows. Protocol allowlist, asset allowlist, LTV check. |
| `SharedTransferTargetPermission` | ERC-20 transfers. Recipient allowlist, token allowlist. |
| `SharedDeFiBundlePermission` | Composite — swap + borrow + transfer in a single registered permission. Selector-routed evaluation. |
| `SharedPendlePermission` | Pendle V2 router: liquidity, PT swaps, YT swaps, mint/redeem, claim rewards. |
| `SharedAMMLiquidityPermission` | Uniswap V3 NPM and Aerodrome (legacy router + Slipstream NPM) liquidity operations. |
| `SharedApproveAndCallBatchPermission` | Batch dispatch via `IBatchPermission`. Atomic approve / protocol call / reset. Token allowlist, spender allowlist, amount cap, mandatory reset to zero. |

### Atomic per-instance templates (legacy)

One contract instance per account, configured via constructor. Available in the repository but **not recommended for new deployments**. Slated for deprecation in a future release.

Available: `BoundedSwapPermission`, `BoundedBorrowPermission`, `BoundedDepositPermission`, `BoundedWithdrawPermission`, `TransferTargetPermission`, `GMXPerpPermission`, `GainsNetworkPerpPermission`, `SynthetixPerpPermission`, `AzuroPredictionPermission`, `LimitlessPredictionPermission`.

### Lifecycle

**Registration.** The Permission Signer signs an EIP-712 registration. The kernel adds the permission contract address to the account's permission list and charges Fee 1.

**Configuration.** For shared templates: the Permission Signer signs a `configure` instruction with the template-specific params blob. Any caller may submit the signed call — the factory is the canonical orchestrator but not the only valid sender.

**Reconfiguration.** A new `configure` call with a fresh nonce. The template clears previous per-account state and applies the new params atomically.

**Revocation.** The Permission Signer signs `revokePermission`. The address is removed from the account's list. Two levels: revoke a single permission to narrow the manager's authority, or revoke the entire session to cut off the manager completely.

---

## Fee model

Two independent fee mechanisms, each capped by immutable constants, each tunable within those caps by governance.

### Fee 1 — Permission registration fee

A flat ETH amount paid to the protocol treasury when a permission is registered with the kernel. The fee is identical regardless of contract size or deployment pattern.

```
total_fee = permissionRegistrationFee × number_of_permissions
```

- Storage variable: `SailGovernance.permissionRegistrationFee`
- Constitutional cap: `MAX_PERMISSION_FEE_WEI = 0.001 ETH` (immutable)
- Governance-tunable via `setPermissionRegistrationFee` (48h timelock)
- Excess `msg.value` is refunded to the caller

Denominated in native ETH; no oracle dependency. Governance is expected to retune the rate periodically as ETH price moves.

### Fee 2 — Protocol cut on manager-collected fees

A percentage of the management and performance fees collected by the manager when `collectFees` is called. The kernel asks the registered `IFeePolicy` for the legitimate fee amount, then splits it:

```
protocol_cut    = manager_gross_fee × currentProtocolCutBps / 10_000
distributor_cut = (optional, set in the fee policy)
manager_take    = manager_gross_fee - protocol_cut - distributor_cut
```

- Storage variable: `SailGovernance.currentProtocolCutBps`
- Constitutional cap: `MAX_PROTOCOL_CUT_BPS = 2_500` (25%, immutable)
- Governance-tunable via `setProtocolCutBps` (48h timelock)
- **Default at deployment: 0**

The kernel does not compute the gross fee — that is the responsibility of the user-deployed `IFeePolicy` contract, which contains the actual schedule (management fee on AUM, performance fee on profits above HWM, hybrid models, custom math).

The Fee 2 mechanism is built into the kernel but disabled by default at protocol launch. It is intended to be activated by governance when the Sail Marketplace launches, providing revenue for the curation and infrastructure layer described in the trust model section below.

---

## Trust model

> **Read this section before depositing funds into an SMA you do not personally control.**

Sail Protocol is open-source, permissionless infrastructure. Anyone can deploy SMAs, configure fee policies, and build products on top of the protocol. The protocol does not curate, endorse, or vet third parties who deploy products on it.

### Manager-attested NAV in `StandardFeePolicy`

The default fee policy — `StandardFeePolicy` — uses a **manager-attested NAV model**. The manager submits the portfolio value (`currentNav`) at fee collection time. The protocol does not independently verify this value.

In the open protocol, a manager operating an SMA where a third party has deposited funds can inflate the reported NAV when collecting fees. The maximum extractable amount is bounded by the Safe's liquid balance and the configured fee parameters but can reach a significant portion of the SMA's value in a single fee collection.

This risk exists in any product built on Sail that uses `StandardFeePolicy` and accepts third-party LP deposits, regardless of whether that product is associated with Sail Protocol.

### Intended use at launch

Sail Protocol is designed for **self-managed SMAs** — developers, AI agent builders, and crypto-native users operating Safes with their own capital. In this configuration the manager-attested NAV trust model is irrelevant because the manager and the LP are the same party.

The kernel enforces a governance-managed allowlist of trusted Safe factory and singleton addresses, preventing a compromised manager from registering a backdoored Safe implementation.

### Future — Sail Marketplace

The Sail Marketplace, a forthcoming curation layer, will provide audited fee policy templates with specific LP protection guarantees suited to different strategy types: `YieldFeePolicy` (trustless NAV via on-chain position adapters), `TradingFeePolicy` (principal-bounded fees, performance crystallized on withdrawal), `AttestedNAVFeePolicy` (independent attester co-signature on NAV updates), and others. Marketplace-listed managers will pay Fee 2 in exchange for discovery, audit guarantees, and the Marketplace's curation.

Until the Sail Marketplace launches, LP-allocated strategies on the open protocol carry the trust risk described above.

### Recommended verification before LP deposit

If you are considering depositing funds into an SMA operated by a third party on Sail Protocol, before depositing you should verify:

- That the SMA is hosted on the official Sail Marketplace (once launched). Products using the open protocol outside the Marketplace are not vetted by Sail.
- The specific fee policy contract address and its trust model.
- The permission templates configured on the Safe and the manager's bounds.
- The manager's identity, track record, and accountability.

Sail Protocol and its contributors do not endorse, vet, or assume responsibility for third-party products built on the open protocol. Use of the open protocol is at the user's own risk.

---

## Oracle conventions

Permission templates that perform price-bounded checks use `IOracle`:

```solidity
function getPrice(address base, address quote) 
    external view returns (uint256 price, uint8 decimals, uint256 updatedAt);
```

Two distinct calling conventions exist in the codebase. Integrators must understand the difference:

1. **Token-pair price oracle.** Used by `SharedBoundedSwapPermission` and the borrow-asset side of LTV checks. `base` and `quote` are ERC-20 token addresses. Standard adapters (Chainlink, Uniswap TWAP, Pyth) satisfy this convention directly.

2. **Account collateral value oracle.** Used by `SharedBoundedBorrowPermission` and `SharedDeFiBundlePermission` for the collateral side of LTV checks. `base` is the Safe account address; the oracle adapter returns the aggregate value of that account's collateral positions across the protocols it holds. **Standard token-price oracles do not satisfy this convention.** A custom adapter must be deployed.

The third return value, `updatedAt`, is the Unix timestamp of the underlying price observation. Oracle adapters SHOULD enforce a maximum acceptable age on `updatedAt` and revert (or return a sentinel) when the source feed is stale, so that downstream permissions reject swaps and borrows priced from outdated data.

Reference adapter implementations for common protocol combinations are planned. Until they ship, integrators using borrow-related permissions are responsible for implementing the account collateral value oracle for their specific position topology.

---

## Use case coverage

The architecture is intentionally permission-agnostic. Any on-chain primitive — AMM swap, lending deposit / borrow / withdraw, LP position, perp trade, restaking deposit, prediction market bet, RWA flow — becomes a permission template.

For venues with off-chain components (Hyperliquid's order book; perp DEXes with off-chain matching; Polymarket's CLOB), permissions can constrain the on-chain boundary — bridge deposit amounts, withdrawal recipients, allowed sub-accounts — but cannot constrain off-chain order signing. **This is a property of the venue, not the protocol.** Integrators must be explicit about which venue categories are fully on-chain enforceable and which inherit venue-specific trust assumptions.

---

## Out of scope

What Sail explicitly does *not* include, with the reasoning:

- **Policy authoring workflow** (drafts, versions, curation, subject lists). Off-chain authoring — Git, IDEs, SDKs, frontends — handles this. The protocol stores deployed permission addresses, not authoring metadata.
- **A constraint grammar.** Solidity inside permission contracts replaces interpreted constraint structs.
- **Workflow execution as a kernel concept.** A workflow is just a kind of permission — "transaction must conform to this multi-step shape."
- **ERC-4337 and EIP-7702 adapters in the kernel.** Peripheral adapter contracts wrap the kernel for users who want those entry points.
- **NAV computation.** Lives in user-deployed valuation modules and oracle adapters; oracle choice is an ecosystem concern.
- **A registry of curators or template authors.** Marketplace function, handled off-chain via the forthcoming Sail Marketplace.
- **Identity primitives (ERC-8004, on-chain KYC).** Permission modules may consult external identity registries; the kernel stays agnostic.

Each exclusion reduces what the protocol owns. The kernel owns less, by design, so that what it does own is provable, auditable, and stable.

---

## Repository structure

```
contracts/
├── core/
│   └── SailKernel.sol                         # trusted core — 590 SLOC
├── governance/
│   └── SailGovernance.sol                     # trusted core — 146 SLOC
├── factory/
│   └── MandateFactory.sol                  # UX orchestrator — 137 SLOC
├── interfaces/                                # trusted core — 113 SLOC total
│   ├── IPermission.sol
│   ├── IConfigurablePermission.sol
│   ├── IBatchPermission.sol
│   ├── IFeePolicy.sol
│   ├── IOracle.sol
│   ├── IPermissionIntrospection.sol
│   ├── IAgentIdentityResolver.sol
│   └── SailCapabilities.sol
├── policies/
│   └── StandardFeePolicy.sol                  # reference fee policy — 147 SLOC
├── safe/
│   └── SafeModuleEnabler.sol                  # deployment helper — out of audit scope (9 SLOC, stateless)
└── templates/
    ├── shared/                                # recommended — 7 templates, 1,230 SLOC
    │   ├── BaseSharedPermission.sol           # abstract base — 86 SLOC
    │   ├── SharedBoundedSwapPermission.sol
    │   ├── SharedBoundedBorrowPermission.sol
    │   ├── SharedTransferTargetPermission.sol
    │   ├── SharedDeFiBundlePermission.sol
    │   ├── SharedPendlePermission.sol
    │   ├── SharedAMMLiquidityPermission.sol
    │   └── SharedApproveAndCallBatchPermission.sol
    └── [atomic per-instance templates — legacy, not recommended]

docs/
├── whitepaper/                                # PDF + LaTeX source
├── spec.md                                    # protocol specification
├── ARCHITECTURE.md
├── KERNEL.md
├── TEMPLATES.md
├── FEE_POLICIES.md
├── GOVERNANCE.md
├── SECURITY.md
├── INTEGRATION.md
├── agent-identity.md
└── off-chain-attribution.md

test/
├── SailKernel.t.sol
├── SailGovernance.t.sol
├── Integration.t.sol
├── SelectiveDispatch.t.sol
├── BatchDispatch.t.sol
├── BatchDispatchBench.t.sol
├── BatchPermissions.t.sol
├── PermissionIntrospection.t.sol
├── AgentIdentity.t.sol
├── MandateFactory.t.sol
├── StandardFeePolicy.t.sol
├── [shared template test files]
├── [legacy template test files]
├── mocks/
├── support/
└── redteam/                                   # adversarial test suite
    ├── RedTeam.t.sol
    └── RedTeam2.t.sol
```

---

## Deployments

The trusted core is live on the following chains as **staging deployments** ahead of a formal launch. All run the selective dispatch model with zero fees. Permission templates are not yet deployed against these kernels.

### Base (8453)

| Contract | Address |
|---|---|
| SailKernel | `0x6319d3dfDDe3804ba93D65752b00c52bFb05a1ab` |
| SailGovernance | `0x7E897D919872b1587577617ffFC42113679d0C50` |
| Timelock | `0x8eC3Ca951E193C6E3713A70022454d7A1f083281` |
| PermissionFactory | `0x7724EACd97C8601d5AC244Aadbf76ad87353Ff31` |
| StandardFeePolicy | `0x65850a8D5050aeAade68289ff96c4F119a24B82e` |
| SafeModuleEnabler | `0xC84EdE78f93291A1fab19F51c4c7e938AB302Edf` |
| Treasury | `0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` |

### Arbitrum (42161)

| Contract | Address |
|---|---|
| SailKernel | `0x2716B12832DED0EF5688519c5Fe069EFc0374E02` |
| SailGovernance | `0xd6AbB7A1036ADc7958Abffec9Da03450c5a2Ec8e` |
| Timelock | `0x114CB7110C780f7E3a6093AfE0B52463a569857C` |
| PermissionFactory | `0x23681A8A4C9819D8EaB37E46B858da6F3c85E683` |
| StandardFeePolicy | `0xAdfB986D48480bC67a7cF3751d30599161632e0D` |
| SafeModuleEnabler | `0xabe2a6D03F592BC602cA1dBDCD885ba2493274f9` |
| Treasury | `0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` |

### Base Sepolia (84532)

| Contract | Address |
|---|---|
| SailKernel | `0xf1D0F4C9893612627409948BAa9d82a01a373799` |
| SailGovernance | `0xEaD44bC6999E7b00b9b2E11c1660248DC2a30993` |
| Timelock | `0x97B863e392C9859336788D5Ec454527d33C95B74` |
| PermissionFactory | `0xdfF6a2272F667cDf78Af4681b9c88A219998db95` |
| StandardFeePolicy | `0x05570F7973b46Eb9Ed4518422891EFC26BD58b97` |
| SafeModuleEnabler | `0xB2C2B52d94412e3472C9fb2B52186eA12a935869` |
| Treasury | `0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` |

These addresses are sourced from the Sailor SDK (`@sail/sdk`, `packages/sdk/src/deployments.ts`), the canonical registry.

---

## Build and test

Requirements:
- Foundry (forge v1.7.1 or later)
- Solidity 0.8.26 (cancun target)
- OpenZeppelin Contracts v5.6.1

```bash
forge install
forge build
forge test
```

Current test count: 1,114 across 23 test files (including the red-team adversarial suite under `test/redteam/`).

---

## Security

The trusted core is under an ongoing external audit by [Octane Security](https://octane.security). An audit of the template layer will follow core audit completion.

### Audit scope

**Primary audit scope — Trusted core (1,129 SLOC)**

This is the mandatory audit surface. A bug anywhere in the trusted core puts every account on the protocol at risk.

| Component | SLOC |
|---|---|
| `SailKernel` | 804 |
| `SailGovernance` | 212 |
| Interfaces (8 files) | 113 |
| **Total** | **1,129** |

**Secondary audit scope — Template layer (1,731 SLOC)**

Each template is independently auditable. A bug in one template affects only accounts that have registered that template. New templates can be deployed and audited post-launch without re-auditing the trusted core.

| Component | SLOC |
|---|---|
| `BaseSharedPermission` | 123 |
| `StandardFeePolicy` | 156 |
| `SharedBoundedSwapPermission` | 165 |
| `SharedBoundedBorrowPermission` | 140 |
| `SharedTransferTargetPermission` | 77 |
| `SharedDeFiBundlePermission` | 284 |
| `SharedPendlePermission` | 262 |
| `SharedAMMLiquidityPermission` | 197 |
| `SharedApproveAndCallBatchPermission` | 142 |
| `MandateFactory` | 185 |
| **Total** | **1,731** |

`MandateFactory` holds no protocol-level privileges and can be bypassed; it is in the secondary scope because it is the canonical path for permission registration and its correctness matters for integrators.

`contracts/safe/SafeModuleEnabler.sol` is a stateless one-shot bootstrap helper (9 SLOC) invoked once during Safe creation via `delegatecall` from `Safe.setup()`. It holds no state, no privileges, and has no runtime role after account creation. Direct calls revert by construction. It is explicitly out of v1 audit scope.

The atomic per-instance templates are out of v1 audit scope and will receive per-template audits as they migrate or are deprecated.

Red-team adversarial test suite covering the specific attack vectors identified in the pre-audit security review: `test/redteam/RedTeam.t.sol` and `test/redteam/RedTeam2.t.sol`.

### Reporting vulnerabilities

A bug bounty program will be announced prior to mainnet launch. For pre-audit vulnerability disclosure: [security contact placeholder].

---

## Headline figures

| Dimension | Sail Protocol |
|---|---|
| Trusted core (kernel + governance + interfaces) | ~849 SLOC |
| Template layer (templates + base + fee policy + factory) | ~1,600 SLOC |
| Constitutional caps (immutable) | 25% max protocol cut; `MAX_PERMISSION_FEE_WEI = 0.001 ETH` |
| Dispatch model | Selective — manager names one registered permission per dispatch |
| Permission evaluation | `staticcall` with per-permission gas cap; fail-closed |
| Custody model | Self-custodial via Gnosis Safe |
| Default protocol cut at launch | 0% |
| Test count | 1,114 |

---

## License

GPL-2.0-or-later — see [LICENSE](./LICENSE)

---

## Acknowledgments

Built on [Gnosis Safe](https://safe.global/). EIP-712 typed data hashing and ERC-1271 verification courtesy of [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts).
