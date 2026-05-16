# Sail Protocol

> A minimal account-abstraction primitive for onchain Separately Managed Accounts run by agents.

Sail is a protocol for onchain Separately Managed Accounts (SMAs). An SMA is an account where capital sits under the LP's custody and a designated manager — typically an autonomous agent, but optionally a human, multisig, or MPC wallet — executes transactions within bounds approved by the account's permission signer. Sail provides the kernel that mediates this relationship: it instantiates the account, registers permissions, gates manager dispatch through those permissions, accounts for fees, and tracks principal.

The protocol is positioned for developers and crypto-native builders deploying autonomous agents on top of Safe accounts. Sail provides the custody layer agents need to act on-chain without being given private keys, and the permission infrastructure that LPs need to bound what an agent can do.

The trusted kernel is ~500 source lines of Solidity. All permission logic, valuation math, fee schedules, and venue-specific gating lives in user-deployed contracts the kernel reads via `staticcall` under a gas cap. Adding a new permission pattern means deploying a new contract — not extending a grammar, not upgrading the kernel.

Sail is currently in audit-prep state. The protocol has not been externally audited and is not deployed on mainnet.

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

Governance is a contract initially held by the team multisig, transferable to a DAO, token, or other mechanism over time. Constitutional caps (the 25% protocol cut, the registration fee ceiling) are immutable in source code and cannot be raised by any governance procedure.

---

## Architecture

```
                        ┌─────────────────────┐
                        │   Permission Signer │
                        │   signs EIP-712     │
                        │   mandate updates   │
                        └──────────┬──────────┘
                                   │
                                   ▼
   ┌──────────┐  dispatch    ┌──────────────────┐  staticcall    ┌─────────────────┐
   │ Manager  │─────────────▶│    SailKernel    │───────────────▶│  Permissions    │
   │ (agent / │              │  (trusted core)  │   evaluate()   │  (user-deployed)│
   │  human / │              │                  │                └─────────────────┘
   │ multisig)│              │  - account reg   │
   └──────────┘              │  - perm registry │
                             │  - dispatch      │  execTransaction
                             │  - fee accounting│   FromModule       ┌──────────┐
                             │                  │──────────────────▶│   Safe   │
                             └──────────┬───────┘                    │ (custody)│
                                        │                            └──────────┘
                                        │ collectFees
                                        ▼
                             ┌──────────────────┐
                             │   Fee Policy     │
                             │ (user-deployed)  │
                             └──────────────────┘
```

### Components

| Component | Role | SLOC |
|---|---|---|
| `SailKernel` | Trusted execution core. Account registration, permission registry, EIP-712 signature verification, manager dispatch via Safe modules, fee collection, principal tracking. | 495 |
| `SailGovernance` | Protocol parameter governance with 48-hour OpenZeppelin TimelockController, two-step transfer, emergency pause with 72h auto-expiry. | 112 |
| `PermissionFactory` | Untrusted UX orchestrator. Bundles configuration and registration into single transactions. Holds no protocol-level privileges. | 131 |
| `BaseSharedPermission` | Abstract base for shared multi-tenant templates. EIP-712 domain, per-account nonces, ECDSA + ERC-1271 signature verification. | 85 |
| Interfaces (`IPermission`, `IConfigurablePermission`, `IFeePolicy`, `IOracle`) | Cross-contract API surface. | 43 |

**Trusted core total:** 866 SLOC.

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

Permissions are called via `staticcall` with a per-permission gas cap. Reentrancy is structurally impossible — `staticcall` prohibits state changes. A permission that exceeds its gas cap or reverts is treated as a `false` result. Dispatch succeeds only if every registered permission returns `true`.

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
- Constitutional cap: `MAX_PERMISSION_FEE_WEI` (immutable, set at deployment)
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

The Fee 2 mechanism is built into the kernel but disabled by default at v1 launch. It is intended to be activated by governance when the Sail Marketplace launches, providing revenue for the curation and infrastructure layer described in the trust model section below.

---

## Trust model

> **Read this section before depositing funds into an SMA you do not personally control.**

Sail Protocol is open-source, permissionless infrastructure. Anyone can deploy SMAs, configure fee policies, and build products on top of the protocol. The protocol does not curate, endorse, or vet third parties who deploy products on it.

### Manager-attested NAV in `StandardFeePolicy`

The default fee policy shipped with v1 — `StandardFeePolicy` — uses a **manager-attested NAV model**. The manager submits the portfolio value (`currentNav`) at fee collection time. The protocol does not independently verify this value.

In the open protocol, a manager operating an SMA where a third party has deposited funds can inflate the reported NAV when collecting fees. The maximum extractable amount is bounded by the Safe's liquid balance and the configured fee parameters but can reach a significant portion of the SMA's value in a single fee collection.

This risk exists in any product built on Sail that uses `StandardFeePolicy` and accepts third-party LP deposits, regardless of whether that product is associated with Sail Protocol.

### Intended use at v1 launch

Sail Protocol v1 is designed for **self-managed SMAs** — developers, AI agent builders, and crypto-native users operating Safes with their own capital. In this configuration the manager-attested NAV trust model is irrelevant because the manager and the LP are the same party.

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
    external view returns (uint256 price, uint8 decimals);
```

Two distinct calling conventions exist in the codebase. Integrators must understand the difference:

1. **Token-pair price oracle.** Used by `SharedBoundedSwapPermission` and the borrow-asset side of LTV checks. `base` and `quote` are ERC-20 token addresses. Standard adapters (Chainlink, Uniswap TWAP, Pyth) satisfy this convention directly.

2. **Account collateral value oracle.** Used by `SharedBoundedBorrowPermission` and `SharedDeFiBundlePermission` for the collateral side of LTV checks. `base` is the Safe account address; the oracle adapter returns the aggregate value of that account's collateral positions across the protocols it holds. **Standard token-price oracles do not satisfy this convention.** A custom adapter must be deployed.

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
│   └── SailKernel.sol
├── governance/
│   └── SailGovernance.sol
├── factory/
│   └── PermissionFactory.sol
├── interfaces/
│   ├── IPermission.sol
│   ├── IConfigurablePermission.sol
│   ├── IFeePolicy.sol
│   └── IOracle.sol
├── policies/
│   └── StandardFeePolicy.sol
└── templates/
    ├── shared/
    │   ├── BaseSharedPermission.sol
    │   ├── SharedBoundedSwapPermission.sol
    │   ├── SharedBoundedBorrowPermission.sol
    │   ├── SharedTransferTargetPermission.sol
    │   ├── SharedDeFiBundlePermission.sol
    │   ├── SharedPendlePermission.sol
    │   └── SharedAMMLiquidityPermission.sol
    └── [atomic per-instance templates — legacy]
```

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

Current test count: 864+ across 21 test files.

---

## Security

The protocol has not yet been externally audited. An external audit is planned before mainnet deployment.

### Audit scope (planned)

**Group 1 — Trusted core (~880 SLOC):**  
`SailKernel`, `SailGovernance`, `PermissionFactory`, `BaseSharedPermission`, and all interfaces.

**Group 2 — Shared templates and policies (~670 SLOC):**  
The six shared templates and `StandardFeePolicy`.

The atomic per-instance templates are out of v1 audit scope and will receive per-template audits as they migrate or are deprecated.

### Reporting vulnerabilities

A bug bounty program will be announced prior to mainnet launch. For pre-audit vulnerability disclosure: [security contact placeholder].

---

## Headline figures

| Dimension | Sail Protocol |
|---|---|
| Trusted core (kernel + governance + factory + interfaces + base) | 866 SLOC |
| Total contracts in v1 audit scope | ~1,550 SLOC |
| Constitutional caps (immutable) | 25% max protocol cut; `MAX_PERMISSION_FEE_WEI` |
| Permission evaluation | `staticcall` with per-permission gas cap |
| Custody model | Self-custodial via Gnosis Safe |
| Default fee 2 at launch | 0% |
| Test count | 864+ |

---

## License

[License placeholder]

---

## Acknowledgments

Built on [Gnosis Safe](https://safe.global/). EIP-712 typed data hashing and ERC-1271 verification courtesy of [OpenZeppelin Contracts](https://github.com/OpenZeppelin/openzeppelin-contracts).
