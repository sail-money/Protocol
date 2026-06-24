# Sail Protocol — Glossary

One-line definitions of the protocol's core terms, consistent with the [whitepaper](./whitepaper/Sail_Protocol_Whitepaper.pdf) and [README](../README.md). For the precise on-chain behaviour of any term, the relevant contract in `contracts/` is the source of truth.

## Concepts

| Term | Definition |
|---|---|
| **SMA** | Separately Managed Account — a self-custodial Safe the owner controls, together with its mandate. Used interchangeably with *account*. |
| **Safe / Account** | The Gnosis Safe v1.4.1 smart account that holds the capital, with the kernel enabled on it as a module. The protocol never takes custody. |
| **Mandate** | The set of permission contracts registered to an SMA — what the Manager is authorized to do. The Safe is the account the mandate applies to, not part of the mandate. |
| **Permission** | An individual rule: a deployed contract implementing `IPermission`, evaluated by the kernel via `staticcall` on each dispatch, returning allow or deny. |
| **Template** | A reusable permission implementation. The launch set is shared and multi-tenant: one deployment per chain serves many accounts, each storing its own configured bounds. |
| **ConfigurablePermission** | The shared base the launch templates inherit — per-account configuration (EIP-712 domain, per-account nonces, ECDSA and ERC-1271 verification). Not deployed on its own. |
| **Batch permission** | A permission implementing `IBatchPermission` that validates and authorizes an entire batch in `dispatchBatch`. |
| **Fee Policy** | A user-deployed `IFeePolicy` contract that computes the legitimate fee at collection time. `StandardFeePolicy` is the reference default; any account may register a different one. |

## Operations

| Term | Definition |
|---|---|
| **Dispatch** | A manager-signed call naming one registered permission as the authorizer. The kernel evaluates that permission alone and executes through the Safe only if it returns true (*selective authorization*). |
| **Batch dispatch** | `dispatchBatch` — an atomic sequence of Safe module calls gated by exactly one batch-aware permission; any subcall failure reverts the whole batch. |
| **Selective authorization** | Each dispatch is gated by the single permission named in the manager's signature; other registered permissions are not consulted. |
| **Constitutional caps** | Immutable bounds in the deployed bytecode — `MAX_PROTOCOL_CUT_BPS` (25%) and the per-deployment registration-fee ceiling (0.01 of the chain's native token). Governance can tune parameters within them but can never raise the caps. |

## Roles

| Role | Definition |
|---|---|
| **Owner** | Holds the Safe and custodies the SMA's capital. Always self-custodial. |
| **Permission Signer** | Authorizes the mandate — signs registration, configuration, and revocation of permissions via EIP-712. May be the Owner, or a separate signing key or multisig. |
| **Manager** | Executes transactions within the mandate's bounds; cannot exceed what the registered permissions allow. An autonomous agent or a human operator; the signing key may be an EOA, multisig, or MPC wallet. |
| **Submitter** | The address that pays gas and submits the manager's signed dispatch. Not an authority role — any address may submit; authority derives from the manager's signature and the registered permissions. |

## Trusted core contracts

| Contract | Definition |
|---|---|
| **SailKernel** | The trusted core: account registration, permission registry, EIP-712 verification, manager dispatch via Safe modules, fee collection, principal tracking. Holds no funds. |
| **SailGovernance** | The protocol parameter store: constitutional caps, timelocked tunable parameters, and the trusted-infrastructure allowlists (Safe factory, singleton, proxy codehash, fee policies). |
| **TimelockController** | The 48-hour timelock through which governance parameter changes and transfers flow. |
| **MandateFactory** | An untrusted UX orchestrator that bundles permission configuration, registration, replacement, and detachment into single transactions. Holds no protocol-level privileges. |
