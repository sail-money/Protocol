# Sail Protocol — Documentation

This directory holds the protocol documentation: the specification and architectural
overview, per-contract references, integration guides, the security model, and the AI
security review reports. For a high-level introduction start with the root
[README](../README.md); for the full design rationale see the
[whitepaper](./whitepaper/Sail_Protocol_Whitepaper.pdf).

## Start here

| Document | What it covers |
|----------|----------------|
| [spec.md](./spec.md) | Normative protocol specification — responsibilities, interfaces, EIP-712 authorization surface, fee model, constitutional caps, headline properties. |
| [ARCHITECTURE.md](./ARCHITECTURE.md) | Narrative + diagram overview of how the kernel, governance, permissions, and fee policy fit together. |
| [GLOSSARY.md](./GLOSSARY.md) | One-line definitions of the protocol's core terms. |
| [whitepaper](./whitepaper/Sail_Protocol_Whitepaper.pdf) | Design rationale and the protocol model in prose. |

## Contract references

| Document | What it covers |
|----------|----------------|
| [KERNEL.md](./KERNEL.md) | `SailKernel` reference — constants, EIP-712 domain/typehashes, state, functions, events, errors. |
| [GOVERNANCE.md](./GOVERNANCE.md) | `SailGovernance` reference — timelock, constitutional caps, tunable parameters, two-step transfer. |
| [FEE_POLICIES.md](./FEE_POLICIES.md) | `IFeePolicy` interface, kernel fee-split mechanics, and the `StandardFeePolicy` reference. |
| [TEMPLATES.md](./TEMPLATES.md) | Catalog of the seven shared permission templates — what each gates and how it decides. |

## Build & integrate

| Document | What it covers |
|----------|----------------|
| [INTEGRATION.md](./INTEGRATION.md) | Operator deployment, building a custom `IPermission`, building a custom `IFeePolicy`, and the EIP-712 signing reference. |
| [oracle-adapters.md](./oracle-adapters.md) | `IOracle` adapter specification for the oracle-gated templates. |
| [agent-identity.md](./agent-identity.md) | The agent-identity layer at the template level and how consumers read it off-chain. |
| [off-chain-attribution.md](./off-chain-attribution.md) | How indexers derive per-template metrics from kernel events and introspection. |

## Operate

| Document | What it covers |
|----------|----------------|
| [DEPLOYMENT.md](./DEPLOYMENT.md) | CREATE2 deployment runbook for the trusted core (identical-address invariant, bootstrap decision, per-chain commands). |
| [deployments/addresses.md](../deployments/addresses.md) | Deployed addresses across all chains, plus the machine-readable `deployments.json` index. |

## Security

| Document | What it covers |
|----------|----------------|
| [SECURITY_MODEL.md](./SECURITY_MODEL.md) | Trust model, security properties, and known limitations of the trusted core and templates. |
| [security/](./security/) | Reports from Sail's AI security review by Octane, with the review scope and boundary. |

For the disclosure policy and how to report a vulnerability, see the root
[SECURITY.md](../SECURITY.md).
