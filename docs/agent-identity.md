# Agent Identity

This document explains the agent-identity interface layer added to the Sail Protocol
template set. It covers design rationale, implementation patterns, off-chain consumption,
and explicit scope boundaries.

> **Status: optional, not kernel-enforced (forward-looking convention).** These interfaces
> exist (`IAgentIdentityResolver`, `IAccountAgentIdentityResolver`, `IAgentWalletVerifier`),
> and the shared base `ConfigurablePermission` implements the per-account resolver
> (`agentIdentityFor`). But **the kernel never reads, verifies, or depends on agent identity**
> at any point, and the launch templates do **not** declare an agent-identity capability in
> `capabilityIds()` (e.g. `BorrowPermission` declares only `BOUNDED_BORROW`) and store no
> identity by default. So this layer is **not load-bearing**: nothing in the shipped protocol
> consumes it. Treat the patterns below as a convention for templates (current or future) that
> opt in — not as an active, enforced feature of the launch set.

---

## 1. Why agent identity is at the template layer, not the kernel layer

The SailKernel treats managers as opaque signers. It verifies that a valid EIP-712
signature was produced by the account's configured manager address — nothing more.
It does not know or care whether that manager is an EOA, an MPC wallet, a Safe, an
AI agent, or a protocol-owned contract.

Identity policy is product-specific:

| Deployment type | Identity requirement |
|---|---|
| Self-managed user | None — the user is their own manager |
| Institutional desk | Internal KYC, off-chain only |
| Strategy marketplace | ERC-8004 identity token required for listing |
| Curated vault | Identity + on-chain reputation score required |

Encoding any of these policies into the kernel would force all users to pay for
requirements that only apply to a subset of deployments. Instead, templates implement
the identity policy that fits their use case inside `evaluate()`, and expose their
identity metadata through `IAgentIdentityResolver` or `IAccountAgentIdentityResolver`
for off-chain indexers and UIs.

---

## 2. Implementing identity-based authorization inside `evaluate()`

A template that requires the manager to be a specific agent wallet checks
`ctx.manager == ref.agentWallet` inside its `evaluate()` function.

```solidity
import {IAgentIdentityResolver, AgentIdentityRef} from
    "../interfaces/IAgentIdentityResolver.sol";

contract AgentGatedPermission is IPermission, IAgentIdentityResolver {
    AgentIdentityRef private immutable _identity;

    constructor(AgentIdentityRef memory identity) {
        _identity = identity;
    }

    function agentIdentity() external view override returns (AgentIdentityRef memory) {
        return _identity;
    }

    function evaluate(bytes calldata txData, Context calldata ctx)
        external view override returns (bool)
    {
        // Only the registered agent wallet may dispatch through this permission.
        if (ctx.manager != _identity.agentWallet) return false;

        // ... additional authorization logic ...
        return true;
    }
}
```

The kernel calls `evaluate()` normally. It never calls `agentIdentity()`. The identity
check happens entirely inside `evaluate()`, within the existing staticcall + gas-cap
boundary.

---

## 3. How consumers read identity off-chain

### Step 1 — discover which templates expose agent identity

Use `IPermissionIntrospection.capabilityIds()` to filter templates by capability without
needing to know their ABI. **Note:** this matches only templates that *declare* the
agent-identity capability — none of the launch templates do, so against the shipped set this
filter returns nothing. It is the discovery pattern for future templates that opt in by adding
`sail.capability.agent-identity.v1` to their `capabilityIds()`:

```javascript
const AGENT_IDENTITY = keccak256("sail.capability.agent-identity.v1");

async function supportsAgentIdentity(permissionAddress) {
  try {
    const perm = new ethers.Contract(permissionAddress, IPermissionIntrospectionABI, provider);
    const caps = await perm.capabilityIds();
    return caps.includes(AGENT_IDENTITY);
  } catch {
    return false; // template does not implement IPermissionIntrospection
  }
}
```

### Step 2 — read the identity

For global-identity templates (one agent per template deployment):
```javascript
const resolver = new ethers.Contract(permissionAddress, IAgentIdentityResolverABI, provider);
const ref = await resolver.agentIdentity();
// ref.agentWallet — the signing wallet
// ref.identityRegistry — ERC-8004 registry address
// ref.agentId — token ID in that registry
```

For per-account templates (shared templates with per-Safe configuration):
```javascript
const resolver = new ethers.Contract(
  permissionAddress,
  IAccountAgentIdentityResolverABI,
  provider
);
const ref = await resolver.agentIdentityFor(safeAddress);
// Returns zero struct if no identity is configured for this account
```

---

## 4. Global identity vs. per-account identity

### `IAgentIdentityResolver` — global

One agent manages **all** accounts that use this template deployment. Appropriate for:
- Single-account deployments (one Safe, one agent)
- Protocol-owned strategies managed by a single operator

```
                ┌──────────────────────────────┐
                │   AgentGatedPermission        │
                │   agentWallet = 0xABC...      │
                └──────────┬───────────────────┘
                           │ same identity
            ┌──────────────┴──────────────┐
            │                             │
        Safe A                        Safe B
   (both managed by 0xABC)     (both managed by 0xABC)
```

### `IAccountAgentIdentityResolver` — per-account

Different accounts on the same shared template deployment may be managed by different
agents. Appropriate for:
- Strategy marketplaces with multiple independent managers
- Shared template factories where each user configures their own agent

```
                ┌──────────────────────────────┐
                │  ConfigurablePermission       │
                │  (multi-tenant base)          │
                └───────┬──────────────┬────────┘
                        │              │
               agentIdentityFor(A)  agentIdentityFor(B)
                = { agentWallet:     = { agentWallet:
                    0xABC... }           0xDEF... }
                        │                    │
                    Safe A               Safe B
              (managed by 0xABC)   (managed by 0xDEF)
```

---

## 5. What is explicitly out of scope

**Live ERC-8004 registry resolution.** The `AgentIdentityRef` struct returned by these
interfaces contains data the template itself supplies. There is no automatic lookup of
`agentId → current wallet` in an external registry at call time. An optional
`IAgentWalletVerifier` interface is available for templates that need live resolution;
implementing it is the template's responsibility, and any external calls consume gas
from the `PERMISSION_GAS_CAP` budget.

**Reputation and ranking.** These interfaces expose identity; they say nothing about
the agent's track record, reputation score, or ranking in any curation registry. Ranking
and reputation are future extension points that may be built on top of this layer.

**Marketplace listing requirements.** Whether a Sail marketplace requires ERC-8004
identity, a minimum reputation score, or any other credential is a marketplace-level
policy decision. It is not enforced by the kernel or by these interfaces.

---

## 6. ERC-8004 metadata keys convention

Templates that publish ERC-8004 metadata (via the registry's tokenURI or equivalent)
should include the following Sail-specific keys in their metadata JSON to enable
cross-platform indexing:

| Key | Value | Description |
|---|---|---|
| `sail.kernel` | `address` | The SailKernel contract address |
| `sail.account` | `address` | The Safe address (if account-specific metadata) |
| `sail.permissionTemplate` | `address` | The permission contract address |
| `sail.chainId` | `uint256` | The deployment chain ID (EIP-155) |

Example metadata JSON:
```json
{
  "name": "Active Trading Strategy v1",
  "description": "Uniswap V3 bounded-swap permission managed by AlphaBot",
  "sail.kernel": "0x1234...5678",
  "sail.account": "0xABCD...EF01",
  "sail.permissionTemplate": "0x9999...AAAA",
  "sail.chainId": 8453
}
```

These keys are a convention, not a protocol requirement. Indexers and marketplaces
that follow this convention can reconstruct the full on-chain context from any
ERC-8004 token without additional off-chain lookup.
