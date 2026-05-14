Sail Protocol Specification

Summary
Sail v2 is a minimal account-abstraction primitive for onchain Separately Managed Accounts. The core does five things: it instantiates Safe accounts from any signer setup; it registers permission modules deployed by users; it gates a delegated manager's transactions through those permissions; it charges fees per permission deployed; and it tracks principal while routing manager-collected fees through a protocol-enforced split with a hard 25% cap. All permission logic, valuation math, and fee schedules live in user-deployed contracts outside the core. The protocol separates three roles — Owner, Permission Signer, Manager — and is governed by a contract initially held by the team multisig, transferable later.

The architecture is minimal-core, permissionless-extension. The trusted kernel is ~1,500 lines of Solidity. Permission grammar (the v1 CallPolicy + Constraint[] + constraint VM) is replaced by an IPermission interface that lets users deploy any expressible policy as a contract. Fee schedules live in user-deployed IFeePolicy contracts. Governance has constitutional caps that bound it forever in the source code.
Motivation
The v1 protocol (~13,000 lines of Solidity) is a sophisticated implementation of permissions-as-data with a fixed grammar — CallPolicy structs containing Constraint[] arrays, interpreted by a constraint VM with enums for conditions, reference types, parameter kinds, value sources, and math operations. The grammar approach has real advantages: auditability (the kernel is audited once and runs all policies identically), gas predictability (constraint evaluation is bounded by struct shape), zero reentrancy surface on the hot path (no external calls during evaluation), and alignment with the established AA session-key pattern at the time it was designed.

The grammar approach also has a ceiling. Every new policy pattern requires extending the grammar — adding enum variants, updating the resolver, updating the discriminator, updating every callsite, shipping a kernel upgrade. The cumulative cost has produced size-fighting compiler settings (via_ir = true, optimizer_runs = 1), a sprawling kernel (17 files, including a 10-line PolicyMathEngine that exists only to manage contract size), and a protocol surface incompatible with the broader AA ecosystem.

v2 is not a refactor of v1. It is a different abstraction: deployed permission contracts instead of interpreted data structures. This admits arbitrary policy logic — anything Solidity can express, including math beyond simple comparison, oracle reads, cross-protocol invariants, signature verification, and ZK proof verification. It reduces the trusted code surface by ~87%. It aligns with ERC-7579 / ERC-4337 conventions the AA ecosystem is converging on.
Specification
Roles
v2 formalises three roles that exist implicitly in v1:

Owner. Holds the Safe. Custody anchor. Self-custodial — may be an EOA, MPC wallet, or multisig.
Permission Signer. Authorises the mandate — decides which permissions apply to the account. In retail, collapses to the Owner. For institutional setups (a fund issuing mandates to a manager), separable from the Owner.
Manager. Executes within bounds. May be a human signer, an institutional fund, or an autonomous agent. Cannot exceed what the registered permissions allow, at calldata level, on every transaction.
Core responsibilities
The kernel does exactly five things:

Account instantiation. Wraps Safe's existing factory to deploy a Safe and register it with Sail in a single transaction.
Permission registry. Each account has a per-account list of registered permission contract addresses. Adding requires Permission Signer authorisation.
Manager dispatch. Verifies manager signature, session validity, nonce/replay protection. Walks the registered permissions. Calls evaluate(tx, ctx) on each via staticcall with a per-permission gas cap (default 100k). Executes via the Safe if all return true.
Fee accounting. Tracks per-account cumulative deposits, cumulative withdrawals, and (when relevant) high-water mark. Validates manager fee collection through registered IFeePolicy contracts. Splits collected fees subject to the constitutional 25% protocol cap.
Principal tracking. Maintains the basis numbers fee policies use to compute legitimate fee amounts. The protocol does not compute NAV — that lives in user-deployed valuation modules.

Nothing else lives in the core. Workflow validation, composable execution, transport adapters (ERC-4337, EIP-7702), constraint interpretation, math operations, fee schedule logic, and policy authoring workflows are explicitly out of scope.
The IPermission interface
interface IPermission {
    /// @notice Decide whether a manager-submitted transaction is allowed.
    /// @dev Called via staticcall by the kernel. No state changes possible.
    function evaluate(bytes calldata txData, Context calldata ctx) 
        external view returns (bool);
    
    /// @notice Optional: pre-hashed lookup key for fast indexing.
    /// @dev Permissions with stable structure (selector + target + asset) declare
    /// a discriminator. Complex permissions return zero and are always evaluated.
    function discriminator() external view returns (bytes32);
}

struct Context {
    address account;        // the Safe
    address manager;        // the delegated signer
    address target;         // the call target
    bytes4  selector;       // the call selector
    uint256 value;          // msg.value
    // additional fields TBD during implementation
}

Permissions are called via staticcall with a gas cap. Reentrancy is structurally impossible — staticcall prohibits state changes. Gas DOS is bounded — the per-permission cap means a runaway permission reverts without affecting the kernel. A permission that exceeds its gas cap or reverts is treated as a false result.
Permission lifecycle
Registration. The Permission Signer signs a registration message containing the permission contract address. The kernel adds it to the account's permission list and charges the per-permission deployment fee (Fee 1, below).

Modification. Three patterns; each template author picks the one fitting their use case:

Mutable parameters. The permission contract exposes setter functions guarded by Permission Signer authorisation. One transaction per parameter change.
Deploy new version. For fully immutable permissions, deploy a new instance with new parameters and call kernel.replacePermission(oldAddress, newAddress) to swap the registration atomically. Two transactions, full per-version immutability.
Kernel-stored parameters. The permission contract is a singleton; parameters live in kernel storage keyed by (account, permissionAddress). The permission reads them at evaluate time. One transaction per parameter change, cheap, no per-user contract deployment.

Revocation. The Permission Signer signs kernel.revokePermission(account, permissionAddress). The address is removed from the account's list. Immediately effective: the next manager transaction that would have required this permission fails.

Two levels of revocation, mirroring v1:

Revoke a single permission — narrows the manager's authority.
Revoke the entire session — cuts off the manager completely; all permissions inactive at once.
Parameterisation
Templates use the factory + EIP-1167 minimal proxy pattern. Logic deployed once; users get cheap proxy instances (~45 bytes on-chain) with their own parameters. Each canonical template ships with its own factory. This makes per-user customisation cost-comparable to v1's per-policy storage cost.
Fee model
Two independent fee mechanisms, each capped by immutable constants, each tunable within those caps by governance.
Fee 1 — Per-permission deployment fee
Charged to the Owner when registering permissions. Paid as msg.value in native ETH on the registration transaction. Scales with permission bytecode size as a complexity proxy:

fee_per_permission = min(BASE_FEE + (bytecode_size × COMPLEXITY_RATE), MAX_PERMISSION_FEE_WEI)
total_fee          = sum(fee_per_permission for each permission in the batch)

MAX_PERMISSION_FEE_WEI is immutable in source code. BASE_FEE and COMPLEXITY_RATE are governance-tunable within the cap. Proceeds go to the protocol treasury; no split.

Denominated in native ETH (no oracle dependency). The ETH cost is bounded by the cap; USD cost varies with ETH price, and governance is expected to retune BASE_FEE and COMPLEXITY_RATE periodically.
Fee 2 — Protocol cut on manager-collected fees
Charged when a Manager calls collectFees(amount) on the kernel. The kernel asks the registered IFeePolicy whether amount is legitimate; if so, splits:

protocol_cut    = manager_gross_fee × CURRENT_PROTOCOL_CUT_BPS / 10_000
remainder       = manager_gross_fee - protocol_cut
distributor_cut = (optional, set in the fee policy)
manager_take    = remainder - distributor_cut

MAX_PROTOCOL_CUT_BPS = 2_500 (25%) is immutable in source. CURRENT_PROTOCOL_CUT_BPS is governance-tunable between 0 and 2,500.

The protocol does not compute the gross fee amount. That is the responsibility of the user-deployed IFeePolicy contract, which contains the actual schedule — management fee on AUM, performance fee on profits above HWM, hybrid models, custom math.
The IFeePolicy interface
interface IFeePolicy {
    /// @notice Compute the legitimate fee owed at this moment.
    function computeFee(address account, uint256 currentNav) 
        external view returns (
            uint256 grossFee, 
            address distributor, 
            uint256 distributorBps
        );
    
    /// @notice Record that a fee was collected (for HWM, accrual tracking).
    function recordCollection(address account, uint256 grossFee, uint256 currentNav) 
        external;
}

NAV computation lives in valuation modules registered alongside the fee policy. The protocol stays oracle-agnostic.
Governance
A SailGovernance contract holds the team multisig as the initial governance address. Single mutator: transferGovernance(newAddress) for transitioning control later — DAO, ownership token, decision-market, or any chosen mechanism.

Constitutional caps (immutable — no governance procedure can change):

MAX_PROTOCOL_CUT_BPS = 2_500
MAX_PERMISSION_FEE_WEI (set at deploy time)

Governance-tunable parameters (within the caps):

CURRENT_PROTOCOL_CUT_BPS
BASE_FEE
COMPLEXITY_RATE

Governance can lower or raise parameters within the caps but never raise the caps themselves. The caps bound governance; governance does not bound the caps.
Rationale
The architectural trade-off
The v1 architecture is not a mistake. The choice of permissions as structured data interpreted by a fixed grammar has genuine advantages, and v1 picked them deliberately. v2 picks the other side of the trade-off and must answer each concern explicitly:

Auditability → a canonical template registry. Common patterns (BoundedSwapPermission, BoundedDepositPermission, BoundedBorrowPermission, TransferTargetPermission, etc.) are formally audited and published with verified bytecode. UIs display verified templates by name with their parameters — the same model Etherscan uses for verified token contracts. Unknown templates carry a warning. Users opting into non-audited templates are making an informed choice.
Gas predictability → all evaluate() calls are staticcall with a per-permission gas cap. Permissions exceeding the cap revert. Bundlers can estimate accurately for known templates.
Reentrancy → staticcall guarantees no state changes during evaluation. Reentrancy is impossible by construction. This is a stricter safety model than v1's, where constraint evaluation runs inside the kernel's main call stack with full state access.
Parameterisation overhead → factory + EIP-1167 minimal proxy pattern. A user pays ~45 bytes of on-chain footprint per registered permission, not full deployment cost.
Ecosystem alignment → v2 is more aligned with the modern AA ecosystem (ERC-7579 modular accounts, ERC-4337 bundlers), not less. The current proprietary CallPolicy grammar is not a recognised standard.
Defensibility
Dimension
v1
v2
Trusted kernel size
~13,000 lines
~1,500 lines
Bug blast radius (kernel bug)
All users
All users (but 87% less code)
Bug blast radius (policy bug)
All users — it lives in the kernel
Only users of that specific template
Audit cycle
Every upgrade = full re-audit
Kernel once + per-template incremental
Reasoning style
Global / monolithic
Local / modular
Formal verification feasibility
Impractical at 13k lines
Practical at 1.5k lines
Upgrade risk
High (every change is global)
Low (kernel rarely changes)


The deepest argument is modular reasoning. In v1, proving the protocol safe requires reasoning about how the constraint VM, the registry, the workflow engine, the composable runtime, the fee kernel, and the transport adapters interact — global state, global reasoning. In v2, proof decomposes:

The kernel handles signature verification, session validity, dispatch, fee splits, and custody isolation — provable in isolation, 1,500 lines.
Each canonical permission template enforces exactly what it claims — provable in isolation, ~100 lines each.
Composition is by construction: the kernel calls each permission independently, so there is no cross-permission interaction to reason about.

Proofs are local. This is what makes formal verification practical for v2 in a way it is not for v1.
Verification preservation
A natural concern is that removing the constraint VM removes verification. It does not. Every execution still passes through full verification — signature, session, nonce, dispatch — in the kernel. The only step that changes is how the policy check is implemented: in v1 the kernel interprets CallPolicy data; in v2 the kernel calls evaluate() on the registered permission contract. The outcome (every transaction is checked before it runs) is identical; the implementation differs.
Use case coverage
The architecture is intentionally permission-agnostic. Any onchain primitive — AMM swap, lending deposit/borrow/withdraw, LP position, options trade, restaking deposit, RWA flow — becomes a permission template. Each template gates the relevant call with whatever invariants the manager and user agreed to (allowlist of routers, slippage bounded against an oracle, LTV cap with liquidation buffer, recipient must be the Safe, etc.).

For venues with off-chain components (Hyperliquid's order book; perp DEXes with off-chain matching), permissions can constrain the on-chain boundary — bridge deposit amounts, withdrawal recipients, allowed sub-accounts — but cannot constrain off-chain order signing. This is a property of the venue, not the protocol. User-facing documentation must be clear about which categories are fully on-chain-enforceable and which inherit venue-specific trust assumptions.
Migration
v1 keeps running. v2 deploys alongside it.

New users: v2 directly, using canonical templates.

Existing v1 users: a migration mapper (off-chain tool) reads a v1 CallPolicy and emits the equivalent v2 permission contract deployment plus parameters. Users sign migration when they choose, at no protocol-imposed deadline. Sail Intelligence engines continue operating as Managers on v1 during the transition and migrate to v2 as accounts move.

v1 deprecation: when v2 reaches feature parity in canonical templates and demonstrates equivalent behaviour for existing TVL, v1 enters maintenance mode (security fixes only). End-of-life timeline is governance-determined.
Out of scope
Things v2 explicitly does not include, with the reasoning for each:

A policy authoring workflow (drafts, versions, curation, subject access lists). Off-chain authoring — Git, IDEs, frontends — handles this. The protocol stores deployed permission addresses, not authoring metadata.
A constraint grammar (Condition / RefType / ParamKind / ValueSource enums, MathOp engine). Replaced by Solidity inside permission contracts.
Workflow execution as a kernel concept. A workflow is just a kind of permission — "transaction must conform to this multi-step shape."
ERC-4337 and EIP-7702 adapters in the kernel. Peripheral adapter contracts wrap the kernel for users who want those entry points.
NAV computation. Lives in user-deployed valuation modules; oracle choice is an ecosystem concern, not a protocol concern.
ERC-8004 identity in the kernel. Permission modules may consult ERC-8004 registries; the kernel stays agnostic.
A registry of curators or template authors. Marketplace function, handled off-chain.

Each exclusion reduces what the protocol owns. v2 owns less, by design, so that what it does own is provable, auditable, and stable for years.
Headline figures
Dimension
v1
v2
Core lines of Solidity
~13,000
~1,500
Files in /kernel
17
1–3
Enums in Types.sol
15 (~70 variants)
3–4 (~10 variants)
Methods on policy registry interface
~60
0 (registry leaves protocol)
Adding a new permission pattern
Extend enums, update resolver, discriminator, engines; kernel upgrade
Deploy a new contract
Trusted code surface reduction
—
~87%




Source basis: Sail Protocol v1 Whitepaper; Sail Protocol v1 codebase (contracts/policy/, contracts/types/Types.sol, contracts/kernel/, FeeKernel.sol, IPolicyRegistry.sol); Complexity Reduction Audit (2026-05-14); working sessions on v2 architecture.


