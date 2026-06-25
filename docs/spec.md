# Sail Protocol — Specification
 
---
 
## Summary
 
Sail is a minimal account-abstraction primitive for onchain Separately Managed Accounts. The protocol does five things: it instantiates Safe accounts from any signer setup; it registers permission modules deployed by users; it gates a delegated manager's transactions through those permissions; it charges fees per permission deployed; and it tracks principal while routing manager-collected fees through a protocol-enforced split with a hard 25% cap. All permission logic, valuation math, and fee schedules live in user-deployed contracts outside the core. The protocol separates three roles — Owner, Permission Signer, Manager — and is governed by a contract initially held by the team multisig, transferable later.
 
The architecture is minimal-core, permissionless-extension: anyone can deploy a permission contract and register it on an account, deploy an SMA, and operate as a manager — all without protocol approval. The permissionless surface is bounded by a small set of governance-curated, safety-critical infrastructure allowlists — the Safe factory, the Safe singleton, the proxy codehash, the fee policies, and the `Safe.setup` module-setup helpers — which are curated precisely because trusting the wrong value there would compromise account custody itself. Permissions and managers are never curated; the infrastructure inputs are. "Fully permissionless" should be read with that distinction in mind. The trusted core is roughly 1,150 lines of Solidity (the kernel itself ~820), small enough to audit in isolation. Permissions are deployed contracts implementing a standard `IPermission` interface. Fee schedules live in user-deployed `IFeePolicy` contracts. Governance has constitutional caps that bound it forever in the source code.
 
## Design Principles
 
Sail is built on five principles:
 
1. **Minimal trusted core.** The protocol owns the smallest possible set of responsibilities. Everything that can live outside the trusted core does.
2. **Permissionless extension.** New permission patterns and fee schedules deploy as user contracts, without protocol upgrades.
3. **Composable with the AA ecosystem.** Sail integrates with Safe, ERC-4337 bundlers, and ERC-7579 modular account conventions.
4. **Local reasoning.** Each component (kernel, permission template, fee policy) is provable in isolation. Composition is by construction.
5. **Constitutional governance.** Caps on fees and protocol cut are immutable in source. Governance can adjust parameters within caps but never raise the caps themselves.
## Specification
 
### Roles
 
Sail formalises three roles:
 
- **Owner.** Holds the Safe. Custody anchor. Self-custodial — may be an EOA, MPC wallet, or multisig.
- **Permission Signer.** Authorises the mandate — decides which permissions apply to the account. In retail, collapses to the Owner. For institutional setups (a fund issuing mandates to a manager), separable from the Owner.
- **Manager.** Executes within bounds. May be a human signer with a hardware wallet, an MPC wallet (Fireblocks, Coinbase Cloud Custody, Privy, etc.), a multisig, an autonomous bot, an AI agent, or a smart contract. The kernel verifies the Manager's signature via ECDSA (for EOAs) or ERC-1271 (for contract signers); identity type is otherwise opaque to the protocol.
### Core Responsibilities
 
The kernel does exactly five things:
 
1. **Account instantiation.** Wraps Safe's existing factory to deploy a Safe and register it with Sail in a single transaction.
2. **Permission registry.** Each account has a per-account list of registered permission contract addresses. Adding requires Permission Signer authorisation.
3. **Manager dispatch.** Verifies manager signature, session validity, nonce/replay protection. The manager's signature names one registered permission as the authorizer; the kernel evaluates that permission alone via `staticcall` under a fixed 150,000-gas cap (a batch evaluates one batch-aware permission under 1,000,000). Executes via the Safe only if it returns true. Other registered permissions are not consulted.
4. **Fee accounting.** Tracks per-account cumulative deposits, cumulative withdrawals, and (when relevant) high-water mark. Validates manager fee collection through registered `IFeePolicy` contracts. Splits collected fees subject to the constitutional 25% protocol cap.
5. **Principal tracking.** Maintains the basis numbers fee policies use to compute legitimate fee amounts. The protocol does not compute NAV — that lives in user-deployed valuation modules.
Nothing else lives in the core. Workflow validation, composable execution, transport adapters (ERC-4337, EIP-7702), NAV computation, fee schedule logic, and policy authoring workflows are explicitly out of scope.
 
### The IPermission Interface
 
```solidity
interface IPermission {
    /// @notice Decide whether a manager-submitted transaction is allowed.
    /// @dev Called via staticcall by the kernel. No state changes possible.
    function evaluate(bytes calldata txData, Context calldata ctx) 
        external view returns (bool);
    
    /// @notice Optional: pre-hashed lookup key for fast indexing.
    function discriminator() external view returns (bytes32);
}
 
struct Context {
    address account;        // the Safe
    address manager;        // the delegated signer
    address submitter;      // msg.sender of the dispatch (may be a relayer/paymaster/bundler)
    address target;         // the call target
    bytes4  selector;       // the call selector
    uint256 value;          // msg.value
    uint256 blockTimestamp; // block.timestamp at dispatch (for time-based gates)
    uint256 blockNumber;    // block.number at dispatch
    uint256 configEpoch;    // kernel's current registration epoch for (account, permission);
                            // read-only freshness tag, not part of any signed digest
}
```

The `submitter` is surfaced to permissions but never constrained by the kernel — authority comes from the manager signature alone, which is what makes Sail compatible with relayers, paymasters, and ERC-4337 bundlers. `configEpoch` lets a configurable permission fail closed on a stale configuration (see *EIP-712 Authorization Surface* and the config-epoch binding below).
 
Permissions are called via `staticcall` with a gas cap. Reentrancy is structurally impossible — staticcall prohibits state changes. Gas DOS is bounded — the per-permission cap means a runaway permission reverts without affecting the kernel. A permission that exceeds its gas cap or reverts is treated as a `false` result.
 
### Permission Lifecycle
 
**Registration.** The Permission Signer signs a registration message containing the permission contract address. The kernel adds it to the account's permission list and charges the per-permission deployment fee.
 
**Modification.** Three patterns; each template author picks the one fitting their use case:
 
- *Mutable parameters.* The permission contract exposes setter functions guarded by Permission Signer authorisation. One transaction per parameter change.
- *Deploy new version.* For fully immutable permissions, deploy a new instance with new parameters and call `kernel.replacePermission(oldAddress, newAddress)` to swap the registration atomically. Two transactions, full per-version immutability.
- *Kernel-stored parameters.* The permission contract is a singleton; parameters live in kernel storage keyed by `(account, permissionAddress)`. The permission reads them at evaluate time. One transaction per parameter change, cheap, no per-user contract deployment.
**Revocation.** The Permission Signer signs `kernel.revokePermission(account, permissionAddress)`. The address is removed from the account's list. Immediately effective: the next manager transaction that would have required this permission fails.
 
Two levels of revocation:
- *Revoke a single permission* — narrows the manager's authority.
- *Revoke the entire session* — cuts off the manager completely; all permissions inactive at once.
### EIP-712 Authorization Surface

Every authority-bearing action is an EIP-712 typed signature. The live type strings are:

**Dispatch (selective authorization).** A manager dispatch names exactly one registered permission as the authorizer; that `permission` is bound into the digest, so the signature authorizes one named permission per dispatch and the kernel evaluates that permission alone:

```
Dispatch(address account,address permission,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)
```

**Batch dispatch.** The batch path authorizes one batch-aware permission over a sequence of calls (`callsHash = keccak256(abi.encode(calls))`):

```
DispatchBatch(address account,address permission,bytes32 callsHash,uint256 nonce,uint256 deadline)
```

`dispatch` and `dispatchBatch` consume independent nonce namespaces (`managerNonces` vs `batchNonces`) so the two paths cannot replay across each other.

**Self-registration.** `registerAccount` is gated by a Safe owner-set + threshold signature over:

```
RegisterAccount(address account,address permissionSigner,address manager,address feePolicy,address feeAsset,uint256 deadline)
```

There is no nonce — registration is one-shot (`registered[account]` never clears); the EIP-712 domain pins `chainId` against cross-chain replay.

**Template configuration (epoch-bound).** A `ConfigurablePermission` template binds the kernel's current registration epoch into the configure and identity digests, so a configure signature cannot be replayed across a revoke/re-register cycle:

```
Configure(address account,bytes32 paramsHash,uint256 nonce,uint256 deadline,uint256 epoch)
SetAgentIdentity(address account,bytes32 identityHash,uint256 nonce,uint256 deadline,uint256 epoch)
```

The template EIP-712 **domain version is `"2"`**. The `"1"` → `"2"` bump invalidates all outstanding configure/identity signatures at deploy (no live mandates pre-launch); off-chain signers must read `kernel.registrationEpoch(account, template)`, include the `epoch` field, and use domain version `"2"`.

The remaining kernel registry operations (`RegisterPermission`, `RevokePermission`, `ReplacePermission`, the `*Permissions` batch variants, `RevokeSession`, `ActivateSession`, `SetFeePolicy`) are each their own typehash over `(account, …, nonce, deadline)`; they share the `signerNonces` namespace, which is independent of the manager dispatch nonces.

### Parameterisation
 
Templates use the factory + EIP-1167 minimal proxy pattern. Logic deployed once; users get cheap proxy instances (~45 bytes on-chain) with their own parameters. Each canonical template ships with its own factory.
 
### Fee Model
 
Two independent fee mechanisms, each capped by immutable constants, each tunable within those caps by governance.
 
#### Fee 1 — Per-permission Deployment Fee
 
Charged to the registering account when permissions are registered. Paid as `msg.value` in native ETH. The fee is flat — the same amount per permission, regardless of contract size or template type:
 
```
total fee = permissionRegistrationFee × n_permissions
```
 
`permissionRegistrationFee` is a governance-tunable parameter set at deployment and changed only through the timelock; it is bounded by the immutable per-deployment ceiling `MAX_PERMISSION_FEE_WEI`, itself capped at a constitutional `0.01 ether` (0.01 of the chain's native token). Proceeds go to the protocol treasury; no split. Excess `msg.value` is refunded.
 
Denominated in native ETH (no oracle dependency). The ETH cost is bounded by the ceiling; USD cost varies with ETH price, and governance is expected to retune the rate periodically.
 
#### Fee 2 — Protocol Cut on Manager-collected Fees
 
Charged when a Manager calls `collectFees(amount)` on the kernel. The kernel asks the registered `IFeePolicy` whether `amount` is legitimate; if so, splits:
 
```
protocol_cut    = manager_gross_fee × CURRENT_PROTOCOL_CUT_BPS / 10_000
remainder       = manager_gross_fee - protocol_cut
distributor_cut = (optional, set in the fee policy)
manager_take    = remainder - distributor_cut
```
 
`MAX_PROTOCOL_CUT_BPS = 2_500` (25%) is immutable in source. `CURRENT_PROTOCOL_CUT_BPS` is governance-tunable between 0 and 2,500.
 
The protocol does not compute the gross fee amount. That is the responsibility of the user-deployed `IFeePolicy` contract, which contains the actual schedule — management fee on AUM, performance fee on profits above HWM, hybrid models, custom math.
 
### The IFeePolicy Interface
 
```solidity
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
```
 
NAV computation lives in valuation modules registered alongside the fee policy. The protocol stays oracle-agnostic.
 
### Governance
 
A `SailGovernance` contract holds the team multisig as the initial governance address. Parameter changes and governance transfer flow through a 48-hour `TimelockController`; governance transfer is two-step (`proposeGovernance` then `acceptGovernance`) so control can move later — DAO, ownership token, decision-market, or any chosen mechanism — without risk of a misdirected one-step handoff.
 
**Constitutional caps** (immutable — no governance procedure can change):
- `MAX_PROTOCOL_CUT_BPS = 2_500`
- `MAX_PERMISSION_FEE_WEI` (set at deploy time; itself capped at `0.01 ether`)
**Governance-tunable parameters** (within the caps):
- `currentProtocolCutBps`
- `permissionRegistrationFee`
- `maxPermissionsPerAccount`
Governance can lower or raise parameters within the caps but never raise the caps themselves. The caps bound governance; governance does not bound the caps.
 
## Security Model
 
The trusted surface is roughly 1,150 lines of Solidity (the kernel itself ~820). The remaining protocol behaviour — policy logic, fee schedules, NAV computation — lives in user-deployed contracts called from the kernel via `staticcall` with strict gas caps.
 
This architecture provides three security properties:
 
**Bounded blast radius.** A bug in a permission template affects only users who registered that specific template. A bug in a fee policy affects only accounts using that policy. The kernel itself is small enough to review in full.
 
**Modular reasoning.** Proving the protocol safe decomposes into three independently verifiable claims:
 
1. The kernel handles signature verification, session validity, dispatch, fee splits, and custody isolation correctly.
2. Each canonical permission template enforces what it claims.
3. Composition is by construction — the kernel calls each permission independently; there is no cross-permission interaction.
**Formal verification feasibility.** A trusted core on the order of 1,150 lines is tractable for tools like Certora, Halmos, and Kontrol. Critical invariants (custody isolation, fee cap enforcement, signature verification) are amenable to formal analysis.
 
## Canonical Templates
 
The protocol ships with a reference set of seven launch permission templates covering common patterns. This is the **reference set Octane is auditing post-freeze** — hardened, with honest "what this cannot protect against" boundaries documented in each contract's NatSpec header; it is *not* an "unaudited example" set (that loud framing is reserved for the future experimental set, currently empty). They remain outside the trusted core — a bug in one affects only accounts that registered it — and they are swappable defaults: any contract implementing `IPermission` can be registered instead. Every launch template fails closed on a stale or absent configuration: evaluation denies unless the account is configured *and* its stamped config epoch matches the kernel's current registration epoch for that `(account, permission)`. The launch set:
 
- **SwapPermission** / **SwapPermissionNoOracle** — gate DEX swaps with router and token allowlists, a size cap, output paid to the account, and a slippage floor (against an independent oracle, or the reference pool's own live price).
- **BorrowPermission** — gates lending borrows with protocol and asset allowlists, a size cap, the position credited to the account, and an optional LTV ceiling.
- **DepositPermission** — gates vault and lending-pool deposits with token and target allowlists and a size cap, crediting the position to the account.
- **WithdrawPermission** — pins ERC-20 movements to one configured recipient, with a token allowlist and size cap.
- **TransferPermission** — gates ERC-20 sends to an allowlisted recipient set.
- **ApproveAndCallBatchPermission** — gates an atomic approve / protocol-call / reset batch.

All inherit a shared base, **ConfigurablePermission**, which provides per-account configuration and is not deployed on its own. Each template is published with verified bytecode. UIs display registered templates by their canonical name and parameters — the same model used for verified token contracts on block explorers. Users registering non-canonical permissions opt into them explicitly.
 
## Use Case Coverage
 
The architecture is permission-agnostic. Any onchain primitive — AMM swap, lending deposit/borrow/withdraw, LP position, options trade, restaking deposit, RWA flow — becomes a permission template. Each template gates the relevant call with whatever invariants the manager and user agreed to (router allowlist, slippage bounded against an oracle, LTV cap with liquidation buffer, recipient enforcement, etc.).
 
For venues with off-chain components (e.g., Hyperliquid's order book; perp DEXes with off-chain matching), permissions can constrain the on-chain boundary — bridge deposit amounts, withdrawal recipients, allowed sub-accounts — but cannot constrain off-chain order signing. This is a property of the venue, not the protocol. User-facing documentation must be clear about which categories are fully on-chain-enforceable and which inherit venue-specific trust assumptions.
 
## Out of Scope
 
Things the protocol explicitly does *not* include:
 
- **A policy authoring workflow** (drafts, versions, curation, subject access lists). Off-chain authoring — Git, IDEs, frontends — handles this. The protocol stores deployed permission addresses, not authoring metadata.
- **Workflow execution as a kernel concept.** A workflow is just a kind of permission — "transaction must conform to this multi-step shape."
- **ERC-4337 and EIP-7702 adapters in the kernel.** Peripheral adapter contracts wrap the kernel for users who want those entry points.
- **NAV computation.** Lives in user-deployed valuation modules; oracle choice is an ecosystem concern, not a protocol concern.
- **ERC-8004 identity in the kernel.** Permission modules may consult ERC-8004 registries; the kernel stays agnostic.
- **A registry of curators or template authors.** Marketplace function, handled off-chain.
Each exclusion reduces what the protocol owns. The protocol owns less, by design, so that what it does own is provable, auditable, and stable for years.
 
## Headline Properties
 
| Property | Value |
|----------|-------|
| Trusted core size | ~1,150 lines of Solidity (kernel ~820) |
| Permission evaluation gas cap | 150,000 (single dispatch) / 1,000,000 (batch) |
| Protocol fee cap (immutable) | 25% of manager-collected fees |
| Permission evaluation | `staticcall`, gas-bounded, no state mutation |
| Reentrancy attack surface in evaluation | Zero (by construction) |
| Custody | Native Safe; protocol never holds funds |
| Manager identity types supported | EOA, MPC wallet, multisig, bot, AI agent, smart contract |
| Composable with | Safe, ERC-4337, ERC-7579 |
 
---
 
*Document prepared by the Sail Protocol working group.*
