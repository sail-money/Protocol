# Security Model

This document describes the trust model, security properties, and known limitations of the Sail Protocol v2 smart contract system.

---

## Trusted Core

The **trusted core** consists of two contracts:

| Contract | Approximate LOC | Role |
|---|---|---|
| `SailKernel` | ~985 | Execution engine, permission evaluation, fee accounting |
| `SailGovernance` | ~200 | Protocol parameter store |
| `IFeePolicy`, `IPermission` | ~50 combined | Interface definitions |

The reference permission templates (`SwapPermission`, `BorrowPermission`, `TransferPermission`, `DepositPermission`, `WithdrawPermission`, `ApproveAndCallBatchPermission`) and fee policies (`StandardFeePolicy`) are all **outside the trusted core**. Their correctness is important for the accounts that use them, but a bug in one template or policy does not affect the kernel itself or accounts using other policies.

---

## Bounded Blast Radius

Security failures in peripheral contracts are contained:

- **Template bug:** affects only accounts that have registered that template. Other accounts and the kernel are unaffected.
- **Fee policy bug:** affects only accounts using that policy. The kernel enforces `grossFee <= maxFee` regardless of policy correctness; a buggy policy can overcharge but cannot drain more than `grossFee` allows.
- **Governance compromise:** an attacker controlling the `governance` key can adjust tunable parameters (protocol cut, registration fees, permissions cap) but cannot exceed constitutional caps. They can also update the treasury address and pause/unpause the protocol. They cannot access account funds directly.

---

## Permission Evaluation — `staticcall` Guarantee

All permission evaluations are performed via `staticcall`. This provides two guarantees:

1. **No state mutation.** A permission contract cannot modify any on-chain state during `evaluate()`. Reentrancy into the kernel from within a permission call is impossible by the EVM's `staticcall` semantics.
2. **Isolation.** A revert inside a permission call does not propagate as a revert to the kernel. It is caught and treated as `false` (denial).

---

## Gas Cap — `PERMISSION_GAS_CAP = 150_000`

A single dispatch evaluates exactly one named permission under a fixed 150,000-gas cap (a batch dispatch evaluates one batch-aware permission's `evaluateBatch` under `BATCH_EVAL_GAS_CAP = 1_000_000`). Consequences:

- A runaway permission that loops indefinitely or performs excessive computation exhausts its budget and is treated as denial — the kernel and the caller's remaining gas are unaffected.
- The kernel does not loop over all of an account's registered permissions; each dispatch consults only the one named in the manager's signature. An account may register up to `maxPermissionsPerAccount` (max 100) permissions, but that bounds how many can be attached, not the gas of any single dispatch.

---

## Selective Authorization — Bounded Compromise

Under selective dispatch, each `dispatch()` call names one registered permission as the authorizer. The blast radius of a compromised permission is bounded along two dimensions.

**Scope:** a compromised permission can (incorrectly) authorize calls only when the manager names it as the authorizer for a specific dispatch. It cannot affect dispatches authorized by any other registered permission on the same account.

**Blast radius:** a compromised permission affects only accounts that have registered it, and only for the call shapes its (broken) `evaluate()` incorrectly allows. Other accounts, and dispatches named under different permissions on the same account, are unaffected.

A compromised permission **cannot**:
- Modify state during evaluation (`staticcall` enforces this structurally).
- Exceed the per-call gas cap.
- Influence dispatches authorized by a different named permission.

The worst-case impact is bounded to the specific set of calls the compromised `evaluate()` would allow, and only on accounts that have registered it. The `permissionSigner` can revoke it in a single transaction to immediately contain the damage.

---

## Reentrancy

`nonReentrant` (OpenZeppelin `ReentrancyGuard`) is applied to **every** mutating kernel entry point — including `dispatch`, `dispatchBatch`, `collectFees`, the full permission-registry family (`registerPermission(s)`, `revokePermission(s)`, `replacePermission(s)`), `setManager`, `revokeSession`, `activateSession`, `setFeePolicy`, `recordDeposit`, and `recordWithdrawal`. The guard is load-bearing on `setFeePolicy` in particular, which makes a trusted external call to `IFeePolicy.onAttach` after finalising its own state (CEI), so a buggy/hostile policy cannot re-enter any kernel mutator.

---

## Deny-by-Default

An account with zero registered permissions cannot dispatch. `dispatch` reverts with `PermissionNotRegistered` (the named permission is not in the account's registry). There is no implicit allow-all state. Accounts must explicitly register at least one permission before any transaction can be executed.

---

## Two-Tier Nonces

| Nonce sequence | Guards | Prevents |
|---|---|---|
| `managerNonces` | `dispatch` | Replay of dispatch signatures as registry operations |
| `signerNonces` | All registry operations | Replay of registry signatures as dispatch calls; replay of one registry operation type as another |

The two sequences are independent. Signing a `Dispatch` message does not increment `signerNonces`, and signing a `RegisterPermission` message does not increment `managerNonces`. Cross-operation replay is impossible.

---

## ERC-1271 Smart Contract Signatures

Both the `manager` and `permissionSigner` may be smart contracts (multisigs, MPC wallets, etc.). The kernel detects contract signers by checking `address.code.length > 0` and calls `IERC1271.isValidSignature(digest, sig)`, checking for the `0x1626ba7e` magic value.

This enables institutional setups where:
- The manager is a 2-of-3 multisig held by co-portfolio managers.
- The permissionSigner is a 3-of-5 governance multisig held by compliance officers.

---

## Salt Binding in `createAccount`

`createAccount` binds the CREATE2 salt to the caller **and** the principals it is deploying for:

```solidity
uint256 boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender, permissionSigner, manager, feePolicy)));
// the proxy CREATE2 salt also folds the full safeInitializer:
bytes32 create2Salt = keccak256(abi.encodePacked(keccak256(safeInitializer), boundSalt));
```

An observer who sees the call in the mempool cannot front-run it and register the resulting Safe address, because the salt — and therefore the deployed address — is a function of the original caller's address, the principals, and the Safe initializer (owners/threshold/module). A squatter who copies the parameters gains no authority over the resulting account. Every CREATE2 salt in Sail follows this doctrine of binding the caller and its principals — including the `MandateFactory.deployAndAttach` clone salt, which binds `keccak256(abi.encode(msg.sender, account, salt, keccak256(initData)))` so distinct accounts under a shared relayer caller get distinct, non-colliding clone addresses. Binding the init-data hash additionally ties the predicted clone address to the exact initialization payload, so a registration signature — which authorizes one specific address — cannot be reused with a substituted payload.

`registerAccount` (the self-registration path for an already-deployed Safe) requires **two** gates: `msg.sender == Safe` (the Safe executes the call through its own threshold mechanism) **and** a Safe owner-set + threshold EIP-712 signature over the `RegisterAccount` struct, verified through the Safe core `checkSignatures`. The owner signature is the robust gate: a `Safe.setup` delegatecall helper can forge the storage-based checks (codehash, trusted-singleton, `nonce()`) but holds no owner keys and so cannot produce the signature. The trusted-singleton (`masterCopy()`) check is ordered ahead of any other `ISafe` call, and the proxy codehash is checked against the governance allowlist. No third party can register a Safe on behalf of its signers.

---

## Constitutional Caps

Three parameters in `SailGovernance` can **never** be raised above their deployment values:

| Cap | Nature | Value |
|---|---|---|
| `MAX_PROTOCOL_CUT_BPS` | `constant` in source | 2 500 (25%) |
| `MAX_PERMISSION_FEE_WEI` | `immutable`, set at deploy | `<= 1e36` |
| `MAX_PERMISSIONS_CAP` | `constant` in source | 100 |

No governance action, no matter how large the protocol cut is set to, can exceed these bounds. Raising `MAX_PROTOCOL_CUT_BPS` or `MAX_PERMISSIONS_CAP` requires a full kernel redeployment — they are hardcoded constants.

---

## Two-Step Governance Transfer

`SailGovernance` uses a propose → accept pattern. The current governance nominates a candidate via `proposeGovernance`; the candidate completes the transfer via `acceptGovernance`. A mistyped address cannot accidentally receive governance because they must sign an accepting transaction from that address to finalise the transfer.

---

## Permission Cap — DoS Prevention

The `maxPermissionsPerAccount` limit (governance-tunable, 1–100, hard cap 100) bounds how many permissions an account can attach. Under selective dispatch the kernel never loops over an account's registered permissions — each dispatch evaluates exactly the one permission named in the manager's signature, under the fixed 150,000-gas `PERMISSION_GAS_CAP` (a batch evaluates one batch-aware permission under `BATCH_EVAL_GAS_CAP = 1,000,000`). So per-dispatch evaluation gas is bounded by the cap regardless of how many permissions are registered; the limit caps registry size and per-account storage, not per-dispatch gas.

---

## Empty Batch No-Op

`registerPermissions` and `revokePermissions` return early without consuming a signer nonce when passed an empty array. This prevents a nonce-griefing attack where an adversary could burn a valid signer nonce by submitting an empty signed batch before the legitimate operation.

---

## Permissionless Protocol, Curated Safety-Critical Inputs

Sail is a **permissionless protocol**: anyone may deploy a permission contract, deploy an SMA, and operate as a manager — no protocol approval, allowlist, or gatekeeper stands between a user and the core. Permissions in particular are never curated; any contract implementing `IPermission` can be registered.

A small, explicit set of **safety-critical infrastructure inputs is governance-curated**, because trusting the wrong value there would compromise account custody itself rather than a single account's mandate:

- `trustedSafeFactory` / `trustedSafeSingleton` / `trustedSafeProxyCodehash` — the Safe deployment surface accounts are built on.
- `trustedFeePolicy` — the fee policies the kernel will route `collectFees` through.
- `trustedModuleSetup` — the `Safe.setup` delegatecall helpers the kernel will accept during account creation.

These allowlists are maintained through the 48-hour governance timelock. The protocol is permissionless on the dimensions that matter for openness (who can build, deploy, and manage), and curated only on the narrow infrastructure dimensions where a malicious input would break the custody model. Statements that the protocol is "fully permissionless" should be read with this distinction in mind: permissions and managers are open; the Safe-deployment / fee-policy / module-setup inputs are allowlisted.

---

## Reference Template Set

The seven launch templates (`SwapPermission`, `SwapPermissionNoOracle`, `BorrowPermission`, `DepositPermission`, `WithdrawPermission`, `TransferPermission`, `ApproveAndCallBatchPermission`) are the **hardened reference set**. They are documented with honest "what this cannot protect against" boundaries in each contract's NatSpec header. They are **not** carriers of a loud "UNAUDITED — EXPERIMENTAL" banner — that framing was for unverified example templates and is wrong for the hardened launch set.

The loud `UNAUDITED — EXPERIMENTAL` banner is reserved for the **future experimental template set** (currently empty). The launch templates remain **outside the trusted core** (a bug in one affects only the accounts that registered it, never the kernel), but "outside the trusted core" is a blast-radius statement, not an "unreviewed" statement.

---

## Hardening Mechanisms

The following mechanisms are summarised here; the per-template NatSpec headers and `docs/spec.md` carry the cross-references.

### Config ↔ Registration-Epoch Binding

The kernel tracks a per-`(account, permission)` `registrationEpoch`, a plain monotonic counter bumped only when a permission *leaves* an account's registry (revoke, the removed side of a replace, or a manager-rotation clear) and **not** on registration. The current epoch is pushed into `Context.configEpoch` / `BatchContext.configEpoch` at dispatch time. A `ConfigurablePermission` stamps the epoch into its per-account config at `configure()` time and binds it cryptographically into the configure/identity EIP-712 digest; evaluation **fails closed** — denies unless the account is configured *and* its stamped epoch equals the kernel's current epoch. This closes both the non-atomic configure+register front-run and configure-signature replay across a revoke/re-register cycle.

**Migration note:** the template EIP-712 domain version bump `"1"` → `"2"` invalidates all outstanding configure/identity signatures at deploy. Off-chain signers must read `kernel.registrationEpoch(account, template)`, add the `epoch` field to the struct, and use domain version `"2"`.

### `registerAccount` Hardening

The public self-registration path now requires a Safe owner-set + threshold EIP-712 signature over the `RegisterAccount` struct, verified through the Safe core `checkSignatures`. The trusted-singleton (`masterCopy()`) check is ordered ahead of any other `ISafe` call, and the proxy codehash is checked against the governance allowlist. See *Salt Binding* above.

### `activateSession` Nonce-Epoch Rotation

`revokeSession` bumps the manager and batch nonce epochs (high 128 bits, `NONCE_EPOCH_INCREMENT = 1<<128`). `activateSession` now rotates both epochs as well, so a dispatch or batch-dispatch the manager pre-signed *during* a suspension cannot execute when the session is reactivated — a revoke → activate cycle invalidates every outstanding manager/batch signature.

### Fee-Policy ↔ Asset Binding

A `(account, policy)` pair is pinned to the single fee asset it was first used with, via an explicit `bound` flag (not `address(0)`, since native ETH is a valid asset). Reusing the same policy instance with a different asset reverts `FeePolicyAssetMismatch`. To change an account's fee asset, point it at a fresh policy instance (which carries fresh per-account state — the correct denomination-change pattern).

### Batch Consuming-Call Binding

In `ApproveAndCallBatchPermission`, the consuming call's target must **be** the approved spender, and its consumed asset must be the approved token. The consumed asset is decoded for seven decodable standard-ABI selectors; any non-decodable selector is denied (fail-closed). A pre-batch zero-allowance check denies if a stale allowance already exists on the approved `(token, spender)` pair.

### Borrow LTV Correctness

`BorrowPermission` enforces a fail-closed, amount-based LTV ceiling with correct oracle-decimal handling (the prior fail-open sub-unit rounding is closed). The operator allowlists the **underlying** asset; on the Compound path the cToken target is resolved via `underlying()`, and targets with no `underlying()` (e.g. cETH) are denied — fail-closed.

### `deployAndAttach` Clone Salt

The `MandateFactory.deployAndAttach` clone CREATE2 salt binds the caller, the account, and the initialization payload (`keccak256(abi.encode(msg.sender, account, salt, keccak256(initData)))`), consistent with the kernel's bound-salt doctrine. Binding `keccak256(initData)` ties the predicted address to the exact init payload, so a registration signature cannot be reused with substituted initData. See *Salt Binding* above.

### Swap Native-Value Rejection

`SwapPermission` and `SwapPermissionNoOracle` reject any dispatch carrying `ctx.value != 0`. These are allowance-based ERC-20 → ERC-20 templates, so no ETH is ever forwarded to a router — closing the payable-router / `refundETH()` ETH-sweep vector.

---

## Known Limitations and Operator Responsibilities

### NAV is Not Verified On-Chain

The `currentNav` value in `collectFees` is provided by the manager. The kernel does not verify it against any oracle. A manager who inflates `currentNav` can unlock a higher `maxFee` ceiling from the fee policy, and the resulting fee is bounded only by the account's own balance — in the limit, approaching a full withdrawal of the account. Because the reference fee policy trusts a manager-attested NAV, a manager (in a non-self-managed deployment) could in principle report an inflated NAV and `collectFees` up to the full Safe balance — which is exactly why the reference `StandardFeePolicy` is scoped to self-managed SMAs (the owner controls the manager key *and* the policy's `feeManager` is the owner's own address), and a third-party allocation warrants a fee policy that validates NAV without manager attestation.

**Operator responsibility:** use a fee policy that validates NAV through a trusted oracle if the manager is not fully trusted. `StandardFeePolicy` does not include oracle validation — it accepts manager-provided NAV values directly.

### Oracle Staleness

`IOracle.getPrice` returns an `updatedAt` timestamp. The reference `SwapPermission` and `BorrowPermission` reject any price older than the per-account `maxPriceAgeSec` (and require a non-zero `maxPriceAgeSec` whenever an oracle is configured). With no oracle configured, `SwapPermission` fails closed by requiring a non-zero caller-supplied `amountOutMin`.

**Operator responsibility:** supply an oracle adapter that sets `updatedAt` honestly and configure a sane `maxPriceAgeSec`. The template enforces the freshness bound, but cannot detect an adapter that reports a falsified `updatedAt`.

**Adapter gas budget (F5).** An oracle-using template's own `evaluate` cost is light — one oracle read plus a decode and a couple of `mulDiv`s — but the whole evaluation runs under `PERMISSION_GAS_CAP = 150,000`. A heavy operator-supplied oracle adapter can push the evaluation over that cap, which fails closed (deny). Operators must budget their adapter's gas so a legitimate dispatch does not get denied on out-of-gas.

### Fee-Manager Transfer Is Two-Step

`StandardFeePolicy` transfers fee-manager control via a two-step `proposeFeeManager` → `acceptFeeManager` handshake: the current `feeManager` nominates a successor, and the transfer finalises only when that successor calls `acceptFeeManager`. Mirroring the kernel's two-step governance transfer, this prevents a mistyped or uncontrolled address from taking — and permanently losing — control of the policy: an address that cannot call `acceptFeeManager` never becomes `feeManager`.

**Operator responsibility:** use a multisig as `feeManager`, and confirm the nominated successor can sign before it calls `acceptFeeManager`.

### `BorrowPermission` LTV Enforcement Is Per-Call

`BorrowPermission` evaluates an LTV ceiling at the time of each borrow when both a collateral and a borrow oracle are configured, normalising each oracle value by its reported decimals before forming the ratio. Without oracles configured, only the per-transaction amount cap applies. In both cases the evaluation is per-call: cumulative exposure across multiple borrows is not tracked on-chain.

**Operator responsibility:** configure both oracles to enforce the LTV ceiling, and rely on the lending protocol's own health-factor enforcement — or a position-monitoring permission read via `staticcall` — for cumulative-exposure control.

### `transferFrom` Source Restriction

`WithdrawPermission` and `TransferPermission` require `from == ctx.account` on the `transferFrom` path, so tokens move only from the account itself and never from third parties that have granted the account an allowance.

**Operator responsibility:** confirm the template in use enforces this restriction before relying on it. A custom permission must check `from == ctx.account` explicitly.

### V2 Intermediate Path Tokens

`SwapPermission` validates only `path[0]` and `path[last]` for V2 swaps. Intermediate tokens in multi-hop paths are not checked.

**Operator responsibility:** ensure the full path is acceptable before enabling V2 multi-hop swaps. An intermediate token could be a honeypot or a token the operator would not otherwise permit.

### Safe-Authorized Entry Points Trust the Safe's Own Authorization

Two owner-side entry points authorize the caller as the account itself (`msg.sender == account`): manager rotation (`setManager`) and direct fee collection (`collectFees`). This deliberately delegates authorization to the Safe's own owner threshold — the custody anchor — rather than duplicating a signature check in the kernel.

The consequence is that anything the Safe lets call out on its behalf can reach these entry points without a fresh owner-threshold approval:

- A Safe that **enables a malicious or compromised module** can have that module invoke these functions through the Safe (so the kernel sees `msg.sender == account`).
- A Safe that **sets the kernel as its fallback handler** can have a crafted external call relayed to the kernel with `msg.sender == account`.

Both are outside the protocol's custody model. A module enabled on the Safe can already move the Safe's assets directly, independent of Sail; and configuring the kernel — which is a module, not a handler — as a fallback handler is a misconfiguration with no legitimate purpose.

**Operator responsibility:** do not enable untrusted modules on the Safe, and do not set the kernel as the Safe's fallback handler.

Fee collection is additionally bounded even under such a misconfiguration: `collectFees` pays only the recipient configured by the fee policy (never the caller), the amount is capped by the policy's computed maximum, and collection frequency is rate-limited by the policy's minimum collection interval. Under the self-managed model (`feeManager == owner`) the recipient is the owner, so a module-triggered collection pays the owner.

The same fallback-handler requirement extends to a Safe used as a `permissionSigner`. The advisory counters `recordDeposit` / `recordWithdrawal` authorize on `msg.sender == permissionSigner`, so a `permissionSigner` Safe that sets the kernel as its fallback handler could have those counters inflated by a relayed call. These counters are informational only — no on-chain logic (fee, NAV, or limit) reads them — so the effect is confined to off-chain accounting, and the single requirement (never set the kernel as any Sail-related Safe's fallback handler) prevents it.

It also extends to the configurable permission templates. Their direct (unsigned) paths — `configureDirect` and `setAgentIdentityDirect` — authorize on `msg.sender == permissionSigner`. If a `permissionSigner` Safe sets a template as its fallback handler, a crafted external call could be relayed to reconfigure the account (e.g. widen recipient/router allowlists), which an adversarial manager could then exploit. **Operator requirement:** never set a permission template as a `permissionSigner` Safe's fallback handler. A contract/Safe signer should configure through the signed paths (`configure` / `setAgentIdentity`, verified by EIP-712 / ERC-1271), which a relay cannot forge; the direct paths are a convenience for an EOA signer. As with the kernel and policy, the dangerous state is an attacker-uninducible misconfiguration, not a default.

---

## Design Decisions and Documented Limitations

The following are deliberate design decisions, or scoped documented limitations. They are recorded here so they read as decisions, not oversights.

### Performance fee on deposits / airdrops (accepted, documented)

`computeFee` charges on any NAV rise above the high-water mark with no flow-netting, so a fresh deposit or airdrop can be taxed as profit. This is the §8.2 **manager-attested-NAV** boundary, and it is deliberate: `StandardFeePolicy` computes fees from a NAV the manager reports at collection — the kernel neither computes nor validates NAV. Keeping the kernel out of valuation is a core design choice. Teaching it to measure NAV across lending / trading / borrowing / LP / etc. would expand the trusted core into an unbounded, venue-specific valuation surface; NAV measurement is therefore the manager's responsibility (and that of future NAV-validating permission/fee templates), never the kernel's. The accepted consequence: a manager can crystallise a performance fee on any reported NAV rise (including fresh deposits or airdrops) and, under manager-attested NAV, can in principle report a NAV that extracts up to the account's balance. The collected fee is paid to the policy's `feeRecipient` (its `feeManager`) and the protocol cut to `treasury` — addresses *independent of the account owner*. The no-external-loss property therefore does **not** follow from "`manager == owner`" alone: for a self-managed SMA it holds when the owner controls the manager key **and** the policy's `feeManager` is the owner's own address (`feeManager == owner`), with the protocol cut at 0. `StandardFeePolicy` is the reference policy for exactly this self-managed scope; a shared / multi-tenant instance whose `feeManager` is a third party is outside it. Third-party allocation (`manager != owner`) is out of scope for this policy and requires a NAV-validating `IFeePolicy` that derives NAV from on-chain position adapters rather than manager attestation — arriving with the Marketplace phase.

### Cross-oracle skew (Low, deferred)

Per-feed staleness is checked, but cross-feed contemporaneity (skew between the collateral and borrow feeds) is not. Valid but deferred: a fix adds config-ABI fields with an off-chain-toolkit ripple, and no funds are at risk at launch under the self-managed model. The lending venue's own LTV enforcement is a live backstop.

### `DepositPermission` `mint()` caps shares, not assets (Low, by design)

The `mint(shares)` path bounds shares; the `deposit(assets)` path and both Aave paths cap assets. An asset cap on the mint path would reintroduce a vault price-read into a deliberately oracle-free template. Shares remain bounded — no drain.

### Replayable manager signatures / permissionless submitter (accepted, by design)

Authority derives solely from the manager EIP-712 signature; the submitter is intentionally unconstrained for relayer / paymaster / ERC-4337 compatibility. Nonces are consumed only on successful execution, so a signature seen on a reverted attempt can be replayed until it succeeds or its deadline expires — but replay stays *within the signed envelope*: permissions re-evaluate against live state and recipients/params are fixed by the signature, so an attacker influences only execution timing/quality (no bypass, no fund redirection). The operational mitigation — short deadlines + private-relay submission — lives in the off-chain toolkit.

### `feeAsset` not in the account salt (accepted, bounded)

The `createAccount` salt binds the principals + the `safeInitializer` (owners/threshold/module), so a squatter gains no authority and cannot collect fees. The only mutable field, `feeAsset`, is correctable by the bound `permissionSigner` via `setFeePolicy` in a single transaction — but, because the fee-asset binding pins the current policy to its existing asset *before* the overwrite, a same-instance re-point to a corrected asset reverts `FeePolicyAssetMismatch`. Recovery therefore points the account at a **different** trusted policy instance (the fresh-policy-instance pattern described under *Fee-Policy ↔ Asset Binding* above). The exposure is bounded and recoverable; folding `feeAsset` into the salt would break same-address portability across the live chains.

### Floor rounding in the fee split (Informational, WONTFIX)

The protocol/distributor cut floor-divide a manager-chosen `grossFee` (only `grossFee <= maxFee` is enforced, not `==`). The shortfall accrues to Sail's own treasury/distributor (cut 0 at launch), is bounded to 1–2 base units, and cannot compound intraday (`MIN_COLLECTION_INTERVAL = 1 day`). A manager choosing `grossFee` up to `maxFee` — including under-collecting — is intended behaviour.

### Permissionless `configure` submission / mempool griefing (accepted, by design)

`MandateFactory` is the untrusted UX orchestrator; it holds no privilege, and every inner call is independently signature-authenticated. A submitter cannot change *what* is configured, only *when* a pre-signed bundle lands. A mempool observer replaying a revealed `configureSig` can consume the per-account config nonce so the factory's configure → register bundle reverts, but the resulting state is benign (no permission activated) and recovery needs no new signature (submit `register*` directly with the existing kernel signature). Same family as the replayable-manager-signature limitation above.

The factory's configure → register (and the `replace`) bundle is **two independently signed legs**: the template `configureSig` and the kernel registration signature, which does **not** bind the config params. A mempool observer can therefore front-run the kernel leg. Every outcome is recoverable and stays within the signer-approved envelope: either an older same-epoch config the signer already authorized activates, or the permission ends up **registered-but-unconfigured** — in which case evaluation **fails closed** (the template's `isConfigured` + epoch freshness gate denies every dispatch) until a single `configure()` is applied. To tighten an existing permission's bounds atomically, use `replacePermission` rather than reconfiguring in place; to avoid the race entirely, submit the bundle via private orderflow. This is accepted and documented; binding the config into the kernel registration signature would expand the trusted core and is deliberately not done.

### `Safe.setup` delegatecall target is codehash-pinned (resolved in code)

The shipped helper (`SafeModuleEnabler`) is **immutable** (no constructor, no state, no proxy, no delegatecall-to-mutable, no `selfdestruct`/metamorphic redeploy). Beyond the `trustedModuleSetup` address allowlist, `createAccount` now **pins the setup target's runtime codehash**: the kernel captures the deployed `SafeModuleEnabler`'s codehash at construction into the immutable `EXPECTED_SETUP_CODEHASH`, and every non-zero setup target must match it or the call reverts `UntrustedModuleSetupCodehash`. The immutable-helper rule is therefore enforced **in code**, not merely operationally — even if governance mistakenly allowlisted a *different*, upgradeable helper at a trusted address, its bytecode would not match the pin and account creation would revert. Because the kernel and the helper ship from the same build, the pin matches the deployed enabler by construction.

> **Operational note (now backstopped in code).** `trustedModuleSetup` should still only ever allowlist the immutable `SafeModuleEnabler`, but allowlisting anything else no longer opens the takeover surface: the codehash pin rejects any target whose bytecode differs from the pinned immutable helper.

### Manager-attested-NAV full drain (the §8.2 boundary)

Recorded above under *NAV is Not Verified On-Chain*: because the reference fee policy trusts a manager-attested NAV, a manager in a non-self-managed deployment could in principle report an inflated NAV and `collectFees` up to the full Safe balance. This is why the reference policy is scoped to self-managed SMAs (the owner controls the manager key *and* the policy's `feeManager` is the owner's own address, with the protocol cut at 0); third-party allocation needs a NAV-validating policy.
