# Sail Protocol — Terminology Mapping (Phase 1 Discovery)

*Branch: `refactor/terminology-alignment` | Date: 2026-05-22*

## Purpose

This document is the output of Phase 1 discovery. It inventories every occurrence of
the key protocol terms across all surfaces and proposes alignment with the agreed
hierarchy. **No code or documentation has been changed.** This file exists for review
before Phase 2 edits begin.

**Agreed hierarchy (not reopened here):**

| Term | Definition |
|---|---|
| **SMA** | The account — a Safe held by the Owner, together with a Mandate |
| **Mandate** | The set of registered Permissions for an SMA; what the Manager is authorized to do |
| **Permission** | An individual rule — a deployed contract implementing `IPermission` |
| **Template** | An example or reusable pattern for building a Permission |

**Unchanged terms:** Manager, Safe, Owner, Permission Signer

---

## 1. CURRENT USAGE INVENTORY

### 1A. Whitepaper (`docs/whitepaper/Sail_Protocol_Whitepaper.tex`)

#### Occurrences of "mandate" / "Mandate"

| Line | Current text (excerpt) | Assessment |
|------|------------------------|------------|
| 149 | "Legal mandates, the substrate that governs traditional SMAs" | Generic English — historical context. OK. |
| 151 | "whose mandate is enforced by smart contracts on every manager transaction" | Abstract sentence — vague on what mandate = . Flagged in §2. |
| 151 | "The Permission Signer authorizes the mandate." | Role description — correct direction. |
| 157 | "With code-enforced mandates and machine managers" | Plural, OK. |
| 162 | keywords: "code-enforced mandates" | OK. |
| 177 | "bounds set by a mandate" | Traditional SMA context — OK. |
| 179 | "The mandate can be revised, narrowed, or revoked at any time." | Traditional SMA property — OK. |
| 187 | "no native concept of a manager bounded by a mandate" | Gap description — OK. |
| 197 | "The mandate — what the agent may and may not do — is enforced by smart contract code" | **Correct under proposed definition.** |
| 197 | "Replacing the legal mandate with a code-enforced mandate" | OK. |
| 201 | "code-enforced mandates enables a new class…" | OK. |
| 203 | "Traditional investment mandates are static." | Traditional context — OK. |
| 205 | "The mandate — expressed as registered permissions — sets the hard outer boundary" | **Correct.** Mandate = permission set. |
| 213 | "the mandate substrate should be minimal" | Systemic reference — OK. |
| 247 | "Legal mandate" | Table — traditional SMA row — OK. |
| 276 | "Authorizes the mandate." | Permission Signer role table — correct. |
| **285** | **`\subsection{The Mandate Object}`** | **Key section — heading fine.** |
| **287** | **"the union of two onchain objects: a Safe held by the Owner … and a list of registered permissions"** | **⚠️ WRONG — includes the Safe in the mandate. See §2.** |
| 291 | "The mandate is therefore enforceable at every transaction." | Correct conclusion, but built on wrong premise at line 287. |
| 381 | "EIP-712 mandate" | TikZ diagram arrow label — Permission Signer's signed operation. Acceptable. |
| 402 | "The Permission Signer authorizes the mandate by EIP-712 signature." | Figure caption — correct. |
| 452 | "The mandate is the union of registered permissions" | **Correct.** Contradicts §3.2 at line 287; this version wins. |
| 461 | "a fixed-grammar mandate language" | Alternative design description — OK. |
| 647 | "permissions can enforce the full set of mandate constraints" | Mandate = permission set — correct. |
| 655 | "cannot exceed its mandate" | Correct. |
| 694 | "mandate-driven" | Adjective — OK. |
| 718 | "a Permission Signer who authorizes the mandate" | Conclusion — correct. |
| 720 | "The mandate must be code, evaluated on every transaction" | Correct. |
| 737 | "whose mandate is enforced by smart contract code" | Glossary: Onchain SMA entry — OK. |

**Notable gap:** "Mandate" has **no standalone glossary entry** in Appendix A. Every other key term (Owner, Permission Signer, Manager, Permission, Shared template) has one. This must be added.

#### Occurrences of "Template" / "template"

| Line | Current text (excerpt) | Assessment |
|------|------------------------|------------|
| 203 | "The same template governs every client." | Traditional investment context — OK. |
| 207 | "the same permission templates, and the same fee model" | Correct: Template = pattern. |
| 317 | "`Shared*Permission` — A starter set of example permission templates" | Correct. |
| 471 | "Sail ships a starter set of example permission templates." | Correct. |
| 478–492 | Table of example templates | Correct. |
| 494 | "These are not the protocol; they are demonstrations of the protocol." | Correct and important. |
| 496–516 | "Shared Multi-Tenant Templates" subsection | Correct. |
| 692 | "any DeFi venue becomes a permission template" | Correct: Template = reusable pattern. |
| 743 | Glossary: "Shared template — A permission contract that serves multiple accounts" | **Partially correct** but does not state the contract IS also a Permission. See §3. |

#### Occurrences of "SMA"

Whitepaper uses "SMA" consistently and correctly throughout (lines 149, 151, 157, 177–222, 255, 275, 287, 634, 637, 655, 692–696, 722, 737). No issues.

#### Occurrences of "Permission" (as noun referring to the concept or contract)

Used correctly throughout — both as the general concept ("registered permissions") and as contract-level identifier. No issues in the whitepaper.

---

### 1B. README.md

| Line | Term | Current text (excerpt) | Assessment |
|------|------|------------------------|------------|
| 5 | mandate | Not used — describes the protocol as "registers permissions, gates manager dispatch through those permissions" | Correct. |
| 46 | mandate | "Authorizes the mandate — decides which permissions apply to the account." | Role table — correct direction. |
| 61 | mandate | ASCII diagram label: "EIP-712 mandate" | Acceptable — refers to the signed operation that establishes the mandate. |

No mandate definition issues in README.md. The README does not attempt to define mandate precisely; it describes the Permission Signer's role correctly.

---

### 1C. docs/spec.md

| Line | Term | Current text (excerpt) | Assessment |
|------|------|------------------------|------------|
| 27 | mandate | "Authorises the mandate — decides which permissions apply to the account." | Correct. |

No issues in spec.md.

---

### 1D. docs/ARCHITECTURE.md

| Line | Term | Current text (excerpt) | Assessment |
|------|------|------------------------|------------|
| 5 | mandate | "It gives a fund manager a signed mandate to execute transactions through a client's Safe multisig" | ⚠️ **"Signed mandate" is ambiguous** — the mandate (permission set) is not itself a signed artefact; the Permission Signer signs individual registration messages. See §2. |
| 7 | mandate | "they hold a cryptographic mandate that the kernel verifies at execution time" | ⚠️ **Imprecise** — the manager holds a signed dispatch message, not the mandate. The mandate is the registered permission set held in the kernel's registry. See §2. |
| 30 | mandate | "signs both the mandate and the transactions themselves" | ⚠️ **Conflates two distinct signing acts** — signing permission registrations (establishing the mandate) and signing dispatches (executing within it). See §2. |
| 70 | mandate | "The mandate is the union of registered permissions" | **Correct.** Keep. |

---

### 1E. docs/KERNEL.md

No "mandate" occurrences. Uses "permission" and "Permission Signer" consistently. No issues.

---

### 1F. docs/TEMPLATES.md

Uses the term "permission templates" consistently and accurately. The document describes
contracts in `contracts/templates/` as both permission contracts and templates (the
dual nature is implicit). No mandate usage. No issues.

---

### 1G. docs/SECURITY.md, docs/INTEGRATION.md, docs/GOVERNANCE.md, docs/FEE_POLICIES.md, docs/agent-identity.md, docs/off-chain-attribution.md

None of these documents use "mandate". They use "permission", "template", "manager",
"permissionSigner", "Safe", and "SMA" consistently and correctly. No issues.

---

### 1H. Solidity contract files (`contracts/`)

**"mandate" in Solidity: ZERO occurrences.** The word does not appear in any `.sol`
file — contract names, function names, event names, error names, struct fields, or
comments. This is the desired state; no protocol-layer Solidity identifier encodes
the mandate concept, because the mandate is a logical abstraction over the permission
registry, not an onchain object.

Solidity uses of "template":

| File | Line | Context | Assessment |
|------|------|---------|------------|
| `SailKernel.sol` | 823 | `// …enables multi-template SMAs` | Inline comment on selective dispatch. ⚠️ Minor: "multi-template" should be "multi-permission". See §5. |
| `contracts/templates/BoundedSwapPermission.sol` | 29, 31 | `/// @dev CLONE TEMPLATE` and `/// @notice Marks this as a single-account template` | Correct — describes deployment pattern. |
| `contracts/templates/BoundedBorrowPermission.sol` | 35, 37 | Same pattern | Correct. |
| `contracts/templates/BoundedDepositPermission.sol` | 27, 29 | Same | Correct. |
| `contracts/templates/BoundedWithdrawPermission.sol` | 19, 21 | Same | Correct. |
| `contracts/templates/TransferTargetPermission.sol` | 35, 37 | Same | Correct. |
| `contracts/templates/BoundedApprovePermission.sol` | 34, 40 | Same | Correct. |
| `contracts/templates/BoundedLiFiPermission.sol` | 61, 67 | Same | Correct. |
| `contracts/templates/GMXPerpPermission.sol` | 14, 16 | Same | Correct. |
| `contracts/templates/GainsNetworkPerpPermission.sol` | 15, 17 | Same | Correct. |
| `contracts/templates/SynthetixPerpPermission.sol` | 14, 16 | Same | Correct. |
| `contracts/templates/AzuroPredictionPermission.sol` | 14, 16 | Same | Correct. |
| `contracts/templates/LimitlessPredictionPermission.sol` | 17, 19 | Same | Correct. |
| `contracts/templates/shared/SharedPendlePermission.sol` | 9 | `/// @notice Multi-account permission template` | Correct — template pattern, also IS a permission. |
| `contracts/templates/shared/SharedAMMLiquidityPermission.sol` | 9 | `/// @notice Multi-account permission template` | Same. |
| `contracts/templates/shared/SharedDeFiBundlePermission.sol` | 11 | `/// @notice Composite multi-account template` | Correct. |
| `contracts/templates/shared/SharedApproveAndCallBatchPermission.sol` | 13, 23, 161 | `/// @dev The batch shape this template authorises` | Correct. |
| `contracts/interfaces/IPermissionIntrospection.sol` | 5–18, 26–28 | "Templates that implement it…", "permissionId identifies the template TYPE" | Correct use — template = type/class of permission. |
| `contracts/interfaces/IConfigurablePermission.sol` | 7, 17 | "A single deployed template can serve unlimited accounts" | Correct. |
| `contracts/interfaces/IAgentIdentityResolver.sol` | 60–62, 66, 103 | "same identity for all accounts that use this template" | Correct. |
| `contracts/interfaces/SailCapabilities.sol` | 5, 17, 37 | "Sail template set", "live Sail template", "Composite template combining…" | See §5. |
| `contracts/factory/PermissionFactory.sol` | 36, 41 | NatSpec: "template.configure" | Correct. |

Solidity uses of "agent":

All occur in `IAgentIdentityResolver.sol` and `BaseSharedPermission.sol` — correctly at
the template/metadata layer only. The kernel (`SailKernel.sol`) does not use "agent".

---

### 1I. Test files (`test/`)

**"mandate" in tests: ZERO occurrences.** No test file uses the word "mandate".

"template" usage in tests is extensive and consistent — always refers to shared
permission contracts serving the template (multi-account) pattern. Key occurrences:

| File | Lines | Pattern | Assessment |
|------|-------|---------|------------|
| `test/SelectiveDispatch.t.sol` | 135, 156, 214–233, 287, 533–635 | "deployed templates", `_signConfigure(template,…)`, section headings | Correct — helpers use `template` as local variable name for a `BaseSharedPermission` instance |
| `test/FactoryDeFi.t.sol` | 11, 36, 291, 306, 404–469 | "Shared template across two Safes", `_attach(account, template, params)` | Correct |
| `test/PermissionIntrospection.t.sol` | 21, 66, 73, 89, 222, 263 | "Template instances", "every template returns…" | Correct |
| `test/PermissionFactory.t.sol` | 103, 150, 153, 161–198, 203, 229 | `address[] memory templates`, test names | Correct |
| `test/BatchDispatch.t.sol` | 202–214, 514, 746–759 | "batch template", "existing IPermission template" | Correct |
| `test/BundlePermission.t.sol` | 8, 10, 41 | "composite template pattern", "ONE template" | Correct |
| `test/AgentIdentity.t.sol` | 238–291 | "template level — no kernel involvement", "non-identity template" | Correct |
| `test/redteam/RedTeam.t.sol` | 587, 589, 1248, 1360–1368 | "Template bypass attacks", `MaliciousTemplateTests` | Correct — adversarial test class names |

---

## 2. MANDATE — CURRENT VS. PROPOSED

### 2.1 Primary problem: whitepaper §3.2 (lines 285–291)

**Current text:**

> In Sail, the mandate is not a document. It is the union of two onchain objects:
> a Safe held by the Owner, which holds the SMA's assets, and a list of registered
> permissions — contracts implementing `IPermission` — against that Safe.
>
> When the Manager submits a transaction, the signature names one registered
> permission as the authorizer. The kernel calls `evaluate()` on that permission
> alone and dispatches the call to the Safe only if it returns `true`. Other
> registered permissions are not consulted during the dispatch.
>
> The mandate is therefore enforceable at every transaction. If the manager attempts
> to swap to an unallowed router, transfer to an unallowed recipient, borrow above
> the configured LTV, or call any function outside the registered permission set,
> the transaction reverts before any state change occurs.

**Problem:** Line 287 defines the mandate as including the Safe. The Safe is the
custody vehicle of the SMA, not a component of the Mandate. The Mandate is the
permission set only.

**Proposed replacement for §3.2 body:**

```latex
In Sail, the mandate is not a document. It is the set of registered permissions for
an SMA: the contracts implementing \code{IPermission} that the Permission Signer has
authorized for the account. The mandate defines what the Manager is authorized to do
--- the specific call shapes, protocols, amounts, recipients, and DeFi operations the
Manager may transact with. Every transaction is evaluated against a named permission
from the mandate; no call outside the registered set can be executed.

The mandate is conceptually distinct from the SMA itself. The SMA consists of a Safe
held by the Owner (which holds the assets) and a mandate (which governs what the
Manager may do with those assets). The Owner holds custody through the Safe; the
Permission Signer establishes the mandate by authorizing which permissions apply.
These are separate roles and separate onchain objects.

When the Manager submits a transaction, the signature names one registered permission
as the authorizer. The kernel calls \code{evaluate()} on that permission alone and
dispatches the call to the Safe only if it returns \code{true}. Other registered
permissions are not consulted during the dispatch.

The mandate is therefore enforceable at every transaction. If the manager attempts
to swap to an unallowed router, transfer to an unallowed recipient, borrow above the
configured LTV, or call any function outside the registered permission set, the
transaction reverts before any state change occurs.
```

### 2.2 Internal contradiction: §5.2 already has the right definition (line 452)

> The mandate is the union of registered permissions; each dispatch selects one as
> its authorizer.

**Assessment:** Correct under the proposed definition. This sentence should be
retained exactly as-is. It contradicts §3.2 and represents the version that wins.

### 2.3 §1.2 already has a correct definition (line 205)

> The mandate — expressed as registered permissions — sets the hard outer boundary
> of what the agent may do.

**Assessment:** Correct. Keep.

### 2.4 Abstract needs a minor precision addition (line 151)

**Current:**
> The protocol formalizes the onchain SMA: a self-custodial account, held by the
> LP through a Safe, whose mandate is enforced by smart contracts on every manager
> transaction.

**Proposed (minor):**
> The protocol formalizes the onchain SMA: a self-custodial account, held by the
> LP through a Safe, whose mandate --- the set of registered permissions --- is
> enforced by smart contracts on every manager transaction.

### 2.5 ARCHITECTURE.md line 5–7 — "signed mandate" and "cryptographic mandate"

**Current (line 5):**
> It gives a fund manager a signed mandate to execute transactions through a
> client's Safe multisig, subject to a set of on-chain constraints called
> permissions.

**Problem:** The mandate (permission set) is not itself a signed artefact. The
Permission Signer signs individual EIP-712 registration messages that collectively
establish the mandate.

**Proposed:**
> It gives a designated Manager permission to execute transactions through a
> client's Safe multisig, within bounds defined by a mandate — a set of
> on-chain permission contracts authorized by the account's Permission Signer.

**Current (line 7):**
> The manager does not hold the assets; they hold a cryptographic mandate that
> the kernel verifies at execution time.

**Problem:** The manager holds a signed dispatch message, not the mandate. The
mandate lives in the kernel's permission registry.

**Proposed:**
> The manager does not hold the assets; they hold a cryptographic authorization
> (a signed dispatch) that the kernel verifies at execution time against the
> account's registered permissions.

### 2.6 ARCHITECTURE.md line 30 — "signs both the mandate and the transactions"

**Current:**
> The owner deploys a Safe, registers it with the kernel, and signs both the
> mandate and the transactions themselves.

**Problem:** Conflates two distinct signing operations: signing permission
registrations (establishing the mandate, done as Permission Signer) and signing
dispatches (executing within it, done as Manager).

**Proposed:**
> The owner deploys a Safe, registers it with the kernel, and — acting as Permission
> Signer — authorizes which permissions apply to the account, then also signs and
> submits dispatch transactions as Manager.

### 2.7 Missing glossary entry for "Mandate" in Appendix A

No glossary entry for "Mandate" exists. All other core roles and concepts have entries.

**Proposed addition** (insert after the "Onchain SMA" row):

```latex
Mandate & The set of registered permissions for an SMA; what the Manager is
authorized to do. Distinct from the account itself: the Safe holds the assets,
the mandate governs what the Manager may do with them. Established and maintained
by the Permission Signer through EIP-712 authorization.\\
```

---

## 3. HIERARCHY ALIGNMENT

All places where the SMA/Mandate/Permission/Template relationship is described
(explicitly or implicitly), with assessment and proposed update.

| Location | Current description | Status | Proposed change |
|---|---|---|---|
| Whitepaper §3.2 line 287 | Mandate = Safe + permission list | **Wrong** | Full rewrite — §2.1 above |
| Whitepaper §5.2 line 452 | "The mandate is the union of registered permissions" | **Correct** | Keep |
| Whitepaper §1.2 line 205 | "The mandate — expressed as registered permissions" | **Correct** | Keep |
| Whitepaper §5.4 intro (line 471) | "example permission templates. Table lists them." | **Correct** but incomplete | Add: each listed contract is both a deployed Permission (registered in the kernel) and a Template (reusable pattern). |
| Whitepaper §5.5 (line 496) | "Shared Multi-Tenant Templates" — one contract, multiple accounts | **Correct** | Keep |
| Whitepaper Appendix A — "Shared template" (line 743) | "A permission contract that serves multiple accounts via per-account configuration storage" | **Partially correct** — does not name it as also being a Permission | Append: "; each shared template is itself a deployed Permission contract." |
| README.md roles table line 46 | Permission Signer: "Authorizes the mandate" | **Correct** | Keep |
| README.md diagram line 61 | "EIP-712 mandate" | Acceptable | Optionally refine to "EIP-712 permission authorization" for precision; current form is defensible |
| ARCHITECTURE.md line 70 | "The mandate is the union of registered permissions" | **Correct** | Keep |
| ARCHITECTURE.md line 5–7 | "signed mandate", "cryptographic mandate" | ⚠️ Imprecise | Rewrite — §2.5 above |
| ARCHITECTURE.md line 30 | "signs both the mandate and the transactions" | ⚠️ Conflates signing acts | Rewrite — §2.6 above |
| spec.md line 27 | "Authorises the mandate — decides which permissions apply" | **Correct** | Keep |
| TEMPLATES.md intro | Uses "permission templates" | **Correct** | No change; optionally add one sentence clarifying dual nature (each is both a Permission and a Template) |

---

## 4. CONTRACT / IDENTIFIER NAMING REVIEW

### 4.1 Core contracts and interfaces

| Identifier | Current name | Consistent with hierarchy? | Proposed name | ABI impact | Notes |
|---|---|---|---|---|---|
| `SailKernel` | `SailKernel` | ✅ Yes | No change | N/A | |
| `SailGovernance` | `SailGovernance` | ✅ Yes | No change | N/A | |
| `PermissionFactory` | `PermissionFactory` | ✅ Yes | No change | N/A | Factory that orchestrates Permission registration |
| `BaseSharedPermission` | `BaseSharedPermission` | ✅ Yes | No change | N/A | Abstract base for shared multi-tenant Permission templates |
| `IPermission` | `IPermission` | ✅ Yes | No change | N/A | **Must not rename — core interface** |
| `IConfigurablePermission` | `IConfigurablePermission` | ✅ Yes | No change | N/A | |
| `IBatchPermission` | `IBatchPermission` | ✅ Yes | No change | N/A | |
| `IPermissionIntrospection` | `IPermissionIntrospection` | ✅ Yes | No change | N/A | |
| `IAgentIdentityResolver` | `IAgentIdentityResolver` | ✅ Yes | No change | N/A | |
| `IFeePolicy` | `IFeePolicy` | ✅ Yes | No change | N/A | |
| `SailCapabilities` | `SailCapabilities` | ✅ Yes | No change | N/A | |
| `StandardFeePolicy` | `StandardFeePolicy` | ✅ Yes | No change | N/A | |

### 4.2 Shared template contracts (`contracts/templates/shared/`)

Each of these contracts is both:
1. **A Permission** — implements `IPermission.evaluate()`, is registered in the kernel's permission registry, and gates dispatch
2. **A Template** — one deployment serves many accounts; demonstrates a reusable pattern

Under the agreed hierarchy this dual nature is correct and the naming is consistent:
the `*Permission` suffix in the identifier reflects that the contract IS a Permission.
The Template designation lives in prose and documentation, not in the identifier.

| Identifier | Consistent? | Notes |
|---|---|---|
| `SharedBoundedSwapPermission` | ✅ Yes | IS a Permission; also serves as a Template |
| `SharedBoundedBorrowPermission` | ✅ Yes | Same |
| `SharedTransferTargetPermission` | ✅ Yes | Same |
| `SharedDeFiBundlePermission` | ✅ Yes | Same |
| `SharedPendlePermission` | ✅ Yes | Same |
| `SharedAMMLiquidityPermission` | ✅ Yes | Same |
| `SharedApproveAndCallBatchPermission` | ✅ Yes | IS a Permission AND implements IBatchPermission; also serves as a Template |

### 4.3 Standalone / clone template contracts (`contracts/templates/`)

Same analysis as §4.2. All correctly named with `*Permission` suffix.

| Identifier | Consistent? | Notes |
|---|---|---|
| `BoundedSwapPermission` | ✅ Yes | IS a Permission; clone-template deployment pattern |
| `BoundedBorrowPermission` | ✅ Yes | Same |
| `BoundedDepositPermission` | ✅ Yes | Same |
| `BoundedWithdrawPermission` | ✅ Yes | Same |
| `TransferTargetPermission` | ✅ Yes | Same |
| `BoundedApprovePermission` | ✅ Yes | Same |
| `BoundedLiFiPermission` | ✅ Yes | Same |
| `GMXPerpPermission` | ✅ Yes | Same |
| `GainsNetworkPerpPermission` | ✅ Yes | Same |
| `SynthetixPerpPermission` | ✅ Yes | Same |
| `AzuroPredictionPermission` | ✅ Yes | Same |
| `LimitlessPredictionPermission` | ✅ Yes | Same |

### 4.4 Struct fields and EIP-712 type strings

All are consistent with the agreed hierarchy. No renames required.

| Identifier | File | Consistent? | Notes |
|---|---|---|---|
| `AccountConfig.permissionSigner` | `SailKernel.sol:161` | ✅ Yes | Matches role name |
| `AccountConfig.manager` | `SailKernel.sol:163` | ✅ Yes | Matches role name |
| `AccountConfig.feePolicy` | `SailKernel.sol:165` | ✅ Yes | |
| `Context.account` | `IPermission.sol:9` | ✅ Yes | The Safe account |
| `Context.manager` | `IPermission.sol:11` | ✅ Yes | The delegated signer |
| `Context.submitter` | `IPermission.sol:13` | ✅ Yes | `msg.sender` of dispatch |
| `PermissionInfo.permission` | `SailKernel.sol:175` | ✅ Yes | |
| `PermissionInfo.isBatch` | `SailKernel.sol:177` | ✅ Yes | |
| `PermissionInfo.hasIntrospection` | `SailKernel.sol:179` | ✅ Yes | |
| `PermissionInfo.permissionId` | `SailKernel.sol:181` | ✅ Yes | |
| `PermissionInfo.permissionVersion` | `SailKernel.sol:183` | ✅ Yes | |
| `DISPATCH_TYPEHASH` type string | `SailKernel.sol:89` | ✅ Yes | |
| `REGISTER_PERMISSION_TYPEHASH` type string | `SailKernel.sol:98` | ✅ Yes | |
| `REVOKE_PERMISSION_TYPEHASH` type string | `SailKernel.sol:104` | ✅ Yes | |
| `REPLACE_PERMISSION_TYPEHASH` type string | `SailKernel.sol:110` | ✅ Yes | |
| `DISPATCH_BATCH_TYPEHASH` type string | `SailKernel.sol:149` | ✅ Yes | |

### 4.5 Directory naming

| Directory | Status | Notes |
|---|---|---|
| `contracts/templates/` | ⚠️ Minor tension | Named "templates" but contains Permission contracts. Under the hierarchy these ARE Permissions that follow Template patterns. Renaming to `contracts/permissions/` would be more strictly consistent but would break every `import` path in the test suite and all contracts. **Recommendation: leave as-is.** The NatSpec already calls them "permission templates"; the contract identifiers use `*Permission`. The directory name is a useful grouping by purpose, not a misrepresentation. |
| `contracts/templates/shared/` | Same | Same recommendation. |

### 4.6 `PermissionFactory` event parameter names: `template`

The factory emits events where the parameter name for a permission contract address
is `template` (e.g., `Attached(account, template, paramsHash)`). This is technically
using "template" where the strict protocol term is "permission".

| Event | Current param | Issue | Proposed param | ABI impact |
|---|---|---|---|---|
| `Attached(account, template, paramsHash)` | `address indexed template` | Uses "template" for permission address | `permission` | Yes — event ABI includes param names |
| `Reconfigured(account, template, paramsHash)` | `address indexed template` | Same | `permission` | Yes |
| `BatchAttached(account, templates)` | `address[] templates` | Same | `permissions` | Yes |
| `Replaced(account, oldTemplate, newTemplate)` | `address indexed oldTemplate, newTemplate` | Same | `oldPermission, newPermission` | Yes |
| `Detached(account, template)` | `address indexed template` | Same | `permission` | Yes |
| `BatchDetached(account, templates)` | `address[] templates` | Same | `permissions` | Yes |

**Assessment:** The "template" names are not wrong — these contracts follow the template
pattern. However, the factory's event vocabulary would be more consistent with the
protocol layer if it used "permission". Given pre-audit, pre-mainnet status this rename
is acceptable. **Decision needed before Phase 2 — see §7.**

---

## 5. COMMENTS AND NATSPEC PASS

NatSpec and inline comments that use Mandate/Permission/Template in ways that need
precision or are inconsistent with the agreed hierarchy:

### 5.1 `SailKernel.sol` inline comment, line 823

**Current:**
```
// The new model enables multi-template SMAs
// where unrelated permissions (e.g., Uniswap, Aave, Transfer) coexist
```

**Problem:** "multi-template SMAs" — an SMA does not have multiple templates; it has
multiple registered Permissions, each of which may follow a Template pattern.

**Proposed:**
```
// The new model enables multi-permission SMAs
// where unrelated permissions (e.g., Uniswap, Aave, Transfer) coexist
```

### 5.2 `SailCapabilities.sol` lines 37–38

**Current:**
```solidity
/// @notice Capability declared by SharedDeFiBundlePermission.
///         Composite template combining swap, borrow, and transfer into one permission.
```

**Minor imprecision:** `SharedDeFiBundlePermission` is one Permission (not multiple).
The "template" description is fine but "Composite template combining … into one
permission" is slightly awkward.

**Proposed:**
```solidity
/// @notice Capability declared by SharedDeFiBundlePermission.
///         Gates swap, borrow, and transfer operations through a single composite permission.
```

### 5.3 `IPermissionIntrospection.sol` — uses "template" throughout

**Assessment:** Correct and intentional. `permissionId` is documented as identifying
the "template TYPE" (i.e., the class of permission). This language is accurate and
should be kept.

### 5.4 `IAgentIdentityResolver.sol` — "template" in comments

**Assessment:** All uses of "template" in this file are correct — they describe
permission contracts that serve as templates (multi-tenant deployment pattern). No
changes needed.

### 5.5 `contracts/factory/PermissionFactory.sol` NatSpec lines 36, 41

**Current:**
```
/// The factory holds no trust: each inner call (template.configure and
/// kernel.registerPermission) is independently signature-authenticated.
///
/// Anyone can deploy a template that implements IConfigurablePermission and have
/// it work with this factory immediately
```

**Assessment:** Acceptable — the factory calls `template.configure` on permission
contracts that follow the template pattern. This phrasing is clear in context. Low
priority; could replace "template" with "permission contract" if desired in Phase 2.

### 5.6 All standalone template `@dev CLONE TEMPLATE` headers

**Assessment:** Correct. "CLONE TEMPLATE" accurately describes the deployment
pattern (EIP-1167 clone per account). No changes needed.

---

## 6. WHITEPAPER CHANGE LIST

### Abstract (lines 147–162)

| Ref | Current (excerpt) | Change needed? | Proposed |
|---|---|---|---|
| 151 | "whose mandate is enforced by smart contracts" | Minor | Insert "(the set of registered Permissions)" after "mandate" |
| 157 | "code-enforced mandates" | No | Keep |
| 162 | keywords: "code-enforced mandates" | No | Keep |

### Section 1 — Introduction

No changes needed in §1.1 or §1.3 (Agentic Dynamic Strategies). Section 1.2 (line 197,
205) already has the correct definition. Keep.

### Section 2 — Problem Statement

Table at line 247: "Legal mandate" in the traditional SMA row — OK, historical context.
No changes needed.

### Section 3.1 — Three Roles

Table at line 276: "Authorizes the mandate." — Correct. Keep.

### Section 3.2 — The Mandate Object ⚠️ FULL REWRITE REQUIRED

**Location:** `docs/whitepaper/Sail_Protocol_Whitepaper.tex`, lines 285–291.

Replace the body of §3.2 with the text specified in §2.1 above. Summary of changes:
1. Remove the statement that mandate includes the Safe.
2. Define mandate as the permission set only.
3. Explicitly state that the SMA = Safe (custody) + Mandate (permission set).
4. Preserve the dispatch-mechanics paragraph (currently line 289) unchanged.
5. Preserve the enforcement paragraph (currently line 291) unchanged.

### Section 4 — Architecture

No changes needed. The dispatch flow description is correct.

Figure caption (line 402): "The Permission Signer authorizes the mandate by EIP-712 signature." — Correct. Keep. The TikZ label "EIP-712 mandate" (line 381) is also acceptable.

### Section 5 — Permission System

| Ref | Current | Change needed? | Proposed |
|---|---|---|---|
| §5.1 line 421 | "A permission is a contract implementing a single interface" | No | Keep |
| §5.2 line 452 | "The mandate is the union of registered permissions" | No — **correct** | Keep |
| §5.3 line 457 | "Full Expressiveness" | No | Keep |
| §5.4 line 471 | "Sail ships a starter set of example permission templates" | Minor | After the sentence, add: "Each listed contract is both a deployed Permission — eligible for kernel registration — and a Template: a reusable pattern that demonstrates the permission interface across a specific DeFi primitive." |
| §5.5 line 496 | "Shared Multi-Tenant Templates" | No | Keep |

### Section 6 — Fee Model

No changes needed. No mandate or template issues.

### Sections 7–11 — Governance, Security, Use Cases, Personalized Finance, Non-Goals

| Ref | Current | Change needed? |
|---|---|---|
| §9 line 655 | "cannot exceed its mandate" | No — correct |
| §10 line 694 | "mandate-driven" | No — correct |
| §12 Conclusion line 718 | "Permission Signer who authorizes the mandate" | No — correct |
| §12 line 720 | "The mandate must be code" | No — correct |

### Appendix A — Glossary ⚠️ ADD MANDATE ENTRY; UPDATE SHARED TEMPLATE ENTRY

**Add Mandate entry** (after "Onchain SMA" row):

```latex
Mandate & The set of registered permissions for an SMA; what the Manager is
authorized to do. Distinct from the account itself: the Safe holds the assets, the
mandate governs what the Manager may do with them. Established by the Permission
Signer through EIP-712 authorization.\\
```

**Update "Shared template" entry** (line 743) — append to existing text:

Current: "A permission contract that serves multiple accounts via per-account configuration storage; the recommended deployment pattern."

Proposed: "A permission contract deployed once that serves multiple accounts via per-account configuration storage; the recommended deployment pattern. Each shared template is itself a deployed Permission registered in the kernel's permission registry."

---

## 7. BREAKING-CHANGE INVENTORY

Based on the full audit, **no public Solidity identifiers strictly require renaming.**
All contract names, interface names, public function names, public events, public
errors, and public struct fields are consistent with the agreed hierarchy.

The single area where a rename could improve protocol-layer precision is the
`PermissionFactory` event parameter names:

### 7.1 PermissionFactory event parameter names: `template` → `permission`

| Identifier | Old name | New name | ABI impact | Source-import impact | Test files affected |
|---|---|---|---|---|---|
| `Attached` event param 2 | `template` | `permission` | **Yes** — event ABI includes param names | No — callsites don't reference param by name | `test/PermissionFactory.t.sol`, `test/FactoryDeFi.t.sol` |
| `Reconfigured` event param 2 | `template` | `permission` | **Yes** | No | `test/PermissionFactory.t.sol` |
| `BatchAttached` event param 2 | `templates` | `permissions` | **Yes** | No | `test/PermissionFactory.t.sol` |
| `Replaced` event params 2–3 | `oldTemplate`, `newTemplate` | `oldPermission`, `newPermission` | **Yes** | No | `test/PermissionFactory.t.sol` |
| `Detached` event param 2 | `template` | `permission` | **Yes** | No | `test/PermissionFactory.t.sol` |
| `BatchDetached` event param 2 | `templates` | `permissions` | **Yes** | No | `test/PermissionFactory.t.sol` |

**ABI note:** Event parameter *names* appear in the ABI JSON and in off-chain event
parsers that reference fields by name (ethers.js, viem, etc.). Renaming them is a
breaking change for any consumer that decodes events by name rather than by index.
Protocol is pre-audit and pre-mainnet — acceptable to rename now.

**Recommendation:** Rename. The gain is protocol-layer consistency between factory
vocabulary and kernel vocabulary. The factory is the canonical orchestrator for
Permission registration; its events should use "permission" as the kernel's events
(`PermissionRegistered`, `PermissionRevoked`) do.

### 7.2 `SailKernel.sol` inline comment (line 823)

Not a breaking change — comment only. Change "multi-template" to "multi-permission".

### 7.3 Directory rename `contracts/templates/` → `contracts/permissions/`

**Not recommended.** High blast radius (all import paths in test/ and contracts/ must
update), low conceptual benefit (the `*Permission` contract identifiers already use
the correct term). Leave directory names unchanged.

---

## 8. PROPOSED PHASE 2 EXECUTION PLAN

All identified changes are documentation or comments — **no ABI-breaking Solidity
identifier renames are required** except the optional `PermissionFactory` event
parameter rename (§7.1, requires explicit approval).

### Commit sequence

#### (a) Whitepaper edits — `docs/whitepaper/Sail_Protocol_Whitepaper.tex`

1. **§3.2 full rewrite** — replace the two-paragraph "union of two onchain objects" body with the four-paragraph corrected version (§2.1).
2. **Abstract line 151** — insert "(the set of registered Permissions)" after "mandate" on first occurrence.
3. **§5.4 intro** — add one sentence clarifying that listed contracts are both Permissions and Templates.
4. **Appendix A** — add Mandate glossary entry (§2.7).
5. **Appendix A** — append to "Shared template" entry that it is also a deployed Permission (§3, last row).

#### (b) README + docs Markdown edits

Files: `README.md`, `docs/ARCHITECTURE.md`, `docs/TEMPLATES.md`

1. **ARCHITECTURE.md lines 5–7** — rewrite "signed mandate" and "cryptographic mandate" passages (§2.5).
2. **ARCHITECTURE.md line 30** — rewrite "signs both the mandate and the transactions" (§2.6).
3. **ARCHITECTURE.md line 70** — already correct; keep.
4. **README.md line 61** — optionally refine "EIP-712 mandate" label to "EIP-712 permission authorization"; current form is defensible — owner decides.
5. **TEMPLATES.md** — add one introductory sentence clarifying the dual nature of template contracts (they are both Permissions and Templates).
6. **spec.md** — no changes needed.

#### (c) NatSpec and inline comment edits

Files: `contracts/core/SailKernel.sol`, `contracts/interfaces/SailCapabilities.sol`

1. **SailKernel.sol line 823** — "multi-template SMAs" → "multi-permission SMAs".
2. **SailCapabilities.sol lines 37–38** — rephrase `SharedDeFiBundlePermission` capability description (§5.2); low priority, owner decides.

#### (d) PermissionFactory event parameter rename (REQUIRES EXPLICIT APPROVAL)

Files: `contracts/factory/PermissionFactory.sol`, `test/PermissionFactory.t.sol`, `test/FactoryDeFi.t.sol`

Rename all `template` / `templates` event parameters to `permission` / `permissions`
as listed in §7.1. Update test assertions that decode events by param name.

#### (e) Test comment updates (optional cleanup)

Files: any test file

Most test uses of "template" are accurate and intentional. Optional cleanup:
- Comments in `test/SelectiveDispatch.t.sol` section headers: "MULTI-TEMPLATE
  COEXISTENCE" → "MULTI-PERMISSION COEXISTENCE"
- `test/redteam/RedTeam.t.sol` class name `MaliciousTemplateTests` — acceptable as-is
  (adversarial test; "template" accurately describes what is being attacked)

### Sequencing constraints

- (a), (b), (c) have no inter-dependencies and can land in any order.
- (d) must be resolved before (e) since (e) updates test assertions.
- Recommended: land (a) first (establishes canonical definition), then (b), then (c),
  then resolve (d) decision, then (e) if (d) is approved.

### Summary of Phase 2 decisions required from owner

| # | Decision | Options |
|---|---|---|
| D1 | README.md "EIP-712 mandate" diagram label | Keep as-is (defensible) OR change to "EIP-712 permission authorization" |
| D2 | PermissionFactory event param rename (`template` → `permission`) | Rename (preferred; ABI-breaking) OR leave as-is (acceptable) |
| D3 | `SailCapabilities.sol` DEFI_BUNDLE description rewrite | Apply (low priority) OR leave as-is |

---

*End of Phase 1 discovery. Awaiting review of this mapping before Phase 2 begins.*
