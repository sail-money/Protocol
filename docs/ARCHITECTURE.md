# Sail Protocol — Architecture

## What Sail Is

Sail is a minimal account-abstraction primitive for on-chain Separately Managed Accounts (SMAs). It gives a designated Manager permission to execute transactions through a client's [Safe](https://safe.global/) multisig, within bounds defined by a mandate — a set of on-chain permission contracts authorized by the account's Permission Signer.

The key insight is that custody never leaves the Safe. The manager does not hold the assets; they hold a cryptographic authorization (a signed dispatch) that the kernel verifies at execution time against the account's registered permissions. Every transaction the manager submits names one registered permission as the authorizer; the kernel evaluates that permission before the Safe executes the call. If the named permission denies the call, nothing happens.

---

## Component Map

| Component | Role |
|---|---|
| `SailKernel` | Central execution engine. Verifies manager signatures, evaluates permissions, executes through the Safe module interface, and handles fee accounting. |
| `SailGovernance` | Protocol parameter store. Holds fee caps, permission registration fees, and the protocol cut. Immutable constitutional caps cannot be raised by any governance action. |
| `IFeePolicy` / `StandardFeePolicy` | Fee computation layer. The kernel delegates fee calculation to the attached policy via `feeRecipient()` (payout target), `computeFee()` (fee ceiling), `recordCollection()` (post-collection state), and the `onAttach()` lifecycle hook (re-anchor on (re)attach). `StandardFeePolicy` implements a management + performance fee schedule with a high-water mark. |
| `IPermission` / permission templates | Pluggable access-control modules. Each permission implements a single `evaluate()` function. A reference set of seven templates ships with the protocol — `SwapPermission`, `SwapPermissionNoOracle`, `BorrowPermission`, `DepositPermission`, `WithdrawPermission`, `TransferPermission`, `ApproveAndCallBatchPermission` — over a shared base, `ConfigurablePermission`. They are swappable defaults; any contract implementing `IPermission` can be registered instead. |

---

## The Three Roles

| Role | Key | Signs | Controls |
|---|---|---|---|
| **Owner** | Holds the Safe | Safe threshold signatures | Asset custody; Safe configuration |
| **PermissionSigner** | `AccountConfig.permissionSigner` | Permission-registry operations (register, revoke, replace, session, fee policy) | What the manager is allowed to do |
| **Manager** | `AccountConfig.manager` | Dispatch calls | Executes transactions within the permitted envelope |

**Retail setup:** all three roles collapse to the same person or multisig. The owner deploys a Safe, registers it with the kernel, and — acting as Permission Signer — authorizes which permissions apply to the account, then also signs and submits dispatch transactions as Manager.

**Institutional setup:** roles separate. A fund management firm holds the Manager key; an independent compliance officer or the client holds the PermissionSigner key and controls what the manager can trade. The Safe signers (Owner) retain custody and can always revoke the module.

For the full role semantics and the authority each key carries, see [spec.md](./spec.md) — *Roles*.

---

## Data Flow — Manager Dispatch

```
Manager (off-chain)
  │
  │  Signs EIP-712 Dispatch struct
  │  {account, permission, target, value, dataHash, nonce, deadline}
  ▼
SailKernel.dispatch()
  │
  ├─ 1. requireRegistered(account)
  ├─ 2. check sessionActive
  ├─ 3. check deadline
  ├─ 4. consume managerNonces[account]++
  ├─ 5. verify EIP-712 manager signature (ECDSA or ERC-1271)
  │
  ├─ 6. SELECTIVE EVALUATION ─────────────────────────────────────────┐
  │       named permission must be registered (_permissionIndex O(1)) │
  │       staticcall permission.evaluate(txData, ctx)                 │
  │       gas: PERMISSION_GAS_CAP (150 000)                           │
  │       revert / OOG / false → PermissionDenied (deny)             │
  └─────────────────────────────────────────────────────────────────── ┘
  │
  └─ 7. ISafe(account).execTransactionFromModule(target, value, data, 0)
           │
           └─ Safe executes the call as a module transaction
```

---

## Selective Authorization and Deny-by-Default

Each `dispatch()` call names one registered permission as the authorizer. The kernel evaluates only that named permission via `staticcall` under a per-call gas cap; other registered permissions on the same account are not consulted.

The mandate is the union of registered permissions; each dispatch selects one as its authorizer. This allows unrelated templates to coexist on one account without falsely denying each other — a swap permission, a borrow permission, and a transfer permission can all be registered, and each call selects the appropriate one.

**Fail-closed:** a permission that returns `false`, reverts, exhausts its gas budget, or returns malformed data causes the dispatch to revert with `PermissionDenied`. There is no partial-allow path.

**Deny-by-default:** if the named permission is not registered for the account, the kernel reverts with `PermissionNotRegistered` before evaluation. There is no implicit allow-all state.

---

## Two-Tier Nonces

The kernel maintains two separate nonce sequences per account:

| Nonce | Map | Guards |
|---|---|---|
| `managerNonces` | `mapping(address => uint256)` | `dispatch` calls |
| `signerNonces` | `mapping(address => uint256)` | All permission-registry operations: `registerPermission`, `revokePermission`, `replacePermission`, `revokeSession`, `activateSession`, `setFeePolicy`, `registerPermissions`, `revokePermissions` |

The separation prevents cross-operation replay. A dispatch signature cannot be replayed as a registry operation and vice versa. (Batch dispatch consumes its own `batchNonces` namespace.) See [spec.md](./spec.md) — *EIP-712 Authorization Surface* — for the full typed-signature and nonce-namespace reference.

---

## How Accounts Connect

```
Safe (custody layer)
  │
  │  registered via createAccount() or registerAccount()
  ▼
SailKernel.configs[account]
  │  AccountConfig {
  │    permissionSigner,
  │    manager,
  │    feePolicy,
  │    sessionActive
  │  }
  │
  ├──► _permissions[account][]
  │      ├── SwapPermission
  │      ├── DepositPermission
  │      └── ... (up to maxPermissionsPerAccount)
  │
  └──► IFeePolicy (StandardFeePolicy or custom)
         └── feeRecipient() / computeFee() / recordCollection() / onAttach()
```

---

## Contract Dependency Diagram

```
SailKernel
  ├── imports SailGovernance          (reads fee params, permission cap)
  ├── imports IPermission             (evaluate interface)
  ├── imports IFeePolicy              (feeRecipient / computeFee / recordCollection / onAttach)
  ├── imports ISafe                   (execTransactionFromModule)
  ├── imports ISafeFactory            (createProxyWithNonce — createAccount only)
  ├── pins SafeModuleEnabler          (deploy-time dependency: the immutable helper must be
  │                                    deployed BEFORE the kernel; the constructor reads its
  │                                    runtime codehash and pins it as the only valid Safe.setup
  │                                    delegatecall target — the codehash pin)
  └── inherits EIP712, ReentrancyGuard

SailGovernance
  └── imports TimelockController      (OpenZeppelin; deployed separately and injected via constructor)

StandardFeePolicy
  ├── implements IFeePolicy
  └── imports Math (OpenZeppelin)

ConfigurablePermission (shared base)
  └── implements IPermission, IConfigurablePermission

SwapPermission / SwapPermissionNoOracle
  ├── extends ConfigurablePermission
  └── imports IOracle (SwapPermission only)

BorrowPermission
  └── extends ConfigurablePermission (imports IOracle)

DepositPermission / WithdrawPermission / TransferPermission
  └── extends ConfigurablePermission

ApproveAndCallBatchPermission
  └── extends ConfigurablePermission, implements IBatchPermission
```

---

## Security Boundaries

The **trusted core** consists of `SailKernel` and `SailGovernance`. These are the contracts every account must trust; the protocol's guarantees are properties of their deployed bytecode.

Permission templates and fee policies are **outside the trusted core**. A bug in a template affects only accounts that registered it; a bug in a fee policy affects only accounts using that policy. The blast radius of any template or policy bug is bounded by the accounts that opted into it.

See [SECURITY_MODEL.md](./SECURITY_MODEL.md) for a complete threat model.
