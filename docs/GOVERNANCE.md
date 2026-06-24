# SailGovernance — Reference

**File:** `contracts/governance/SailGovernance.sol`

`SailGovernance` is the protocol parameter store. It holds fee caps, permission registration fees, and the protocol cut fraction. The kernel reads from it at account registration time and at each fee collection.

The contract distinguishes two categories of settings:

- **Constitutional caps** — immutable after deployment. No governance action can raise them. They establish hard bounds on all tunable parameters.
- **Tunable parameters** — adjustable by the current `governance` address within those caps.

---

## Timelock and Deployment

All parameter changes flow through a `TimelockController` enforcing a **48-hour delay** (the parameter setters are `onlyTimelock`). The emergency admin may pause the kernel for up to 72 hours without a timelock.

**The timelock is injected, not constructed inline.** `SailGovernance` accepts a pre-deployed `TimelockController` as its final constructor argument rather than building one in its constructor. The timelock is deployed first — with the governance wallet as its sole proposer / executor / canceller, `address(0)` as admin (self-administered), and a 48-hour minimum delay. The `SailGovernance` constructor then validates the injected timelock:

- it reverts with `TimelockDelayMismatch` unless `getMinDelay()` is **exactly** 48 hours (`REQUIRED_TIMELOCK_DELAY`),
- it reverts with `GovernanceNotProposer` unless `initialGovernance` holds `PROPOSER_ROLE`,
- it reverts with `GovernanceNotExecutor` unless `initialGovernance` holds `EXECUTOR_ROLE` (rejects open-executor timelocks where `address(0)` is executor), and
- it reverts with `TimelockNotSelfAdministered` unless the timelock holds the admin role over its own `PROPOSER_ROLE` and `initialGovernance` does not (rejects timelocks deployed with the governance EOA as admin).

The deploy script independently asserts the same self-administration property and additionally checks the deployer does not hold the admin role.

**Why injected?** Extracting the timelock makes every `SailGovernance` constructor argument chain-independent. Combined with deterministic **CREATE2** deployment using a **global, chain-independent salt** (see `script/core/DeployCore.s.sol`), this yields the **same `SailGovernance` address — and the same kernel, Safe initializer, and SMA address — on every chain**. The on-chain security behaviour is identical to constructing the timelock inline; only the deployment transaction that creates the timelock moves into the deploy script.

---

## Constitutional Caps

These values are locked at deployment and cannot be raised by any governance action.

| Name | Value | Description |
|---|---|---|
| `MAX_PROTOCOL_CUT_BPS` | `2_500` | Maximum protocol share of each fee collection (25%). A `constant` in source — cannot change. |
| `MAX_PERMISSION_FEE_WEI` | Set at deploy; constructor reverts if `> 0.01 ether` | Hard ceiling on the per-permission registration fee in wei. An `immutable` set in the constructor, itself bounded by a constitutional ceiling of `0.01 ether` (0.01 of the chain's native token). |
| `MAX_PERMISSIONS_CAP` | `100` | Hard ceiling on the number of permissions per account. Bounds the maximum gas cost of the dispatch loop (`100 × 150,000 gas = 15,000,000 gas`). A `constant` — cannot change. |

`MAX_PERMISSION_FEE_WEI` is the per-deployment immutable ceiling on the registration fee; the constructor reverts if a deployment passes a value above the `0.01 ether` constitutional ceiling.

---

## Governance-Tunable Parameters

These can be adjusted by the current `governance` address, subject to the caps above.

| Name | Default | Range | Description |
|---|---|---|---|
| `currentProtocolCutBps` | `0` | `0 – MAX_PROTOCOL_CUT_BPS` | Protocol's share of each fee collection in basis points. |
| `permissionRegistrationFee` | `0` | `0 – MAX_PERMISSION_FEE_WEI` | Flat fee in wei charged per permission registered. The same amount regardless of contract size or template type. |
| `maxPermissionsPerAccount` | `20` | `1 – MAX_PERMISSIONS_CAP` | Live limit on registered permissions per account. |

**Fee formula** (applied by the kernel at registration time):

```
total fee = permissionRegistrationFee × n_permissions
```

The registration fee is flat — it does not scale with bytecode size. `permissionRegistrationFee` is bounded by `MAX_PERMISSION_FEE_WEI`; the setter reverts if a value above that immutable ceiling is requested.

**Note on `maxPermissionsPerAccount`:** lowering the limit does not retroactively revoke permissions from accounts already at or above the new limit. It only prevents further registrations until those accounts fall below the live limit.

---

## Governance Transfer — Two-Step

Governance transfer requires two steps to prevent irrecoverable loss from a mistyped successor address. A misdirected one-step transfer would leave the protocol with no governance.

```
Step 1: current governance calls proposeGovernance(candidate)
  → sets pendingGovernance = candidate
  → emits GovernanceProposed

Step 2: candidate calls acceptGovernance()
  → sets governance = pendingGovernance
  → clears pendingGovernance
  → emits GovernanceTransferred
```

Calling `proposeGovernance` again before acceptance overwrites `pendingGovernance`, allowing the current governance to cancel or redirect an in-flight nomination.

---

## Functions

### `proposeGovernance(address candidate)`

- **Access:** `onlyTimelock`
- **What it does:** Step 1 of governance transfer. Sets `pendingGovernance = candidate`. No immediate effect on protocol operation.
- **Parameters:** `candidate` — nominated successor; must not be `address(0)`.
- **Events:** `GovernanceProposed(currentGovernance, proposedGovernance)`
- **Errors:** `NotGovernance`, `ZeroAddress`

---

### `acceptGovernance()`

- **Access:** `pendingGovernance` only
- **What it does:** Step 2 of governance transfer. Caller must be the address set in `pendingGovernance`. Completes the transfer and clears `pendingGovernance`.
- **Events:** `GovernanceTransferred(previousGovernance, newGovernance)`
- **Errors:** `NotPendingGovernance`

---

### `setProtocolCutBps(uint256 newBps)`

- **Access:** `onlyTimelock`
- **What it does:** Updates the protocol's share of each fee collection.
- **Parameters:** `newBps` — new basis-point value; must not exceed `MAX_PROTOCOL_CUT_BPS` (2 500).
- **Events:** `ProtocolCutUpdated(oldBps, newBps)`
- **Errors:** `NotTimelock`, `ExceedsProtocolCutCap(requested, cap)`

---

### `setPermissionRegistrationFee(uint256 newFee)`

- **Access:** `onlyTimelock`
- **What it does:** Updates the flat per-permission registration fee.
- **Parameters:** `newFee` — new fee in wei; must not exceed `MAX_PERMISSION_FEE_WEI`.
- **Events:** `PermissionRegistrationFeeUpdated(oldFee, newFee)`
- **Errors:** `NotTimelock`, `FeeExceedsCap(requested, cap)`

---

### `setMaxPermissionsPerAccount(uint256 newLimit)`

- **Access:** `onlyTimelock`
- **What it does:** Sets the live per-account permission limit. Raising the limit increases the maximum dispatch gas cost by up to `PERMISSION_GAS_CAP` gas per additional slot.
- **Parameters:** `newLimit` — new limit; must be `>= 1` and `<= MAX_PERMISSIONS_CAP` (100).
- **Events:** `MaxPermissionsPerAccountUpdated(oldLimit, newLimit)`
- **Errors:** `NotTimelock`, `ExceedsPermissionsCap(requested, cap)` (also thrown when `newLimit == 0`)

---

## Events

| Event | When |
|---|---|
| `GovernanceTransferred(previousGovernance, newGovernance)` | Governance transfer accepted; also emitted at construction with `previousGovernance = address(0)` |
| `GovernanceProposed(currentGovernance, proposedGovernance)` | Step 1 of governance transfer |
| `ProtocolCutUpdated(oldBps, newBps)` | `setProtocolCutBps` succeeds |
| `PermissionRegistrationFeeUpdated(oldFee, newFee)` | `setPermissionRegistrationFee` succeeds |
| `MaxPermissionsPerAccountUpdated(oldLimit, newLimit)` | `setMaxPermissionsPerAccount` succeeds |

---

## Errors

| Error | Meaning |
|---|---|
| `NotGovernance()` | Caller is not the current `governance` address |
| `NotPendingGovernance()` | `acceptGovernance()` caller is not `pendingGovernance` |
| `ExceedsProtocolCutCap(requested, cap)` | Requested `currentProtocolCutBps` exceeds `MAX_PROTOCOL_CUT_BPS` |
| `FeeExceedsCap(requested, cap)` | Requested `permissionRegistrationFee` exceeds `MAX_PERMISSION_FEE_WEI`; also thrown by constructor if `maxPermissionFeeWei > 0.01 ether` |
| `ExceedsPermissionsCap(requested, cap)` | Requested `maxPermissionsPerAccount` is zero or exceeds `MAX_PERMISSIONS_CAP` |
| `NotTimelock()` | Caller of a timelocked setter is not the `TimelockController` |
| `ZeroAddress()` | `initialGovernance` or `candidate` is `address(0)` |
