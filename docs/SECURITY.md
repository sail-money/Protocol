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

`nonReentrant` (OpenZeppelin `ReentrancyGuard`) is applied to all mutating kernel functions:
`registerPermission`, `revokePermission`, `replacePermission`, `registerPermissions`, `revokePermissions`, `dispatch`, `collectFees`.

`revokeSession`, `activateSession`, `setFeePolicy`, `recordDeposit`, and `recordWithdrawal` do not carry reentrancy risk (no external calls to untrusted contracts) and are not marked `nonReentrant`.

---

## Deny-by-Default

An account with zero registered permissions cannot dispatch. `dispatch` reverts with `NoPermissionsRegistered`. There is no implicit allow-all state. Accounts must explicitly register at least one permission before any transaction can be executed.

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

`createAccount` binds the CREATE2 salt to `msg.sender`:

```solidity
uint256 boundSalt = uint256(keccak256(abi.encode(saltNonce, msg.sender)));
```

An observer who sees the call in the mempool cannot front-run it and register the resulting Safe address, because the Salt — and therefore the deployed address — is a function of the original caller's address.

`registerAccount` prevents front-running by requiring `msg.sender == Safe` (the Safe must execute the call through its own threshold mechanism). No third party can register a Safe on behalf of its signers.

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

The `maxPermissionsPerAccount` limit (governance-tunable, 1–100, hard cap 100) prevents a DoS attack where an account registers enough permissions to make its dispatch calls prohibitively expensive. At the hard cap, a dispatch call consumes at most 10 000 000 gas in permission evaluation alone.

---

## Empty Batch No-Op

`registerPermissions` and `revokePermissions` return early without consuming a signer nonce when passed an empty array. This prevents a nonce-griefing attack where an adversary could burn a valid signer nonce by submitting an empty signed batch before the legitimate operation.

---

## Known Limitations and Operator Responsibilities

### NAV is Not Verified On-Chain

The `currentNav` value in `collectFees` is provided by the manager. The kernel does not verify it against any oracle. A manager who inflates `currentNav` can unlock a higher `maxFee` ceiling from the fee policy, and the resulting fee is bounded only by the account's own balance — in the limit, approaching a full withdrawal of the account. This model fits accounts where the manager and the owner are the same party; a third-party allocation warrants a fee policy that validates NAV without manager attestation.

**Operator responsibility:** use a fee policy that validates NAV through a trusted oracle if the manager is not fully trusted. `StandardFeePolicy` does not include oracle validation — it accepts manager-provided NAV values directly.

### Oracle Staleness

`IOracle.getPrice` returns an `updatedAt` timestamp. The reference `SwapPermission` and `BorrowPermission` reject any price older than the per-account `maxPriceAgeSec` (and require a non-zero `maxPriceAgeSec` whenever an oracle is configured). With no oracle configured, `SwapPermission` fails closed by requiring a non-zero caller-supplied `amountOutMin`.

**Operator responsibility:** supply an oracle adapter that sets `updatedAt` honestly and configure a sane `maxPriceAgeSec`. The template enforces the freshness bound, but cannot detect an adapter that reports a falsified `updatedAt`.

### `transferFeeManager` is Single-Step

Unlike the kernel's two-step governance transfer, `StandardFeePolicy.transferFeeManager` is single-step. A mistyped address permanently loses control of the policy.

**Operator responsibility:** use a multisig as `feeManager`. Verify the new address's ability to sign before calling `transferFeeManager`.

### `BorrowPermission` LTV Enforcement Is Per-Call

`BorrowPermission` evaluates an LTV ceiling at the time of each borrow when both a collateral and a borrow oracle are configured, normalising each oracle value by its reported decimals before forming the ratio. Without oracles configured, only the per-transaction amount cap applies. In both cases the evaluation is per-call: cumulative exposure across multiple borrows is not tracked on-chain.

**Operator responsibility:** configure both oracles to enforce the LTV ceiling, and rely on the lending protocol's own health-factor enforcement — or a position-monitoring permission read via `staticcall` — for cumulative-exposure control.

### `transferFrom` Source Restriction

`WithdrawPermission` and `TransferPermission` require `from == ctx.account` on the `transferFrom` path, so tokens move only from the account itself and never from third parties that have granted the account an allowance.

**Operator responsibility:** confirm the template in use enforces this restriction before relying on it. A custom permission must check `from == ctx.account` explicitly.

### V2 Intermediate Path Tokens

`SwapPermission` validates only `path[0]` and `path[last]` for V2 swaps. Intermediate tokens in multi-hop paths are not checked.

**Operator responsibility:** ensure the full path is acceptable before enabling V2 multi-hop swaps. An intermediate token could be a honeypot or a token the operator would not otherwise permit.
