# Octane Warning Responses

Paste each block into the corresponding warning on the Octane web UI.

---

## W1 — Missing prohibition of Safe self-target in dispatch/dispatchBatch

Resolved. `dispatch`, `dispatchBatch`, and `previewBatch` now reject any call where `target == account` (the Safe itself), reverting with `AccountSelfTarget`. This closes the path where a malicious or compromised manager could trigger a Safe self-call via the module interface — which satisfies `onlySelf` inside Safe v1.4.1 — and reconfigure the Safe (enable a malicious module, change owners/threshold, set a malicious guard or fallback handler) or steal funds. The check is applied at the kernel level unconditionally, so no individual permission needs to replicate it. PR #13.

---

## W2 — Unconditional fee state update on partial/zero collection in collectFees/StandardFeePolicy

Resolved. `collectFees` now guards against advancing fee policy state when the collected amount is zero. HWM and `lastCollectionTimestamp` are only updated via `recordCollection` after a non-zero transfer succeeds. PR #9.

---

## W3 — Missing oracle freshness enforcement in oracle-consuming permissions

Resolved. All five oracle-consuming permission templates (`BoundedSwapPermission`, `BoundedBorrowPermission`, `SharedBoundedSwapPermission`, `SharedBoundedBorrowPermission`, `SharedDeFiBundlePermission`) now accept a `maxPriceAgeSec` parameter covering both the swap-domain slippage check and the borrow-domain LTV check.

When `maxPriceAgeSec > 0`, the `updatedAt` timestamp returned by `IOracle.getPrice` is validated: the permission denies if `updatedAt == 0` (oracle never updated) or `block.timestamp - updatedAt > maxPriceAgeSec` (price stale). For borrow permissions with two oracles, both collateral and borrow prices must pass the freshness check independently. Setting `maxPriceAgeSec = 0` preserves opt-out behaviour for deployments that enforce freshness at the adapter level.

Sequencer-uptime check (L2 Chainlink sequencer feed): intentionally out of scope for this fix. It requires a deployment-specific sequencer oracle address and grace-period configuration that cannot be expressed as a single generic parameter. This is a known residual risk for L2 deployments; operators must enforce sequencer health at the oracle adapter layer. PR #14.

---

## W4 — Mutable/upgradeable fee policy trusted in collectFees allows post-approval fee redirection

Resolved. `SailGovernance` now maintains a `trustedFeePolicy` allowlist (timelock-gated via `setTrustedFeePolicy(address, bool)`). `registerAccount` and `setFeePolicy` both revert with `UntrustedFeePolicy` if the provided policy is not on the allowlist. A compromised or upgraded policy address that was not pre-approved cannot be substituted. PR #9.

---

## W5 — code.length-based signer type detection in _recoverOrERC1271 causes denial under EIP-7702-style transient code

Resolved. `_recoverOrERC1271` now always attempts ECDSA recovery first. Only if the recovered address does not match the expected signer does it fall back to ERC-1271 `isValidSignature`. This removes the `code.length` branch entirely — EOAs work regardless of transient code presence, and ERC-1271 contracts are still supported. PR #13.

---

## W6 — Manager-only fee crystallization causes protocol/distributor/fee-recipient revenue loss

Resolved. `collectFees` now accepts calls from the account's `manager`, `account` (Safe itself), or `permissionSigner` — not only the manager. This ensures fee collection is not blocked if the manager is unresponsive or adversarial. PR #13.

---

## W7 — Direct-caller-only authorization in collectFees with non-forwarding ERC-1271 manager causes blocked fee collection

Resolved as part of the W6 fix. Expanding `collectFees` access to include `account` and `permissionSigner` means fee collection is never gated solely on the manager's ability to directly call the kernel. PR #13.

---

## W8 — Full returndata materialization after staticcall in permission evaluation causes gas-exhaustion DoS instead of fail-closed

Resolved. `_evaluatePermission` now decodes the staticcall return as `uint256` and checks `== 1` (strict). The assembly-level staticcall uses a fixed 32-byte return buffer rather than materialising unbounded returndata, and any non-1 value (including gas-exhaustion or revert) is treated as denial. PR #13.

---

## W9 — Paused gating of setFeePolicy causes post-unpause one-time fee extraction by compromised manager

Resolved. `setFeePolicy` now blocks any non-zero update while the account session is paused. A compromised manager cannot pre-stage a malicious fee policy during a pause window to execute immediately on unpause. PR #13.

---

## W10 — Missing safeguard against self-target payout addresses in collectFees causes ERC-20 fee trapping

Resolved. `collectFees` now explicitly rejects the kernel's own address as a fee payout destination, reverting with a dedicated error. This prevents ERC-20 fees from being trapped in the non-withdrawable kernel contract. PR #13.

---

## W11 — Ambiguous permission order contract in getPermissionsWithInfo causes off-chain misinterpretation

Resolved. `getPermissionsWithInfo` NatSpec updated to explicitly document that the returned array order matches the internal registry insertion order and that callers must not assume any other ordering. Off-chain consumers relying on position-based permission selection must account for this. PR #12.
