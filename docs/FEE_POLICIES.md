# Fee Policies — Reference

---

## IFeePolicy Interface

**File:** `contracts/interfaces/IFeePolicy.sol`

Every fee policy attached to a Sail account must implement this interface. The kernel calls `feeRecipient()`, `computeFee()`, and `recordCollection()` during `collectFees`, and `onAttach()` when a policy is (re)attached via `setFeePolicy`.

```solidity
interface IFeePolicy {
    function feeRecipient() external view returns (address);

    function computeFee(address account, uint256 currentNav)
        external
        view
        returns (uint256 grossFee, address distributor, uint256 distributorBps);

    function recordCollection(address account, uint256 grossFee, uint256 currentNav)
        external;

    function onAttach(address account) external;
}
```

### `computeFee(address account, uint256 currentNav)`

Pure computation — must not modify state. Returns the maximum fee that may be collected in a single `collectFees` call.

| Return value | Type | Description |
|---|---|---|
| `grossFee` | `uint256` | Maximum fee the kernel may collect. The caller may pass a lower amount; the kernel enforces `requested <= grossFee`. |
| `distributor` | `address` | Address to receive the distributor share. `address(0)` means no distributor. |
| `distributorBps` | `uint256` | Fraction of the post-protocol-cut remainder forwarded to `distributor`, in basis points. |

**Trust model:** `currentNav` is provided by the manager and is not verified on-chain. The kernel passes whatever value the manager supplies. Policies must either validate NAV through an oracle or accept manager-provided values. A dishonest manager could supply an inflated NAV to unlock a larger `grossFee` ceiling and pass a correspondingly large fee request.

If `lastCollectionTimestamp` is unset (first call, no prior state), implementations should return `(0, distributor, distributorBps)`.

### `recordCollection(address account, uint256 grossFee, uint256 currentNav)`

Called by the kernel after the fee transfer completes. Used to update per-account state: high-water mark, last collection timestamp, etc.

**Only the kernel should call this.** Implementations should check `msg.sender == kernel` and revert otherwise.

Implementations may also revert on precondition violations (e.g., `HWMNotSeeded` if the account's high-water mark has not been seeded).

### `feeRecipient()`

Returns the address that receives the manager's net fee share. The kernel reads this directly and routes the manager take to it — a caller cannot redirect the payout. On `StandardFeePolicy` this returns `feeManager`.

### `onAttach(address account)`

Lifecycle hook the kernel invokes from `setFeePolicy` when an account (re)attaches this policy. It receives **only** the account — no NAV — so the kernel never learns or computes valuation. Stateful policies re-anchor their per-account accounting here; a stateless policy may implement it as a no-op. `StandardFeePolicy` uses it to re-anchor `lastCollectionTimestamp` (and flag a high-water-mark re-base) so a detach→reattach of the same instance is not billed across the dormant interval.

On reattach `StandardFeePolicy` also refreshes its per-account applied-rate snapshots to the current global schedule, so the first post-reattach window is priced at today's rate rather than a rate captured before the detach. This is prospective only: the dormant interval is not billed (the timestamp is reset) and the performance leg is suppressed for that first window.

**Zero-management reattach.** On a schedule whose management rate is `0` (or a tiny rate that floors to zero on a small NAV), the suppressed first post-reattach window would otherwise compute a zero gross fee. The kernel rejects a zero fee (`ZeroFee`), and the re-anchor flag only clears once a collection settles — so the account could never collect again. To avoid this, `computeFee` returns a minimal fee of `1` for that window so a collection can settle and clear the flag; normal pricing resumes immediately afterward. **Boundary:** if the Safe holds no balance of the configured fee asset, even this 1-unit transfer cannot settle and the account stays stuck until it is funded.

**First registration with a pre-configured policy (operator step).** Registration (`createAccount` / `registerAccount` with a non-zero `feePolicy`) stores the policy and asset but does **not** call `onAttach` — registration is not a reattach, so it also does not bind the policy's asset. If the policy is a freshly deployed instance with no prior per-account accounting, this is fine. But if it is a **pre-seeded** stateful instance (one that already carries a high-water mark or `lastCollectionTimestamp` for this account from before), the first `collectFees` would bill management over the interval since that stale timestamp and performance against the stale high-water mark. To anchor a pre-seeded policy to the moment of registration, call `setFeePolicy(samePolicy)` once after registering — this triggers `onAttach` (re-anchor) and binds the asset — before the first collection.

---

## Fee Split Mechanics (in Kernel)

The kernel applies this split to every `collectFees` call:

```
protocolCut    = grossFee × currentProtocolCutBps / 10_000
remainder      = grossFee - protocolCut
distributorCut = remainder × distributorBps / 10_000
                 (if distributor == address(0), distributorCut is forced to 0
                  and the full remainder goes to managerTake)
managerTake    = remainder - distributorCut
```

Each non-zero component is transferred from the Safe (via `execTransactionFromModule`) to its respective recipient. If `feeToken == address(0)`, transfers are native ETH; otherwise they are ERC-20 `transfer` calls.

ERC-20 transfers follow SafeERC20 semantics: a token that returns nothing is tolerated as success (some non-standard tokens, e.g. certain USDT deployments, return no data). A consequence is that the configured `feeAsset` **must be a deployed ERC-20 token contract** — a call to a non-contract address returns success with empty data, which would advance fee state while moving nothing. Only the account's trusted roles set `feeAsset`, so configure it to a real token.

All arithmetic uses `Math.mulDiv` (OpenZeppelin) to prevent intermediate overflow.

---

## StandardFeePolicy

**File:** `contracts/policies/StandardFeePolicy.sol`

`StandardFeePolicy` implements a classic management-plus-performance fee schedule. It is deployed per-operator (or shared across multiple accounts belonging to the same operator).

### Fee Schedule

**Management fee** — annualised rate on AUM, accrued per collection based on elapsed time:

```
managementFee = currentNav × managementFeeBps × elapsed
                ──────────────────────────────────────────
                      SECONDS_PER_YEAR × 10_000
```

where `SECONDS_PER_YEAR = 365 days` and `elapsed = block.timestamp - lastCollectionTimestamp[account]`.

**Performance fee** — applied to gains above the high-water mark (HWM):

```
performanceFee = max(currentNav - HWM, 0) × performanceFeeBps / 10_000
```

**Gross fee:**

```
grossFee = managementFee + performanceFee
```

### High-Water Mark

- Stored per account in `highWaterMark[account]`.
- Updated after each collection to `max(HWM, currentNav)` — it only ever moves up.
- The HWM is **not** auto-seeded on the first collection. It must be seeded explicitly first via `seedHighWaterMark(account, initialNav)` (see Setters); a `recordCollection` before seeding reverts `HWMNotSeeded`.

### HWM Seeding Guard (`HWMNotSeeded` / `AlreadySeeded`)

The HWM must be explicitly seeded by the `feeManager` before any collection. `seedHighWaterMark(account, initialNav)` is `onlyFeeManager`, one-shot (a second call reverts `AlreadySeeded`), and requires a non-zero `initialNav` (a zero seed reverts `HWMNotSeeded`). `recordCollection` reverts `HWMNotSeeded` until the account has been seeded. This prevents a manager from seeding the HWM at 0 and then immediately claiming a performance fee on the full portfolio value as if it were pure profit.

### Caps

| Parameter | Constant | Cap |
|---|---|---|
| Management fee rate | `MAX_MANAGEMENT_FEE_BPS` | 1 000 bps (10% per year) |
| Performance fee rate | `MAX_PERFORMANCE_FEE_BPS` | 5 000 bps (50%) |
| Distributor share | `MAX_DISTRIBUTOR_BPS` | 10 000 bps (100%) |

These constants are set in source and cannot be raised without redeployment.

### State

| Name | Type | Description |
|---|---|---|
| `managementFeeBps` | `uint256` | Annual management fee rate |
| `performanceFeeBps` | `uint256` | Performance fee rate on HWM gains |
| `distributor` | `address` | Distributor address; `address(0)` = no split |
| `distributorBps` | `uint256` | Distributor's share of manager's net fee |
| `highWaterMark` | `mapping(address => uint256)` | Per-account highest recorded NAV |
| `lastCollectionTimestamp` | `mapping(address => uint256)` | Per-account timestamp of last collection; 0 = uninitialised |
| `kernel` | `address` (immutable) | Only caller allowed on `recordCollection` |
| `feeManager` | `address` | Controls fee parameters |

### Constructor

```solidity
constructor(
    uint256 _managementFeeBps,   // <= MAX_MANAGEMENT_FEE_BPS (1_000)
    uint256 _performanceFeeBps,  // <= MAX_PERFORMANCE_FEE_BPS (5_000)
    address _distributor,        // address(0) = no split
    uint256 _distributorBps,     // <= MAX_DISTRIBUTOR_BPS (10_000)
    address _kernel,             // must not be address(0)
    address _feeManager          // must not be address(0)
)
```

Reverts with the corresponding `*TooHigh` or `ZeroAddress` error if any parameter is out of range.

### Setters

| Function | Caller | Constraint | Effect |
|---|---|---|---|
| `setManagementFeeBps(uint256)` | `feeManager` | <= 1 000 | Updates annual management fee rate |
| `setPerformanceFeeBps(uint256)` | `feeManager` | <= 5 000 | Updates performance fee rate |
| `setDistributor(address)` | `feeManager` | None (`address(0)` allowed) | Updates distributor address |
| `setDistributorBps(uint256)` | `feeManager` | <= 10 000 | Updates distributor's share |
| `seedHighWaterMark(address,uint256)` | `feeManager` | One-shot per account; `initialNav != 0` | Seeds the account's HWM before its first collection (required) |
| `proposeFeeManager(address)` | `feeManager` | Must not be `address(0)` | Step 1: nominates the next fee manager |
| `acceptFeeManager()` | `pendingFeeManager` | Caller must be the pending fee manager | Step 2: finalises the transfer |

### Fee-Manager Transfer — Two-Step

Fee-manager control transfers via a two-step `proposeFeeManager` → `acceptFeeManager` handshake, mirroring the kernel's two-step governance transfer: the current `feeManager` nominates a successor, and the transfer finalises only when that successor calls `acceptFeeManager` (calling `proposeFeeManager` again before acceptance overwrites the pending nominee). Because an address that cannot call `acceptFeeManager` never becomes `feeManager`, a mistyped or uncontrolled successor cannot take — or permanently lose — control of the policy. Always use a multisig or hardware-wallet-controlled address as `feeManager`, and confirm the nominee can sign before it calls `acceptFeeManager`.

### Events

| Event | When |
|---|---|
| `ManagementFeeUpdated(oldBps, newBps)` | `setManagementFeeBps` |
| `PerformanceFeeUpdated(oldBps, newBps)` | `setPerformanceFeeBps` |
| `DistributorUpdated(oldDistributor, newDistributor)` | `setDistributor` |
| `DistributorBpsUpdated(oldBps, newBps)` | `setDistributorBps` |
| `FeeManagerProposed(currentFeeManager, proposedFeeManager)` | `proposeFeeManager` |
| `FeeManagerTransferred(oldFeeManager, newFeeManager)` | `acceptFeeManager` |
| `FeesCollected(account, grossFee, currentNav, newHighWaterMark)` | every `recordCollection` (the account is seeded first via `seedHighWaterMark`, so there is no skipped first emission) |

### Errors

| Error | Meaning |
|---|---|
| `NotKernel()` | `recordCollection` called by a non-kernel address |
| `NotFeeManager()` | Setter called by a non-feeManager address |
| `NotPendingFeeManager()` | `acceptFeeManager` called by an address other than the pending fee manager |
| `ZeroAddress()` | `kernel`, `feeManager`, or `proposeFeeManager` target is `address(0)` |
| `HWMNotSeeded()` | `recordCollection` called before the account's HWM was seeded, or `seedHighWaterMark` called with `initialNav == 0` |
| `AlreadySeeded()` | `seedHighWaterMark` called a second time for an account already seeded |
| `CollectionTooFrequent()` | `recordCollection` called before `MIN_COLLECTION_INTERVAL` (1 day) has elapsed since the last collection |
| `ManagementFeeTooHigh(bps)` | Requested rate exceeds `MAX_MANAGEMENT_FEE_BPS` |
| `PerformanceFeeTooHigh(bps)` | Requested rate exceeds `MAX_PERFORMANCE_FEE_BPS` |
| `DistributorBpsTooLarge(bps)` | Requested distributor share exceeds `MAX_DISTRIBUTOR_BPS` |

---

## Building a Custom IFeePolicy

See [INTEGRATION.md — Building a custom IFeePolicy](./INTEGRATION.md#c-building-a-custom-ifeepolicy) for implementation guidance.
