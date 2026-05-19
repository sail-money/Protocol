# SailKernel — Reference

**File:** `contracts/core/SailKernel.sol`
**Inherits:** `EIP712("SailKernel", "1")`, `ReentrancyGuard`

The kernel is the central execution engine of the Sail protocol. It maintains a registry of Safe accounts, evaluates permission sets, executes transactions through the Safe module interface, and enforces fee collection. All mutating functions are protected by `nonReentrant`.

---

## Constants

| Name | Value | Description |
|---|---|---|
| `PERMISSION_GAS_CAP` | `100_000` | Gas budget forwarded to each permission's `evaluate()` staticcall. A revert or gas exhaustion inside a permission is treated as `false` (denial) without affecting the kernel or burning the caller's full gas. |
| `ERC1271_MAGIC` | `0x1626ba7e` | ERC-1271 magic value checked when verifying smart-contract signatures. |

---

## EIP-712 Domain

```
name:    "SailKernel"
version: "1"
chainId: <deployment chain>
verifyingContract: <kernel address>
```

---

## EIP-712 Type Hashes

All nine type hashes are `public constant bytes32` on the contract and can be read directly.

### `DISPATCH_TYPEHASH`

```
Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)
```

Used by `dispatch()`. `dataHash` is `keccak256(calldata)` — the raw bytes are recoverable from the transaction.

### `REGISTER_PERMISSION_TYPEHASH`

```
RegisterPermission(address account,address permission,uint256 nonce)
```

Used by `registerPermission()`.

### `REVOKE_PERMISSION_TYPEHASH`

```
RevokePermission(address account,address permission,uint256 nonce)
```

Used by `revokePermission()`.

### `REPLACE_PERMISSION_TYPEHASH`

```
ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce)
```

Used by `replacePermission()`.

### `REVOKE_SESSION_TYPEHASH`

```
RevokeSession(address account,uint256 nonce)
```

Used by `revokeSession()`.

### `ACTIVATE_SESSION_TYPEHASH`

```
ActivateSession(address account,uint256 nonce)
```

Used by `activateSession()`.

### `SET_FEE_POLICY_TYPEHASH`

```
SetFeePolicy(address account,address newFeePolicy,uint256 nonce)
```

Used by `setFeePolicy()`.

### `REGISTER_PERMISSIONS_TYPEHASH`

```
RegisterPermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)
```

Used by `registerPermissions()`. The `address[]` field is encoded as `keccak256(abi.encodePacked(abi.encode(arr)))` — each address zero-padded to 32 bytes, matching EIP-712 §4 array encoding. See [EIP-712 signing reference](./INTEGRATION.md#d-eip-712-signing-reference).

### `REVOKE_PERMISSIONS_TYPEHASH`

```
RevokePermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)
```

Used by `revokePermissions()`. Same array encoding as `REGISTER_PERMISSIONS_TYPEHASH`.

---

## State

### `AccountConfig` Struct

```solidity
struct AccountConfig {
    address permissionSigner;  // Signs permission-registry operations
    address manager;           // Signs dispatch calls
    address feePolicy;         // Fee policy contract; address(0) = none
    bool    sessionActive;     // When false, all dispatch calls are blocked
}
```

### Mappings

| Name | Type | Description |
|---|---|---|
| `configs` | `mapping(address => AccountConfig)` | Per-account configuration. Publicly readable. |
| `registered` | `mapping(address => bool)` | Whether an account has been registered. |
| `managerNonces` | `mapping(address => uint256)` | Per-account nonce for dispatch signatures. |
| `signerNonces` | `mapping(address => uint256)` | Per-account nonce for all permission-registry operations. |
| `cumulativeDeposits` | `mapping(address => uint256)` | Running deposit total recorded by the permissionSigner (informational). |
| `cumulativeWithdrawals` | `mapping(address => uint256)` | Running withdrawal total recorded by the permissionSigner (informational). |

### Other State

| Name | Type | Description |
|---|---|---|
| `governance` | `SailGovernance` (immutable) | The governance contract. Read for fee parameters and permission caps. |
| `treasury` | `address` | Receives the protocol's share of collected fees. Settable by governance. |
| `paused` | `bool` | When `true`, `dispatch` and `collectFees` revert. |

---

## Functions

### `setTreasury(address newTreasury)`

- **Access:** `onlyGovernance`
- **What it does:** Replaces the treasury address that receives the protocol's fee share.
- **Parameters:** `newTreasury` — new treasury address; must not be `address(0)`.
- **Events:** `TreasuryUpdated(oldTreasury, newTreasury)`
- **Errors:** `NotGovernance`, `ZeroAddress`

---

### `pause()`

- **Access:** `onlyGovernance`
- **What it does:** Sets `paused = true`. All subsequent `dispatch` and `collectFees` calls revert with `ProtocolPaused`.
- **Events:** `Paused(by)`
- **Errors:** `NotGovernance`

---

### `unpause()`

- **Access:** `onlyGovernance`
- **What it does:** Sets `paused = false`, restoring normal operation.
- **Events:** `Unpaused(by)`
- **Errors:** `NotGovernance`

---

### `createAccount(safeFactory, safeSingleton, safeInitializer, saltNonce, permissionSigner, manager, feePolicy) → address account`

- **Access:** Anyone (permissionless)
- **What it does:** Deploys a new Safe proxy via the provided factory and registers it with the kernel in a single transaction. The CREATE2 salt is derived as `uint256(keccak256(abi.encode(saltNonce, msg.sender)))`, binding the deployment address to `msg.sender`. This prevents an observer from front-running registration by claiming a Safe they did not deploy.
- **Parameters:**

| Parameter | Description |
|---|---|
| `safeFactory` | Address of the Safe proxy factory |
| `safeSingleton` | Address of the Safe singleton (implementation) |
| `safeInitializer` | Calldata for the Safe's `setup()` call |
| `saltNonce` | Caller-chosen nonce combined with `msg.sender` to form the CREATE2 salt |
| `permissionSigner` | Address authorised to sign permission-registry operations |
| `manager` | Address authorised to sign dispatch calls |
| `feePolicy` | Fee policy contract; `address(0)` = no fee policy |

- **Returns:** `account` — the newly deployed Safe proxy address.
- **Events:** `AccountRegistered(account, permissionSigner, manager)`
- **Errors:** `AccountAlreadyRegistered`, `ZeroAddress` (if `permissionSigner` or `manager` is zero)

---

### `registerAccount(permissionSigner, manager, feePolicy)`

- **Access:** The Safe itself (`msg.sender == Safe`)
- **What it does:** Registers an existing Safe that has already added this kernel as a module. Must be called via a Safe transaction (the Safe executes this call through its own threshold mechanism), which prevents any third party from registering a Safe they do not control.
- **Parameters:** Same as the last three parameters of `createAccount`.
- **Events:** `AccountRegistered(account, permissionSigner, manager)`
- **Errors:** `AccountAlreadyRegistered`, `ZeroAddress`

---

### `registerPermission(account, permission, sig)` (payable)

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Adds a single permission to an account's permission set. Requires a valid EIP-712 `RegisterPermission` signature from the account's `permissionSigner` and an ETH registration fee (computed from the permission's bytecode size via governance parameters).
- **Parameters:**

| Parameter | Description |
|---|---|
| `account` | The registered Safe account |
| `permission` | Permission contract address to register |
| `sig` | EIP-712 signature over `RegisterPermission` struct |

- **Fee:** `min(baseFee + complexityRate × codeSize, MAX_PERMISSION_FEE_WEI)`. Overpayment is refunded to `msg.sender`.
- **Events:** `PermissionRegistered(account, permission)`
- **Errors:** `AccountNotRegistered`, `PermissionAlreadyRegistered`, `TooManyPermissions`, `InvalidSignerSignature`, `InsufficientFee`, `FeeTransferFailed`

---

### `revokePermission(account, permission, sig)`

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Removes a single permission from an account's set. No ETH fee required. Uses swap-and-pop internally to keep the permission array compact.
- **Events:** `PermissionRevoked(account, permission)`
- **Errors:** `AccountNotRegistered`, `InvalidSignerSignature`, `PermissionNotRegistered`

---

### `replacePermission(account, oldPermission, newPermission, sig)` (payable)

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Atomically removes `oldPermission` and inserts `newPermission` at the same array slot. One signer nonce is consumed. Requires an ETH fee for the new permission. Reverts if `newPermission` is already registered or `oldPermission` is not registered.
- **Events:** `PermissionReplaced(account, oldPermission, newPermission)`
- **Errors:** `AccountNotRegistered`, `PermissionAlreadyRegistered` (for newPermission), `PermissionNotRegistered` (for oldPermission), `InvalidSignerSignature`, `InsufficientFee`, `FeeTransferFailed`

---

### `revokeSession(account, sig)`

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Sets `sessionActive = false` for the account. All subsequent `dispatch` calls revert with `SessionInactive`. Used to instantly suspend a manager's ability to trade without revoking permissions.
- **Events:** `SessionRevoked(account)`
- **Errors:** `AccountNotRegistered`, `InvalidSignerSignature`

---

### `activateSession(account, sig)`

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Re-enables dispatch for a previously suspended account. Requires a fresh permissionSigner signature to confirm the key is still under the operator's control.
- **Events:** `SessionActivated(account)`
- **Errors:** `AccountNotRegistered`, `InvalidSignerSignature`

---

### `setFeePolicy(account, newFeePolicy, sig)`

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Replaces the fee policy for an account. `newFeePolicy = address(0)` clears the policy, making `collectFees` revert with `FeePolicyNotSet`.
- **Events:** `FeePolicyUpdated(account, newFeePolicy)`
- **Errors:** `AccountNotRegistered`, `InvalidSignerSignature`

---

### `registerPermissions(account, permissions[], deadline, sig)` (payable)

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Registers multiple permissions atomically. One signer nonce is consumed for the entire batch. The total ETH fee equals the sum of individual permission fees. Empty arrays return early without consuming a nonce (prevents nonce griefing).

  The `address[]` is EIP-712 encoded as `keccak256` of the ABI-packed zero-padded addresses.

- **Parameters:**

| Parameter | Description |
|---|---|
| `account` | The registered Safe account |
| `permissions` | Array of permission contract addresses |
| `deadline` | Unix timestamp — signature expires after this |
| `sig` | EIP-712 signature over `RegisterPermissions` struct |

- **Events:** `PermissionRegistered(account, permission)` for each permission added
- **Errors:** `AccountNotRegistered`, `DeadlineExpired`, `TooManyPermissions`, `PermissionAlreadyRegistered`, `InvalidSignerSignature`, `InsufficientFee`, `FeeTransferFailed`

---

### `revokePermissions(account, permissions[], deadline, sig)`

- **Access:** Anyone (signature-gated by permissionSigner)
- **What it does:** Revokes multiple permissions atomically. One signer nonce consumed for the batch. No ETH fee. Empty arrays return early without consuming a nonce.
- **Events:** `PermissionRevoked(account, permission)` for each permission removed
- **Errors:** `AccountNotRegistered`, `DeadlineExpired`, `PermissionNotRegistered`, `InvalidSignerSignature`

---

### `getPermissions(account) → address[]`

- **Access:** View — anyone
- **What it does:** Returns the full ordered array of permission contract addresses registered for the account.

---

### `isPermissionRegistered(account, permission) → bool`

- **Access:** View — anyone
- **What it does:** Returns `true` if `permission` is currently registered for `account`.

---

### `dispatch(account, permission, target, value, data, managerSig, deadline)`

- **Access:** Anyone (manager signature required; `nonReentrant`, `whenNotPaused`)
- **What it does:** The single-permission execution path.
  1. Verifies the account is registered and the session is active.
  2. Checks `deadline`.
  3. Verifies the named `permission` is registered for the account (O(1) `_permissionIndex` check) — reverts `PermissionNotRegistered` if absent.
  4. Verifies the EIP-712 `Dispatch` signature from the account's manager over `(account, permission, target, value, keccak256(data), nonce, deadline)`.
  5. Increments `managerNonces[account]`.
  6. Evaluates `permission.evaluate(data, ctx)` via `staticcall` under `PERMISSION_GAS_CAP`; reverts `PermissionDenied` if the call returns `false`, reverts, or exhausts gas.
  7. Calls `ISafe(account).execTransactionFromModule(target, value, data, 0)`.
  8. Emits `Dispatched(account, permission, target, selector, value)`.
- **Parameters:**

| Parameter | Description |
|---|---|
| `account` | The registered Safe to execute through |
| `permission` | A permission registered for `account`; evaluated as the sole authorizer for this dispatch |
| `target` | Call target address |
| `value` | Native ETH to forward (wei) |
| `data` | Calldata for the target |
| `managerSig` | EIP-712 signature over `(account, permission, target, value, keccak256(data), nonce, deadline)` |
| `deadline` | Unix timestamp — signature expires after this |

- **Events:** `Dispatched(account indexed, permission indexed, target, selector, value)`
- **Errors:** `AccountNotRegistered`, `SessionInactive`, `DeadlineExpired`, `PermissionNotRegistered(permission)`, `InvalidManagerSignature`, `PermissionDenied(permission)`, `SafeExecutionFailed`, `ProtocolPaused`

---

### `collectFees(account, grossFee, currentNav, feeToken, recipient)`

- **Access:** `cfg.manager` only (`nonReentrant`, `whenNotPaused`)
- **What it does:** Validates `grossFee` against the policy's computed maximum and distributes fees to the treasury, distributor, and manager recipient according to the protocol split.

  **Trust assumption:** `currentNav` is provided by the manager and is not verified on-chain. A dishonest manager could inflate `currentNav` to unlock a larger fee ceiling. Deployers must use a fee policy that validates NAV through an oracle if the manager is not trusted.

  Fee split:
  ```
  protocolCut    = grossFee × currentProtocolCutBps / 10_000
  remainder      = grossFee - protocolCut
  distributorCut = remainder × distributorBps / 10_000
                   (if distributor == address(0), distributorCut = 0 and folds into managerTake)
  managerTake    = remainder - distributorCut
  ```

- **Parameters:**

| Parameter | Description |
|---|---|
| `account` | The Safe account to collect fees from |
| `grossFee` | Requested fee amount; must not exceed policy's `maxFee` |
| `currentNav` | Manager-reported net asset value |
| `feeToken` | ERC-20 token for payment; `address(0)` = native ETH |
| `recipient` | Address receiving the manager's net share; must not be `address(0)` |

- **Events:** `FeesCollected(account, feeToken, grossFee, protocolCut, distributorCut, managerTake)`
- **Errors:** `AccountNotRegistered`, `ZeroAddress`, `NotManager`, `FeePolicyNotSet`, `FeeTooLarge`, `DistributorBpsTooLarge`, `FeeTransferFailed`, `ProtocolPaused`

---

### `recordDeposit(account, amount)`

- **Access:** `permissionSigner` only
- **What it does:** Increments `cumulativeDeposits[account]` by `amount`. Informational — not used to constrain fee collection on-chain.
- **Events:** `DepositRecorded(account, amount, cumulative)`
- **Errors:** `AccountNotRegistered`, `NotPermissionSigner`

---

### `recordWithdrawal(account, amount)`

- **Access:** `permissionSigner` only
- **What it does:** Increments `cumulativeWithdrawals[account]` by `amount`. Informational.
- **Events:** `WithdrawalRecorded(account, amount, cumulative)`
- **Errors:** `AccountNotRegistered`, `NotPermissionSigner`

---

### `hashTypedDataV4(structHash) → bytes32`

- **Access:** View — anyone
- **What it does:** Exposes the internal `_hashTypedDataV4` function for off-chain tooling, frontends, and tests. Applies the domain separator to a pre-computed struct hash and returns the final EIP-712 digest.

---

## Events

| Event | When |
|---|---|
| `AccountRegistered(account, permissionSigner, manager)` | New account registered via `createAccount` or `registerAccount` |
| `PermissionRegistered(account, permission)` | Permission added (single or batch) |
| `PermissionRevoked(account, permission)` | Permission removed (single or batch) |
| `PermissionReplaced(account, oldPermission, newPermission)` | Atomic replacement |
| `SessionRevoked(account)` | Session suspended |
| `SessionActivated(account)` | Session re-enabled |
| `FeePolicyUpdated(account, newFeePolicy)` | Fee policy changed |
| `Dispatched(account indexed, permission indexed, target, selector, value)` | Successful dispatch |
| `FeesCollected(account, feeToken, grossFee, protocolCut, distributorCut, managerTake)` | Fee collection |
| `DepositRecorded(account, amount, cumulative)` | Deposit recorded |
| `WithdrawalRecorded(account, amount, cumulative)` | Withdrawal recorded |
| `TreasuryUpdated(oldTreasury, newTreasury)` | Treasury address changed |
| `Paused(by)` | Protocol paused |
| `Unpaused(by)` | Protocol unpaused |

---

## Errors

| Error | Meaning |
|---|---|
| `AccountAlreadyRegistered(account)` | `createAccount`/`registerAccount` called for an address that is already registered |
| `AccountNotRegistered(account)` | Operation requires registration but the account has not been registered |
| `SessionInactive(account)` | `dispatch` called while `sessionActive == false` |
| `DeadlineExpired(deadline, current)` | `block.timestamp` exceeds the provided deadline |
| `InvalidManagerSignature()` | EIP-712 manager signature could not be verified |
| `InvalidSignerSignature()` | EIP-712 permissionSigner signature could not be verified |
| `PermissionDenied(permission)` | A permission returned `false` (or reverted) during dispatch |
| `SafeExecutionFailed()` | `ISafe.execTransactionFromModule` returned `false` |
| `PermissionAlreadyRegistered(permission)` | Attempt to register a permission that is already in the set |
| `PermissionNotRegistered(permission)` | Operation requires the permission to be registered but it is not |
| `TooManyPermissions(account, limit)` | Adding permissions would exceed `governance.maxPermissionsPerAccount()` |
| `InsufficientFee(required, provided)` | `msg.value` is below the computed registration fee |
| `FeePolicyNotSet()` | `collectFees` called with no fee policy attached to the account |
| `FeeTooLarge(requested, maxAllowed)` | `grossFee` exceeds the policy's computed maximum |
| `FeeTransferFailed()` | ETH or ERC-20 fee transfer via the Safe failed |
| `NotManager(caller, expected)` | Caller of a manager-only function is not the account's manager |
| `NotGovernance()` | Caller is not the current governance address |
| `NotPermissionSigner()` | Caller is not the account's permissionSigner |
| `ZeroAddress()` | A required address argument is `address(0)` |
| `DistributorBpsTooLarge(bps)` | `distributorBps` returned by the fee policy exceeds 10 000 |
| `NoPermissionsRegistered(account)` | Retained for ABI compatibility; no longer emitted by `dispatch`. The caller now names a specific permission and receives `PermissionNotRegistered` if it is absent. |
| `ProtocolPaused()` | `dispatch` or `collectFees` called while the protocol is paused |
