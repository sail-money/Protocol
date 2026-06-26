# Integration Guide

This guide covers three audiences: operators deploying the protocol, developers building custom permissions, and developers building custom fee policies. An EIP-712 signing reference is included at the end.

---

## A. Deploying as an Operator

This section walks through deploying a fully functional Sail instance from scratch.

> **Use the canonical deploy script.** In practice you should deploy with
> `script/core/DeployCore.s.sol`, which deploys the whole core via **deterministic CREATE2 with a
> global salt** so every contract lands at the **same address on every chain** (Base, Arbitrum,
> Unichain, Ethereum, Base Sepolia, Eth Sepolia) and users get the same SMA address everywhere.
> The hand-written steps below show the dependency order and constructor arguments; the script
> wraps them in CREATE2 calls and verifies each deployed address against its predicted address.

### 1. Deploy the TimelockController

`SailGovernance` does not construct its own timelock — it accepts a pre-deployed one as a
constructor argument (this is what makes its constructor arguments chain-independent, and so the
CREATE2 address identical across chains). Deploy the timelock first, with the governance wallet as
the sole proposer/executor/canceller, no admin (self-administered), and a **48-hour** delay:

```solidity
address[] memory proposers = new address[](1);
proposers[0] = multisigAddress;            // governance wallet — sole proposer
address[] memory executors = new address[](1);
executors[0] = multisigAddress;            // ...and sole executor
TimelockController timelock = new TimelockController(
    48 hours,                              // MUST be exactly 48h — SailGovernance enforces this
    proposers,
    executors,
    address(0)                             // no admin: self-administered
);
```

### 2. Deploy SailGovernance

```solidity
SailGovernance governance = new SailGovernance(
    multisigAddress,        // initialGovernance — use a multisig in production; must be the timelock proposer
    0.001 ether,            // maxPermissionFeeWei — per-deployment immutable cap (≤ 0.01 ether constitutional ceiling)
    emergencyAdmin,         // may pause the kernel for up to 72h without a timelock delay
    0,                      // initialPermissionRegistrationFee — 0 leaves registration free
    timelock                // injected TimelockController (48h delay, multisigAddress as proposer)
);
```

`maxPermissionFeeWei` is immutable after deployment and is itself capped at `0.01 ether` by the
constructor. The constructor enforces all four injected-timelock invariants and reverts if any fails:
- **`TimelockDelayMismatch`** — `getMinDelay()` is not exactly 48 hours.
- **`GovernanceNotProposer`** — `initialGovernance` does not hold `PROPOSER_ROLE`.
- **`GovernanceNotExecutor`** — `initialGovernance` does not hold `EXECUTOR_ROLE` (rejects open-executor timelocks).
- **`TimelockNotSelfAdministered`** — the governance EOA holds the admin role over the timelock's roles (rejects timelocks deployed with `admin == initialGovernance`).

### 3. Deploy SailKernel

Deploy the immutable `SafeModuleEnabler` **before** the kernel: the kernel captures the helper's
runtime codehash at construction and pins it as the only permissible `Safe.setup` delegatecall
target (W2 — see [SECURITY.md](./SECURITY.md)). The enabler is dependency-free (no constructor args),
so its address and codehash are deterministic per chain.

```solidity
// Deploy the Safe.setup helper FIRST — its codehash is pinned into the kernel below.
SafeModuleEnabler setupEnabler = new SafeModuleEnabler();

SailKernel kernel = new SailKernel(
    address(governance),
    treasuryAddress,            // receives protocol's share of collected fees
    address(setupEnabler)       // immutable Safe.setup helper; its codehash is pinned (W2)
);
```

When seeding `governance.trustedModuleSetup`, allowlist **only** this immutable `SafeModuleEnabler` —
the kernel additionally requires the setup target's codehash to equal the pinned value, so a
mutable/look-alike helper is rejected even if mistakenly allowlisted.

### 4. Configure Governance Parameters

All parameter changes flow through the **48-hour timelock** (the setters are `onlyTimelock`):
schedule each call on `governance.timelock()`, wait 48 hours, then execute.

```solidity
// Encoded and scheduled/executed via the TimelockController by the governance wallet:
governance.setProtocolCutBps(500);                  // 5% of each fee collection to protocol
governance.setPermissionRegistrationFee(0.0005 ether); // flat fee per permission registration (<= maxPermissionFeeWei)
// maxPermissionsPerAccount defaults to 20; leave or adjust:
governance.setMaxPermissionsPerAccount(10);
```

### 5. Configure Permission Templates

The launch templates are shared, multi-tenant contracts: one deployment per chain serves every account, and each account stores its own bounds set through `configure()` (see [TEMPLATES.md](./TEMPLATES.md)) — they are not constructed per account. The snippet below is illustrative of the bounds a swap template enforces:

```solidity
address[] memory routers = new address[](1);
routers[0] = UNISWAP_V3_ROUTER;

address[] memory tokensIn = new address[](2);
tokensIn[0] = USDC;
tokensIn[1] = WETH;

address[] memory tokensOut = new address[](2);
tokensOut[0] = WETH;
tokensOut[1] = USDC;

// SwapPermission bounds (encoded and applied per account via configure()):
//   routers       — allowlisted swap routers
//   tokensIn      — allowlisted input tokens
//   tokensOut     — allowlisted output tokens
//   maxAmountPerTx: 100_000e6   // 100,000 USDC
//   maxSlippageBps: 200         // 2%
//   oracle        — IOracle implementation for the slippage floor
```

### 6. Deploy a Fee Policy

```solidity
StandardFeePolicy feePolicy = new StandardFeePolicy(
    200,                    // managementFeeBps: 2% per year
    2_000,                  // performanceFeeBps: 20%
    distributorAddress,     // address(0) for no distributor
    0,                      // distributorBps
    address(kernel),        // only the kernel may call recordCollection
    feeManagerAddress       // use a multisig
);
```

### 7. Register an Account

**New Safe (createAccount):**

```solidity
address account = kernel.createAccount(
    SAFE_FACTORY,
    SAFE_SINGLETON,
    safeInitializerCalldata,    // output of Safe's setup() encoding
    saltNonce,                  // arbitrary nonce; combined with msg.sender for CREATE2
    permissionSignerAddress,
    managerAddress,
    address(feePolicy)
);
```

**Existing Safe (registerAccount):** must be called via the Safe's own threshold mechanism (the Safe executes this call as a module or direct call):

```solidity
// This transaction must be submitted through the Safe itself
kernel.registerAccount(permissionSignerAddress, managerAddress, address(feePolicy));
```

Before calling `registerAccount`, the Safe must have added the kernel as a module. This is typically done in the same Safe transaction that calls `registerAccount`.

### 8. Register Permissions

Off-chain, build the EIP-712 signature for `RegisterPermission` using the current `signerNonces[account]`:

```solidity
// On-chain call (anyone can submit; signature enforces authorization)
kernel.registerPermission{value: registrationFee}(
    account,
    address(swapPerm),
    permissionSignerSig
);
```

For multiple permissions at once use `registerPermissions` (one nonce consumed):

```solidity
address[] memory perms = new address[](2);
perms[0] = address(swapPerm);
perms[1] = address(depositPerm);

kernel.registerPermissions{value: totalFee}(
    account,
    perms,
    deadline,
    permissionSignerSig
);
```

### 9. Manager Dispatch

Once permissions are registered, the manager can sign and submit dispatch calls:

```solidity
// Manager signs Dispatch struct off-chain
kernel.dispatch(
    account,
    permission,   // the one registered permission that authorizes this call
    target,
    value,
    calldata,
    managerSig,
    deadline
);
```

---

## B. Building a Custom IPermission

### Interface

```solidity
interface IPermission {
    function evaluate(bytes calldata txData, Context calldata ctx)
        external view returns (bool);

    function discriminator() external view returns (bytes32);
}
```

### Constraints

- `evaluate` is called via `staticcall` — no state changes are possible and none will persist even if attempted.
- Gas budget: **150,000 gas** (`PERMISSION_GAS_CAP`) for single dispatch; **1,000,000 gas** (`BATCH_EVAL_GAS_CAP`) for a batch permission's `evaluateBatch`. Stay well under the limit — allow margin for calldata decoding, memory allocation, and any on-chain reads.
- A revert inside `evaluate` is caught by the kernel and treated as `false`. Revert-as-false is safe but can make debugging harder; prefer explicit `return false` branches.

### Context Fields Available

```solidity
struct Context {
    address account;        // the Safe whose assets are being moved
    address manager;        // signed the dispatch request
    address submitter;      // msg.sender of dispatch (may be a relayer)
    address target;         // call target address
    bytes4  selector;       // leading 4 bytes of calldata; bytes4(0) if calldata < 4 bytes
    uint256 value;          // native ETH forwarded (wei)
    uint256 blockTimestamp; // block.timestamp at dispatch
    uint256 blockNumber;    // block.number at dispatch
}
```

### Implementation Checklist

1. **Check calldata length before decoding.** Insufficient calldata will cause `abi.decode` to revert, which is treated as `false`. Always guard with a length check before decoding.

2. **Return `false` for unknown selectors.** Any selector your permission does not explicitly handle should return `false`, not revert.

3. **Validate the target address.** Unless your permission is intentionally selector-only, check `ctx.target` against an allowlist.

4. **Check `ctx.value` for ERC-20 calls.** Token transfers should carry no ETH. A non-zero `ctx.value` on an ERC-20 call is suspicious and should return `false`.

5. **Return `false` for malformed calldata or out-of-bounds values.** Never assume well-formed input.

6. **Implement `discriminator()`.** Return `keccak256("YourPermissionName")` for easy off-chain indexing and deduplication. Use `bytes32(0)` only if the permission is generic or multi-purpose.

### Minimal Example

```solidity
contract AllowTargetPermission is IPermission {
    address public immutable allowedTarget;

    constructor(address _target) {
        allowedTarget = _target;
    }

    function evaluate(bytes calldata, Context calldata ctx)
        external view returns (bool)
    {
        return ctx.target == allowedTarget;
    }

    function discriminator() external pure returns (bytes32) {
        return keccak256("AllowTargetPermission");
    }
}
```

### Gas Estimation Guidance

| Operation | Approximate gas |
|---|---|
| `staticcall` overhead | ~3 000 |
| `abi.decode` (2 params) | ~1 000–2 000 |
| Single `SLOAD` (mapping lookup) | 2 100 (cold) / 100 (warm) |
| External oracle call | 5 000–20 000+ |

A permission with three mapping lookups and a decode should comfortably fit in 20 000 gas, leaving 80 000 in reserve for complex on-chain reads.

---

## C. Building a Custom IFeePolicy

### Interface

```solidity
interface IFeePolicy {
    // Where the manager's net fee share is paid (kernel pulls this; the caller cannot redirect it).
    function feeRecipient() external view returns (address);

    function computeFee(address account, uint256 currentNav)
        external view
        returns (uint256 grossFee, address distributor, uint256 distributorBps);

    function recordCollection(address account, uint256 grossFee, uint256 currentNav)
        external;

    // Lifecycle hook: the kernel calls this when an account (re)attaches this policy via
    // setFeePolicy. Account only — no NAV is passed. Stateful policies re-anchor per-account
    // accounting here; a stateless policy may no-op it.
    function onAttach(address account) external;
}
```

### `computeFee` Requirements

- Must be a pure view — no state changes.
- `grossFee` should be the maximum collectable fee; the kernel enforces `requested <= grossFee`. A policy may return `0` to block collection.
- `distributor`: `address(0)` means no distributor. When `address(0)` is returned, `distributorBps` is ignored and the full manager remainder goes to `managerTake`.
- `distributorBps` must be `<= 10_000`. Values above 10 000 cause the kernel to revert with `DistributorBpsTooLarge`.

### `recordCollection` Requirements

- Guard with `msg.sender == kernel`. Only the kernel should call this function.

```solidity
modifier onlyKernel() {
    require(msg.sender == kernel, "NotKernel");
    _;
}
```

- This is where you update HWM, timestamps, or any per-account accounting state.
- You may revert on precondition violations (e.g., zero initial NAV). The kernel propagates the revert.

### NAV Trust Model

`currentNav` is manager-provided. If your threat model requires independent NAV validation:

```solidity
function computeFee(address account, uint256 currentNav)
    external view returns (uint256 grossFee, address dist, uint256 distBps)
{
    uint256 verifiedNav = oracle.getNav(account);
    require(verifiedNav > 0, "oracle unavailable");
    // Use verifiedNav instead of currentNav
    // ...
}
```

---

## D. EIP-712 Signing Reference

### Domain Separator

```
domainSeparator = keccak256(abi.encode(
    keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"),
    keccak256("SailKernel"),
    keccak256("1"),
    block.chainid,
    address(kernel)
))
```

Use `kernel.hashTypedDataV4(structHash)` to apply the domain separator on-chain or in tests.

### `address[]` Array Encoding

For `RegisterPermissions` and `RevokePermissions`, the `address[]` field is encoded as:

```solidity
bytes32 arrHash = keccak256(abi.encodePacked(abi.encode(arr)));
```

Each address is zero-padded to 32 bytes (standard ABI encoding), and the concatenated bytes are hashed. This matches EIP-712 §4 dynamic type encoding.

### Struct Hashes

**Dispatch**

```
bytes32 structHash = keccak256(abi.encode(
    DISPATCH_TYPEHASH,       // "Dispatch(address account,address permission,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    account,
    permission,              // the registered permission authorizing this dispatch
    target,
    value,
    keccak256(data),         // dataHash
    managerNonces[account],  // current nonce before increment
    deadline
));
```

**RegisterPermission**

```
bytes32 structHash = keccak256(abi.encode(
    REGISTER_PERMISSION_TYPEHASH,  // "RegisterPermission(address account,address permission,uint256 nonce)"
    account,
    permission,
    signerNonces[account]
));
```

**RevokePermission**

```
bytes32 structHash = keccak256(abi.encode(
    REVOKE_PERMISSION_TYPEHASH,    // "RevokePermission(address account,address permission,uint256 nonce)"
    account,
    permission,
    signerNonces[account]
));
```

**ReplacePermission**

```
bytes32 structHash = keccak256(abi.encode(
    REPLACE_PERMISSION_TYPEHASH,   // "ReplacePermission(address account,address oldPermission,address newPermission,uint256 nonce)"
    account,
    oldPermission,
    newPermission,
    signerNonces[account]
));
```

**RevokeSession**

```
bytes32 structHash = keccak256(abi.encode(
    REVOKE_SESSION_TYPEHASH,       // "RevokeSession(address account,uint256 nonce)"
    account,
    signerNonces[account]
));
```

**ActivateSession**

```
bytes32 structHash = keccak256(abi.encode(
    ACTIVATE_SESSION_TYPEHASH,     // "ActivateSession(address account,uint256 nonce)"
    account,
    signerNonces[account]
));
```

**SetFeePolicy**

```
bytes32 structHash = keccak256(abi.encode(
    SET_FEE_POLICY_TYPEHASH,       // "SetFeePolicy(address account,address newFeePolicy,uint256 nonce)"
    account,
    newFeePolicy,
    signerNonces[account]
));
```

**RegisterPermissions**

```
bytes32 arrHash = keccak256(abi.encodePacked(abi.encode(permissions)));

bytes32 structHash = keccak256(abi.encode(
    REGISTER_PERMISSIONS_TYPEHASH, // "RegisterPermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    account,
    arrHash,                       // EIP-712 array encoding
    signerNonces[account],
    deadline
));
```

**RevokePermissions**

```
bytes32 arrHash = keccak256(abi.encodePacked(abi.encode(permissions)));

bytes32 structHash = keccak256(abi.encode(
    REVOKE_PERMISSIONS_TYPEHASH,   // "RevokePermissions(address account,address[] permissions,uint256 nonce,uint256 deadline)"
    account,
    arrHash,
    signerNonces[account],
    deadline
));
```

### Final Digest

```
bytes32 digest = kernel.hashTypedDataV4(structHash);
// or equivalently:
bytes32 digest = keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
```

Sign `digest` with the appropriate key (manager key for Dispatch; permissionSigner key for all other operations).
