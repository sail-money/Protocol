# Integration Guide

This guide covers three audiences: operators deploying the protocol, developers building custom permissions, and developers building custom fee policies. An EIP-712 signing reference is included at the end.

---

## A. Deploying as an Operator

This section walks through deploying a fully functional Sail instance from scratch.

### 1. Deploy SailGovernance

```solidity
SailGovernance governance = new SailGovernance(
    multisigAddress,        // initialGovernance — use a multisig in production
    1e18                    // maxPermissionFeeWei — constitutional cap on registration fee
);
```

`maxPermissionFeeWei` is immutable after deployment. Set it to a value that covers your intended fee schedule without being so large that it could cause UI/UX friction. `1e18` (1 ETH equivalent) is a reasonable production ceiling for most deployments.

### 2. Deploy SailKernel

```solidity
SailKernel kernel = new SailKernel(
    address(governance),
    treasuryAddress         // receives protocol's share of collected fees
);
```

### 3. Configure Governance Parameters

```solidity
// All calls from the governance multisig
governance.setProtocolCutBps(500);          // 5% of each fee collection to protocol
governance.setBaseFee(0.001 ether);         // flat fee per permission registration
governance.setComplexityRate(1_000);        // 1_000 wei per byte of permission bytecode
// maxPermissionsPerAccount defaults to 20; leave or adjust:
governance.setMaxPermissionsPerAccount(10);
```

### 4. Deploy Permission Templates

Deploy one or more permission templates for your allowed trading scope:

```solidity
address[] memory routers = new address[](1);
routers[0] = UNISWAP_V3_ROUTER;

address[] memory tokensIn = new address[](2);
tokensIn[0] = USDC;
tokensIn[1] = WETH;

address[] memory tokensOut = new address[](2);
tokensOut[0] = WETH;
tokensOut[1] = USDC;

BoundedSwapPermission swapPerm = new BoundedSwapPermission(
    routers,
    tokensIn,
    tokensOut,
    100_000e6,          // maxAmountPerTx: 100,000 USDC
    200,                // maxSlippageBps: 2%
    address(oracle),    // IOracle implementation
    permissionSignerAddress
);
```

### 5. Deploy a Fee Policy

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

### 6. Register an Account

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

### 7. Register Permissions

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

### 8. Manager Dispatch

Once permissions are registered, the manager can sign and submit dispatch calls:

```solidity
// Manager signs Dispatch struct off-chain
kernel.dispatch(
    account,
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
- Gas budget: **100 000 gas** (`PERMISSION_GAS_CAP`). Stay well under this limit — allow margin for calldata decoding, memory allocation, and any on-chain reads.
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
    function computeFee(address account, uint256 currentNav)
        external view
        returns (uint256 grossFee, address distributor, uint256 distributorBps);

    function recordCollection(address account, uint256 grossFee, uint256 currentNav)
        external;
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
    DISPATCH_TYPEHASH,       // "Dispatch(address account,address target,uint256 value,bytes32 dataHash,uint256 nonce,uint256 deadline)"
    account,
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
