# Permission Templates — Reference

The Sail protocol ships five audited permission templates. Each implements `IPermission` and may be registered on any account via the kernel's permission registry.

Each contract listed here is both a deployed Permission — eligible for kernel registration — and a Template: a reusable pattern that demonstrates the permission interface across a specific DeFi primitive. The distinction is contextual: when the contract is registered against an SMA it is acting as that SMA's Permission; when it is referenced as a reusable shape for other deployments it is acting as a Template.

All templates share the same operational pattern:
- `evaluate(bytes calldata txData, Context calldata ctx)` is called via `staticcall` — no state changes are possible.
- Return `false` (or revert) to deny the transaction. Return `true` to approve it.
- Every template enforces a per-transaction amount cap, an address allowlist, and a safe-address recipient check where applicable.

See [INTEGRATION.md](./INTEGRATION.md) for guidance on building custom permissions.

---

## Common `Context` Fields

All templates receive a `Context` struct:

| Field | Type | Description |
|---|---|---|
| `account` | `address` | The Safe account whose assets are being moved |
| `manager` | `address` | The manager who signed the dispatch |
| `submitter` | `address` | `msg.sender` of the dispatch call (may be a relayer) |
| `target` | `address` | The call target address |
| `selector` | `bytes4` | Leading 4 bytes of calldata; `bytes4(0)` if calldata < 4 bytes |
| `value` | `uint256` | Native ETH forwarded with the call (wei) |
| `blockTimestamp` | `uint256` | `block.timestamp` at dispatch time |
| `blockNumber` | `uint256` | `block.number` at dispatch time |

---

## BoundedSwapPermission

**File:** `contracts/templates/BoundedSwapPermission.sol`
**discriminator:** `keccak256("BoundedSwapPermission")`

### Purpose

Gates DEX swaps so the manager can only trade through approved routers, with approved token pairs, within a per-transaction amount cap, and — when an oracle is configured — within a slippage band derived from an on-chain price.

### Supported Selectors

| Selector | Function | Protocol |
|---|---|---|
| `0x414bf389` | `exactInputSingle((address tokenIn, address tokenOut, uint24 fee, address recipient, uint256 deadline, uint256 amountIn, uint256 amountOutMinimum, uint160 sqrtPriceLimitX96))` | Uniswap V3 SwapRouter |
| `0x38ed1739` | `swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)` | Uniswap V2 Router |

Any other selector returns `false`.

### Invariants Enforced

For **both** selectors:
1. `ctx.target` is in `isAllowedRouter`.
2. `tokenIn` (V3) or `path[0]` (V2) is in `isAllowedTokenIn`.
3. `tokenOut` (V3) or `path[last]` (V2) is in `isAllowedTokenOut`.
4. `recipient` (V3) or `to` (V2) equals `ctx.account` (the Safe).
5. `amountIn` <= `maxAmountPerTx`.
6. Oracle slippage check passes (if oracle and `maxSlippageBps` are configured).

**Oracle slippage check:**

```
expectedOut  = amountIn × price / 10^decimals
oracleMinOut = expectedOut × (10_000 - maxSlippageBps) / 10_000
require: amountOutMin >= oracleMinOut
```

The oracle check is disabled when `priceOracle == address(0)` OR `maxSlippageBps == 0`. Setting `maxSlippageBps = 0` is an explicit opt-out — use it only when you intend to remove slippage protection entirely.

If the oracle returns `price == 0` or `decimals > 77` (which would overflow `10^decimals`), the check returns `false` (deny).

### Constructor Parameters

| Parameter | Description |
|---|---|
| `allowedRouters` | DEX router addresses to pre-populate `isAllowedRouter` |
| `allowedTokensIn` | Input token addresses to pre-populate `isAllowedTokenIn` |
| `allowedTokensOut` | Output token addresses to pre-populate `isAllowedTokenOut` |
| `_maxAmountPerTx` | Initial per-transaction `amountIn` cap |
| `_maxSlippageBps` | Initial slippage tolerance (0–9 999 bps). 0 = oracle disabled |
| `_priceOracle` | Oracle address; `address(0)` = oracle disabled |
| `_permissionSigner` | Address permitted to call mutable setters |

### Mutable Setters

| Function | Caller | Effect |
|---|---|---|
| `setMaxAmountPerTx(uint256)` | `permissionSigner` | Updates `maxAmountPerTx`. Setting to 0 blocks all swaps. |
| `setMaxSlippageBps(uint256)` | `permissionSigner` | Updates `maxSlippageBps`. Must be <= 9 999. Setting to 0 disables oracle check. |

There is no setter for `priceOracle`. The oracle address is set at deployment and is immutable (field is public storage but has no setter function).

### Security Notes

- **Intermediate V2 path tokens are not validated.** Only `path[0]` and `path[last]` are checked against `isAllowedTokenIn` / `isAllowedTokenOut`. Operators must ensure the full path is acceptable out-of-band.
- **Oracle staleness:** `IOracle` has no `updatedAt` field. Oracle adapter implementations must handle staleness internally; see [SECURITY.md](./SECURITY.md).
- Setting `maxSlippageBps = 9_999` bps with a live oracle provides a very loose floor (0.01% of expected output). Use a conservative value (e.g., 50–200 bps) for real portfolios.

---

## BoundedDepositPermission

**File:** `contracts/templates/BoundedDepositPermission.sol`
**discriminator:** `keccak256("BoundedDepositPermission")`

### Purpose

Gates ERC-20 deposits into lending pools and ERC-4626 vaults. Ensures the manager can only deposit into approved protocols, with approved tokens, within a per-transaction cap, and that the Safe always receives the resulting position.

### Supported Selectors

| Selector | Function | Protocol |
|---|---|---|
| `keccak256("deposit(uint256,address)")[:4]` | `deposit(uint256 assets, address receiver)` | ERC-4626 / simple vault |
| `keccak256("deposit(address,uint256,address,uint16)")[:4]` | `deposit(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)` | Aave v2 |
| `keccak256("mint(uint256,address)")[:4]` | `mint(uint256 shares, address receiver)` | ERC-4626 |
| `keccak256("supply(address,uint256,address,uint16)")[:4]` | `supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)` | Aave v3 |

### Invariants Enforced

For **all** selectors:
1. `ctx.target` is in `isAllowedTarget`.
2. `amount` (or `shares` for `mint`) <= `maxAmountPerTx`.
3. `receiver` / `onBehalfOf` == `ctx.account` (the Safe).

For **Aave selectors only** (`DEPOSIT_AAVE`, `SUPPLY_AAVE`):
4. `asset` is in `isAllowedToken`.

For **`deposit(uint256,address)`** and **`mint(uint256,address)`**:
- The asset does not appear in calldata. Token safety is delegated to the `isAllowedTarget` allowlist. Operators must ensure each allowed target only accepts tokens they intend to permit.

### Constructor Parameters

| Parameter | Description |
|---|---|
| `allowedTargets` | Vault / lending pool addresses |
| `allowedTokens` | ERC-20 addresses (checked for Aave selectors only) |
| `_maxAmountPerTx` | Initial amount / shares cap |
| `_permissionSigner` | Address permitted to call mutable setters |

### Mutable Setters

| Function | Caller | Effect |
|---|---|---|
| `setMaxAmountPerTx(uint256)` | `permissionSigner` | Updates `maxAmountPerTx`. Setting to 0 blocks all deposits. |

### Security Notes

- **`mint` cap is in shares, not underlying assets.** At high share prices (e.g., 1 share = 1 000 USDC), the effective asset cap is `maxAmountPerTx × sharePrice`. Set `maxAmountPerTx` with this in mind when configuring a vault with non-unit share prices.
- **`isAllowedTarget` is the last line of defence for ERC-4626 selectors.** Ensure each target only handles tokens acceptable to the operator.

---

## BoundedBorrowPermission

**File:** `contracts/templates/BoundedBorrowPermission.sol`
**discriminator:** `keccak256("BoundedBorrowPermission")`

### Purpose

Gates ERC-20 borrows from lending protocols. Ensures the manager borrows only from approved protocols, of approved tokens (Aave path), within a per-transaction cap, and that the Safe is always the borrower.

### Supported Selectors

| Selector | Function | Protocol |
|---|---|---|
| `keccak256("borrow(address,uint256,uint256,uint16,address)")[:4]` | `borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)` | Aave v2 / v3 |
| `keccak256("borrow(uint256,address)")[:4]` | `borrow(uint256 assets, address receiver)` | ERC-4626-style / simple lending |

### Invariants Enforced

For **both** selectors:
1. `ctx.value == 0` (borrow calls carry no ETH).
2. `ctx.target` is in `isAllowedTarget`.
3. `amount` <= `maxAmountPerTx`.
4. `onBehalfOf` (Aave) or `receiver` (simple) == `ctx.account` (the Safe).

For **Aave path only**:
5. `asset` is in `isAllowedToken`.

For **simple path**:
- The asset does not appear in calldata. Token safety is delegated to `isAllowedTarget`.

### Constructor Parameters

| Parameter | Description |
|---|---|
| `allowedTargets` | Lending protocol addresses |
| `allowedTokens` | ERC-20 addresses (checked for Aave path only) |
| `_maxAmountPerTx` | Initial per-transaction borrow cap |
| `_permissionSigner` | Address permitted to call mutable setters |

### Mutable Setters

| Function | Caller | Effect |
|---|---|---|
| `setMaxAmountPerTx(uint256)` | `permissionSigner` | Updates `maxAmountPerTx`. Setting to 0 blocks all non-zero borrows. |

### Security Notes

**This permission enforces a per-transaction cap only, not a lifetime LTV cap.** Outstanding borrows across multiple transactions are not tracked on-chain. For portfolio-level exposure control, operators should either:
- Rely on the lending protocol's own health-factor enforcement, or
- Compose this permission with a position-monitoring permission that reads the protocol's borrow state via `staticcall`.

---

## BoundedWithdrawPermission

**File:** `contracts/templates/BoundedWithdrawPermission.sol`
**discriminator:** `keccak256("BoundedWithdrawPermission")`

### Purpose

Gates ERC-20 withdrawals where the recipient must always be a fixed address set at deployment — typically the owner's Safe address for safe-to-safe consolidation. Ensures the manager can only move approved tokens, within a per-transaction cap, to that single fixed recipient.

### Supported Selectors

| Selector | Function |
|---|---|
| `0xa9059cbb` | `transfer(address to, uint256 amount)` |
| `0x23b872dd` | `transferFrom(address from, address to, uint256 amount)` |

### Invariants Enforced

1. `ctx.value == 0` (ERC-20 calls carry no ETH).
2. `ctx.target` (the token contract) is in `isAllowedToken`.
3. `to` (decoded from calldata) == `allowedRecipient` (immutable).
4. `amount` <= `maxAmountPerTx`.

### Constructor Parameters

| Parameter | Description |
|---|---|
| `safe` | The Safe address that must receive all tokens. **Immutable after deployment.** |
| `allowedTokens` | ERC-20 addresses the manager may move |
| `_maxAmountPerTx` | Initial per-transaction amount cap |
| `_permissionSigner` | Address permitted to call mutable setters |

### Mutable Setters

| Function | Caller | Effect |
|---|---|---|
| `setMaxAmountPerTx(uint256)` | `permissionSigner` | Updates `maxAmountPerTx`. Setting to 0 blocks all non-zero transfers. |

### Security Notes

- **`transferFrom` does not validate the `from` field.** A manager can pull tokens from any address that has previously approved the Safe (e.g., an integrated DeFi protocol whose approval was set elsewhere). If only pulling from the Safe's own balance is intended, use the `transfer` path, or deploy a policy that explicitly restricts `from == ctx.account`.
- `allowedRecipient` is immutable — to change the allowed recipient, a new instance must be deployed and the old one replaced via `replacePermission`.

---

## TransferTargetPermission

**File:** `contracts/templates/TransferTargetPermission.sol`
**discriminator:** `keccak256("TransferTargetPermission")`

### Purpose

Gates ERC-20 transfers and plain ETH sends to a mutable allowlist of approved recipient addresses. Unlike `BoundedWithdrawPermission` — which enforces a single immutable Safe recipient — this permission allows transfers to any pre-approved external address. Suitable for whitelisting partner protocols, CEX deposit addresses, or co-manager wallets.

### Supported Selectors / Operations

| Path | Selector / Condition |
|---|---|
| `transfer(address to, uint256 amount)` | `0xa9059cbb` |
| `transferFrom(address from, address to, uint256 amount)` | `0x23b872dd` |
| Plain ETH send | `txData.length < 4` (no function selector) |

### Invariants Enforced

**ERC-20 paths (`transfer`, `transferFrom`):**
1. `ctx.value == 0`.
2. `ctx.target` (token contract) is in `isAllowedToken`.
3. `to` (decoded from calldata) is in `isAllowedRecipient`.
4. `amount` <= `maxAmountPerTx`.

**Plain ETH send:**
1. `ctx.target` (the ETH recipient) is in `isAllowedRecipient`.
2. `ctx.value` <= `maxAmountPerTx`.
3. No token check — ETH gating uses the recipient allowlist and amount cap only.

### Difference from `BoundedWithdrawPermission`

| Dimension | `BoundedWithdrawPermission` | `TransferTargetPermission` |
|---|---|---|
| Recipient | Single immutable address (`allowedRecipient`) | Mutable mapping (`isAllowedRecipient`) |
| ETH sends | Not supported | Supported (calldata < 4 bytes) |
| Recipient changes | Requires redeployment | `setAllowedRecipient` |
| Use case | Returning funds to the owner's Safe | Sending to partner protocols, CEX addresses, or wallets |

### Constructor Parameters

| Parameter | Description |
|---|---|
| `allowedRecipients` | Initial set of permitted recipient addresses |
| `allowedTokens` | ERC-20 addresses the manager may transfer (not applied to ETH sends) |
| `_maxAmountPerTx` | Initial per-transaction amount cap |
| `_permissionSigner` | Address permitted to update allowlist and cap |

### Mutable Setters

| Function | Caller | Effect |
|---|---|---|
| `setMaxAmountPerTx(uint256)` | `permissionSigner` | Updates `maxAmountPerTx`. Setting to 0 blocks all non-zero transfers. |
| `setAllowedRecipient(address, bool)` | `permissionSigner` | Adds (`true`) or removes (`false`) an address from `isAllowedRecipient`. Must not be `address(0)`. |

### Security Notes

- **`transferFrom` does not validate the `from` field.** Same caveat as `BoundedWithdrawPermission` — the manager can pull from any address that has approved the Safe.
- **The recipient allowlist is mutable.** Because `permissionSigner` can add new recipients after deployment, operators should use a multisig or time-locked address as `permissionSigner` in production. A compromised `permissionSigner` key can add arbitrary recipient addresses.
- Adding a recipient address that is itself a malicious contract could allow indirect fund extraction. Vet recipient addresses carefully.
