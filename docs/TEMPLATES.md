# Sail Permission Templates — Operator Guide

This is the operator-facing companion to the permission templates that ship with Sail. It explains what each template is for, what you configure, and — just as importantly — what each one does **not** guarantee. For source-level detail, read each contract's header NatSpec in `contracts/templates/`; for the protocol's security model, see [`SECURITY.md`](./SECURITY.md).

The launch set is **seven user-facing templates**, plus one shared base they all inherit (`ConfigurablePermission`, not deployed on its own). They are reference implementations: swappable defaults you are responsible for reviewing against your own use, and any contract implementing `IPermission` can be registered instead.

---

## The shared model (read this once)

**What a permission template is.** A template is a contract the kernel calls on **every dispatch**, via `staticcall`, to decide whether the manager's proposed transaction is allowed. It returns allow/deny only — it **never moves funds** and **cannot change state** (custody stays in the Safe). Evaluation is **fail-closed**: a revert, an out-of-gas, or a `false` return all mean *deny*. A single-dispatch `evaluate` runs under a fixed **150,000-gas cap** (a batch template's `evaluateBatch` runs under **1,000,000**), and each dispatch is gated by **one** named permission the manager selects (selective authorization) — so the bounds you register are exactly the bounds that apply.

**What that buys the operator.** Every bound below is enforced **on-chain, in Solidity, at call time**. A compromised or buggy manager can only ever act *within* the bounds of a registered template — it cannot exceed them. The owner can **revoke a permission in a single block**. Nothing here depends on off-chain trust in the manager.

**Configuration & multi-tenancy.** One template contract serves **any number of accounts**: each account stores its own bounds. You set those bounds with `configure(...)`, authorized by an **EIP-712 signature from the account's permission signer** (or `configureDirect` when the signer calls directly). All seven inherit this config/auth spine from `ConfigurablePermission`; reconfiguring replaces an account's bounds.

**The honest caveat.** These templates enforce a **shape and bounds** — which selector, which token/router/recipient, how much per call, output pinned to the account — **not the honesty of the venue** they point at. Allowlisting a malicious or buggy router/vault/pool is not something a template can catch. A template is only as good as its configuration and the keys behind the permission signer and manager. Read each template's "does NOT" section before relying on it.

**Oracle adapters and the gas cap.** Oracle-backed templates (`SwapPermission`, `BorrowPermission`) read their configured `IOracle` adapter inside `evaluate`, which runs under the 150,000-gas cap. A heavy adapter — one that performs multiple external reads or expensive math — can exhaust that budget, and `evaluate` then fails closed (deny), blocking otherwise-valid dispatches. Budget the adapter's read cost against the cap and test the heaviest adapter you intend to allowlist end-to-end before relying on it in production.

---

## SwapPermission — oracle-gated swap *(recommended default)*

Gates DEX swaps to allowlisted tokens/routers, within a size cap, with a slippage band measured against an independent price oracle.

- **You configure:** `routers[]`, `tokensIn[]`, `tokensOut[]` (allowlists); `maxAmountPerTx` (per-trade input cap); `maxSlippageBps` (tolerance vs the oracle, 0–9_999); `priceOracle` (an injected `IOracle` adapter — **required**); `maxPriceAgeSec` (freshness bound). Validated at configure: slippage ≤ 9_999, an oracle must be set (else `OracleRequired`), and a non-zero freshness bound is required.
- **Enforces:** input/output tokens and router allowlisted · `amountIn ≤ cap` · **output recipient == the account** · oracle fresh and non-zero · `amountOutMin ≥ oracleMinOut` (the band); if the derived floor rounds to zero, it **denies** rather than waving the trade through.
- **Compatibility:** standard router ABIs only — V2 `swapExactTokensForTokens` and V3/SwapRouter02 `exactInputSingle`. These are shared byte-for-byte by Uniswap and its forks (PancakeSwap, SushiSwap, etc.) — coverage comes from the **router allowlist**, not per-protocol code. **Not covered:** Universal Router, Uniswap V4, or DEX aggregators (1inch/CoW/etc.) — their parameters live in an opaque blob this template won't decode.
- **Does NOT:** protect against a manipulated or compromised oracle (the band is only as good as the feed); bound *cumulative* trading — the cap is per-transaction; judge whether a trade is wise.

## SwapPermissionNoOracle — pool-referenced hallucination guard for tokens without an oracle

A pool-referenced hallucination guard for tokens that have **no oracle** — no independent, manipulation-resistant feed. It is the non-oracle tier; for manipulation-resistant price protection use the oracle-gated `SwapPermission`.

- **You configure:** `routers[]`, `tokensIn[]`, `tokensOut[]`, `maxAmountPerTx`, and — per pair — a **reference pool**: its address, an operator-declared **kind** (`V2` or `V3`), and a per-pair **tolerance band** (bps, capped at 50%). Validated strictly at configure: every tradeable `(tokenIn, tokenOut)` pair must have a reference pool whose `token0`/`token1` match the pair (orientation is fixed then), each tolerance ≤ 50%, and each pool non-zero — otherwise `configure()` reverts.
- **Enforces:** input/output tokens and router allowlisted · `amountIn ≤ cap` · **output recipient == the account** · `amountOutMin` non-zero · **the sanity band** — it reads the named reference pool's **live** price (V2 reserves / V3 `sqrtPriceX96`) and rejects the swap if `amountOutMin` is more than the pair's tolerance below the output that price implies. Fail-closed: it denies if the reference pool is missing, unreadable, illiquid, or does not correspond to the pair, or if the tolerance-adjusted floor rounds to zero.
- **Compatibility:** same selector/venue scope as `SwapPermission` — V2 `swapExactTokensForTokens` and V3/SwapRouter02 `exactInputSingle`; not the Universal Router, Uniswap V4, or aggregators. The reference pool is a V2 pair or a V3 pool, declared per pair.
- **Does NOT:** protect against price **manipulation**. The reference is a **single pool's live spot price**, which any party can move within the same transaction — a sandwich/MEV bot, a malicious manager, or a compromised agent can flash-loan the pool to a price of their choosing right before the gated swap. Against that threat this band provides **no protection** and is **not a slippage defense**. It is a **hallucination guard**: it catches an *honest* agent's price mistake, because a confused agent is not also manipulating the pool. The named pool is a convenience reference, **not** a trusted or manipulation-resistant source. For manipulation-resistant price protection, use `SwapPermission`.

## BorrowPermission — bounded borrow with optional LTV ceiling

Gates borrows on allowlisted lending protocols/assets, within a size cap, optionally under an LTV ceiling.

- **You configure:** `protocols[]`, `assets[]`, `maxAmountPerTx`, `maxLtvBps`, `collateralOracle`, `borrowOracle`, `maxPriceAgeSec`. Validated at configure: `maxLtvBps ≤ 10_000`; oracles must be a **matched pair** — zero or both, never exactly one (`OracleConfigInconsistent`); a freshness bound is required when oracles are set.
- **Enforces:** protocol (call target) and asset allowlisted · `amount ≤ cap` · the position is **credited to the account** (`onBehalfOf`/`receiver` == account) · with both oracles set, resulting **LTV ≤ `maxLtvBps`** (computed at full precision, no truncation).
- **Compatibility:** Aave V3 `borrow`, Morpho `borrow`, and Compound V2 `borrow` selectors.
- **Does NOT:** apply an LTV ceiling at all when **zero oracles** are configured — that mode is **size-cap-only** (the `maxLtvBps` value is stored but unused). The LTV check is **per-call, not cumulative**: it bounds each borrow step against collateral at that moment, but does not bound the cumulative LTV of a position built across multiple borrows (e.g. a leverage loop). It is checked at borrow time only, not ongoing health, and cannot protect against a dishonest feed. For cumulative-position safety rely on the lending protocol's own health factor and/or a separate monitoring permission.

## TransferPermission — ERC-20 transfer to an allowlisted recipient set

Gates ERC-20 sends to a pre-approved **set** of recipients.

- **You configure:** `allowedRecipients[]`, `allowedTokens[]`, `maxAmountPerTx`. Validated at configure: each list ≤ 50 entries, non-empty, no zero addresses.
- **Enforces:** token (call target) allowlisted · `amount ≤ cap` · destination in the recipient allowlist · on `transferFrom`, `from == the account` (so the manager can't pull tokens a third party approved to the account) · native ETH rejected (`msg.value != 0` denies).
- **Compatibility:** ERC-20 `transfer` and `transferFrom` only; any other selector (including `approve`) is denied. This is a plain token-transfer gate — it does **not** interpret vault/pool/router calldata.
- **Does NOT:** vet the recipients — they're an open set the permission signer controls; a malicious-but-allowlisted recipient isn't caught. The cap is per-transaction, not cumulative. A `maxAmountPerTx` of 0 blocks every non-zero transfer (fail-closed).

## DepositPermission — ERC-20 deposit credited to the account

Gates deposits into allowlisted vaults/lending pools, always crediting the account.

- **You configure:** `targets[]` (protocols/vaults), `tokens[]`, `maxAmountPerTx`. Validated at configure: each list ≤ 50, non-empty, no zero addresses.
- **Enforces:** target allowlisted · deposited token/asset allowlisted · `amount ≤ cap` · the **position recipient** (`receiver` for ERC-4626, `onBehalfOf` for Aave-style) **== the account** · native ETH rejected.
- **Compatibility:** ERC-4626 `deposit(assets,receiver)` / `mint(shares,receiver)` and Aave-style `deposit`/`supply(asset,amount,onBehalfOf,uint16)`; any other selector is denied. **Vault-allowlist note:** the ERC-4626 paths do **not** carry the underlying token in calldata — only the vault. Since a vault accepts exactly one fixed underlying, you allowlist the **vault address itself** in `tokens[]` (as well as `targets[]`); that authorizes deposits of that one token. Aave-style paths carry the asset in calldata and allowlist it directly.
- **Does NOT:** size the `mint()` cap in underlying assets — it caps **shares**, whose value floats with the share price (size it accordingly). The cap is per-transaction, not cumulative. An allowlisted-but-malicious vault/pool is not vetted.

## WithdrawPermission — ERC-20 move to a single pinned recipient

Gates ERC-20 movements so funds only ever reach **one configured recipient** (typically the owner's own Safe — e.g. safe-to-safe consolidation).

- **You configure:** `tokens[]`, a single `allowedRecipient`, `maxAmountPerTx`. Validated at configure: token list ≤ 50 and non-empty, recipient non-zero, no zero-address tokens.
- **Enforces:** token allowlisted · `amount ≤ cap` · destination **== the single `allowedRecipient`** · on `transferFrom`, `from == the account` · native ETH rejected.
- **Compatibility:** ERC-20 `transfer` and `transferFrom` only; any other selector (including `approve`) is denied. This moves ERC-20s to a pinned address — it is **not** a protocol-withdraw interface (no vault/pool redeem/withdraw). To redeem from a vault, pair it with a separate permission.
- **Does NOT:** make the recipient immutable — it is whatever the latest configuration set, and the permission signer can change it by reconfiguring (the pin is only as trustworthy as that key). The cap is per-transaction, not cumulative. A `maxAmountPerTx` of 0 blocks every non-zero withdrawal (fail-closed).

## ApproveAndCallBatchPermission — atomic approve / consume / reset

Authorizes exactly the three-call pattern **approve → consuming call → reset-to-zero**, so an allowance exists only for the lifetime of one batch.

- **You configure:** `tokens[]` with index-parallel `maxApprovalAmounts[]`; `spenders[]`; `consumingPairs[]` (each a bound `(target, selector)`); `requireAmountMatch` (bool); `requireRecipientIsAccount` (bool, default off). Validated at configure: lists ≤ 50, non-empty, no zero entries.
- **Enforces:** `calls[0]` is `approve(spender, amount)` on an allowlisted token, `0 < amount ≤ cap`, spender allowlisted · `calls[1]` is on an **allowlisted `(target, selector)` pair** — a selector is valid only on the target it was paired with, never on any other allowlisted target · optional: the consuming call's leading amount must equal the approve amount (`requireAmountMatch`) · `calls[2]` resets the same token/spender allowance to exactly zero.
- **Optional recipient pinning (`requireRecipientIsAccount`):** when on, the consuming call's output recipient is decoded and must equal the account, for a fixed set of standard selectors whose recipient sits at a known calldata offset (Uniswap V2/V3 swaps, Aave `supply`/`deposit`, ERC-4626 `deposit`/`mint`); **any other selector is denied** (fail closed). Prefer turning it **on** whenever every consuming selector you authorize is in that set.
- **Does NOT:** with recipient pinning **off** (the default), constrain where the consuming call sends its output — the bracket bounds the *allowance*, not the destination. It does not vet the venue behind an allowlisted `(target, selector)` pair.

---

*Substantive change to any template requires re-review. This guide describes the current launch set; if a template's logic changes, update this file alongside it.*
