# Sail Permission Templates — A First-Principles Guide

This guide explains the seven permission templates that ship with Sail at launch: what each one is for, what you configure on it, **how it actually decides** whether to allow a transaction (branch by branch, in plain language), and — just as importantly — what it **cannot** protect against.

It is written to be understandable without reading Solidity. For the exact source, each template's header NatSpec in `contracts/templates/` is the canonical boundary text and this guide expands on it; for the kernel and governance security model, see [`SECURITY.md`](./SECURITY.md) and [`spec.md`](./spec.md).

---

## What a permission template *is* (and is not)

A **permission** is a small contract the Sail kernel calls on every transaction a manager proposes, to answer one yes/no question: *is this specific call allowed for this account right now?* It returns **allow** or **deny** and nothing else. It never moves funds, never holds funds, and cannot change any on-chain state — custody stays in the account's Safe the whole time. (The kernel calls it with `staticcall`, which makes state changes physically impossible.)

A **template** is a permission written to be **reused**: one deployment per chain serves *every* account that registers it, with each account's own limits stored separately. You don't deploy your own copy — you register the shared contract and configure your bounds on it.

Two framings matter, and they are easy to confuse:

- **The protocol is permissionless.** Sail does not bless a fixed menu of permissions. Anyone can write and deploy their own permission contract for any venue, and the kernel will register and dispatch through *any* contract that implements the `IPermission` interface. The seven templates below are not "the protocol" — they are a **curated starting set**.
- **These seven are the hardened reference set.** They are the launch templates: hardened, and documented here with honest limits. They are **not** marked "UNAUDITED — EXPERIMENTAL" — that label is reserved for the future *experimental* set (see the end of this document), which is currently empty. "Outside the trusted core" (which they are) is a statement about *blast radius* — a bug in one template can only affect accounts that registered that template, never the kernel or other accounts — not a statement that they are unreviewed.

The shared permission templates were reviewed by Octane Security alongside the core contracts across multiple analyses; all reported vulnerabilities resolved or acknowledged, and the remaining lower-severity warnings are documented or accepted by design. The most recent analysis (2026-06-29) identified no critical- or high-severity findings (see [Security](../README.md#security) and [docs/security](./security/)). Each template documents the boundary of what it enforces — review a template against your intended use before registering it.

---

## The shared model (read this once)

All seven templates inherit the same configuration-and-evaluation spine from a shared base, `ConfigurablePermission` (which is abstract — never deployed on its own). Understanding it once means you only have to read the *differences* in each section below.

**Multi-tenant by design.** One template contract serves any number of accounts. Each account's allowlists and caps live in per-account storage, keyed by the account address. Your configuration never affects anyone else's, and theirs never affects yours.

**You configure with a signed message.** You set an account's bounds by calling `configure(...)`, authorized by an **EIP-712 signature from that account's permission signer** (the role that decides which permissions and bounds apply — see [`spec.md`](./spec.md)). There is also `configureDirect(...)`, usable when the permission signer is the one sending the transaction itself. Reconfiguring **replaces** the account's bounds wholesale. Signatures are single-use (nonce-tracked) and carry a deadline.

**Evaluation is fail-closed.** Deny is the default. A template denies on a `false` return, *and* on any revert or out-of-gas — the kernel treats all three identically as "deny." There is no way for an error to accidentally allow a transaction.

**The first check is always "is this configuration current?"** Every template's first decision is a freshness gate: it denies unless the account is configured **and** the configuration it has matches the *current registration epoch* for that account-and-template. In plain terms: if a permission was revoked and re-registered, any configuration left over from before is treated as stale and ignored until you configure again. This closes a class of attacks where an old, broader configuration could be revived. The mechanism (the config↔registration-epoch binding) is described in [`SECURITY.md`](./SECURITY.md); you don't need to re-derive it here — just know that **a stale or absent configuration always denies.**

**Gas is bounded, and one permission decides each dispatch.** A single transaction is gated by exactly **one** permission that the manager names in their signature (selective authorization); the kernel does not consult every permission you've registered. That one permission's `evaluate` runs under a fixed **150,000-gas** cap (`PERMISSION_GAS_CAP`). The one batch-aware template runs its `evaluateBatch` under a larger **1,000,000-gas** cap (`BATCH_EVAL_GAS_CAP`), and a batch may contain at most **16** sub-calls (`MAX_BATCH_LENGTH`). If a permission runs out of gas, that is a deny.

**The honest caveat that applies to all seven.** A template enforces a **shape and bounds** — which selector, which token/router/recipient, how much per call, output pinned to the account. It does **not** vet the *honesty of the venue* you point it at. Allowlisting a malicious or buggy router, vault, or pool is not something any template can catch. A template is only as strong as its configuration and the keys behind the permission signer and the manager.

---

## How to read each template section

Each of the seven follows the same four-part structure:

1. **Purpose** — the one venue/action it gates.
2. **What you configure** — the bounds you set, and what each choice means for safety.
3. **How evaluation decides** — the deny/allow checks **in the order the code runs them.** This is the part to read closely: it is the literal decision the contract makes.
4. **What it cannot protect against** — the honest boundary, expanded from the contract's own header.

---

## 1. SwapPermission — oracle-gated swap *(recommended default)*

**Purpose.** Gate DEX swaps to allowlisted tokens and routers, within a size cap, with a slippage floor measured against an **independent price oracle** (not the pool being traded).

**What you configure.**
- `routers[]`, `tokensIn[]`, `tokensOut[]` — the allowlists of which router contracts and which input/output tokens are permitted. Each list is capped at **50 entries** (matching the other launch templates); a longer list reverts `AllowlistTooLong` at configure time.
- `maxAmountPerTx` — the cap on the input amount per single trade. (Per trade, not cumulative.) It is a single **raw-unit** cap applied uniformly to every allowlisted input token, so it does **not** normalize for token decimals: a value sized for an 18-decimal asset permits a far larger token count for a low-decimal asset (a `5e18` cap is 5 tokens of an 18-decimal asset but 5,000,000,000,000 tokens of a 6-decimal asset). This is a deliberate, oracle-free tradeoff — value still stays in the account and the per-trade bound still holds in raw units. Operators mixing tokens of different decimals under one instance should size the cap for the **lowest-decimal** asset, or use a separate instance per decimal class.
- `maxSlippageBps` — how far below the oracle-implied output the trade's minimum-out may sit, in basis points (0–9,999). `0` means "exact oracle price or better" — the strictest setting, never a bypass.
- `priceOracle` — an injected `IOracle` adapter. **Mandatory:** configuring without one reverts (`OracleRequired`). This is deliberately *not* the pool being traded, so the price reference is independent of the spot price an attacker could move.
- `maxPriceAgeSec` — how old the oracle's price may be before it is rejected. Must be non-zero whenever an oracle is set (a zero would silently accept arbitrarily stale prices).

**How evaluation decides** (in order):
1. **Configuration current?** Deny if the account isn't configured for the current registration epoch.
2. **Any ETH attached?** Deny if `value != 0`. These swaps pull the input token via ERC-20 allowance; no supported router call needs ETH, and allowing it would let value be forwarded to a payable router and swept back out.
3. **Router allowlisted?** Deny if the call target isn't in `routers[]`.
4. **Recognized swap shape?** It decodes exactly three standard ABIs — Uniswap V2 `swapExactTokensForTokens`, and V3 `exactInputSingle` in both the SwapRouter (with deadline) and SwapRouter02 (no deadline) layouts. Anything else: deny. For the matched shape it then checks, in order:
   - input token allowlisted → else deny;
   - output token allowlisted → else deny;
   - the swap's recipient is **the account itself** → else deny;
   - input amount ≤ `maxAmountPerTx` → else deny;
   - finally the **oracle band**.
5. **The oracle band.** It reads the configured oracle for the (tokenIn, tokenOut) price. It denies if the price is stale (older than `maxPriceAgeSec`), zero, or reports an implausible decimals value. It computes the oracle-implied output, lowers it by `maxSlippageBps` to get a floor, and **allows only if the trade's own minimum-out is at least that floor.** If the floor math rounds down to zero (a dust-sized trade), it **denies** rather than wave through a zero minimum. Note that because the floor math floors, for very-low-decimal output tokens (especially 0-decimal) the computed floor can sit up to one base unit below the exact oracle-implied minimum near an integer boundary — i.e. the band can be up to one base unit lax. This is negligible for typical 6–18 decimal tokens and bounded to a single base unit; the oracle band is a sanity bound, and the manager-supplied minimum-out remains the primary slippage floor.

**What it cannot protect against.** The band is **only as strong as the configured oracle feed** — it does not protect against a manipulated or compromised oracle. The cap is **per-transaction, not cumulative**: a manager can make many at-cap trades. It only decodes standard router ABIs — it does **not** cover the Universal Router, Uniswap V4, or DEX aggregators (1inch/CoW/Matcha), whose parameters live in an opaque blob it won't decode; coverage of forks (PancakeSwap, SushiSwap, etc.) comes from the *router allowlist*, since those share the same ABIs byte-for-byte. And it does not judge whether a trade is *wise* — only whether it is within shape and bounds. Note also (shared with all oracle-backed templates) that a **heavy oracle adapter can exhaust the 150,000-gas cap**, which fails closed — budget your adapter's read cost.

---

## 2. SwapPermissionNoOracle — pool-referenced sanity band for tokens with no oracle

**Purpose.** Gate swaps for tokens that have **no independent price feed**, using a sanity band measured against an operator-named **reference pool's live price**. This is the non-oracle tier; for manipulation-resistant pricing use `SwapPermission` instead. It is **not** zero protection, and it is **not** a slippage defense — read the boundary carefully.

**What you configure.**
- `routers[]`, `tokensIn[]`, `tokensOut[]`, `maxAmountPerTx` — same meaning as `SwapPermission` (allowlists capped at 50 entries; `maxAmountPerTx` is the same single raw-unit, decimal-unnormalized per-trade cap — see the mixed-decimal note above). The per-pair `referencePools` set is **not** separately capped: with the token lists capped at 50, the (tokensIn × tokensOut) coverage requirement already bounds it.
- A **reference pool per tradeable pair** — each entry is the pool's address, an operator-declared kind (`V2` or `V3`), and a per-pair tolerance band in basis points (capped at 50%). Configuration is strict: every tradeable (tokenIn, tokenOut) pair must have a reference pool whose two tokens actually match the pair (orientation is fixed at configure time), each tolerance ≤ 50%, and each pool non-zero — otherwise `configure()` reverts. Surfacing a gap at configure time is clearer than silent denials later.

**How evaluation decides** (in order):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Any ETH attached?** Deny if `value != 0` (same reasoning as `SwapPermission`).
3. **Router allowlisted?** Deny if the target isn't in `routers[]`.
4. **Recognized swap shape?** Same three standard ABIs as `SwapPermission`. For the matched shape: input token allowlisted, output token allowlisted, recipient is the account, input amount ≤ cap — each a deny if it fails — then the **sanity band**.
5. **The sanity band.** It reads the named reference pool's **live** price (V2 reserves, or V3 `sqrtPriceX96`), computes the implied output, and denies if the trade's minimum-out is more than the pair's tolerance below that. It fails closed if the reference pool is missing, unreadable, illiquid, doesn't correspond to the pair, or if the tolerance-adjusted floor rounds to zero.

**What it cannot protect against.** **Price manipulation — completely.** The reference is a *single pool's live spot price*, which any party can move within the same transaction: a sandwich/MEV bot, a malicious manager, or a compromised agent can flash-loan the pool to any price right before the gated swap. Against that, this band provides **no protection** and must not be relied on as slippage defense. What it *is*: a **hallucination guard** — it catches an *honest* manager or agent that tries to trade at a wildly wrong price (a misparsed quote, a fabricated number), because a confused agent is not also manipulating the pool. The named pool is a convenience reference, not a trusted source. Same venue scope and per-transaction cap caveats as `SwapPermission`; ETH is rejected.

---

## 3. BorrowPermission — bounded borrow with an optional LTV ceiling

**Purpose.** Gate borrows on allowlisted lending protocols and assets, within a size cap, optionally under a loan-to-value (LTV) ceiling enforced with a pair of price oracles.

**What you configure.**
- `protocols[]`, `assets[]` — allowlists of lending-protocol targets and the **underlying** borrow assets.
- `maxAmountPerTx` — per-borrow size cap.
- `maxLtvBps` — the LTV ceiling in basis points (≤ 10,000).
- `collateralOracle`, `borrowOracle` — the price feeds for each side. They must be configured as a **matched pair**: either *both* set (LTV enforced) or *neither* (size-cap-only). Exactly one is rejected at configure time (`OracleConfigInconsistent`), because an LTV ratio needs both sides priced.
- `maxPriceAgeSec` — freshness bound, mandatory when oracles are set.

**How evaluation decides** (in order):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Any ETH attached?** Deny if `value != 0` (no supported borrow selector is payable). This makes all 7 functional templates uniform in rejecting native ETH.
3. **Protocol allowlisted?** Deny if the call target isn't in `protocols[]`.
4. **Recognized borrow shape?** It decodes three selectors — Aave V3 `borrow`, Morpho `borrow`, and Compound V2 `borrow`. Anything else: deny. For each:
   - the borrow **asset** must be allowlisted — for Compound, the call target is the cToken, so it resolves the **underlying** via `underlying()` and allowlists *that*; a target with no `underlying()` (e.g. cETH) resolves nothing and is **denied** (fail-closed);
   - amount ≤ `maxAmountPerTx` → else deny;
   - the position is credited to **the account** (`onBehalfOf` / `receiver` == account) → else deny;
   - **Aave only:** the interest-rate mode must be **variable** (mode `2`); a stable-rate borrow is **denied**. This is the reference template's opinionated default, not a claim that variable is universally safer — a strategy that needs stable-rate debt should use a dedicated permission. Morpho and Compound carry no rate-mode argument and are unaffected. The Aave **referral code is unconstrained** — it is off-chain attribution with no effect on funds or the resulting position;
   - then the **LTV check**.
5. **The LTV check.** If no oracles are configured, this step passes (size-cap-only mode). If both are set: it reads collateral value and borrow price, denies on a stale or zero/implausible reading, and computes the **largest borrow amount the ceiling permits**, comparing the requested amount against it. The math is **fail-closed and amount-based**: it applies the LTV fraction to the full-precision collateral value first and collapses decimal scale last, flooring in the borrower's disfavour at every step — so a borrow over the ceiling can never slip through, and the prior bug where a sub-1-unit borrow rounded to zero LTV is closed.

**What it cannot protect against.** With **zero oracles**, there is **no LTV ceiling at all** — only the size cap applies (the stored `maxLtvBps` is unused in that mode). The LTV check is **per-call, not cumulative**: it bounds each borrow step against collateral at that instant, not the cumulative LTV of a position built across many borrows (a leverage loop). It is checked only at borrow time, not ongoing position health, and cannot detect a dishonest feed. For cumulative-position safety, rely on the lending protocol's own health factor and/or a separate monitoring permission. As with `SwapPermission`, a heavy oracle adapter can exhaust the gas cap and fail closed. Because the LTV math rounds conservatively at every step, a borrow that is **marginally within** the true ceiling may be rejected — the fail-closed direction, never an over-LTV approval; the recourse is to borrow slightly less. Finally, restricting Aave to variable rate means that if a market's variable-rate borrowing is paused/disabled while stable remains open, this template cannot borrow there at all (a bounded availability limitation, not a loss of funds).

**Compound V2 soft-fail (nonce burn).** Aave and Morpho borrows **revert** on failure, so a failed borrow leaves the manager's signing nonce intact. Compound V2's `borrow` is different: it returns a non-zero **status code without reverting** on a soft-fail (borrow cap reached, insufficient market cash, comptroller rejection). The kernel treats any non-reverting module call as success (it is venue-agnostic by design and does not decode return data), so a Compound V2 soft-fail in that window **consumes the manager's pre-signed dispatch nonce with no borrow executed** — a recoverable nonce-burn (re-sign with the next nonce), no funds at risk. Operators registering Compound V2 borrow should be aware of this; Aave/Morpho are unaffected.

**Mixed-decimal size cap.** `maxAmountPerTx` is a single raw-unit cap applied uniformly to every allowlisted borrow asset; it does **not** normalize for token decimals (a value sized for an 18-decimal asset permits a far larger token count for a low-decimal asset). Deliberate oracle-free tradeoff; the borrow is still bounded in raw units and credited to the account. Operators mixing decimals should size for the lowest-decimal asset or use separate instances — the same boundary as the swap and deposit templates.

---

## 4. TransferPermission — ERC-20 transfer to an allowlisted recipient set

**Purpose.** Gate ERC-20 sends so funds move only to a pre-approved **set** of recipients, in approved tokens, within a per-transaction cap.

**What you configure.**
- `allowedRecipients[]` — the set of addresses funds may be sent to.
- `allowedTokens[]` — the tokens that may be moved.
- `maxAmountPerTx` — per-transfer cap. Each list is capped at 50 entries, must be non-empty, and may not contain the zero address. (A `maxAmountPerTx` of 0 is allowed and blocks every non-zero transfer — fail-closed.)

**How evaluation decides** (in order):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Any ETH attached?** Deny if `value != 0` (ERC-20 calls carry no ETH).
3. **Token allowlisted?** Deny if the call target (the token) isn't in `allowedTokens[]`.
4. **Recognized transfer shape?** It decodes exactly `transfer(to, amount)` and `transferFrom(from, to, amount)`; any other selector — including `approve` — is denied. Then:
   - amount ≤ `maxAmountPerTx` → else deny;
   - the destination `to` must be in `allowedRecipients[]` → else deny;
   - on `transferFrom`, additionally `from` must be **the account itself**, so the manager cannot pull tokens a third party has approved to the account.

**What it cannot protect against.** It does **not vet the recipients** — they are an open set the permission signer controls, and an allowlisted-but-malicious recipient contract is not caught here. The cap is per-transaction, not cumulative. It is a plain token-transfer gate: it does **not** interpret vault/pool/router calldata of any kind.

---

## 5. DepositPermission — ERC-20 deposit credited to the account

**Purpose.** Gate deposits into allowlisted vaults and lending pools, always crediting the resulting position to the account.

**What you configure.**
- `targets[]` — the vault/protocol addresses you may deposit into.
- `tokens[]` — the allowlisted assets (see the vault note below).
- `maxAmountPerTx` — per-deposit cap. Lists capped at 50, non-empty, no zero addresses.

**How evaluation decides** (in order):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Any ETH attached?** Deny if `value != 0` (no supported deposit selector is payable; wrap to WETH first).
3. **Target allowlisted?** Deny if the call target isn't in `targets[]`.
4. **Recognized deposit shape?** It decodes four selectors — ERC-4626 `deposit(assets, receiver)` and `mint(shares, receiver)`, and Aave-style `deposit`/`supply(asset, amount, onBehalfOf, uint16)`. Anything else: deny. For each:
   - the asset must be token-allowlisted. **Important:** the two ERC-4626 paths do *not* carry the underlying token in calldata — only the vault address. Since a vault accepts exactly one fixed underlying, you allowlist the **vault address itself** in `tokens[]` (in addition to `targets[]`), which authorizes deposits of that one token. The Aave-style paths carry the asset in calldata and allowlist it directly.
   - amount (or shares — see below) ≤ `maxAmountPerTx` → else deny;
   - the position recipient (`receiver` for ERC-4626, `onBehalfOf` for Aave-style) is **the account** → else deny.

**What it cannot protect against.** On the `mint(shares, receiver)` path, the cap is denominated in **shares, not underlying assets** — by design. The `deposit(assets, ...)` path and both Aave paths cap the *asset* amount directly; `mint` bounds *shares*, whose asset/USD value floats with the share price. These templates are intentionally oracle-free, so an asset cap on the mint path would reintroduce a vault price-read; shares stay bounded, so there is no drain, but an operator sizing a mint cap must account for the share price.

For ERC-4626, **`mint(shares)` is the donation-safe path**: it pins the share outcome (you receive exactly `shares`, credited to the account). The `deposit(assets)` path has no minimum-shares guard, so a classic vault **donation/inflation attack** can cause a manager-triggered `deposit(assets)` to mint near-zero shares to the account. This is **negative-EV griefing** (the attacker must donate more than they destroy) and the assets/shares stay credited to the account (griefing, not theft) — but operators wanting a pinned outcome should prefer `mint(shares)`.

`maxAmountPerTx` is a single raw-unit cap applied uniformly across all allowlisted assets; it does **not** normalize for token decimals (the same mixed-decimal boundary as the swap and borrow templates) — size for the lowest-decimal asset or use separate instances. The cap is per-transaction, not cumulative, and an allowlisted-but-malicious vault is not vetted.

---

## 6. WithdrawPermission — ERC-20 move to a single pinned recipient

**Purpose.** Gate ERC-20 movements so funds can only ever reach **one configured recipient** — typically the owner's own Safe (e.g. safe-to-safe consolidation).

**What you configure.**
- `tokens[]` — allowlisted tokens (≤ 50, non-empty, no zero addresses).
- `allowedRecipient` — the **single** address funds may go to (non-zero).
- `maxAmountPerTx` — per-move cap (0 allowed; blocks all non-zero withdrawals — fail-closed).

**How evaluation decides** (in order):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Any ETH attached?** Deny if `value != 0`.
3. **Token allowlisted?** Deny if the call target isn't in `tokens[]`.
4. **Recognized transfer shape?** Exactly `transfer` and `transferFrom`; any other selector (including `approve`) denied. Then:
   - amount ≤ `maxAmountPerTx` → else deny;
   - the destination must equal **the single `allowedRecipient`** (not an open set) → else deny;
   - on `transferFrom`, `from` must be **the account itself**.

**What it cannot protect against.** The recipient is **not immutable** — it is whatever the latest configuration set, and the permission signer can change it by reconfiguring, so the pin is only as trustworthy as that key. The cap is per-transaction, not cumulative. It moves ERC-20s to a pinned address — it is **not** a protocol-withdraw interface and does not recognize vault/pool redeem or withdraw calls; to redeem from a vault, pair it with a separate permission.

---

## 7. ApproveAndCallBatchPermission — atomic approve / consume / reset

**Purpose.** Authorize exactly one three-step pattern — **approve → consuming call → reset-to-zero** — so an allowance exists only for the lifetime of a single batch and is always reset before the transaction completes. This is the one **batch-aware** template: the kernel evaluates the whole sequence at once via `evaluateBatch`, under the 1,000,000-gas batch cap.

**What you configure.**
- `tokens[]` with index-parallel `maxApprovalAmounts[]` — the approvable tokens and each one's per-approval cap.
- `spenders[]` — the addresses that may receive the allowance.
- `consumingPairs[]` — bound `(target, selector)` pairs: a selector is valid **only** on the target it is paired with, never on any other allowlisted target.
- `requireAmountMatch` (bool) — optionally require the consuming call's leading amount to equal the approved amount.
- `allowUnconstrainedRecipient` (bool, **default off → recipient pinned**) — the consuming call's output recipient is pinned to the account **by default**; set this flag true to deliberately opt out and leave the recipient unconstrained. **Note:** this is a change from the prior default, which left the recipient unconstrained unless a pin was explicitly enabled.

**How evaluation decides** (in order, on the three-call batch):
1. **Configuration current?** Deny if not configured for the current epoch.
2. **Exactly three calls?** Deny otherwise.
3. **Call 0 — the approve.** Must carry no ETH; must be `approve(spender, amount)` on an allowlisted token; the token's cap must be non-zero (i.e. allowlisted); the spender must be allowlisted; `0 < amount ≤ cap`. **And the pre-batch allowance on that (token, spender) pair must already be zero** — so the consuming call can only ever draw the allowance *this* batch grants, never a stale one.
4. **Call 1 — the consuming call.** Must carry no ETH; long enough to decode; its `(target, selector)` must be an allowlisted **pair**. Then two unconditional bindings:
   - the call's target must **be the approved spender** (you approve the router/pool/vault and call that same address);
   - the **asset it pulls must be the approved token**, decoded for the seven decodable standard-ABI selectors (the V2/V3 swaps, Aave `supply`/`deposit`, ERC-4626 `deposit`/`mint`); a selector whose consumed asset can't be located safely is **denied** (fail-closed).
   Then: `requireAmountMatch` (if set) checks the leading amount equals the approve amount; and **by default** the output recipient is decoded and required to equal the account (denying any selector outside the decodable set), unless `allowUnconstrainedRecipient` was set to opt out.
5. **Call 2 — the reset.** Must carry no ETH; must be `approve(spender, 0)` on the **same** token and spender as call 0, resetting the allowance to exactly zero.

If every check passes, the batch is allowed.

**What it cannot protect against.** By default the output recipient is pinned to the account. If you set `allowUnconstrainedRecipient` to opt out, the template no longer constrains where the consuming call sends its output — the bracket then bounds the *allowance* (and binds it to the approved token and spender), not the destination. Opt out only when an authorized consuming selector falls outside the decodable set and an unconstrained recipient is genuinely intended; the default pin is the safer configuration. The consuming selector **must** be one of the seven decodable standard-ABI selectors — aggregators, the Universal Router, Uniswap V4, and opaque command payloads are **out of scope by design** (non-decodable → fail-closed). It does not vet the venue behind an allowlisted pair. The batch is capped at 16 sub-calls and 1,000,000 gas.

---

## The experimental set (currently empty)

There is no experimental template directory in the repository today (`contracts/experimental/` is absent). This is where future, **not-yet-audited** templates will live — candidates include bridging, Hyperliquid/CoreWriter trading, Pendle, prediction markets, and the aggregator / Universal-Router / Uniswap-V4 "balance-delta" swap path that the hardened `Swap` templates deliberately exclude.

When that set is populated, each contract in it will carry a loud **"UNAUDITED — EXPERIMENTAL"** banner and will **not** be part of the hardened launch set described above. That banner belongs *only* to the experimental set — it does **not** apply to the seven launch templates, which are the hardened reference set. Treat anything in the experimental set as unreviewed until stated otherwise, and review it against your own use before registering it.

---

*This guide describes the current launch set against the merged, frozen code. Any substantive change to a template requires re-review; update this file alongside the contract and keep it consistent with the contract's header NatSpec, which is canonical.*
