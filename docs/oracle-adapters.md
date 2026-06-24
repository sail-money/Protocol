# Oracle Adapter Specification

`SwapPermission` and `BorrowPermission` do not read prices themselves — they read an
operator-supplied contract implementing [`IOracle`](../contracts/interfaces/IOracle.sol).
Oracle choice (Chainlink, a TWAP, a custom feed, …) is an ecosystem concern, not a
protocol concern: Sail ships the interface and the consuming templates, not a blessed
adapter. This document fixes the semantic contract every adapter must satisfy so the
templates behave correctly.

```solidity
function getPrice(address base, address quote)
    external view
    returns (uint256 price, uint8 decimals, uint256 updatedAt);
```

There are three adapter *roles*. One contract may serve more than one role, but each
role has distinct call semantics.

| Role | Called as | `base` | `quote` | Returns |
|------|-----------|--------|---------|---------|
| Swap oracle | `getPrice(tokenIn, tokenOut)` | token being sold | token being bought | price of `tokenIn` in `tokenOut` units |
| Borrow oracle | `getPrice(asset, address(0))` | the borrow asset | common numeraire | per-unit value of `asset` in the numeraire |
| Collateral oracle | `getPrice(account, address(0))` | the **account** | common numeraire | the account's **aggregate** collateral value in the numeraire |

---

## 1. Units / denomination of `price`

`price` is a fixed-point mantissa: **1 unit of `base` = `price / 10^decimals` units of
`quote`**, with both sides in the tokens' own native units — no external normalization
([`IOracle.sol:6-7`](../contracts/interfaces/IOracle.sol)).

The templates consume it exactly this way:

- Swap: `expectedOut = Math.mulDiv(amountIn, price, 10**decimals)`
  ([`SwapPermission.sol:249`](../contracts/templates/SwapPermission.sol)).
- Borrow: `borrowScaled = Math.mulDiv(amount, borPrice, 10**borDecimals)`
  ([`BorrowPermission.sol:221`](../contracts/templates/BorrowPermission.sol)).

An adapter that returns a price in any other convention will produce wrong swap floors
or LTV ratios.

---

## 2. `base` / `quote` meaning

Per the interface, `base` is "the token being sold in a swap" and `quote` is "the token
being bought" ([`IOracle.sol:17-18`](../contracts/interfaces/IOracle.sol)). The three
roles specialise this:

### Swap oracle — `getPrice(tokenIn, tokenOut)`
`base = tokenIn` (sold), `quote = tokenOut` (bought). The returned price implies the
expected `tokenOut` for a given `tokenIn` input, which the template turns into a
slippage floor ([`SwapPermission.sol:245`](../contracts/templates/SwapPermission.sol)).

### Borrow oracle — `getPrice(asset, address(0))`
`base = asset` (the borrow asset), `quote = address(0)`. `address(0)` is not a token —
it denotes a **common numeraire** in which value is expressed. The adapter returns the
per-unit value of the borrow asset in that numeraire
([`BorrowPermission.sol:205-206`](../contracts/templates/BorrowPermission.sol)).

### Collateral oracle — `getPrice(account, address(0))`
`base = account` (the Safe account itself, **not** a token), `quote = address(0)` (the
same common numeraire). The adapter is trusted to report the account's **aggregate
collateral value**, queried by account address — it is a portfolio valuation, not a
single-token balance or price
([`BorrowPermission.sol:205`](../contracts/templates/BorrowPermission.sol), NatSpec
[`:42-43`](../contracts/templates/BorrowPermission.sol)).

### Hard requirement: shared numeraire
The borrow oracle and the collateral oracle **MUST express value in the same
numeraire.** The LTV check compares borrow value against collateral value
([`BorrowPermission.sol:224`](../contracts/templates/BorrowPermission.sol)); if the two
adapters use different numeraires the ratio is meaningless and the ceiling provides no
protection. (Borrow oracles are configured in a matched pair — exactly one oracle is
rejected at `configure()`; configure either both or neither.)

---

## 3. `decimals` range and interpretation

`decimals` is the precision of `price`. Valid range is **0..77 inclusive**; a value
above 77 is denied because `10^78` overflows `uint256`
([`IOracle.sol:20-22`](../contracts/interfaces/IOracle.sol)). Enforcement:

- Swap: `if (dec > 77) return false;`
  ([`SwapPermission.sol:248`](../contracts/templates/SwapPermission.sol)).
- Borrow: `if (colDec > 77 || borDec > 77) return false;`
  ([`BorrowPermission.sol:212`](../contracts/templates/BorrowPermission.sol)).

Each role may use its own `decimals`; the template folds `10^decimals` into its `mulDiv`
math, so adapters need not agree on a shared scale (they must, however, agree on the
numeraire — see §2).

---

## 4. `updatedAt` and L2 sequencer-uptime gating

`updatedAt` is the unix timestamp of the last price update. The templates enforce
freshness as **`block.timestamp - updatedAt <= maxPriceAgeSec`**, and treat
`updatedAt == 0` as stale (denied):

- Swap: [`SwapPermission.sol:246`](../contracts/templates/SwapPermission.sol).
- Borrow: both feeds checked, [`BorrowPermission.sol:207-209`](../contracts/templates/BorrowPermission.sol).

A non-zero `maxPriceAgeSec` is mandatory whenever an oracle is configured, so the
freshness bound is always active for an oracle-gated account.

**Adapter responsibilities** ([`IOracle.sol:9-14`](../contracts/interfaces/IOracle.sol),
[`SECURITY.md`](./SECURITY.md)):

- Return a **meaningful `updatedAt`** for every price. Returning `0` or a constant
  timestamp disables freshness protection downstream.
- On **L2s, gate on sequencer-uptime before returning a price.** The templates do **not**
  call a sequencer-uptime feed — that gating is the adapter's responsibility, which is
  what lets a single template serve every chain while the adapter stays
  chain-appropriate.
- The template enforces the freshness bound but **cannot detect a falsified
  `updatedAt`** — an adapter that lies about freshness defeats the check. Operators must
  supply an honest adapter and a sane `maxPriceAgeSec`.

---

## What the template enforces vs. what the adapter must guarantee

| Concern | Template enforces | Adapter must guarantee |
|---------|-------------------|------------------------|
| Price units | consumes `price / 10^decimals` | price expressed in that fixed-point convention (§1) |
| base/quote roles | passes the documented args, uses the result | correct valuation per role; shared numeraire for borrow+collateral (§2) |
| `decimals` | rejects `> 77`, applies `10^decimals` | report true precision in 0..77 (§3) |
| Freshness | `block.timestamp - updatedAt <= maxPriceAgeSec`, rejects `updatedAt==0` | honest `updatedAt`; non-stale data (§4) |
| L2 sequencer uptime | *not checked by the template* | gate on sequencer-uptime before returning a price (§4) |
| Manipulation resistance | *not checked by the template* | use a manipulation-resistant source if that property is required |

The slippage band (swap) and LTV ceiling (borrow) are only as good as the configured
adapter's honesty and freshness; neither template protects against a manipulated or
compromised feed. That guarantee belongs to the adapter the operator allowlists.
