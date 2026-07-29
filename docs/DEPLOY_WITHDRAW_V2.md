# Deploying the vault-exit `WithdrawPermission` to all 12 chains

Runbook for shipping `contracts/templates/WithdrawPermission.sol` (branch
`feat/withdraw-permission`) — the rewritten template that gates **ERC-4626 vault exits and Aave
v2/v3 pool withdrawals**, replacing the original ERC-20-transfer withdraw gate.

**Status: COMPLETE.** Deployed and verified on all 12 chains — see §5. Retained as the record of
what was done and why, and as the template for future single-template rollouts.

---

## 1. What is shipping, and why at a new address

The old `WithdrawPermission` gated `transfer` / `transferFrom` to a single allowed recipient. The new
one gates three exit selectors and pins recipient/owner to the account:

| Selector | Signature | Venue |
|----------|-----------|-------|
| `0xb460af94` | `withdraw(uint256 assets, address receiver, address owner)` | ERC-4626 (Morpho, etc.) |
| `0xba087652` | `redeem(uint256 shares, address receiver, address owner)` | ERC-4626 |
| `0x69328dec` | `withdraw(address asset, uint256 amount, address to)` | Aave v2 LendingPool + v3 Pool |

This is a **new deployment at a new address**, not an upgrade. The templates are immutable and
non-proxied, so the salt is rotated (`sail.template.withdraw.v1` → `.v2`) and the old contract stays
live and untouched:

| | Address | Status |
|---|---|---|
| v1 (ERC-20 transfer gate) | `0xF5eF5dda450a130e3020d54f565E830e4a7531f8` | live, superseded — **not** disabled or revoked |
| v2 (vault exit) | `0xB8A6CC40466c0C33a230f87a1EBC368568B96269` | **live on all 12 chains** |

Accounts that already registered v1 keep working exactly as before. Nothing revokes it on their
behalf; migrating an account is a per-account `replacePermission` (or revoke + register), which
requires that account's permission-signer signature and pays the registration fee again.

**No governance action is required.** Unlike the core deploy, permission templates are not
allowlisted: `SailKernel.registerPermission` accepts any non-zero contract address, gated by the
account's own EIP-712 signature and the registration fee (`contracts/core/SailKernel.sol:1015`).
There is no `bootstrapAllowlists` equivalent, no timelock, and no Safe transaction for this.

---

## 2. Decisions baked into the pinned address

Each of these changes the contract bytecode, and therefore the CREATE2 address. Once the first chain
is broadcast the address is frozen — revisiting any of them afterwards means starting over at a
third address.

### 2a. `permissionId()` / `permissionVersion()` bumped to `.v2` — resolved

As written on the branch, the rewritten contract self-declared the **same** introspection identity as
the ERC-20 template it replaces:

```solidity
permissionId()      => keccak256("sail.permission.WithdrawPermission.v1")   // old AND new
permissionVersion() => keccak256("v1")                                      // old AND new
```

…while being semantically incompatible: disjoint selector sets and a different config blob
(`(address[] tokens, address allowedRecipient, uint256)` → `(address[] targets, address[] tokens,
uint256)`). Both contracts are live simultaneously, so any consumer resolving a permission through
`IPermissionIntrospection` rather than by raw address could not tell them apart — and would decode
the config blob with the wrong ABI.

**Resolved: bumped to `sail.permission.WithdrawPermission.v2` / `keccak256("v2")`.** The other six
templates keep `.v1`, which stays correct — they were never rewritten. `discriminator()` and the
`SailCapabilities.WITHDRAW` capability id deliberately carry over unchanged.

This is unrelated to the `"2"` in `ConfigurablePermission(_kernel, "WithdrawPermission", "2")`, which
is the EIP-712 domain version and is `"2"` on every template. Domain separators already differ
between the two contracts because `verifyingContract` differs, so configure-signatures could never
be replayed across them either way.

The bump changed the pinned address — `0x6f2517fa…` (pre-bump) → **`0xB8A6CC40…`**. Both the deploy
script's `EXPECTED_*` constants and this runbook reflect the post-bump values.

### 2b. Registry model for the superseded v1 — decided, change if you disagree

The merge script (`scripts/apply-withdraw-v2.mjs`) advances `withdraw` to v2 and records v1 as
`withdrawV1Superseded` (per-chain) / `canonicalAddresses.supersededTemplates` (index), rather than
dropping it. Keeping it published matters: accounts still have it registered, and its address will
keep appearing in explorers and support questions.

### 2c. Reproducible builds — optional, flag only

`foundry.toml` does not set `bytecode_hash`, so solc's default IPFS metadata hash is embedded. A
third party cannot reproduce `0xB8A6CC40…` from source unless their build produces a byte-identical
metadata hash. Setting `bytecode_hash = "none"` would make the address independently derivable —
but it changes the address, and it is a repo-wide compiler setting worth deciding on its own merits
rather than mid-rollout. `deployments/deployments.json` already tracks this as a pre-launch item
(`provenanceNote`). The rollout below does not depend on it: parity is enforced by pinning the
initCode hash, not by rebuilding.

---

## 3. Preflight

```bash
forge test --match-path "test/WithdrawPermission*"
```

80 tests across three suites (unit, adversarial stress, independent red-team) — all passing on the
branch tip.

```bash
forge script script/templates/PredictSharedTemplates.s.sol:PredictSharedTemplates
```

Prints, per template, the address this working tree would produce vs what is live. Expected output on
the branch tip:

- **All six unchanged templates MISMATCH.** This is the known solc metadata drift, not a
  regression — see §4.
- Withdraw under the `.v1` salt also mismatches, which is why the salt is rotated.
- `Withdraw v2 predicted: 0xB8A6CC40466c0C33a230f87a1EBC368568B96269`,
  `initCodeHash: 0x633477be…e02cee9a`.

If either v2 value differs from what is pinned in `DeployWithdrawPermission.s.sol`, **stop** — the
build drifted, and continuing would land different addresses on different chains.

---

## 4. Do not use `--target templates-shared`

`DeploySharedTemplates.s.sol` deploys all seven templates and reuses any that already exist by
checking `predicted.code.length != 0`. That reuse check **no longer works**: this tree's solc
metadata hash has drifted since the original deploy, so every one of the six unchanged templates now
predicts a *different, empty* address. Re-running the shared target on a live chain would therefore:

1. deploy six duplicate templates at non-canonical addresses,
2. overwrite `templates.shared.json` with addresses no downstream consumer knows, and
3. leave the canonical registry disagreeing with all 12 chains.

This is the same drift that forced the Robinhood (4663) deploy onto calldata replay — see that
chain's `deploymentNote`.

`script/deploy.sh` now refuses `--target templates-shared` on any chain that already has a
shared-templates manifest, and points at the withdraw-only target instead. Override is
`SAIL_ALLOW_SHARED_REDEPLOY=1`, which you should not need.

Use `--target templates-withdraw`, which deploys only `WithdrawPermission` and hard-asserts, before
spending gas, that kernel, author, initCode hash, and predicted address all match what is pinned.

---

## 5. Rollout

Cost is negligible on 11 of 12 chains: **~1.93M gas** actual (forge's pre-flight simulation
estimated 2,654,749). **MegaETH is the exception at ~88M gas** — see the subsection below; budget
from each chain's own `eth_estimateGas`, not from a single cross-chain figure.

The table below is the pre-flight budget, measured against live gas prices with the deployer
`0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6` funded on every chain (thinnest margin BSC ~15×). Every
figure held except MegaETH, whose real cost was ~0.000106 ETH rather than the 0.0000027 shown:

| Chain | ID | Cost (native) | Deployer balance | Margin |
|---|---|---|---|---|
| Ethereum | 1 | 0.000216 ETH | 0.023261 | 108× |
| Optimism | 10 | 0.0000027 ETH | 0.001498 | 564× |
| Unichain | 130 | 0.0000040 ETH | 0.001270 | 319× |
| Arbitrum | 42161 | 0.0000536 ETH | 0.002117 | 40× |
| MegaETH | 4326 | 0.0000027 ETH | 0.002499 | 941× |
| World | 480 | 0.0000040 ETH | 0.000981 | 246× |
| BSC | 56 | 0.000133 BNB | 0.002016 | 15× |
| Base | 8453 | 0.0000159 ETH | 0.003421 | 215× |
| HyperEVM | 999 | 0.000265 HYPE | 0.008501 | 32× |
| EthSepolia | 11155111 | 0.00275 ETH | 0.124483 | 45× |
| BaseSepolia | 84532 | 0.0000159 ETH | 0.036036 | 2262× |
| Robinhood | 4663 | 0.0000641 ETH | 0.001737 | 27× |

Gas prices move; re-check before broadcasting. Balances were confirmed live during preparation.

### Order

Testnets first, then one cheap mainnet, then the rest. The first successful broadcast freezes the
address, so treat step 1 as the point of no return.

```bash
# 1. testnets
script/deploy.sh base_sepolia --target templates-withdraw --dry-run
script/deploy.sh base_sepolia --target templates-withdraw
script/deploy.sh sepolia      --target templates-withdraw

# 2. first mainnet — confirm the address matches the testnet result before continuing
script/deploy.sh base --target templates-withdraw

# 3. remaining mainnets
for c in optimism unichain arbitrum megaeth world bsc mainnet hyperliquid robinhood; do
  script/deploy.sh "$c" --target templates-withdraw
done
```

`--verify` is added automatically except on `hyperliquid` and `robinhood`, which have no
Etherscan-v2 verifier configured (`foundry.toml` `[etherscan]`); the script now skips it there
instead of failing the run after a successful broadcast.

Each run is idempotent — a retry after a failed broadcast reuses existing code at the predicted
address rather than reverting.

### Progress — COMPLETE (all 12 chains)

Deployed at `0xB8A6CC40466c0C33a230f87a1EBC368568B96269` on every chain, confirmed by direct RPC
read (8437-byte runtime, `kernel()` = canonical kernel, `permissionId()` =
`keccak256("sail.permission.WithdrawPermission.v2")`) — not merely from deploy logs.

| Chain | ID | Deployed | Explorer-verified |
|---|---|---|---|
| Ethereum | 1 | ✅ | ✅ |
| Optimism | 10 | ✅ | ✅ |
| Unichain | 130 | ✅ | ✅ |
| Arbitrum | 42161 | ✅ | ✅ |
| MegaETH | 4326 | ✅ | ✅ |
| World | 480 | ✅ | ✅ |
| BSC | 56 | ✅ | ✅ |
| Base | 8453 | ✅ | ✅ |
| HyperEVM | 999 | ✅ | n/a — no verifier |
| EthSepolia | 11155111 | ✅ | ✅ |
| BaseSepolia | 84532 | ✅ | ✅ |
| Robinhood | 4663 | ✅ | n/a — no verifier |

All 10 chains with an Etherscan-v2 verifier are source-verified. Registry merged via
`scripts/apply-withdraw-v2.mjs`; `scripts/validate-deployments.mjs` passes.

### MegaETH (4326) prices contract creation ~46x higher — needs an explicit gas multiplier

MegaETH's first two attempts failed. It was NOT a bytecode or opcode problem (MegaETH supports
MCOPY and TLOAD; the same initCode simulated fine on Base). MegaETH simply charges far more gas for
contract creation: `eth_estimateGas` for this deploy returns **~89M gas** there vs **~1.93M** on
every other chain. `forge`'s own estimate (~2.1M) is derived from local simulation, not the chain, so
the tx ran out of gas. Its block gas limit is 10B, so there is plenty of headroom — the limit just
has to be set:

```bash
script/deploy.sh megaeth --target templates-withdraw -- --gas-estimate-multiplier 5000
```

Final MegaETH deploy used 87,930,275 gas (~0.000106 ETH). Every other chain used ~1.93M.

Two traps this exposed, both now handled by `deploy.sh`:

1. **A status-1 tx can deploy nothing.** The CREATE2 factory does not revert when its inner `create`
   fails, so an underfunded-gas deploy reports "ONCHAIN EXECUTION COMPLETE & SUCCESSFUL" while
   leaving no code. Never treat forge's success line as proof; read `codesize`.
2. **A manifest is written during simulation, before the broadcast is sent.** A send-time failure
   therefore leaves a manifest describing a contract that does not exist — and that manifest is
   exactly what the merge step and the registry treat as proof of deployment. `deploy.sh` now
   confirms `codesize` on-chain after every run and deletes the manifest if there is no code.
   Because a node can lag its own writes (observed on MegaETH: deploy landed, immediate read said 0
   bytes), that check polls for ~25s before concluding failure.

### Expect verification to lag the broadcast

On EthSepolia the broadcast succeeded and `--verify` then failed five polls in a row with
`Unable to locate ContractCode` — the explorer's indexer had not caught up with a brand-new CREATE2
address. `forge` exits nonzero for this, which looks identical to a failed deploy. **Do not
re-broadcast.** Confirm and verify separately:

```bash
cast codesize 0xB8A6CC40466c0C33a230f87a1EBC368568B96269 --rpc-url <chain>
forge verify-contract 0xB8A6CC40466c0C33a230f87a1EBC368568B96269 \
  contracts/templates/WithdrawPermission.sol:WithdrawPermission \
  --chain <chain> --watch \
  --constructor-args "$(cast abi-encode 'c(address,address)' \
    0x38b508756c976e876EFF05a29E731A4d348BA6ED 0xB01dCE443d052e44b7D13726c0EC9fFB7f5815B6)"
```

`deploy.sh` now diagnoses a nonzero exit for you, distinguishing three cases: the overwrite guard
refused (nothing broadcast), the deploy landed but a later step failed (verification lag — the case
above), and the deploy genuinely did not complete (safe to re-run).

### Robinhood (4663) — expect the verifier to be the only difference

Robinhood's core and shared templates were deployed by calldata replay, not a fresh build. That does
not apply here: v2 is a brand-new address, so a fresh build from this tree is exactly right. The
pinned-initCode guard makes it byte-identical to what every other chain gets.

---

## 6. Merge the registry

Only after **all 12** chains are deployed:

```bash
node scripts/apply-withdraw-v2.mjs --check   # verify manifests agree; writes nothing
node scripts/apply-withdraw-v2.mjs           # patch the registry
node scripts/validate-deployments.mjs
```

`--check` refuses to proceed unless every chain has a `templates.withdraw.v2.json` and all 12 agree
on address, initCode hash, kernel, and author. The merge patches the 12 per-chain
`templates.shared.json` files plus `deployments.json` and `addresses.json`, then lists the remaining
prose mentions of the v1 address for manual editing:

- `deployments/addresses.md:65` — shared-template table row
- `README.md:107` — chains/templates table row

Both need a hand edit: add the v2 row and mark v1 superseded. Wording is a human call, so the script
deliberately does not rewrite prose.

`validate-deployments.mjs` gained a rollout check that fails on the two dangerous half-states:
canonical advertising v2 while some chain has no v2 deploy, and any chain's v2 manifest disagreeing
with the others. It is a no-op before the rollout starts.

---

## 7. Downstream propagation (outside this repo)

The new address and the **new config-blob shape** both have to reach the workspace. Not doing this
is the most likely way the deploy appears to "work" and then breaks at configure time:

| File | Change |
|---|---|
| `Sailor/packages/sdk/src/deployments.ts:128` | `CREATE2_TEMPLATES.withdraw` → v2 |
| `SKILLS/sail-templates/deployed.json` | `WithdrawPermission` → v2, all 12 chains |
| `Sailor/scaffold/.agents/skills/sailor-templates/deployed.json` | same |
| `SKILLS/sail-templates/references/config-schemas.md:82-89` | **still documents the old ERC-20 shape** — rewrite for the vault-exit blob |

The config schema change is the breaking one:

```
old: abi.encode(address[] tokens, address allowedRecipient, uint256 maxAmountPerTx)
new: abi.encode(address[] targets, address[] tokens,        uint256 maxAmountPerTx)
```

Both arrays must be non-empty and ≤ 50 entries, and reject the zero address. `tokens` is consulted
**only on the Aave path** (where the asset is in calldata); on the ERC-4626 paths only `targets` and
the cap apply — but a non-empty `tokens` array is still required by `_applyConfig`, so an
ERC-4626-only config must pass a placeholder rather than an empty array.

Also worth carrying into the docs: the `redeem` cap is denominated in **shares**, not underlying
assets, so an operator sizing it must account for share price.

---

## 8. What cannot be undone

- **The address, once broadcast.** CREATE2 with a fixed salt + initCode. A mistake means rotating to
  `.v3` and redoing the rollout.
- **The v1 contract stays live forever.** It is immutable and there is no protocol-level kill switch
  for a permission template. Accounts must migrate themselves.
- Nothing else. The registry files, docs, and downstream catalogs are all revertible with git, and no
  governance or timelock action is involved.

---

## 9. Files added or changed for this rollout

| File | Purpose |
|---|---|
| `script/templates/DeployWithdrawPermission.s.sol` | new — withdraw-only deploy, pinned-address guards |
| `script/templates/PredictSharedTemplates.s.sol` | new — offline preflight; documents the metadata drift |
| `scripts/apply-withdraw-v2.mjs` | new — registry merge with all-12-chains gate |
| `script/deploy.sh` | `templates-withdraw` target; shared-redeploy guard; all 12 chainIds mapped; auto-skip `--verify` where unsupported; `SAIL_DRY_RUN` |
| `scripts/validate-deployments.mjs` | rollout coverage + parity check |
| `docs/DEPLOY_WITHDRAW_V2.md` | this runbook |
