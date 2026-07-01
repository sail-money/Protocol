# Sail Core — CREATE2 Deployment Runbook

Operational runbook for the **deterministic CREATE2 redeploy** of the Sail trusted core
(`script/core/DeployCore.s.sol`). Following this gets every core contract to the **same address on
every chain** and unblocks testing immediately via the **genesis allowlist bootstrap**.

Target chains: **Base (8453), Arbitrum (42161), Unichain (130), Ethereum (1), Base Sepolia (84532),
Eth Sepolia (11155111)**.

---

## 1. ⚠️ CRITICAL INVARIANT — identical args on every chain

The same-address-across-chains property holds **only if the deployment uses byte-for-byte identical
configuration on every chain.** A CREATE2 address is
`keccak256(0xff ++ factory ++ salt ++ keccak256(initCode))[12:]`. The salt is global (no chainId);
the factory is the same everywhere — so the address is identical **iff the constructor args (part of
`initCode`) are identical.** Change one value on one chain and that contract's address diverges on
that chain, cascading to every contract that references it.

**These env vars MUST be identical on all eleven supported chains:**

| Env var | Why it must match |
|---|---|
| `INITIAL_GOVERNANCE` | constructor arg of TimelockController + SailGovernance |
| `TREASURY` | constructor arg of SailKernel |
| `EMERGENCY_ADMIN` | constructor arg of SailGovernance |
| `FEE_MANAGER` | constructor arg of StandardFeePolicy |
| `DISTRIBUTOR` | constructor arg of StandardFeePolicy |
| `MAX_PERMISSION_FEE_WEI` | constructor arg of SailGovernance |
| `INITIAL_PERMISSION_REGISTRATION_FEE` | constructor arg of SailGovernance |
| `MGMT_FEE_BPS` | constructor arg of StandardFeePolicy |
| `PERF_FEE_BPS` | constructor arg of StandardFeePolicy |
| `DISTRIBUTOR_BPS` | constructor arg of StandardFeePolicy |

> **Do NOT rely on the per-field "default: deployer" fallbacks if your deployer wallet differs per
> chain.** `INITIAL_GOVERNANCE`, `TREASURY`, `EMERGENCY_ADMIN`, and `FEE_MANAGER` each default to
> `DEPLOYER_ADDRESS` when unset — if the deployer EOA is different on different chains, those args
> (and thus the addresses) diverge. **Set them all explicitly to fixed addresses.**

Note: `DEPLOYER_ADDRESS` / `DEPLOYER_PRIVATE_KEY` do **not** enter any `initCode` (contracts are
created by the CREATE2 factory, and no constructor reads `msg.sender`), so the deployer wallet itself
may differ per chain **without** affecting addresses — **except** that the genesis bootstrap requires
`DEPLOYER_ADDRESS == INITIAL_GOVERNANCE` (see §4).

> **Canonical production values.** The env-var defaults below are the script defaults, not the
> values behind the live deployment. The production core was deployed with
> `MAX_PERMISSION_FEE_WEI = 0.01 ether` (`10000000000000000` — the constitutional ceiling),
> `INITIAL_PERMISSION_REGISTRATION_FEE = 0.00015 ether` (`150000000000000`), and
> `MGMT_FEE_BPS = PERF_FEE_BPS = DISTRIBUTOR_BPS = 0`. To reproduce the canonical addresses you
> must use these exact args (see §1). The **live** per-chain registration fee was then tuned by
> governance post-deploy via the 48h timelock — currently `0.00015 ETH` on the nine ETH-gas
> chains, `0.005 HYPE` on HyperEVM, and `0.00045 BNB` on BSC — which does not affect the
> already-locked addresses. The authoritative figures are in
> [`../deployments/deployments.json`](../deployments/deployments.json).

---

## 2. Prerequisites

- **Foundry** installed (`forge` / `cast`). `forge --version`.
- **RPC URLs** for all eleven supported chains, exported as the env vars the `foundry.toml` aliases reference:
  - `BASE_MAINNET_RPC_URL`     → alias `base`
  - `ARBITRUM_MAINNET_RPC_URL` → alias `arbitrum`
  - `UNICHAIN_RPC_URL`         → alias `unichain`
  - `ETH_MAINNET_RPC_URL`      → alias `mainnet`
  - `BASE_SEPOLIA_RPC_URL`     → alias `base_sepolia`
  - `SEPOLIA_RPC_URL`          → alias `sepolia`
- **Deployer wallet funded** on each chain (gas).
- **`SAFE_PROXY_CODEHASH`** — required when bootstrapping (see §4). It's the keccak256 of a deployed
  Safe v1.4.1 `SafeProxy`'s runtime bytecode. The proxy runtime is identical across chains, so the
  value is the **same on every chain** — capture it once and reuse. To capture it from any existing
  1.4.1 SafeProxy on a chain:
  ```bash
  # <SAFE_PROXY> = any Safe created by the v1.4.1 factory on that chain
  cast keccak "$(cast code <SAFE_PROXY> --rpc-url $BASE_MAINNET_RPC_URL)"
  ```
- **(Optional) `ETHERSCAN_API_KEY`** if you pass `--verify` (the `foundry.toml` `[etherscan]` block
  uses one key across all chains via the Etherscan v2 endpoint).
- **(Optional) `GIT_COMMIT`** — recorded into each manifest header for provenance.

The standard CREATE2 factory (`0x4e59b44847b379578588920cA78FbF26c0B4956C`) and the Safe v1.4.1 proxy
factory (`0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67`) are already present on all eleven supported chains — no
factory deployment step is required.

---

## 3. Environment variables (complete)

| Variable | Purpose | Required? | Default | Identical across chains? |
|---|---|---|---|---|
| `DEPLOYER_PRIVATE_KEY` | Broadcasting key | **Required** | — | No (but = `INITIAL_GOVERNANCE`'s key if bootstrapping) |
| `DEPLOYER_ADDRESS` | Deployer EOA | **Required** | — | No (must equal `INITIAL_GOVERNANCE` if bootstrapping) |
| `INITIAL_GOVERNANCE` | Governance wallet; timelock proposer/executor | Optional | `DEPLOYER_ADDRESS` | **YES** (§1) |
| `TREASURY` | Receives protocol fee cut | Optional | `DEPLOYER_ADDRESS` | **YES** (§1) |
| `EMERGENCY_ADMIN` | Can pause kernel (no timelock) | Optional | `DEPLOYER_ADDRESS` | **YES** (§1) |
| `FEE_MANAGER` | Tunes StandardFeePolicy | Optional | `DEPLOYER_ADDRESS` | **YES** (§1) |
| `DISTRIBUTOR` | Fee distributor address | Optional | `address(0)` | **YES** (§1) |
| `MAX_PERMISSION_FEE_WEI` | Per-deployment immutable fee cap (≤ `0.01 ether` constitutional ceiling) | Optional | `0.001 ether` (1e15) | **YES** (§1) |
| `INITIAL_PERMISSION_REGISTRATION_FEE` | Initial reg fee | Optional | `0` | **YES** (§1) |
| `MGMT_FEE_BPS` | Management fee (bps) | Optional | `200` | **YES** (§1) |
| `PERF_FEE_BPS` | Performance fee (bps) | Optional | `1000` | **YES** (§1) |
| `DISTRIBUTOR_BPS` | Distributor share (bps) | Optional | `0` | **YES** (§1) |
| `SAIL_BOOTSTRAP_ALLOWLISTS` | Seed allowlists at genesis (§4) | Optional | unset (off) | n/a (post-deploy state, not an address input) |
| `SAFE_PROXY_CODEHASH` | SafeProxy v1.4.1 runtime codehash | **Required IF bootstrapping** | — | Same value everywhere |
| `SAIL_DEPLOY_FRESH` | Allow overwriting an existing `core.json` manifest | Optional | unset (off) | n/a |
| `GIT_COMMIT` | Provenance string in manifest header | Optional | `""` | n/a |

Boolean env vars (`SAIL_BOOTSTRAP_ALLOWLISTS`, `SAIL_DEPLOY_FRESH`) are "on" for any non-empty value
other than the literal `"0"`. Use `=1`.

---

## 4. The bootstrap decision — READ THIS

**Without `SAIL_BOOTSTRAP_ALLOWLISTS=1`:** the core deploys, but `SailKernel.createAccount()` /
`registerAccount()` will **revert** until governance seeds the onboarding allowlists. Those setters
are `onlyTimelock`, so seeding them means: schedule on the 48h timelock → **wait 48 hours** → execute.
**This blocks all account creation / testing for 48 hours.**

**With `SAIL_BOOTSTRAP_ALLOWLISTS=1`:** the deploy script calls `SailGovernance.bootstrapAllowlists(...)`
**in the same broadcast**, seeding the onboarding allowlists at genesis and bypassing the timelock
**exactly once** (the `allowlistBootstrapped` latch then closes this path forever; all later changes
go through the 48h timelock). This is what lets **testing begin immediately after deploy.**

What the bootstrap seeds (from `_bootstrapAllowlists` + `SafeConstants`):

| Allowlist | Value seeded |
|---|---|
| `trustedSafeFactory` | `0x4e1DCf7AD4e460CfD30791CCC4F9c8a4f820ec67` (Safe v1.4.1 ProxyFactory) |
| `trustedSafeSingleton` | `0x41675C099F32341bf84BFc5382aF534df5C7461a` (Safe 1.4.1) **and** `0x29fcB43b46531BcA003ddC8FCB67FFE91900C762` (SafeL2 1.4.1) |
| `trustedModuleSetup` | the freshly deployed **SafeModuleEnabler** |
| `trustedFeePolicy` | the freshly deployed **StandardFeePolicy** |
| `trustedSafeProxyCodehash` | the `SAFE_PROXY_CODEHASH` env value |

**Requirements when bootstrapping:**
- `DEPLOYER_ADDRESS == INITIAL_GOVERNANCE` — the bootstrap call comes from the deployer EOA and the
  script asserts `governance() == deployer` (`bootstrapAllowlists` is `onlyGovernance`).
- `SAFE_PROXY_CODEHASH` must be set to a non-zero value (the script reverts otherwise).

> ✅ **Recommendation for the staging/testing redeploy: USE `SAIL_BOOTSTRAP_ALLOWLISTS=1`** so onboarding
> works the moment the deploy lands — no 48-hour wait.

---

## 5. Deploy commands — per chain

Set the shared, identical config **once** (export so every chain run inherits it):

```bash
# ── Identical on every chain (see §1) ─────────────────────────────────────────
export INITIAL_GOVERNANCE=0xYOUR_GOVERNANCE_WALLET     # also the deployer when bootstrapping
export TREASURY=0xYOUR_TREASURY
export EMERGENCY_ADMIN=0xYOUR_EMERGENCY_ADMIN
export FEE_MANAGER=0xYOUR_FEE_MANAGER
export DISTRIBUTOR=0x0000000000000000000000000000000000000000
export MAX_PERMISSION_FEE_WEI=1000000000000000          # 0.001 ether
export INITIAL_PERMISSION_REGISTRATION_FEE=0
export MGMT_FEE_BPS=0                                    # staging: zero fees
export PERF_FEE_BPS=0
export DISTRIBUTOR_BPS=0

# ── Deployer (must equal INITIAL_GOVERNANCE when bootstrapping) ────────────────
export DEPLOYER_ADDRESS=0xYOUR_GOVERNANCE_WALLET
export DEPLOYER_PRIVATE_KEY=0xYOUR_KEY

# ── Genesis bootstrap (recommended for staging) ───────────────────────────────
export SAIL_BOOTSTRAP_ALLOWLISTS=1
export SAFE_PROXY_CODEHASH=0xYOUR_CAPTURED_CODEHASH     # see §2 (same on every chain)

# ── RPC URLs (foundry.toml aliases reference these) ───────────────────────────
export BASE_MAINNET_RPC_URL=...
export ARBITRUM_MAINNET_RPC_URL=...
export UNICHAIN_RPC_URL=...
export ETH_MAINNET_RPC_URL=...
export BASE_SEPOLIA_RPC_URL=...
export SEPOLIA_RPC_URL=...

export GIT_COMMIT=$(git rev-parse HEAD)                 # optional provenance
```

Then run per chain (identical command, only the `--rpc-url` alias changes):

```bash
# Base (8453)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url base         --broadcast

# Arbitrum (42161)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url arbitrum     --broadcast

# Unichain (130)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url unichain     --broadcast

# Ethereum (1)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url mainnet      --broadcast

# Base Sepolia (84532)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url base_sepolia --broadcast

# Eth Sepolia (11155111)
forge script script/core/DeployCore.s.sol:DeployCore --rpc-url sepolia      --broadcast
```

Add `--verify` to any run to source-verify on the block explorer (needs `ETHERSCAN_API_KEY`). Add
`-vvv` for full traces. If a `core.json` already exists for a chain and you intend to overwrite it,
add `SAIL_DEPLOY_FRESH=1` (archive the old one first).

Deployment order inside the script (you don't manage this — listed for reference):
**(1) TimelockController → (2) SailGovernance → (3) SailKernel → (4) MandateFactory →
(5) StandardFeePolicy → (6) SafeModuleEnabler**, each via CREATE2 with its global salt:

| Contract | Salt |
|---|---|
| TimelockController | `keccak256("sail.timelock.v1")` |
| SailGovernance | `keccak256("sail.governance.v1")` |
| SailKernel | `keccak256("sail.kernel.v1")` |
| MandateFactory | `keccak256("sail.mandatefactory.v1")` |
| StandardFeePolicy | `keccak256("sail.feepolicy.v1")` |
| SafeModuleEnabler | `keccak256("sail.modulenabler.v1")` |

---

## 6. What the script guarantees (fails loudly otherwise)

- **Predicted == deployed.** `_deploy2` computes each contract's predicted CREATE2 address up front
  (`vm.computeCreate2Address(salt, keccak256(initCode), factory)`) and, after the factory call,
  asserts code exists at exactly that address — reverting (`CREATE2 produced no code...` /
  `CREATE2 deploy failed...`) on any mismatch. Misconfigured args on a chain cause the deploy to
  **halt rather than land a wrong address**.
- **Timelock self-administration assertion.** After deploying the timelock the script asserts the
  admin role of `PROPOSER_ROLE` is `DEFAULT_ADMIN_ROLE`, that the **timelock itself holds it**, and
  that **neither the deployer nor the governance wallet** holds it.
- **Constructor re-validation (defense-in-depth).** `SailGovernance`'s constructor independently
  rejects a misconfigured timelock: non-zero address, **exactly 48h** delay (`TimelockDelayMismatch`),
  `initialGovernance` holds PROPOSER_ROLE (`GovernanceNotProposer`) **and** EXECUTOR_ROLE
  (`GovernanceNotExecutor`), and self-administration (`TimelockNotSelfAdministered`).
- **Same address per contract across chains** — provided §1 is honored.

---

## 7. After deployment

Each chain writes its manifest to **`deployments/<chainId>/core.json`** (via `ManifestIO`), containing
the deployed addresses (`timelock`, `governance`, `kernel`, `mandateFactory`, `standardFeePolicy`,
`safeModuleEnabler`), the config snapshot, `deploymentMode: "create2-global-salt"`, and the
`create2Factory` address.

Follow-ups:

1. **Populate the README address tables.** `README.md` → *Deployments* currently has
   `<to be populated on CREATE2 redeploy>` placeholders. Fill in the deployed addresses; note that
   **all chains share the same address per contract**, so the "Core (identical address on every
   chain)" table needs each contract filled once. Do the same in `deployments/addresses.json` and
   `deployments/addresses.md`.
2. **Update Sailor SDK** — `packages/sdk/src/deployments.ts` (separate repo, separate task): add the
   new addresses and the new chains (Ethereum 1, Eth Sepolia 11155111).
3. **Verify onboarding works** — confirm `createAccount()` succeeds on a chain (this confirms the
   genesis bootstrap seeded the allowlists). If you did **not** bootstrap, you must first seed the
   four `onlyTimelock` allowlists via the 48h timelock before this will pass.

---

## 8. Per-chain verification checklist

After each chain's run, confirm:

- [ ] Script exited successfully (no `CREATE2 ...` / `Timelock...` / `Governance...` revert).
- [ ] `deployments/<chainId>/core.json` written with all six addresses.
- [ ] **Predicted == deployed** for each contract (implicit — the script asserts it; the run would
      have halted otherwise).
- [ ] **Same address as other chains**: each contract's address in this chain's `core.json` matches
      the same contract on already-deployed chains. (If not → a config value differed; see §1.)
- [ ] Timelock log shows `timelock minDelay : 172800` (48h) and the self-admin asserts passed.
- [ ] **If bootstrapped:** logs show `=== BOOTSTRAPPED allowlists at genesis (no timelock) ===` and
      `createAccount()` works. Confirm `governance.allowlistBootstrapped() == true`.
- [ ] **If NOT bootstrapped:** logs show the `POST-DEPLOY: allowlist via 48h timelock` reminder —
      onboarding stays blocked until those setters are executed via the timelock.
