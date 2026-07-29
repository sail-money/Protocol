#!/usr/bin/env bash
# Sail protocol deployment orchestrator.
#
# Usage:
#   script/deploy.sh <chain> [--target <t1,t2,...>] [--fresh] [--no-verify] [--dry-run] [-- <extra forge args>]
#
# <chain> is one of the keys in foundry.toml [rpc_endpoints]:
#   mainnet | sepolia | base | base_sepolia | arbitrum | optimism
#   plasma  | hyperliquid | unichain | robinhood
# (bsc, world, megaeth are also valid rpc_endpoints but predate this script's
#  chain_id_for() coverage — unrelated to this change, left as-is)
#
# Targets (comma-separated; default: core,templates-shared):
#   core                  — SailKernel, Governance, MandateFactory, StandardFeePolicy, SafeModuleEnabler
#   templates-shared      — all 7 reference permission singletons bound to the kernel
#   templates-withdraw    — ONLY the vault-exit WithdrawPermission, under the .v2 salt
#
# WARNING — `templates-shared` is NOT safe to re-run on an already-deployed chain. This tree no
# longer reproduces the six unchanged templates' live bytecode (solc metadata drift), so a re-run
# deploys six duplicates at non-canonical addresses and overwrites templates.shared.json. To ship
# the rewritten WithdrawPermission to a live chain, use `--target templates-withdraw`. Verify the
# drift yourself with:
#   forge script script/templates/PredictSharedTemplates.s.sol:PredictSharedTemplates
#
# Flags:
#   --fresh           Snapshot existing manifests under deployments/<chainId>/_archive/<date>/
#                     before writing new ones. Required when redeploying over a tracked manifest.
#   --no-verify       Skip Etherscan verification (forge --verify). Applied automatically on chains
#                     with no Etherscan-v2 verifier (hyperliquid/999, robinhood/4663, plasma).
#   --dry-run         Simulate without broadcasting. Exports SAIL_DRY_RUN=1 so deploy scripts skip
#                     their manifest write — `vm.writeFile` runs during simulation too, and a
#                     manifest for an address that was never broadcast is indistinguishable from a
#                     real deploy downstream. (Only templates-withdraw honours this so far; core and
#                     templates-shared still write on a dry run.)
#
# Examples:
#   script/deploy.sh base_sepolia
#   script/deploy.sh base --fresh
#   script/deploy.sh base --target templates-withdraw
#   script/deploy.sh base --target templates-withdraw --dry-run

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <chain> [--target <t1,t2,...>] [--fresh] [--no-verify] [--dry-run] [-- <extra forge args>]" >&2
  exit 1
fi

CHAIN="$1"; shift
TARGETS="core,templates-shared"
NO_VERIFY=0
DRY_RUN=0
FRESH=0
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)    TARGETS="$2"; shift 2 ;;
    --target=*)  TARGETS="${1#--target=}"; shift ;;
    --fresh)     FRESH=1; shift ;;
    --no-verify) NO_VERIFY=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    --)          shift; EXTRA=("$@"); break ;;
    *)           EXTRA+=("$1"); shift ;;
  esac
done

# Load .env from container root (one dir above this repo).
ROOT_ENV="$(cd "$(dirname "$0")/../.." && pwd)/.env"
if [[ -f "$ROOT_ENV" ]]; then
  set -a
  # shellcheck disable=SC1090
  source "$ROOT_ENV"
  set +a
else
  echo "warn: $ROOT_ENV not found — relying on shell env" >&2
fi

: "${DEPLOYER_PRIVATE_KEY:?DEPLOYER_PRIVATE_KEY must be set}"
: "${DEPLOYER_ADDRESS:?DEPLOYER_ADDRESS must be set}"

# Pin the deploy to a git commit so manifests carry provenance.
if command -v git >/dev/null 2>&1; then
  GIT_COMMIT="$(git -C "$(dirname "$0")/.." rev-parse HEAD 2>/dev/null || echo "")"
  if [[ -n "${GIT_COMMIT}" ]] && ! git -C "$(dirname "$0")/.." diff --quiet 2>/dev/null; then
    GIT_COMMIT="${GIT_COMMIT}-dirty"
  fi
  export GIT_COMMIT
fi

cd "$(dirname "$0")/.."

# Resolve chainId from foundry.toml rpc alias. Falls back to cast for unknown
# aliases. Uses a case statement instead of `declare -A` so the script works on
# macOS's bash 3.2.
chain_id_for() {
  case "$1" in
    mainnet)      echo 1 ;;
    sepolia)      echo 11155111 ;;
    base)         echo 8453 ;;
    base_sepolia) echo 84532 ;;
    arbitrum)     echo 42161 ;;
    optimism)     echo 10 ;;
    unichain)     echo 130 ;;
    bsc)          echo 56 ;;
    world)        echo 480 ;;
    megaeth)      echo 4326 ;;
    hyperliquid)  echo 999 ;;
    robinhood)    echo 4663 ;;
    *)            echo "" ;;
  esac
}

# Chains with no Etherscan-v2 contract verifier configured in foundry.toml [etherscan].
# Passing --verify on these fails the run after a successful broadcast, so skip it.
chain_has_verifier() {
  case "$1" in
    hyperliquid|robinhood|plasma) return 1 ;;
    *)                            return 0 ;;
  esac
}
CHAIN_ID="$(chain_id_for "$CHAIN")"
if [[ -z "$CHAIN_ID" ]]; then
  # Unknown alias — try cast as a best-effort fallback.
  if command -v cast >/dev/null 2>&1; then
    CHAIN_ID="$(cast chain-id --rpc-url "$CHAIN" 2>/dev/null || echo "")"
  fi
fi
if [[ -z "$CHAIN_ID" ]]; then
  echo "error: could not resolve chainId for '$CHAIN'. Add it to chain_id_for() in deploy.sh." >&2
  exit 1
fi

CHAIN_DIR="deployments/${CHAIN_ID}"
mkdir -p "$CHAIN_DIR"

# Map target name -> script contract spec.
script_for_target() {
  case "$1" in
    core)                 echo "script/core/DeployCore.s.sol:DeployCore" ;;
    templates-shared)     echo "script/templates/DeploySharedTemplates.s.sol:DeploySharedTemplates" ;;
    templates-withdraw)   echo "script/templates/DeployWithdrawPermission.s.sol:DeployWithdrawPermission" ;;
    *)                    echo "" ;;
  esac
}

# Map target name -> manifest file.
manifest_for_target() {
  case "$1" in
    core)                 echo "${CHAIN_DIR}/core.json" ;;
    templates-shared)     echo "${CHAIN_DIR}/templates.shared.json" ;;
    templates-withdraw)   echo "${CHAIN_DIR}/templates.withdraw.v2.json" ;;
    *)                    echo "" ;;
  esac
}

KNOWN_TARGETS="core templates-shared templates-withdraw"

# Validate every requested target before doing anything.
IFS=',' read -r -a TARGET_LIST <<< "$TARGETS"
for t in "${TARGET_LIST[@]}"; do
  if [[ -z "$(script_for_target "$t")" ]]; then
    echo "error: unknown target '$t'. Known: $KNOWN_TARGETS" >&2
    exit 1
  fi
done

# Guard rail: re-running `templates-shared` on a chain that already has a shared-templates manifest
# is almost never what the operator means. This tree no longer reproduces the six unchanged
# templates' live bytecode (solc metadata drift), so the deploy script's "already deployed" reuse
# check misses and it silently deploys six duplicates at non-canonical addresses, then overwrites
# the manifest. Require an explicit opt-out so it cannot happen by muscle memory.
for t in "${TARGET_LIST[@]}"; do
  if [[ "$t" == "templates-shared" && -f "${CHAIN_DIR}/templates.shared.json" && "${SAIL_ALLOW_SHARED_REDEPLOY:-0}" != "1" ]]; then
    cat >&2 <<EOF
error: chain $CHAIN_ID already has ${CHAIN_DIR}/templates.shared.json.

  Re-running 'templates-shared' here would deploy SIX DUPLICATE templates at non-canonical
  addresses, because this working tree no longer reproduces their live bytecode (solc metadata
  drift). Confirm for yourself with:

    forge script script/templates/PredictSharedTemplates.s.sol:PredictSharedTemplates

  To ship the rewritten vault-exit WithdrawPermission, use:

    $0 $CHAIN --target templates-withdraw

  If you genuinely intend a full shared-template redeploy (new addresses for all 7, plus a
  downstream registry migration), re-run with SAIL_ALLOW_SHARED_REDEPLOY=1.
EOF
    exit 1
  fi
done

# --fresh: snapshot existing manifests for the requested targets under _archive/<date>/.
if [[ $FRESH -eq 1 ]]; then
  STAMP="$(date -u +%Y-%m-%dT%H-%M-%SZ)"
  ARCHIVE_DIR="${CHAIN_DIR}/_archive/${STAMP}"
  ARCHIVED=0
  for t in "${TARGET_LIST[@]}"; do
    M="$(manifest_for_target "$t")"
    if [[ -f "$M" ]]; then
      mkdir -p "$ARCHIVE_DIR"
      mv "$M" "$ARCHIVE_DIR/"
      ARCHIVED=$((ARCHIVED + 1))
    fi
  done
  if [[ $ARCHIVED -gt 0 ]]; then
    echo "+ archived $ARCHIVED manifest(s) to $ARCHIVE_DIR"
  fi
  export SAIL_DEPLOY_FRESH=1
fi

if [[ $DRY_RUN -eq 1 ]]; then
  export SAIL_DRY_RUN=1
fi

echo "+ chain=$CHAIN ($CHAIN_ID) targets=$TARGETS fresh=$FRESH dry_run=$DRY_RUN"

for t in "${TARGET_LIST[@]}"; do
  SCRIPT_SPEC="$(script_for_target "$t")"
  # --sender forces forge to read the broadcaster's live nonce from the RPC at
  # simulation start. Without it, foundry starts the simulated broadcaster at
  # nonce 0; when the deployer already has on-chain history (e.g. the second
  # target in a multi-target deploy, or any redeploy), the broadcast then fails
  # with "EOA nonce changed unexpectedly. Expected 0 got N from provider."
  ARGS=(forge script "$SCRIPT_SPEC" --rpc-url "$CHAIN" --sender "$DEPLOYER_ADDRESS" --slow)
  if [[ $DRY_RUN -eq 0 ]]; then
    ARGS+=(--broadcast)
    if [[ $NO_VERIFY -eq 0 ]]; then
      if chain_has_verifier "$CHAIN"; then
        ARGS+=(--verify)
      else
        echo "note: no Etherscan-v2 verifier for '$CHAIN' — skipping --verify"
      fi
    fi
  fi
  ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")
  echo
  echo "▶ target=$t"
  echo "+ ${ARGS[*]}"

  # forge exits nonzero for three very different situations, which need opposite responses. Tell
  # them apart by whether the target manifest existed before this run and whether it exists now.
  M="$(manifest_for_target "$t")"
  MANIFEST_PREEXISTED=0
  [[ -f "$M" ]] && MANIFEST_PREEXISTED=1

  set +e
  "${ARGS[@]}"
  RC=$?
  set -e

  # A manifest is written by `vm.writeFile` DURING SIMULATION, before the broadcast is sent. So a
  # send-time failure (bad gas params, RPC rejection, dropped tx) leaves a manifest describing a
  # contract that does not exist. That manifest is what scripts/apply-withdraw-v2.mjs and the
  # deployments registry treat as proof of deployment, so it must never be allowed to survive.
  # Confirm against chain state and delete it if there is no code. Observed for real on MegaETH
  # ("intrinsic gas too low"): manifest written, nothing deployed.
  if [[ $DRY_RUN -eq 0 && -f "$M" && $MANIFEST_PREEXISTED -eq 0 ]]; then
    DEPLOYED_ADDR="$(node -e "const m=require('./$M');process.stdout.write(m.withdraw||'')" 2>/dev/null || echo "")"
    if [[ -n "$DEPLOYED_ADDR" ]] && command -v cast >/dev/null 2>&1; then
      # Poll rather than reading once. A node can accept and include the tx while its own
      # eth_getCode still returns empty for a few seconds (observed on MegaETH: the deploy had
      # landed with status 1, but an immediate read said 0 bytes). Concluding "failed" from a
      # single early read would delete a manifest for a perfectly good deploy.
      ONCHAIN_SIZE=""
      for attempt in 1 2 3 4 5 6; do
        ONCHAIN_SIZE="$(cast codesize "$DEPLOYED_ADDR" --rpc-url "$CHAIN" 2>/dev/null || echo "")"
        [[ -n "$ONCHAIN_SIZE" && "$ONCHAIN_SIZE" != "0" ]] && break
        [[ $attempt -lt 6 ]] && sleep 5
      done
      if [[ "$ONCHAIN_SIZE" == "0" ]]; then
        rm -f "$M"
        echo
        echo "✗ $M claimed $DEPLOYED_ADDR but that address still has NO CODE on $CHAIN after ~25s."
        echo "  The manifest was written during simulation; the broadcast did not land. Note the"
        echo "  CREATE2 factory does NOT revert when its inner create fails, so a status-1 tx can"
        echo "  still deploy nothing — usually too little gas for the inner create."
        echo "  Removed the false manifest so it cannot be mistaken for a real deploy."
        echo "  Re-run once the send failure is addressed; deploys are idempotent."
        exit 1
      elif [[ -n "$ONCHAIN_SIZE" ]]; then
        echo "+ on-chain confirmation: $DEPLOYED_ADDR has ${ONCHAIN_SIZE} bytes of code on $CHAIN"
      fi
    fi
  fi

  if [[ $RC -ne 0 && $DRY_RUN -eq 0 ]]; then
    if [[ $MANIFEST_PREEXISTED -eq 1 ]]; then
      # ManifestIO.guardOverwrite refuses to clobber a tracked manifest. Nothing was broadcast.
      echo
      echo "⚠ forge exited $RC and $M already existed before this run."
      echo "  Most likely the manifest-overwrite guard refused (nothing was broadcast) — this chain"
      echo "  is already deployed. Check the existing manifest before doing anything else."
      echo "  To deliberately redeploy over it, re-run with --fresh (archives the old manifest)."
    elif [[ -f "$M" ]]; then
      # The script got far enough to write its manifest, so the CREATE2 deploy itself landed.
      echo
      echo "⚠ forge exited $RC, but this run WROTE $M — the DEPLOY succeeded and only a later step"
      echo "  (almost always Etherscan verification) failed. On a fresh CREATE2 address the"
      echo "  explorer's indexer often has not caught up by the time --verify polls, and reports"
      echo "  'Unable to locate ContractCode' for a contract that is demonstrably live."
      echo "  DO NOT re-broadcast in response to this. Confirm, then verify separately:"
      echo
      echo "    cast codesize <address> --rpc-url $CHAIN"
      echo "    forge verify-contract <address> <path>:<Contract> --chain $CHAIN --watch \\"
      echo "      --constructor-args \"\$(cast abi-encode 'c(address,address)' <kernel> <author>)\""
    else
      echo
      echo "⚠ forge exited $RC and no manifest was written — the deploy did NOT complete."
      echo "  Re-running is safe: the deploy scripts are idempotent and reuse existing code at the"
      echo "  predicted CREATE2 address, so a partially-landed broadcast is picked up rather than"
      echo "  duplicated."
    fi
    exit $RC
  fi
  if [[ $RC -ne 0 ]]; then exit $RC; fi
done

echo
echo "done. Artifacts under $CHAIN_DIR/"
