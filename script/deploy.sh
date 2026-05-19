#!/usr/bin/env bash
# Sail protocol deployment orchestrator.
#
# Usage:
#   script/deploy.sh <chain> [--target <t1,t2,...>] [--fresh] [--no-verify] [--dry-run] [-- <extra forge args>]
#
# <chain> is one of the keys in foundry.toml [rpc_endpoints]:
#   mainnet | sepolia | base | base_sepolia | arbitrum | optimism
#   plasma  | hyperliquid | unichain
#
# Targets (comma-separated; default: core,templates-shared,templates-standalone):
#   core                  — SailKernel, Governance, PermissionFactory, StandardFeePolicy, SafeModuleEnabler
#   templates-shared      — 7 Shared* permission singletons bound to the kernel
#   templates-standalone  — 12 standalone permission logic contracts (EIP-1167 clone implementations)
#
# Flags:
#   --fresh           Snapshot existing manifests under deployments/<chainId>/_archive/<date>/
#                     before writing new ones. Required when redeploying over a tracked manifest.
#   --no-verify       Skip Etherscan verification (forge --verify).
#   --dry-run         Simulate without broadcasting; manifests are NOT written.
#
# Examples:
#   script/deploy.sh base_sepolia
#   script/deploy.sh base --fresh
#   script/deploy.sh base --target templates-shared
#   script/deploy.sh base --target core --dry-run

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <chain> [--target <t1,t2,...>] [--fresh] [--no-verify] [--dry-run] [-- <extra forge args>]" >&2
  exit 1
fi

CHAIN="$1"; shift
TARGETS="core,templates-shared,templates-standalone"
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
    *)            echo "" ;;
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
    templates-standalone) echo "script/templates/DeployStandaloneTemplates.s.sol:DeployStandaloneTemplates" ;;
    *)                    echo "" ;;
  esac
}

# Map target name -> manifest file.
manifest_for_target() {
  case "$1" in
    core)                 echo "${CHAIN_DIR}/core.json" ;;
    templates-shared)     echo "${CHAIN_DIR}/templates.shared.json" ;;
    templates-standalone) echo "${CHAIN_DIR}/templates.standalone.json" ;;
    *)                    echo "" ;;
  esac
}

KNOWN_TARGETS="core templates-shared templates-standalone"

# Validate every requested target before doing anything.
IFS=',' read -r -a TARGET_LIST <<< "$TARGETS"
for t in "${TARGET_LIST[@]}"; do
  if [[ -z "$(script_for_target "$t")" ]]; then
    echo "error: unknown target '$t'. Known: $KNOWN_TARGETS" >&2
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

echo "+ chain=$CHAIN ($CHAIN_ID) targets=$TARGETS fresh=$FRESH dry_run=$DRY_RUN"

for t in "${TARGET_LIST[@]}"; do
  SCRIPT_SPEC="$(script_for_target "$t")"
  ARGS=(forge script "$SCRIPT_SPEC" --rpc-url "$CHAIN" --slow)
  if [[ $DRY_RUN -eq 0 ]]; then
    ARGS+=(--broadcast)
    if [[ $NO_VERIFY -eq 0 ]]; then
      ARGS+=(--verify)
    fi
  fi
  ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")
  echo
  echo "▶ target=$t"
  echo "+ ${ARGS[*]}"
  "${ARGS[@]}"
done

echo
echo "done. Artifacts under $CHAIN_DIR/"
