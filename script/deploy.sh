#!/usr/bin/env bash
# Sail core protocol deployment wrapper.
#
# Usage:
#   script/deploy.sh <chain> [--no-verify] [--dry-run] [-- <extra forge args>]
#
# <chain> is one of the keys in foundry.toml [rpc_endpoints]:
#   mainnet | sepolia | base | base_sepolia | arbitrum | optimism
#   plasma  | hyperliquid | unichain
#
# Examples:
#   script/deploy.sh base_sepolia
#   script/deploy.sh base_sepolia --dry-run
#   script/deploy.sh base --no-verify

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <chain> [--no-verify] [--dry-run] [-- <extra forge args>]" >&2
  exit 1
fi

CHAIN="$1"; shift
NO_VERIFY=0
DRY_RUN=0
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --no-verify) NO_VERIFY=1; shift ;;
    --dry-run)   DRY_RUN=1;   shift ;;
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

cd "$(dirname "$0")/.."
mkdir -p deployments

ARGS=(forge script script/Deploy.s.sol:Deploy --rpc-url "$CHAIN" --slow)

if [[ $DRY_RUN -eq 0 ]]; then
  ARGS+=(--broadcast)
  if [[ $NO_VERIFY -eq 0 ]]; then
    ARGS+=(--verify)
  fi
fi

ARGS+=("${EXTRA[@]+"${EXTRA[@]}"}")

echo "+ ${ARGS[*]}"
"${ARGS[@]}"

echo
echo "done. Artifact: deployments/<chainId>.json"
