#!/usr/bin/env bash
# Sail protocol contract verification.
#
# Reads deployed addresses and constructor args from the committed manifests and
# submits or re-submits source verification to the chain explorer.
#
# Use this when:
#   - Etherscan was unavailable or rate-limited during the initial deploy.
#   - A contract shows as "Unverified" on the explorer after deploy.
#   - You need to verify on a second explorer (e.g. Blockscout).
#
# forge script --broadcast --verify handles verification on the happy path.
# This script is the fallback for everything that doesn't land automatically.
#
# Usage:
#   script/verify.sh <chain> [--target <t1,t2,...>] [--check] [-- <extra forge args>]
#
# <chain>: rpc alias from foundry.toml (base | base_sepolia | mainnet | ...)
#
# Targets (comma-separated; default: core,templates-shared):
#   core                  — 5 core protocol contracts
#   templates-shared      — the six reference permission singletons + the ConfigurablePermission base
#
# (Only the audited shared/ reference templates are deployed and verified.)
#
# Flags:
#   --check    Print what would be verified without actually submitting.
#
# Examples:
#   script/verify.sh base
#   script/verify.sh base --target core
#   script/verify.sh base_sepolia --check

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <chain> [--target <t1,t2,...>] [--check] [-- <extra forge args>]" >&2
  exit 1
fi

CHAIN="$1"; shift
TARGETS="core,templates-shared"
CHECK=0
EXTRA=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --target)   TARGETS="$2"; shift 2 ;;
    --target=*) TARGETS="${1#--target=}"; shift ;;
    --check)    CHECK=1; shift ;;
    --)         shift; EXTRA=("$@"); break ;;
    *)          EXTRA+=("$1"); shift ;;
  esac
done

# Load .env
ROOT_ENV="$(cd "$(dirname "$0")/../.." && pwd)/.env"
if [[ -f "$ROOT_ENV" ]]; then
  set -a; source "$ROOT_ENV"; set +a
else
  echo "warn: $ROOT_ENV not found — relying on shell env" >&2
fi

: "${ETHERSCAN_API_KEY:?ETHERSCAN_API_KEY must be set}"

chain_id_for() {
  case "$1" in
    mainnet)      echo 1 ;;
    sepolia)      echo 11155111 ;;
    base)         echo 8453 ;;
    base_sepolia) echo 84532 ;;
    arbitrum)     echo 42161 ;;
    optimism)     echo 10 ;;
    unichain)     echo 130 ;;
    *)            echo "" ;;
  esac
}
CHAIN_ID="$(chain_id_for "$CHAIN")"
if [[ -z "$CHAIN_ID" ]]; then
  echo "error: unknown chain '$CHAIN'. Add it to chain_id_for() in verify.sh." >&2
  exit 1
fi

CHAIN_DIR="deployments/${CHAIN_ID}"

cd "$(dirname "$0")/.."

# Dependencies check
for cmd in jq cast forge; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "error: '$cmd' not found on PATH" >&2
    exit 1
  fi
done

# -------------------------------------------------------------------------
# Helpers
# -------------------------------------------------------------------------

jq_read() {
  local file="$1" key="$2"
  jq -r "$key" "$file"
}

verify_contract() {
  local label="$1"
  local contract_path="$2"     # e.g. contracts/core/SailKernel.sol:SailKernel
  local address="$3"
  local constructor_args="${4:-}"  # hex-encoded ABI bytes (without 0x), or ""

  echo
  echo "▶ $label"
  echo "  address  : $address"
  echo "  contract : $contract_path"
  [[ -n "$constructor_args" ]] && echo "  ctor args: 0x$constructor_args"

  if [[ $CHECK -eq 1 ]]; then
    echo "  (--check: skipped)"
    return
  fi

  local args=(
    forge verify-contract
    "$address"
    "$contract_path"
    --chain "$CHAIN_ID"
    --etherscan-api-key "$ETHERSCAN_API_KEY"
    --via-ir
    --optimizer-runs 200
    --watch
  )

  [[ -n "$constructor_args" ]] && args+=(--constructor-args "$constructor_args")
  args+=("${EXTRA[@]+"${EXTRA[@]}"}")

  echo "+ ${args[*]}"
  "${args[@]}"
}

# -------------------------------------------------------------------------
# Target: core
# -------------------------------------------------------------------------

verify_core() {
  local m="${CHAIN_DIR}/core.json"
  if [[ ! -f "$m" ]]; then
    echo "error: $m not found — deploy core first" >&2
    return 1
  fi

  echo "=== verifying core (chain $CHAIN_ID) ==="

  local governance initialGovernance treasury emergencyAdmin feeManager distributor kernel
  local safeModuleEnabler mandateFactory standardFeePolicy timelock
  local maxPermissionFeeWei initialPermissionRegistrationFee
  local managementFeeBps performanceFeeBps distributorBps

  safeModuleEnabler=$(jq_read "$m" '.safeModuleEnabler')
  governance=$(jq_read "$m" '.governance')
  # initialGovernance is the admin wallet arg passed to SailGovernance's constructor,
  # not the deployed contract address itself.
  initialGovernance=$(jq_read "$m" '.initialGovernance')
  kernel=$(jq_read "$m" '.kernel')
  mandateFactory=$(jq_read "$m" '.mandateFactory')
  standardFeePolicy=$(jq_read "$m" '.standardFeePolicy')
  treasury=$(jq_read "$m" '.treasury')
  emergencyAdmin=$(jq_read "$m" '.emergencyAdmin')
  feeManager=$(jq_read "$m" '.feeManager')
  distributor=$(jq_read "$m" '.distributor')
  maxPermissionFeeWei=$(jq_read "$m" '.maxPermissionFeeWei')
  initialPermissionRegistrationFee=$(jq_read "$m" '.initialPermissionRegistrationFee')
  managementFeeBps=$(jq_read "$m" '.managementFeeBps')
  performanceFeeBps=$(jq_read "$m" '.performanceFeeBps')
  distributorBps=$(jq_read "$m" '.distributorBps')

  # SafeModuleEnabler — no constructor args
  verify_contract \
    "SafeModuleEnabler" \
    "contracts/safe/SafeModuleEnabler.sol:SafeModuleEnabler" \
    "$safeModuleEnabler" \
    ""

  # SailGovernance(address initialGovernance, uint256 maxPermissionFeeWei,
  #                address emergencyAdmin, uint256 initialPermissionRegistrationFee)
  local gov_args
  gov_args=$(cast abi-encode \
    "constructor(address,uint256,address,uint256)" \
    "$initialGovernance" \
    "$maxPermissionFeeWei" \
    "$emergencyAdmin" \
    "$initialPermissionRegistrationFee" \
    | sed 's/0x//')
  verify_contract \
    "SailGovernance" \
    "contracts/governance/SailGovernance.sol:SailGovernance" \
    "$governance" \
    "$gov_args"

  # SailKernel(address governance, address treasury)
  local kernel_args
  kernel_args=$(cast abi-encode \
    "constructor(address,address)" \
    "$governance" \
    "$treasury" \
    | sed 's/0x//')
  verify_contract \
    "SailKernel" \
    "contracts/core/SailKernel.sol:SailKernel" \
    "$kernel" \
    "$kernel_args"

  # MandateFactory(address kernel)
  local factory_args
  factory_args=$(cast abi-encode \
    "constructor(address)" \
    "$kernel" \
    | sed 's/0x//')
  verify_contract \
    "MandateFactory" \
    "contracts/factory/MandateFactory.sol:MandateFactory" \
    "$mandateFactory" \
    "$factory_args"

  # StandardFeePolicy(uint256 managementFeeBps, uint256 performanceFeeBps,
  #                   address distributor, uint256 distributorBps,
  #                   address kernel, address feeManager)
  local fee_args
  fee_args=$(cast abi-encode \
    "constructor(uint256,uint256,address,uint256,address,address)" \
    "$managementFeeBps" \
    "$performanceFeeBps" \
    "$distributor" \
    "$distributorBps" \
    "$kernel" \
    "$feeManager" \
    | sed 's/0x//')
  verify_contract \
    "StandardFeePolicy" \
    "contracts/policies/StandardFeePolicy.sol:StandardFeePolicy" \
    "$standardFeePolicy" \
    "$fee_args"
}

# -------------------------------------------------------------------------
# Target: templates-shared
# -------------------------------------------------------------------------

verify_shared_templates() {
  local m="${CHAIN_DIR}/templates.shared.json"
  if [[ ! -f "$m" ]]; then
    echo "error: $m not found — deploy templates-shared first" >&2
    return 1
  fi

  echo "=== verifying templates-shared (chain $CHAIN_ID) ==="

  local kernel
  kernel=$(jq_read "$m" '.kernel')

  # The reference templates (approveAndCallBatch/borrow/swap/transfer) take
  # (address kernel, address author) — their verification requires re-encoding the
  # constructor args with the author used at deploy time. (The experimental template
  # catalog has been removed; only the audited shared/ reference set is verified here.)
  local kernel_args
  kernel_args=$(cast abi-encode "constructor(address)" "$kernel" | sed 's/0x//')

  local pairs=(
    "approveAndCallBatch|contracts/templates/ApproveAndCallBatchPermission.sol:ApproveAndCallBatchPermission"
    "borrow|contracts/templates/BorrowPermission.sol:BorrowPermission"
    "swap|contracts/templates/SwapPermission.sol:SwapPermission"
    "transfer|contracts/templates/TransferPermission.sol:TransferPermission"
  )

  for pair in "${pairs[@]}"; do
    local key="${pair%%|*}"
    local contract="${pair#*|}"
    local address
    address=$(jq_read "$m" ".${key}")
    verify_contract "$key" "$contract" "$address" "$kernel_args"
  done
}

# -------------------------------------------------------------------------
# Dispatch
# -------------------------------------------------------------------------

IFS=',' read -r -a TARGET_LIST <<< "$TARGETS"
for t in "${TARGET_LIST[@]}"; do
  case "$t" in
    core)                  verify_core ;;
    templates-shared)      verify_shared_templates ;;
    *)
      echo "error: unknown target '$t'. Known: core, templates-shared" >&2
      exit 1
      ;;
  esac
done

echo
echo "done."
