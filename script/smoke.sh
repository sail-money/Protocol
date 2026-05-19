#!/usr/bin/env bash
# Sail protocol post-deploy smoke test.
#
# Validates the deployed manifests for a chain by:
#   - confirming every contract has bytecode at its recorded address
#   - confirming every cross-reference (factory.kernel == kernel, etc.) matches
#   - confirming standalone clone-logic contracts are locked (initialized() == true)
#
# Read-only. Zero gas. Safe to run anytime.
#
# Usage:
#   script/smoke.sh <chain>
#
# Example:
#   script/smoke.sh base

set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "usage: $0 <chain>" >&2
  exit 1
fi

CHAIN="$1"

# Load .env
ROOT_ENV="$(cd "$(dirname "$0")/../.." && pwd)/.env"
if [[ -f "$ROOT_ENV" ]]; then set -a; source "$ROOT_ENV"; set +a; fi

chain_id_for() {
  case "$1" in
    mainnet) echo 1 ;;
    sepolia) echo 11155111 ;;
    base) echo 8453 ;;
    base_sepolia) echo 84532 ;;
    arbitrum) echo 42161 ;;
    optimism) echo 10 ;;
    *) echo "" ;;
  esac
}

CHAIN_ID="$(chain_id_for "$CHAIN")"
if [[ -z "$CHAIN_ID" ]]; then
  echo "error: unknown chain '$CHAIN'" >&2
  exit 1
fi

cd "$(dirname "$0")/.."
CHAIN_DIR="deployments/${CHAIN_ID}"
CORE="${CHAIN_DIR}/core.json"
SHARED="${CHAIN_DIR}/templates.shared.json"
STANDALONE="${CHAIN_DIR}/templates.standalone.json"

for f in "$CORE" "$SHARED" "$STANDALONE"; do
  [[ -f "$f" ]] || { echo "error: $f missing"; exit 1; }
done

# Pick the RPC URL the foundry alias points to so cast doesn't need the alias map.
case "$CHAIN" in
  base) RPC="$BASE_MAINNET_RPC_URL" ;;
  base_sepolia) RPC="$BASE_SEPOLIA_RPC_URL" ;;
  mainnet) RPC="$ETH_MAINNET_RPC_URL" ;;
  arbitrum) RPC="$ARBITRUM_MAINNET_RPC_URL" ;;
  *) RPC="$CHAIN" ;;
esac

PASS=0
FAIL=0
FAIL_DETAILS=()

check() {
  local label="$1" expected="$2" actual="$3"
  local lhs rhs
  lhs="$(printf '%s' "$expected" | tr '[:upper:]' '[:lower:]')"
  rhs="$(printf '%s' "$actual"   | tr '[:upper:]' '[:lower:]')"
  if [[ "$lhs" == "$rhs" ]]; then
    PASS=$((PASS + 1))
    echo "  ✓ $label"
  else
    FAIL=$((FAIL + 1))
    FAIL_DETAILS+=("$label: expected $expected, got $actual")
    echo "  ✗ $label"
    echo "    expected: $expected"
    echo "    actual:   $actual"
  fi
}

# cast call with a typed sig returns the decoded value, sometimes with an
# annotation like "1000000000000000 [1e15]". Strip annotations and whitespace.
# These helpers swallow stderr (so cast's nightly warning doesn't leak) and
# tolerate cast errors by returning empty strings.
_cast_decoded() {
  cast call --rpc-url "$RPC" "$1" "$2" 2>/dev/null \
    | awk 'NR==1 {sub(/[[:space:]]+\[.*\]$/,""); print $1}'
}
addr_call() { _cast_decoded "$1" "$2"; }
uint_call() { _cast_decoded "$1" "$2"; }
bool_call() {
  local raw
  raw="$(_cast_decoded "$1" "$2")"
  if [[ "$raw" == "true" ]]; then echo "true"; else echo "false"; fi
}
has_code() {
  local code
  code=$(cast code "$1" --rpc-url "$RPC" 2>/dev/null || echo "0x")
  [[ -n "$code" && "$code" != "0x" ]]
}

echo "=== Sail smoke test on $CHAIN (chain $CHAIN_ID) ==="
echo "RPC: $RPC"
echo

# ─── Core ────────────────────────────────────────────────────────────────────
echo "▶ Core"
kernel=$(jq -r '.kernel' "$CORE")
governance=$(jq -r '.governance' "$CORE")
timelock=$(jq -r '.timelock' "$CORE")
factory=$(jq -r '.permissionFactory' "$CORE")
feePolicy=$(jq -r '.standardFeePolicy' "$CORE")
treasury=$(jq -r '.treasury' "$CORE")
safeModuleEnabler=$(jq -r '.safeModuleEnabler' "$CORE")
maxFee=$(jq -r '.maxPermissionFeeWei' "$CORE")

for c in kernel governance timelock factory feePolicy safeModuleEnabler; do
  addr=$(eval echo "\$$c")
  if has_code "$addr"; then
    PASS=$((PASS + 1)); echo "  ✓ $c has bytecode"
  else
    FAIL=$((FAIL + 1)); echo "  ✗ $c missing bytecode at $addr"
  fi
done

# SailKernel.governance() == governance
check "SailKernel.governance() == manifest.governance" \
  "$governance" "$(addr_call "$kernel" "governance()(address)")"

# SailKernel.treasury() == treasury
check "SailKernel.treasury() == manifest.treasury" \
  "$treasury" "$(addr_call "$kernel" "treasury()(address)")"

# SailGovernance.timelock() == timelock
check "SailGovernance.timelock() == manifest.timelock" \
  "$timelock" "$(addr_call "$governance" "timelock()(address)")"

# SailGovernance.MAX_PERMISSION_FEE_WEI() == manifest.maxPermissionFeeWei
actual_max=$(uint_call "$governance" "MAX_PERMISSION_FEE_WEI()(uint256)")
check "SailGovernance.MAX_PERMISSION_FEE_WEI() == manifest.maxPermissionFeeWei" \
  "$maxFee" "$actual_max"

# PermissionFactory.kernel() == kernel
check "PermissionFactory.kernel() == manifest.kernel" \
  "$kernel" "$(addr_call "$factory" "kernel()(address)")"

# StandardFeePolicy.kernel() == kernel
check "StandardFeePolicy.kernel() == manifest.kernel" \
  "$kernel" "$(addr_call "$feePolicy" "kernel()(address)")"

echo

# ─── Shared templates ────────────────────────────────────────────────────────
echo "▶ Shared templates (kernel() should match manifest.kernel)"
shared_kernel=$(jq -r '.kernel' "$SHARED")
check "shared manifest.kernel == core manifest.kernel" "$kernel" "$shared_kernel"

for key in sharedAmmLiquidity sharedApproveAndCallBatch sharedBoundedBorrow \
           sharedBoundedSwap sharedDeFiBundle sharedPendle sharedTransferTarget; do
  addr=$(jq -r ".${key}" "$SHARED")
  if has_code "$addr"; then
    PASS=$((PASS + 1)); echo "  ✓ $key has bytecode"
  else
    FAIL=$((FAIL + 1)); echo "  ✗ $key missing bytecode at $addr"; continue
  fi
  check "$key.kernel() == manifest.kernel" "$kernel" "$(addr_call "$addr" "kernel()(address)")"
done

echo

# ─── Standalone clone-logic ──────────────────────────────────────────────────
echo "▶ Standalone clone-logic (initialized() should be true — implementations locked)"
for key in azuroPrediction boundedApprove boundedBorrow boundedDeposit \
           boundedLiFi boundedSwap boundedWithdraw gmxPerp gainsNetworkPerp \
           limitlessPrediction synthetixPerp transferTarget; do
  addr=$(jq -r ".${key}" "$STANDALONE")
  if has_code "$addr"; then
    PASS=$((PASS + 1)); echo "  ✓ $key has bytecode"
  else
    FAIL=$((FAIL + 1)); echo "  ✗ $key missing bytecode at $addr"; continue
  fi
  actual_init=$(bool_call "$addr" "initialized()(bool)")
  check "$key.initialized() == true" "true" "$actual_init"
done

echo
echo "=== Summary ==="
echo "PASS: $PASS"
echo "FAIL: $FAIL"
if [[ $FAIL -gt 0 ]]; then
  echo
  echo "Failures:"
  for d in "${FAIL_DETAILS[@]}"; do echo "  - $d"; done
  exit 1
fi
echo "All smoke tests passed."
