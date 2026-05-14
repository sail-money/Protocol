# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
forge build                        # compile all contracts
forge test                         # run test suite
forge test --match-test <name>     # run a single test
forge test -vvv                    # verbose output with traces
forge fmt                          # format Solidity files
```

## Status

Specification is finalized; Solidity implementation is in progress. The single source of truth for protocol design is [`docs/spec.md`](./docs/spec.md).

## Protocol Architecture

Sail is a minimal account-abstraction primitive for onchain Separately Managed Accounts. It wraps Safe accounts with a permission gating layer.

### Roles

- **Owner** — holds the Safe; custody anchor (EOA, MPC, or multisig)
- **Permission Signer** — authorises which permission contracts apply; may collapse to Owner in retail setups
- **Manager** — executes transactions within bounds; may be an EOA, MPC wallet, multisig, bot, AI agent, or smart contract (verified via ECDSA or ERC-1271)

### Core Components (to be implemented)

**`SailKernel`** (~1,500 lines) — the only trusted surface:
1. Account instantiation via Safe factory
2. Permission registry (per-account list of `IPermission` contract addresses)
3. Manager dispatch — verifies signature, session, nonce, then calls `evaluate(txData, ctx)` on each registered permission via `staticcall` with a 100k gas cap per permission
4. Fee accounting — validates manager fee collection through `IFeePolicy`; enforces the 25% protocol cut cap
5. Principal tracking — maintains deposit/withdrawal basis for fee policy math

**`SailGovernance`** — holds the team multisig; single mutator `transferGovernance(newAddress)`. Governance can tune `CURRENT_PROTOCOL_CUT_BPS`, `BASE_FEE`, and `COMPLEXITY_RATE` within immutable constitutional caps.

### Key Interfaces

```solidity
interface IPermission {
    function evaluate(bytes calldata txData, Context calldata ctx) external view returns (bool);
    function discriminator() external view returns (bytes32);
}

struct Context {
    address account;   // the Safe
    address manager;   // the delegated signer
    address target;    // call target
    bytes4  selector;  // call selector
    uint256 value;     // msg.value
}

interface IFeePolicy {
    function computeFee(address account, uint256 currentNav)
        external view returns (uint256 grossFee, address distributor, uint256 distributorBps);
    function recordCollection(address account, uint256 grossFee, uint256 currentNav) external;
}
```

### Immutable Constants (must never be made configurable)

- `MAX_PROTOCOL_CUT_BPS = 2_500` (25%)
- `MAX_PERMISSION_FEE_WEI` — set at deploy time, never changeable

### Permission Templates (to be shipped with protocol)

Factory + EIP-1167 minimal proxy pattern. Logic deployed once; users get cheap proxy instances (~45 bytes). Canonical templates: `BoundedSwapPermission`, `BoundedDepositPermission`, `BoundedBorrowPermission`, `BoundedWithdrawPermission`, `TransferTargetPermission`.

### Security Invariants

- Permission `evaluate` calls use `staticcall` — no state mutation possible by construction
- A permission exceeding its gas cap or reverting is treated as `false` (not a kernel revert)
- The kernel never holds funds; custody is native Safe
- Cross-permission interaction is impossible — each permission is called independently

### What is explicitly out of scope for the kernel

Policy authoring workflows, workflow execution, ERC-4337/EIP-7702 adapters (peripheral contracts only), NAV computation, ERC-8004 identity, and curator registries. These live outside the trusted core.
