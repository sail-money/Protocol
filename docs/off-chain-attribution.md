# Off-Chain Attribution

This document describes how indexers and analytics consumers derive per-template
metrics from existing kernel events combined with `IPermissionIntrospection` calls.
No `PermissionUsed` event is emitted — all attribution is reconstructed off-chain.

---

## Background

The kernel emits a small set of lifecycle events per account. Permission templates
that implement `IPermissionIntrospection` expose a stable `permissionId()` that
identifies the template type across all deployments. Combining these two sources
allows consumers to reconstruct template-level metrics without any per-dispatch
on-chain overhead.

Relevant kernel events:

```
PermissionRegistered(address indexed account, address indexed permission)
PermissionRevoked(address indexed account, address indexed permission)
SessionActivated(address indexed account)
SessionRevoked(address indexed account)
Dispatched(address indexed account, address indexed target, bytes4 selector, uint256 value)
```

---

## Derivation Patterns

### 1. Registered accounts per template

**Goal:** count how many distinct accounts have registered a given template type.

```
# Cache permissionId per unique permission address (one call per new address)
permissionIdCache = {}

def get_permission_id(permission_address):
    if permission_address not in permissionIdCache:
        try:
            pid = permission_address.call("permissionId()")
            permissionIdCache[permission_address] = pid
        except:
            permissionIdCache[permission_address] = None  # not introspectable
    return permissionIdCache[permission_address]

# Process PermissionRegistered events
accountsByTemplate = defaultdict(set)
for event in query("PermissionRegistered"):
    pid = get_permission_id(event.permission)
    if pid is not None:
        accountsByTemplate[pid].add(event.account)

# Process PermissionRevoked events
for event in query("PermissionRevoked"):
    pid = get_permission_id(event.permission)
    if pid is not None:
        accountsByTemplate[pid].discard(event.account)

registered_count = {pid: len(accounts) for pid, accounts in accountsByTemplate.items()}
```

---

### 2. Active sessions per template

**Goal:** identify accounts that currently have an active session AND have a given
template registered.

```
# Build active-session set from SessionActivated / SessionRevoked
activeSessions = set()
for event in query("SessionActivated"):
    activeSessions.add(event.account)
for event in query("SessionRevoked"):
    activeSessions.discard(event.account)

# Cross-reference with registered accounts per template (from derivation 1)
def active_accounts_for_template(template_pid):
    registered = accountsByTemplate.get(template_pid, set())
    return registered & activeSessions
```

---

### 3. Dispatch count per template

**Goal:** count how many dispatches were attributed to each template type.

Because a single account may have multiple permissions registered, a dispatch is
attributed to template T if T is registered on that account at the time of the
dispatch AND the dispatch succeeded (revert would emit no Dispatched event).

```
# Build a snapshot: at each block, which permissions does each account have?
# Maintain a running set updated by PermissionRegistered / PermissionRevoked events.
accountPermissions = defaultdict(set)  # account → {permission_address}

def attribute_dispatch(event_dispatched, block_number):
    account = event_dispatched.account
    attributed = set()
    for perm_addr in accountPermissions[account]:
        pid = get_permission_id(perm_addr)
        if pid is not None:
            attributed.add(pid)
    return attributed

dispatchCount = defaultdict(int)
for event in query("Dispatched", order="asc"):
    for pid in attribute_dispatch(event, event.blockNumber):
        dispatchCount[pid] += 1
```

> **Note:** a dispatch is attributed to every registered template simultaneously.
> If an account has two templates registered, the dispatch increments both counters.
> This matches the kernel's AND-semantics: all registered permissions evaluate each dispatch.

---

### 4. Native value routed through template dispatches

**Goal:** sum the ETH value forwarded through dispatches attributed to each template.

```
nativeValueRouted = defaultdict(int)  # pid → total wei

for event in query("Dispatched", order="asc"):
    if event.value > 0:
        for pid in attribute_dispatch(event, event.blockNumber):
            nativeValueRouted[pid] += event.value
```

> **Intentional exclusion:** ERC-20 token notional value is not included. Computing
> token value requires price oracles and introduces off-chain data dependencies that
> are outside the scope of this derivation. Consumers that need token-level attribution
> should augment with their own oracle pipeline.

---

### 5. Churn rate

**Goal:** measure what fraction of accounts that registered a template later revoked it,
within a rolling time window.

```
def churn_rate(template_pid, window_seconds):
    cutoff = now() - window_seconds
    registrations = [
        e for e in query("PermissionRegistered")
        if get_permission_id(e.permission) == template_pid
        and e.timestamp >= cutoff
    ]
    revocations_in_window = set(
        e.account for e in query("PermissionRevoked")
        if get_permission_id(e.permission) == template_pid
        and e.timestamp >= cutoff
    )
    if not registrations:
        return 0.0
    churned = sum(1 for e in registrations if e.account in revocations_in_window)
    return churned / len(registrations)
```

---

## Summary

The protocol does not emit a `PermissionUsed` event on each dispatch. Attribution
reconstructs template-level metrics from existing events without adding per-dispatch
gas overhead.
