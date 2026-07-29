# Security Review

These are the reports from Sail's **AI security review** by **Octane**
([octane.security](https://www.octane.security)), an AI source-code security scanner. The review
covered **both the trusted core and the seven shared permission templates** — not the core alone
— across **three successive security analyses** (2026-06-24, 2026-06-26, 2026-06-29). The
**third and final analysis (2026-06-29) identified no critical- or high-severity findings**; all
reported vulnerabilities were resolved or acknowledged, and the remaining lower-severity warnings
are documented, accepted by design, or out of scope.

**What was reviewed.** The trusted core (`SailKernel`, `SailGovernance`, the timelock, and the
core interfaces) together with the shared permission templates (`SwapPermission`,
`SwapPermissionNoOracle`, `BorrowPermission`, `DepositPermission`, `WithdrawPermission`,
`TransferPermission`, `ApproveAndCallBatchPermission`).

**Review boundary.** The reviews cover `main` through PR #79 (commit `8d1e122`). Changes on
`main` after that point are limited to documentation and deployment metadata, not trusted-core
logic. Scope was defined by files and contracts; the reviewer did not state a line-count
figure.

> **Note:** the `WithdrawPermission` covered by these reviews was the earlier ERC-20-transfer
> gate. It has since been rewritten as the vault/lending-pool exit permission (ERC-4626
> `withdraw`/`redeem` and Aave v2/v3 `withdraw`). The current vault-exit implementation is new
> code that postdates the review boundary above: it is not covered by these reports and has not
> been independently reviewed.

## Reports

The reports are Octane's signed deliverables and are kept here as PDFs (they are not
inline-embedded; open or download via the links below).

| Review | Date | Reviewer | Pages | Report |
|--------|------|----------|:-----:|--------|
| Third analysis (most recent) | 2026-06-29 | Octane | 153 | [PDF](https://github.com/sail-money/Protocol/raw/main/docs/security/octane-security-analysis-03-2026-06-29.pdf) |
| Second analysis | 2026-06-26 | Octane | 175 | [PDF](https://github.com/sail-money/Protocol/raw/main/docs/security/octane-security-analysis-02-2026-06-26.pdf) |
| First analysis | 2026-06-24 | Octane | 108 | [PDF](https://github.com/sail-money/Protocol/raw/main/docs/security/octane-security-analysis-01-2026-06-24.pdf) |

The most recent review (2026-06-29) reflects the current state of the reviewed code; earlier
reviews are retained for transparency.

## Not a guarantee

A security review is not a proof of correctness. It reduces risk in the reviewed code; it does
not eliminate it, and it does not extend to code deployed by users. In particular, the
correctness of any user-deployed permission or fee policy remains the author's responsibility.
See the [Known Limitations and Operator Responsibilities](../SECURITY_MODEL.md#known-limitations-and-operator-responsibilities)
in the security model for the boundaries that hold by design.

## Reporting a vulnerability

See the canonical [Security Policy](../../SECURITY.md) at the repository root.
