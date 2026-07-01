# Security Policy

## Reporting a vulnerability

Please report suspected vulnerabilities **privately** to **hello@sail.money**. Do not open a
public issue or pull request for a security report, and do not disclose the issue publicly
until it has been addressed.

We will acknowledge reports on a best-effort basis and work with you on coordinated disclosure.
We do not commit to a fixed response timeline.

## Scope

In scope — the trusted core and the protocol-deployed contracts:

- `SailKernel`
- `SailGovernance` and its timelock
- `MandateFactory`
- `StandardFeePolicy`
- `SafeModuleEnabler`

Out of scope — user-deployed code and its assumptions. The correctness of any user-deployed
permission or fee policy is the author's responsibility, and several properties hold only under
documented conditions (for example, NAV is manager-attested and not verified on-chain, and
off-chain venue components are outside the contracts). See
[docs/SECURITY_MODEL.md](./docs/SECURITY_MODEL.md) — *Known Limitations and Operator
Responsibilities* — for the boundaries that hold by design.

## Bug bounty

There is no formal bug-bounty program at this time. We still welcome reports and will credit
reporters who wish to be acknowledged.

## Security review

The trusted core and the shared permission templates were the subject of a security review by
Octane. The reports and index are in [docs/security](./docs/security/). A security review is
not a guarantee of correctness.
