# Shared permission templates

This directory holds Sail's seven shared permission templates —
`SwapPermission`, `SwapPermissionNoOracle`, `BorrowPermission`, `DepositPermission`,
`WithdrawPermission`, `TransferPermission`, and `ApproveAndCallBatchPermission` — over their
common base, `ConfigurablePermission`. They are multi-tenant: one deployment per chain serves
every account, with per-account bounds set through `configure()`. They are swappable
defaults — any contract implementing `IPermission` can be registered instead.

This README is only a pointer; the source below and its NatSpec headers are canonical.

- **Catalog — what each template gates and how it decides:** [../../docs/TEMPLATES.md](../../docs/TEMPLATES.md)
- **The shared multi-tenant pattern (design rationale):** the whitepaper's Permission System section (§4), [../../docs/whitepaper/Sail_Protocol_Whitepaper.pdf](../../docs/whitepaper/Sail_Protocol_Whitepaper.pdf)
- **Security model and the templates' blast-radius boundary:** [../../docs/SECURITY_MODEL.md](../../docs/SECURITY_MODEL.md)
- **AI security review reports (core + templates):** [../../docs/security/](../../docs/security/)
