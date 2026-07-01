# Contributing to Sail Protocol

Sail is an onchain primitive for Separately Managed Accounts run by agents — a lean trusted core
that wraps a Safe with a permission-gating layer. See the [README](./README.md) for an
introduction and [docs/](./docs/) for the specification, architecture, and references.

**License.** The trusted core and the shared permission templates are GPL-2.0-or-later; the
interface/import-surface files are MIT. See [LICENSE](./LICENSE) — by contributing you agree your
contributions are licensed under the same terms as the files they touch.

---

## ⚠️ Security issues do not go here

**Never file a security vulnerability as a public issue or pull request.** Report it privately per
the [Security Policy](./SECURITY.md) — email **hello@sail.money**. Public disclosure of an
unpatched vulnerability puts users at risk; please follow coordinated disclosure.

---

## Building & testing

Sail is a [Foundry](https://book.getfoundry.sh/) project. See the [README](./README.md) for full
setup. In short:

```bash
forge build        # compile
forge test         # run the test suite
forge snapshot     # regenerate the gas snapshot
```

Please make sure `forge build` and `forge test` pass before opening a pull request.

---

## How to contribute

Contributions are welcome via **issues** and **pull requests**.

Sail's design is deliberately a **lean, fail-closed trusted core**: the kernel and governance own
the smallest possible surface, and everything else lives in user-deployed contracts. A practical
consequence is that **most new DeFi integrations are permissions/templates that anyone can deploy
and register — they do not require kernel changes.** So the most welcome contributions are:

- **Permission templates** — new `IPermission` implementations for venues and strategies (these
  are the primary extension surface; they need no protocol change).
- **Documentation** — corrections, clarifications, and guides.
- **Tooling** — scripts, indexers, and integration helpers.
- **Bug fixes** — with a test that reproduces the bug.

Changes to the **trusted core** (`SailKernel`, `SailGovernance`, and the interfaces they depend
on) carry a **higher bar and more scrutiny**, because every account relies on that bytecode. Open
an **issue to discuss first** before a large core change, rather than a surprise PR.

---

## Pull request process

- **One logical unit per PR.** Keep changes focused and reviewable.
- **Tests added or updated and passing** (`forge test`).
- **Gas snapshot updated** if the change is gas-relevant (`forge snapshot`).
- **Docs updated** alongside any behavioral, interface, or address change.
- **Discuss trusted-core changes first** — open an issue before a large PR to `SailKernel` /
  `SailGovernance`.
- **No attribution footers** in commit messages (no `Co-Authored-By`, no tool signatures).

### Reviews

Protocol pull requests require review from **all three** of **@AlvaroAlonso-0**, **@dreski3**, and
**@aadopii**. @aadopii is the product owner and a required final approver on protocol changes.
Documentation- and tooling-only PRs are lighter-touch, but protocol changes need all three
approvals before merge.

---

## Code style

- Follow standard Solidity conventions and match the style of the surrounding code.
- **NatSpec** on public and external functions, events, and errors — document the boundary of what
  a contract enforces, and be honest about what it does not.
- **Terminology.** The codebase and docs say **"security review"**, never "audit". Keep that
  consistent in code comments and documentation.

---

## Questions

For non-security questions, email **hello@sail.money** or open a
[discussion/issue](./README.md). Project site: <https://sail.money>.
