# Repository Setup Checklist (manual — owner runs before going public)

These are GitHub settings to configure by hand before flipping the repository public. Nothing here
is applied automatically; this is a checklist for the product owner.

## About / metadata

- [ ] **Description:** `Onchain Separately Managed Accounts run by agents — the trusted core and shared permission templates.`
- [ ] **Topics:** `defi`, `ethereum`, `solidity`, `smart-accounts`, `safe`, `account-abstraction`, `agents`, `sma`, `permissionless`, `foundry`
- [ ] **Website:** `https://sail.money`
- [ ] **Social preview image:** brand assets exist in [`docs/brand/`](./brand/) (`sail_logo.png`, `sail_logo_black.png`, `sail_logo_3D.png`, `sail_logo.pdf`). Pick/produce a 1280×640 preview. OWNER TO SPECIFY: which asset (or a dedicated preview image).

## Features

- [ ] **Issues:** enabled (full-open contribution posture; issue templates are in `.github/ISSUE_TEMPLATE/`).
- [ ] **Discussions:** optional — enable if you want a Q&A/community space. OWNER TO SPECIFY: community channel (Discord/forum) if one exists — none is referenced in the repo today.
- [ ] **Private vulnerability reporting:** enable (recommended) — this is the private channel referenced by [`SECURITY.md`](../SECURITY.md), complementing hello@sail.money.

## Branch protection on `main`

- [ ] Require a pull request before merging.
- [ ] Require approvals before merge.
- [ ] Enforce that **protocol changes** are approved by **all three**: `@AlvaroAlonso-0`, `@dreski3`, and `@aadopii`.

> **Important:** naming three specific required reviewers is enforced by a **CODEOWNERS file** or a
> **branch-protection ruleset**, NOT by the PR template alone — the template is only a reminder;
> the setting is the actual gate. To make the three-reviewer rule robust, add a `CODEOWNERS` file
> and enable "Require review from Code Owners" in branch protection. A minimal starting point:
>
> ```
> # .github/CODEOWNERS
> # Trusted core — all three required
> /contracts/core/         @AlvaroAlonso-0 @dreski3 @aadopii
> /contracts/governance/   @AlvaroAlonso-0 @dreski3 @aadopii
> /contracts/interfaces/   @AlvaroAlonso-0 @dreski3 @aadopii
> # Whole protocol fallback
> /contracts/              @AlvaroAlonso-0 @dreski3 @aadopii
> ```
>
> (Left for the owner to add deliberately, since committing it changes review-gating behavior once
> branch protection references it.)

## Before making public

- [ ] Confirm no secrets in the repository **history** (keys, mnemonics, RPC URLs, API keys). The
      final pre-launch sweep covers a full history scan; do not flip public until it passes.
- [ ] Confirm `LICENSE`, `SECURITY.md`, `CONTRIBUTING.md`, and the `.github/` templates are present
      and render.
