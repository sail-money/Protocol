#!/usr/bin/env node
// Merge the deployed vault-exit WithdrawPermission (.v2 salt) into the canonical deployment
// registry, after `script/deploy.sh <chain> --target templates-withdraw` has run on every chain.
//
// Why a script instead of hand edits: the address has to land identically in 12 per-chain
// manifests plus 3 index files, and the old address has to survive as `withdrawV1Superseded`
// rather than simply vanish (it stays live on-chain and accounts may still have it registered).
// Hand-editing 15 files is how one chain ends up with a typo that the parity validator then
// reports as a cross-chain divergence.
//
// What it does:
//   1. Reads deployments/<chainId>/templates.withdraw.v2.json for every chain in deployments.json.
//   2. Refuses to write unless every chain is present and agrees on withdraw address, initCodeHash,
//      kernel, and author. Partial coverage is reported and exits nonzero — merge only at the end.
//   3. Patches, preserving key order and the v1 address as `withdrawV1Superseded`:
//        deployments/<chainId>/templates.shared.json   withdraw -> v2
//        deployments/deployments.json                  canonicalAddresses.sharedTemplates
//        deployments/addresses.json                    templates.withdraw
//   4. Reports every remaining prose occurrence of the v1 address (addresses.md, README.md) for
//      manual review — wording is a human call, not a regex's.
//
// Usage:
//   node scripts/apply-withdraw-v2.mjs --check   # verify manifests only, write nothing
//   node scripts/apply-withdraw-v2.mjs           # verify, then patch the registry
//
// Dependency-free: Node stdlib only.

import { readFileSync, writeFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX_PATH = join(REPO, 'deployments', 'deployments.json');
const ADDRESSES_PATH = join(REPO, 'deployments', 'addresses.json');

const WITHDRAW_V1 = '0xF5eF5dda450a130e3020d54f565E830e4a7531f8';
const PROSE_FILES = ['deployments/addresses.md', 'README.md'];

const CHECK_ONLY = process.argv.includes('--check');

const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
const eq = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

const failures = [];
const fail = (m) => failures.push(m);

// ---- 1. collect per-chain withdraw-v2 manifests ------------------------------
const idx = load(INDEX_PATH);
const chainIds = idx.chains.map((c) => c.chainId);
const found = new Map();
const missing = [];

for (const cid of chainIds) {
  const p = join(REPO, 'deployments', String(cid), 'templates.withdraw.v2.json');
  if (!existsSync(p)) { missing.push(cid); continue; }
  found.set(cid, load(p));
}

if (found.size === 0) {
  console.error('FAIL: no templates.withdraw.v2.json found on any chain — nothing to merge.');
  console.error('      Deploy first: script/deploy.sh <chain> --target templates-withdraw');
  process.exit(1);
}

// ---- 2. consistency: every chain present, all fields identical ---------------
if (missing.length) {
  fail(`not yet deployed on ${missing.length}/${chainIds.length} chain(s): ${missing.join(', ')}`);
}

const first = found.get([...found.keys()][0]);
for (const field of ['withdraw', 'initCodeHash', 'kernel', 'author', 'salt']) {
  if (!first[field]) fail(`[manifest] missing field '${field}' in the first withdraw-v2 manifest`);
}
for (const [cid, m] of found) {
  for (const field of ['withdraw', 'initCodeHash', 'kernel', 'author', 'salt']) {
    if (!eq(m[field], first[field])) {
      fail(`[parity] chain ${cid}: ${field} ${m[field]} != ${first[field]} (chain ${[...found.keys()][0]})`);
    }
  }
  if (!eq(m.kernel, idx.canonicalAddresses.core.SailKernel)) {
    fail(`[kernel] chain ${cid}: manifest kernel ${m.kernel} != canonical ${idx.canonicalAddresses.core.SailKernel}`);
  }
  if (eq(m.withdraw, WITHDRAW_V1)) {
    fail(`[sanity] chain ${cid}: withdraw address equals the superseded v1 address — salt not rotated?`);
  }
  if (m.reusedExistingCode === undefined) {
    fail(`[manifest] chain ${cid}: missing 'reusedExistingCode' — manifest predates this workflow?`);
  }
}

const WITHDRAW_V2 = first.withdraw;

console.log('WithdrawPermission v2 registry merge');
console.log('====================================');
console.log(`  v1 (superseded, stays live): ${WITHDRAW_V1}`);
console.log(`  v2 (new canonical)         : ${WITHDRAW_V2}`);
console.log(`  initCodeHash               : ${first.initCodeHash}`);
console.log(`  chains with a v2 manifest  : ${found.size}/${chainIds.length}`);
console.log('');

if (failures.length) {
  console.error(`FAIL — ${failures.length} problem(s); registry NOT modified:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
console.log('  all chains present and in agreement.');

if (CHECK_ONLY) {
  console.log('');
  console.log('PASS (--check) — manifests are consistent. Re-run without --check to patch the registry.');
  process.exit(0);
}

// ---- 3. patch the registry ---------------------------------------------------
// Rewrites go through JSON.parse/stringify, so formatting is normalised. The per-chain template
// manifests are already machine-written single-line JSON; the two index files are pretty-printed
// and are re-emitted with the same 2-space indent.
const written = [];

// 3a. per-chain templates.shared.json
for (const cid of chainIds) {
  const p = join(REPO, 'deployments', String(cid), 'templates.shared.json');
  if (!existsSync(p)) { console.warn(`  warn: chain ${cid}: no templates.shared.json — skipped`); continue; }
  const m = load(p);
  if (eq(m.withdraw, WITHDRAW_V2)) continue; // already merged — idempotent
  if (!eq(m.withdraw, WITHDRAW_V1)) {
    console.error(`FAIL: chain ${cid}: templates.shared.json withdraw is ${m.withdraw}, expected v1 ${WITHDRAW_V1} or v2 ${WITHDRAW_V2}. Aborting; no further files written.`);
    process.exit(1);
  }
  m.withdraw = WITHDRAW_V2;
  m.withdrawV1Superseded = WITHDRAW_V1;
  m.withdrawNote =
    'withdraw is the vault-exit WithdrawPermission deployed under the sail.template.withdraw.v2 salt ' +
    '(see templates.withdraw.v2.json). withdrawV1Superseded is the original ERC-20-transfer ' +
    'WithdrawPermission: still live on-chain and still usable by accounts that registered it, but no ' +
    'longer the recommended withdraw template.';
  writeFileSync(p, JSON.stringify(m) + '\n');
  written.push(`deployments/${cid}/templates.shared.json`);
}

// 3b. deployments/deployments.json
{
  const m = load(INDEX_PATH);
  m.canonicalAddresses.sharedTemplates.WithdrawPermission = WITHDRAW_V2;
  m.canonicalAddresses.supersededTemplates = {
    ...(m.canonicalAddresses.supersededTemplates ?? {}),
    'WithdrawPermission.v1': {
      address: WITHDRAW_V1,
      status: 'live but superseded',
      note:
        'Original ERC-20-transfer WithdrawPermission (single allowed recipient). Replaced by the ' +
        'vault-exit WithdrawPermission at canonicalAddresses.sharedTemplates.WithdrawPermission, ' +
        'deployed under a rotated salt (sail.template.withdraw.v2) so the two do not collide. This ' +
        'contract is NOT upgraded or disabled: accounts that already registered it keep working, and ' +
        'nothing revokes it on their behalf. New registrations should use the v2 address.',
    },
  };
  writeFileSync(INDEX_PATH, JSON.stringify(m, null, 2) + '\n');
  written.push('deployments/deployments.json');
}

// 3c. deployments/addresses.json
{
  const m = load(ADDRESSES_PATH);
  m.templates.withdraw = WITHDRAW_V2;
  m.templates.withdrawV1Superseded = WITHDRAW_V1;
  writeFileSync(ADDRESSES_PATH, JSON.stringify(m, null, 2) + '\n');
  written.push('deployments/addresses.json');
}

console.log('');
console.log(`patched ${written.length} file(s):`);
for (const w of written) console.log(`  ${w}`);

// ---- 4. report prose occurrences for manual review ---------------------------
console.log('');
console.log('remaining references to the v1 address — review by hand (wording is a human call):');
let proseHits = 0;
for (const rel of PROSE_FILES) {
  const p = join(REPO, rel);
  if (!existsSync(p)) continue;
  const lines = readFileSync(p, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (line.toLowerCase().includes(WITHDRAW_V1.toLowerCase())) {
      proseHits++;
      console.log(`  ${rel}:${i + 1}: ${line.trim().slice(0, 120)}`);
    }
  });
}
if (proseHits === 0) console.log('  (none)');

console.log('');
console.log('next: node scripts/validate-deployments.mjs');
