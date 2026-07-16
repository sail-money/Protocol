#!/usr/bin/env node
// Validate deployments/deployments.json against the per-chain manifests.
//
// Assertions:
//   1. Every referenced per-chain manifest (core + templates) exists.
//   2. Cross-chain address parity: each canonical core + template address is
//      byte-identical in every chain's manifest.
//   3. Governance parity: the three Safes + deployer are identical everywhere.
//   4. Fee-cap invariant: every perChainActive deploy-time + current fee <= capWei (BigInt).
//   5. Chain count: exactly 12 (10 mainnet + 2 testnet), expected chainId set.
//   6. Exit 0 only if all assertions pass; nonzero + report otherwise.
//
// Chains flagged `templatesPending: true` in a chain entry (core deployed, shared
// templates not yet deployed there) are exempt from the templates-manifest-exists
// and template-parity checks (2) but still count toward chain-count/id-set (5).
//
// Dependency-free: Node stdlib only. Run: node scripts/validate-deployments.mjs

import { readFileSync, existsSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX = join(REPO, 'deployments', 'deployments.json');

const failures = [];
const fail = (msg) => failures.push(msg);
const load = (p) => JSON.parse(readFileSync(p, 'utf8'));
const eq = (a, b) => String(a).toLowerCase() === String(b).toLowerCase();

// Canonical index -> manifest field mappings.
const CORE_FIELD = {
  Timelock: 'timelock',
  SailGovernance: 'governance',
  SailKernel: 'kernel',
  MandateFactory: 'mandateFactory',
  StandardFeePolicy: 'standardFeePolicy',
  SafeModuleEnabler: 'safeModuleEnabler',
};
const TEMPLATE_FIELD = {
  ApproveAndCallBatchPermission: 'approveAndCallBatch',
  BorrowPermission: 'borrow',
  DepositPermission: 'deposit',
  SwapPermission: 'swap',
  SwapPermissionNoOracle: 'swapNoOracle',
  TransferPermission: 'transfer',
  WithdrawPermission: 'withdraw',
};
const GOV_FIELD = {
  adminSafe: 'feeManager',
  treasurySafe: 'treasury',
  emergencySafe: 'emergencyAdmin',
  deployerEOA: 'deployer',
};
const EXPECTED_IDS = [1, 10, 130, 42161, 4326, 480, 56, 8453, 999, 11155111, 84532, 4663];
const EXPECTED_TESTNETS = new Set([11155111, 84532]);

if (!existsSync(INDEX)) {
  console.error(`FAIL: missing ${INDEX}`);
  process.exit(1);
}
const idx = load(INDEX);

// ---- 1. manifests exist, load them ------------------------------------------
const core = {};
const tmpl = {};
for (const c of idx.chains) {
  const corePath = join(REPO, c.manifest);
  if (!existsSync(corePath)) { fail(`[manifest] chain ${c.chainId}: missing core manifest ${c.manifest}`); continue; }
  core[c.chainId] = load(corePath);
  if (c.templatesPending) continue; // shared templates not deployed on this chain yet
  const tmplPath = join(REPO, c.templatesManifest);
  if (!existsSync(tmplPath)) { fail(`[manifest] chain ${c.chainId}: missing templates manifest ${c.templatesManifest}`); continue; }
  tmpl[c.chainId] = load(tmplPath);
}

// ---- 2. cross-chain address parity (core + templates) -----------------------
for (const [name, field] of Object.entries(CORE_FIELD)) {
  const want = idx.canonicalAddresses.core[name];
  for (const c of idx.chains) {
    const got = core[c.chainId]?.[field];
    if (!eq(got, want)) fail(`[parity/core] ${name} on chain ${c.chainId}: manifest ${got} != canonical ${want}`);
  }
}
for (const [name, field] of Object.entries(TEMPLATE_FIELD)) {
  const want = idx.canonicalAddresses.sharedTemplates[name];
  for (const c of idx.chains) {
    if (c.templatesPending) continue;
    const got = tmpl[c.chainId]?.[field];
    if (!eq(got, want)) fail(`[parity/template] ${name} on chain ${c.chainId}: manifest ${got} != canonical ${want}`);
  }
}

// ---- 3. governance parity ----------------------------------------------------
for (const [gname, field] of Object.entries(GOV_FIELD)) {
  const want = idx.governance[gname].address;
  for (const c of idx.chains) {
    const got = core[c.chainId]?.[field];
    if (!eq(got, want)) fail(`[parity/gov] ${gname} on chain ${c.chainId}: manifest ${got} != canonical ${want}`);
  }
}

// ---- 4. fee-cap invariant (BigInt) — both deploy-time and current fees ------
const capWei = BigInt(idx.fees.permissionRegistrationFee.capWei);
for (const [cid, f] of Object.entries(idx.fees.permissionRegistrationFee.perChainActive)) {
  for (const field of ['deployTimeActiveWei', 'currentActiveWei']) {
    if (f[field] === undefined) { fail(`[fee-cap] chain ${cid}: missing ${field}`); continue; }
    const v = BigInt(f[field]);
    if (v > capWei) fail(`[fee-cap] chain ${cid}: ${field} ${v} > capWei ${capWei}`);
  }
}

// ---- 5. chain count + id set -------------------------------------------------
const ids = idx.chains.map((c) => c.chainId);
if (ids.length !== 12) fail(`[chains] expected 12 chains, found ${ids.length}`);
const mainnets = idx.chains.filter((c) => !c.isTestnet).length;
const testnets = idx.chains.filter((c) => c.isTestnet).length;
if (mainnets !== 10) fail(`[chains] expected 10 mainnets, found ${mainnets}`);
if (testnets !== 2) fail(`[chains] expected 2 testnets, found ${testnets}`);
const missing = EXPECTED_IDS.filter((x) => !ids.includes(x));
const extra = ids.filter((x) => !EXPECTED_IDS.includes(x));
if (missing.length) fail(`[chains] missing chainIds: ${missing.join(', ')}`);
if (extra.length) fail(`[chains] unexpected chainIds: ${extra.join(', ')}`);
for (const c of idx.chains) {
  const shouldBeTestnet = EXPECTED_TESTNETS.has(c.chainId);
  if (shouldBeTestnet !== c.isTestnet) fail(`[chains] chain ${c.chainId}: isTestnet=${c.isTestnet}, expected ${shouldBeTestnet}`);
}

// ---- report ------------------------------------------------------------------
const checks = [
  'manifests present',
  'core + template address parity across 12 chains (excluding templatesPending chains from template checks)',
  'governance (3 Safes + deployer) parity',
  'fee-cap invariant (deploy-time + current fee <= capWei)',
  'chain count + chainId set (10 mainnet + 2 testnet)',
];
console.log('Sail deployments validation');
console.log('===========================');
for (const c of checks) console.log(`  checked: ${c}`);
console.log('');
if (failures.length === 0) {
  console.log(`PASS — all assertions passed across ${ids.length} chains.`);
  process.exit(0);
} else {
  console.error(`FAIL — ${failures.length} assertion(s) failed:`);
  for (const f of failures) console.error(`  - ${f}`);
  process.exit(1);
}
