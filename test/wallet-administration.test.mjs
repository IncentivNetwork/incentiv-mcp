import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { MAINNET, configurationId } from "../src/config.ts";
import { WalletStore, credentialNames } from "../src/wallet/store.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { digest, Journal } from "../src/wallet/journal.ts";
import { backupWallet, restoreWallet } from "../src/wallet/backup.ts";
import { exists } from "../src/wallet/files.ts";
import { fixture, args, password, limits } from "../scripts/wallet-pipeline-fixture.mjs";

function proposed() {
  const config = structuredClone(MAINNET);
  config.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
  config.manifest.manifestId = configurationId(config.manifest, "manifestId");
  return config;
}

test("capability approval preserves identity, ledger and request IDs, cancels unsigned approvals and requires policy review", async t => {
  const f = await fixture(t), id = randomUUID();
  await f.service.send("transfer", args(id));
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"33".repeat(32)}` });
  await f.service.operation(id);
  const pending = randomUUID();
  await f.service.send("transfer", { ...args(pending), amount: "0.00000000000002" });
  const scopes = [];
  const before = await f.store.createOrLoad(), config = proposed(), store = new WalletStore(config, { ...f.deps, verify: async (...input) => { scopes.push(input[2] ?? "local"); await f.deps.verify(...input); } });
  await assert.rejects(store.createOrLoad(), { code: "capability_manifest_unapproved" });
  const review = await reviewCapabilities(store, MAINNET, config);
  await assert.rejects(approveCapabilities(store, MAINNET, config, Buffer.from("wrong password"), digest(review)), { code: "policy_denied" });
  await assert.rejects(approveCapabilities(store, MAINNET, config, password, digest({ stale: true })), { code: "policy_denied" });
  const result = await approveCapabilities(store, MAINNET, config, password, digest(review));
  assert.equal(result.account, before.account); assert.equal(result.owner, before.owner);
  assert.equal(result.wallet_id, before.wallet_id); assert.equal(result.manifest_id, config.manifest.manifestId);
  assert.equal(result.policy.enabled, false);
  assert.deepEqual(scopes, ["local", "all", "all", "all", "all"]);
  await store.session(async s => {
    const journal = await Journal.open(s);
    assert.deepEqual(journal.used(), { native: "1200" });
    assert.equal(journal.data.records[0].requestId, id);
    assert.equal(journal.data.records[0].manifestId, MAINNET.manifest.manifestId);
    assert.equal(journal.data.records[1].status, "cancelled");
    const record = await journal.create(randomUUID(), journal.data.records[0].intent);
    assert.equal(record.manifestId, config.manifest.manifestId);
    await journal.transition(record, "failed");
  });
  await assert.rejects(f.store.createOrLoad(), { code: "capability_manifest_unapproved" });
  const freshReview = await reviewCapabilities(store, MAINNET, config);
  assert.equal((await approveCapabilities(store, MAINNET, config, password, digest(freshReview))).approval, "already_current");
  const out = join(f.parent, "capability-backup.json");
  await backupWallet(config, store, out, password, password);
  const restored = new WalletStore(config, { ...f.deps, root: join(f.parent, "restored") });
  assert.equal((await restoreWallet(config, restored, out, password)).account, before.account);
  await restored.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "1200" }));
});

test("capability changes reject pending signatures, mismatched reviewed configuration and network changes", async t => {
  const f = await fixture(t), config = proposed();
  await f.service.send("transfer", args(randomUUID()));
  const store = new WalletStore(config, f.deps), review = await reviewCapabilities(store, MAINNET, config);
  await assert.rejects(approveCapabilities(store, MAINNET, config, password, digest(review)), { code: "operation_pending" });
  await assert.rejects(reviewCapabilities(store, MAINNET, MAINNET), { code: "policy_denied" });
  const other = structuredClone(config);
  other.identity.genesisHash = `0x${"34".repeat(32)}`;
  other.identity.networkId = configurationId(other.identity, "networkId");
  other.manifest.networkId = other.identity.networkId;
  other.manifest.manifestId = configurationId(other.manifest, "manifestId");
  await assert.rejects(reviewCapabilities(new WalletStore(other, f.deps), MAINNET, other), { code: "wallet_network_mismatch" });
});

test("capability approval recovers at each durable boundary without replacing the wallet", async t => {
  for (const point of ["capability_journal_committed", "capability_envelope_committed"]) await t.test(point, async t => {
    const f = await fixture(t), before = await f.store.createOrLoad(), config = proposed();
    const crashed = new WalletStore(config, { ...f.deps, checkpoint: async name => { if (name === point) throw new Error("injected interruption"); } });
    const review = await reviewCapabilities(crashed, MAINNET, config);
    await assert.rejects(approveCapabilities(crashed, MAINNET, config, password, digest(review)));
    const store = new WalletStore(config, f.deps), next = await reviewCapabilities(store, MAINNET, config);
    const result = await approveCapabilities(store, MAINNET, config, password, digest(next));
    assert.equal(result.account, before.account); assert.equal(result.policy.enabled, false);
    await store.session(s => Journal.open(s));
  });
});

async function creation(t, point, file = false) {
  const f = await fixture(t, { existing: true }), values = new Map();
  const credentials = {
    read: async name => values.has(name) ? Buffer.from(values.get(name)) : undefined,
    create: async (name, value) => { assert.equal(values.has(name), false); values.set(name, Buffer.from(value)); },
    remove: async name => { values.get(name)?.fill(0); values.delete(name); },
  };
  t.after(() => { for (const value of values.values()) value.fill(0); });
  const deps = { ...f.deps, allowFileKey: file, credentials: async () => credentials };
  const store = new WalletStore(MAINNET, deps);
  const interrupted = new WalletStore(MAINNET, { ...deps, checkpoint: async name => { if (name === point) throw new Error("interrupted creation"); } });
  return { ...f, store, deps, values, interrupted };
}

test("interactive initialization establishes disabled policy, authenticated recovery and permanent commit evidence", async t => {
  const f = await creation(t);
  const wallet = await f.store.initialize(limits, password);
  assert.equal(wallet.policy.configured, true); assert.equal(wallet.policy.enabled, false);
  await f.store.session(async s => assert.equal((await Journal.open(s)).data.records.length, 0));
  assert.equal(await exists(join(f.root, "wallet.commit.json")), true);
  assert.ok([...f.values.keys()].some(name => name.startsWith("commit:")));
  await assert.rejects(f.store.reviewOrphan(), { code: "wallet_recovery_required" });
  await assert.rejects(f.store.initialize(limits, password), { code: "wallet_recovery_required" });
});

test("authenticated recovery discards only provably uncommitted incomplete attempts", async t => {
  for (const point of ["binding_written", "credential_anchor_written", "pending_credential_written", "staging_created", "file_key_written"]) await t.test(point, async t => {
    const f = await creation(t, point, point === "file_key_written");
    await assert.rejects(f.interrupted.initialize(limits, password));
    const review = await f.store.reviewOrphan();
    await assert.rejects(f.store.recoverOrphan(Buffer.from("incorrect password"), review.review_digest), { code: "policy_denied" });
    await assert.rejects(f.store.recoverOrphan(password, "stale review"), { code: "policy_denied" });
    assert.equal((await f.store.recoverOrphan(password, review.review_digest)).status, "orphan_discarded");
    assert.equal(await exists(join(f.root, "wallet.binding.json")), false); assert.equal(f.values.size, 0);
    const wallet = await f.store.initialize(limits, password); assert.notEqual(wallet.wallet_id, review.wallet_id);
  });
});

test("recovery preserves complete staged wallets and resumes their original owner", async t => {
  const f = await creation(t, "keystore_written");
  await assert.rejects(f.interrupted.initialize(limits, password));
  const binding = JSON.parse(await readFile(join(f.root, "wallet.binding.json"), "utf8"));
  const staged = JSON.parse(await readFile(join(f.root, `wallet.tmp-${binding.walletId}`, "wallet.json"), "utf8"));
  await assert.rejects(f.store.reviewOrphan(), { code: "wallet_recovery_required" });
  const loaded = await f.store.createOrLoad(); assert.equal(loaded.owner, staged.owner);
  await f.store.session(s => Journal.open(s));
});

test("lost committed filesystem evidence cannot turn into an authenticated orphan", async t => {
  const f = await creation(t);
  await f.store.initialize(limits, password);
  const binding = JSON.parse(await readFile(join(f.root, "wallet.binding.json"), "utf8"));
  await rm(join(f.root, "wallet"), { recursive: true });
  await rm(join(f.root, "wallet.commit.json"));
  // Even losing the ordinary committed credential leaves the independent barrier.
  f.values.delete(credentialNames(binding).committed);
  await assert.rejects(f.store.reviewOrphan(), { code: "wallet_recovery_required" });
  assert.equal(await exists(join(f.root, "wallet.binding.json")), true);
});

test("interrupted orphan cleanup remains authenticated and retryable", async t => {
  const f = await creation(t, "pending_credential_written");
  await assert.rejects(f.interrupted.initialize(limits, password));
  const review = await f.store.reviewOrphan();
  const crashing = new WalletStore(MAINNET, { ...f.deps, checkpoint: async point => { if (point === "orphan_pending_removed") throw new Error("interruption"); } });
  await assert.rejects(crashing.recoverOrphan(password, review.review_digest));
  const retry = await f.store.reviewOrphan();
  assert.equal((await f.store.recoverOrphan(password, retry.review_digest)).status, "orphan_discarded");
});

test("legacy creation orphans cannot be deleted without authenticated proof", async t => {
  const f = await creation(t, "pending_credential_written");
  await assert.rejects(f.interrupted.createOrLoad());
  await assert.rejects(f.store.reviewOrphan(), { code: "wallet_recovery_required" });
  assert.ok(f.values.size > 0);
});
