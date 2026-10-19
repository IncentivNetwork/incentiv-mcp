import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { MAINNET, configurationId } from "../src/config.ts";
import { assertImplementationUpgrade, previousImplementationConfig } from "../src/account-upgrade.ts";
import { Ctx } from "../src/context.ts";
import { deriveSmartAccount, NetworkError } from "../src/network.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { WalletService } from "../src/wallet/service.ts";
import { reviewImplementation, approveImplementation } from "../src/wallet/implementation.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { digest, Journal } from "../src/wallet/journal.ts";
import { authorize } from "../src/wallet/policy.ts";
import { parseEnvelope, unlockWallet } from "../src/wallet/keystore.ts";
import { exists } from "../src/wallet/files.ts";
import { fixture, args, password, limits } from "../scripts/wallet-pipeline-fixture.mjs";

const previous = previousImplementationConfig(MAINNET);
const snapshot = root => Promise.all(["wallet.json", "operations/journal.json"].map(async path => {
  try { return await readFile(join(root, "wallet", path)); }
  catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
}));
const approve = async (store, passphrase = password, initialLimits) => approveImplementation(store, MAINNET, passphrase, digest(await reviewImplementation(store, MAINNET)), initialLimits);

test("implementation approval accepts only the reviewed network transition and preserves address derivation", () => {
  assert.equal(previous.identity.accountImplementation.address.toLowerCase(), "0x43fb62a71d0ce27fd6ab70347a438d67ec2dfc6c");
  assert.equal(previous.identity.networkId, "0xd2710c6ff1e86a0c66fb2274612b5f8b770e7b4956cd59ca70b7edc328b11d49");
  assert.equal(previous.manifest.manifestId, "0x6fe24377ccfc78465ee7febb06cbc71eb0a975285432b5f15531438dbc2877c4");
  const owner = "0xb6204d2a6f872e96ed273fefbe9b3190099fa4f9";
  assert.equal(deriveSmartAccount(previous, owner), deriveSmartAccount(MAINNET, owner));
  const customEndpoint = structuredClone(MAINNET);
  customEndpoint.endpoints.rpcUrls = ["https://rpc.example.test/"];
  assert.deepEqual(previousImplementationConfig(customEndpoint).endpoints, customEndpoint.endpoints);
  for (const mutate of [
    c => { c.identity.accountImplementation.address = "0x0000000000000000000000000000000000000001"; },
    c => { c.identity.accountImplementation.codeHash = `0x${"12".repeat(32)}`; },
    c => { c.identity.genesisHash = `0x${"12".repeat(32)}`; },
    c => { c.identity.accountFactory.address = "0x0000000000000000000000000000000000000001"; },
  ]) {
    const config = structuredClone(MAINNET); mutate(config);
    config.identity.networkId = configurationId(config.identity, "networkId");
    config.manifest.networkId = config.identity.networkId;
    config.manifest.manifestId = configurationId(config.manifest, "manifestId");
    assert.throws(() => previousImplementationConfig(config));
  }
  const changedCapabilities = structuredClone(MAINNET);
  changedCapabilities.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
  changedCapabilities.manifest.manifestId = configurationId(changedCapabilities.manifest, "manifestId");
  assert.throws(() => assertImplementationUpgrade(previous, changedCapabilities), { code: "wallet_network_mismatch" });
});

test("implementation approval preserves wallet, keys, history and spend while cancelling unsigned authorizations", async t => {
  const f = await fixture(t, { config: previous }), confirmed = randomUUID(), unsigned = randomUUID(), preparing = randomUUID();
  await f.service.send("transfer", args(confirmed));
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"33".repeat(32)}` });
  await f.service.operation(confirmed);
  await f.service.send("transfer", { ...args(unsigned), amount: "0.00000000000002" });
  let confirmedRecord, beforeEnvelope;
  await f.store.session(async s => {
    beforeEnvelope = structuredClone(s.envelope);
    const journal = await Journal.open(s);
    confirmedRecord = structuredClone(journal.data.records[0]);
    const pending = journal.data.records[1];
    pending.approval = { intentHash: pending.intentHash, userOpHash: pending.userOpHash, operationDigest: digest(pending.operation), expiresAt: Date.now() + 60_000 };
    await journal.create(preparing, confirmedRecord.intent);
  });
  const keyBefore = await readFile(join(f.root, "wallet", "master.key")), filesBefore = await snapshot(f.root), scopes = [];
  const store = new WalletStore(MAINNET, { ...f.deps, verify: async (...input) => { scopes.push(input[2] ?? "local"); await f.deps.verify(...input); } });
  await assert.rejects(store.createOrLoad(), { code: "wallet_network_mismatch" });
  const review = await reviewImplementation(store, MAINNET);
  await assert.rejects(approveImplementation(store, MAINNET, Buffer.from("incorrect password"), digest(review)), { code: "policy_denied" });
  assert.deepEqual(await snapshot(f.root), filesBefore);
  await assert.rejects(approveImplementation(store, MAINNET, password, digest({ stale: true })), { code: "policy_denied" });
  assert.deepEqual(await snapshot(f.root), filesBefore);
  const result = await approveImplementation(store, MAINNET, password, digest(review));
  assert.equal(result.wallet_id, beforeEnvelope.walletId); assert.equal(result.owner, beforeEnvelope.owner); assert.equal(result.account, beforeEnvelope.account);
  assert.equal(result.network_id, MAINNET.identity.networkId); assert.equal(result.manifest_id, MAINNET.manifest.manifestId);
  assert.equal(result.policy.enabled, false); assert.deepEqual(result.policy.limits, limits);
  assert.deepEqual(scopes, ["local", "local", "local", "local", "local"]);
  await store.session(async s => {
    assert.deepEqual(s.envelope.keyStorage, beforeEnvelope.keyStorage);
    assert.deepEqual(s.envelope.policy.administration, beforeEnvelope.policy.administration);
    assert.equal(s.envelope.salt, beforeEnvelope.salt);
    const journal = await Journal.open(s);
    assert.equal(journal.data.networkId, previous.identity.networkId);
    assert.ok(journal.data.approvedNetworkIds.includes(MAINNET.identity.networkId));
    assert.deepEqual(journal.data.records[0], confirmedRecord);
    assert.deepEqual(journal.used(), { native: "1200" });
    for (const id of [unsigned, preparing]) {
      const record = journal.data.records.find(r => r.requestId === id);
      assert.equal(record.status, "cancelled"); assert.equal(record.approval, undefined);
    }
    const fresh = await journal.create(randomUUID(), confirmedRecord.intent);
    assert.equal(fresh.manifestId, MAINNET.manifest.manifestId);
    await journal.transition(fresh, "failed");
  });
  assert.deepEqual(await readFile(join(f.root, "wallet", "master.key")), keyBefore); keyBefore.fill(0);
  await assert.rejects(f.store.createOrLoad(), { code: "wallet_network_mismatch" });
  const currentFiles = await snapshot(f.root);
  assert.equal((await approve(store)).approval, "already_current");
  assert.deepEqual(await snapshot(f.root), currentFiles);
  const service = new WalletService(new Ctx(MAINNET), store, f.chain, true);
  await assert.rejects(service.send("transfer", args(randomUUID())), { code: "wallet_locked" });
});

test("implementation approval retains every nonce-owning state and reservation but revokes old approvals", async t => {
  for (const status of ["signed", "submitting", "submitted", "submission_unknown", "superseding"]) await t.test(status, async t => {
    const f = await fixture(t, { config: previous }), id = randomUUID();
    await f.service.send("transfer", args(id));
    if (status === "superseding") {
      const replacement = await f.service.reviewReplacement(id);
      await f.service.replace(id, password, digest(replacement.records[0]));
    }
    const submissionsBefore = f.submissions.length;
    let original;
    await f.store.session(async s => {
      const journal = await Journal.open(s), record = journal.data.records[0];
      record.status = status;
      record.approval = { intentHash: record.intentHash, userOpHash: record.userOpHash, operationDigest: digest(record.operation), expiresAt: Date.now() + 60_000, policyDigest: digest(s.envelope.policy) };
      await journal.save(); original = structuredClone(record);
    });
    const store = new WalletStore(MAINNET, f.deps);
    await approve(store);
    await store.session(async s => {
      const journal = await Journal.open(s), record = journal.data.records[0];
      for (const field of ["requestId", "intent", "intentHash", "status", "operation", "replacement", "userOpHash", "nonce", "reservation", "manifestId"]) assert.deepEqual(record[field], original[field]);
      assert.equal(record.approval, undefined); assert.deepEqual(journal.used(), original.reservation);
      assert.equal(s.envelope.policy.enabled, false);
    });
    const service = new WalletService(new Ctx(MAINNET), store, f.chain, true);
    await assert.rejects(service.send("transfer", args(id)), { code: "wallet_locked" });
    assert.equal(f.submissions.length, submissionsBefore);
    if (status === "submitted") {
      const capabilities = structuredClone(MAINNET);
      capabilities.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
      capabilities.manifest.manifestId = configurationId(capabilities.manifest, "manifestId");
      const changedStore = new WalletStore(capabilities, f.deps), changedReview = await reviewCapabilities(changedStore, MAINNET, capabilities);
      await assert.rejects(approveCapabilities(changedStore, MAINNET, capabilities, password, digest(changedReview)), { code: "operation_pending" });
      f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"44".repeat(32)}` });
      assert.equal((await service.operation(id)).status, "confirmed");
      await store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "1200" }));
      assert.equal(f.submissions.length, 1, "receipt reconciliation does not sign or submit");
    }
    if (status === "submission_unknown") {
      const review = await service.review();
      await service.configure(limits, password, false, digest(review.records));
      const state = f.chain.state;
      f.chain.state = async () => ({ ...await state(), fees: { baseFeePerGas: 2n, maxFeePerGas: 2n, maxPriorityFeePerGas: 1n } });
      await assert.rejects(service.send("transfer", args(id)), { code: "validation_failed" });
      assert.equal(f.submissions.length, 1, "retry revalidates current gas before submitting");
      f.chain.state = state;
      assert.equal((await service.send("transfer", args(id))).status, "submitted");
      assert.deepEqual(f.submissions[1], original.operation, "retry keeps the original signed bytes");
    }
  });
});

test("implementation approval resumes both durable boundaries with the same wallet and disabled policy", async t => {
  for (const point of ["implementation_journal_committed", "implementation_envelope_committed"]) await t.test(point, async t => {
    const f = await fixture(t, { config: previous }), before = await f.store.createOrLoad();
    const crashed = new WalletStore(MAINNET, { ...f.deps, checkpoint: async name => { if (name === point) throw new Error("injected interruption"); } });
    await assert.rejects(approve(crashed));
    const store = new WalletStore(MAINNET, f.deps), result = await approve(store);
    assert.equal(result.wallet_id, before.wallet_id); assert.equal(result.owner, before.owner); assert.equal(result.account, before.account);
    assert.equal(result.policy.enabled, false);
    await store.session(s => Journal.open(s));
    assert.equal((await approve(store)).approval, "already_current");
  });
});

test("unconfigured legacy wallets require initial limits and a new administration password", async t => {
  const f = await fixture(t, { config: previous, existing: true }), before = await f.store.createOrLoad();
  const store = new WalletStore(MAINNET, f.deps), beforeFiles = await snapshot(f.root);
  await assert.rejects(approve(store), { code: "policy_not_configured" });
  await assert.rejects(approve(store, Buffer.from("short"), limits), { code: "policy_denied" });
  assert.deepEqual(await snapshot(f.root), beforeFiles);
  const result = await approve(store, password, limits);
  assert.equal(result.wallet_id, before.wallet_id); assert.equal(result.account, before.account);
  assert.equal(result.policy.configured, true); assert.equal(result.policy.enabled, false); assert.deepEqual(result.policy.limits, limits);
  await store.session(async s => { await authorize(s.envelope.policy, password); assert.equal((await Journal.open(s)).data.records.length, 0); });
});

test("reviewed configuration and authenticated journal are checked before implementation changes", async t => {
  const f = await fixture(t, { config: previous }), store = new WalletStore(MAINNET, f.deps);
  const before = await snapshot(f.root), changedEndpoint = structuredClone(MAINNET);
  changedEndpoint.endpoints.rpcUrls = ["https://rpc.example.test/"];
  await assert.rejects(reviewImplementation(store, changedEndpoint), { code: "policy_denied" });
  const review = await reviewImplementation(store, MAINNET);
  await f.store.session(async s => { const journal = await Journal.open(s); const record = await journal.create(randomUUID(), { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "1", gasToken: "native", to: "0x0000000000000000000000000000000000000002", slippageBps: 0, feeTier: 3000 }); await journal.transition(record, "failed"); });
  const changedFiles = await snapshot(f.root);
  await assert.rejects(approveImplementation(store, MAINNET, password, digest(review)), { code: "policy_denied" });
  assert.deepEqual(await snapshot(f.root), changedFiles);
  assert.deepEqual(changedFiles[0], before[0]);
});

test("target verification failure prevents credential reads and preserves implementation upgrade evidence", async t => {
  const f = await fixture(t, { config: previous, existing: true }), values = new Map(), reads = [];
  let credentialCalls = 0;
  const credentials = {
    read: async name => { reads.push(name); return values.has(name) ? Buffer.from(values.get(name)) : undefined; },
    create: async (name, value) => { assert.equal(values.has(name), false); values.set(name, Buffer.from(value)); },
    remove: async name => { values.get(name)?.fill(0); values.delete(name); },
  };
  t.after(() => { for (const value of values.values()) value.fill(0); });
  const deps = { ...f.deps, allowFileKey: false, credentials: async () => { credentialCalls++; return credentials; } };
  await new WalletStore(previous, deps).initialize(limits, password);
  const review = await reviewImplementation(new WalletStore(MAINNET, deps), MAINNET), before = await snapshot(f.root);
  credentialCalls = 0; reads.length = 0;
  const rejected = new WalletStore(MAINNET, { ...deps, verify: async (config, wallet, scope) => {
    assert.equal(config.identity.networkId, MAINNET.identity.networkId); assert.equal(wallet, undefined); assert.equal(scope, "local");
    throw new NetworkError("wallet_network_mismatch", "Test target implementation is unverified");
  } });
  await assert.rejects(reviewImplementation(rejected, MAINNET), { code: "wallet_network_mismatch" });
  await assert.rejects(approveImplementation(rejected, MAINNET, password, digest(review)), { code: "wallet_network_mismatch" });
  assert.equal(credentialCalls, 0); assert.deepEqual(reads, []);
  assert.deepEqual(await snapshot(f.root), before);
});

test("unconfigured implementation upgrade retries a committed journal with fresh review and chosen administration", async t => {
  const f = await fixture(t, { config: previous, existing: true }), before = await f.store.createOrLoad();
  const beforeEnvelope = (await snapshot(f.root))[0];
  const crashed = new WalletStore(MAINNET, { ...f.deps, checkpoint: async point => { if (point === "implementation_journal_committed") throw new Error("interrupted unconfigured upgrade"); } });
  const firstReview = await reviewImplementation(crashed, MAINNET);
  await assert.rejects(approveImplementation(crashed, MAINNET, password, digest(firstReview), limits), { code: "wallet_recovery_required" });
  const interruptedFiles = await snapshot(f.root);
  assert.deepEqual(interruptedFiles[0], beforeEnvelope); assert.ok(interruptedFiles[1]);
  assert.equal((await f.store.createOrLoad()).policy.configured, false);
  const store = new WalletStore(MAINNET, f.deps), chosenPassword = Buffer.from("PUBLIC_TEST_RETRY_ADMIN_CANARY_2026");
  t.after(() => chosenPassword.fill(0));
  const chosenLimits = { ...limits, maxGasUnits: "1000001" };
  await assert.rejects(approveImplementation(store, MAINNET, chosenPassword, digest(firstReview), chosenLimits), { code: "policy_denied" });
  assert.deepEqual(await snapshot(f.root), interruptedFiles);
  const freshReview = await reviewImplementation(store, MAINNET);
  assert.notEqual(digest(freshReview), digest(firstReview));
  const result = await approveImplementation(store, MAINNET, chosenPassword, digest(freshReview), chosenLimits);
  assert.equal(result.wallet_id, before.wallet_id); assert.equal(result.owner, before.owner); assert.equal(result.account, before.account);
  assert.equal(result.policy.configured, true); assert.equal(result.policy.enabled, false); assert.deepEqual(result.policy.limits, chosenLimits);
  await store.session(async s => {
    await authorize(s.envelope.policy, chosenPassword);
    await assert.rejects(authorize(s.envelope.policy, password), { code: "policy_denied" });
    assert.equal((await Journal.open(s)).data.records.length, 0);
  });
});

test("implementation upgrade resumes complete staged legacy wallets without replacing their keys or evidence", async t => {
  for (const initialized of [true, false]) await t.test(initialized ? "initialized" : "unconfigured", async t => {
    const f = await fixture(t, { config: previous, existing: true });
    const interrupted = new WalletStore(previous, { ...f.deps, checkpoint: async point => { if (point === "keystore_written") throw new Error("interrupted legacy creation"); } });
    await assert.rejects(initialized ? interrupted.initialize(limits, password) : interrupted.createOrLoad(), { code: "wallet_recovery_required" });
    const bindingPath = join(f.root, "wallet.binding.json"), bindingBytes = await readFile(bindingPath), binding = JSON.parse(bindingBytes);
    const staging = join(f.root, `wallet.tmp-${binding.walletId}`), envelopeBytes = await readFile(join(staging, "wallet.json"));
    const envelope = parseEnvelope(JSON.parse(envelopeBytes)), wrappingKey = await readFile(join(staging, "master.key")), ownerKey = unlockWallet(previous, envelope, wrappingKey);
    t.after(() => { wrappingKey.fill(0); ownerKey.fill(0); });
    assert.equal(await exists(join(f.root, "wallet")), false);
    const store = new WalletStore(MAINNET, f.deps), review = await reviewImplementation(store, MAINNET);
    assert.equal(review.wallet.wallet_id, envelope.walletId); assert.equal(review.wallet.owner, envelope.owner); assert.equal(review.wallet.account, envelope.account);
    assert.deepEqual(await readFile(join(f.root, "wallet", "wallet.json")), envelopeBytes, "review resumes the original encrypted wallet before upgrade approval");
    assert.deepEqual(await readFile(bindingPath), bindingBytes);
    assert.equal(await exists(staging), false, "staged evidence is promoted to the committed wallet");
    const result = await approveImplementation(store, MAINNET, password, digest(review), initialized ? undefined : limits);
    assert.equal(result.wallet_id, envelope.walletId); assert.equal(result.owner, envelope.owner); assert.equal(result.account, envelope.account);
    assert.equal(result.policy.configured, true); assert.equal(result.policy.enabled, false);
    await store.session(async s => {
      const upgradedOwner = unlockWallet(MAINNET, s.envelope, s.wrappingKey);
      try { assert.ok(upgradedOwner.equals(ownerKey)); assert.ok(s.wrappingKey.equals(wrappingKey)); }
      finally { upgradedOwner.fill(0); }
      assert.deepEqual(s.envelope.keyStorage, envelope.keyStorage);
      assert.equal((await Journal.open(s)).data.records.length, 0);
      await authorize(s.envelope.policy, password);
    });
    assert.deepEqual(await readFile(bindingPath), bindingBytes);
  });
});
