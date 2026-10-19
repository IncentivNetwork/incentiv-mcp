import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { fixture, args, limits, password } from "../scripts/wallet-pipeline-fixture.mjs";
import { Journal, digest } from "../src/wallet/journal.ts";
import { backupWallet, restoreWallet, migrateWallet } from "../src/wallet/backup.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { MAINNET } from "../src/config.ts";
import { unlockWallet } from "../src/wallet/keystore.ts";

test("ambiguous broadcast retries identical signed bytes, preserves reservations and lifetime idempotency", async t => {
  const f = await fixture(t), id = randomUUID();
  const relay = f.chain.relay;
  f.chain.relay = async operation => { await relay(operation); throw new Error("SECRET_CANARY lost response"); };
  const first = await f.service.send("transfer", args(id));
  assert.equal(first.status, "submission_unknown");
  f.chain.relay = relay;
  assert.equal((await f.service.send("transfer", args(id))).status, "submitted");
  assert.equal(f.builds(), 1); assert.deepEqual(f.submissions[0], f.submissions[1]);
  await assert.rejects(f.service.send("transfer", { ...args(id), amount: "0.1" }), { code: "idempotency_conflict" });
  await assert.rejects(f.service.send("transfer", args(randomUUID())), { code: "operation_pending" });
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}` });
  const confirmed = await f.service.operation(id);
  assert.equal(confirmed.status, "confirmed");
  assert.equal(confirmed.actual_native_gas_cost_wei, "200");
  assert.equal(confirmed.last_error, undefined);
  assert.equal((await f.service.send("transfer", args(id))).status, "confirmed");
  assert.equal(f.builds(), 1);
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "1200" }));
  const journal = await readFile(join(f.root, "wallet", "operations", "journal.json"), "utf8");
  const key = await readFile(join(f.root, "wallet", "master.key"));
  assert.ok(!journal.includes(key.toString("base64"))); assert.ok(!journal.includes(password.toString()));
  assert.ok(!JSON.stringify(first).includes("SECRET_CANARY"));
  await f.store.session(async s => {
    const ownerKey = unlockWallet(MAINNET, s.envelope, s.wrappingKey);
    try {
      const visible = journal + JSON.stringify(first) + JSON.stringify(f.submissions);
      for (const secret of [ownerKey, s.wrappingKey, password]) for (const encoding of ["hex", "base64", "utf8"]) assert.ok(!visible.includes(secret.toString(encoding)));
    } finally { ownerKey.fill(0); }
  });
});

test("disable prevents new signatures and exact rebroadcast while allowing read-only reconciliation", async t => {
  const f = await fixture(t), id = randomUUID();
  await f.service.send("transfer", args(id)); await f.store.disable();
  await assert.rejects(f.service.send("transfer", args(id)), { code: "wallet_locked" });
  await assert.rejects(f.service.resolve(id, password), { code: "wallet_locked" });
  assert.equal(f.submissions.length, 1);
  f.setReceipt({ success: false, actualGasCost: 150n, transactionHash: `0x${"22".repeat(32)}` });
  const reverted = await f.service.operation(id);
  assert.equal(reverted.status, "reverted");
  assert.equal(reverted.actual_native_gas_cost_wei, "150");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "150" }));
});

test("wallet status exposes reusable EntryPoint gas deposits separately from transferable balance", async t => {
  const f = await fixture(t);
  f.chain.gasDeposit = async () => "123456";
  const status = await f.service.get();
  assert.equal(status.entrypoint_gas_deposit_wei, "123456");
  assert.equal(status.balances.native, "1000000");
  assert.equal(status.spendable_before_new_gas.native, "1000000");
});

test("an expired signed deadline requires explicit same-nonce resolution without a fresh signature", async t => {
  const f = await fixture(t), id = randomUUID();
  await f.service.send("transfer", args(id));
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].deadline = 1; await journal.save(); });
  await assert.rejects(f.service.send("transfer", args(id)), { code: "operation_pending" });
  assert.equal(f.submissions.length, 1); assert.equal(f.builds(), 1);
});

test("policy exceptions bind to the exact reviewed operation and require the separate administration factor", async t => {
  const f = await fixture(t), id = randomUUID();
  const input = { ...args(id), amount: "0.00000000000002" };
  assert.equal((await f.service.send("transfer", input)).status, "approval_required");
  assert.equal(f.submissions.length, 0);
  const review = await f.service.review(id);
  await assert.rejects(f.service.approve(id, Buffer.from("wrong password"), digest(review.records[0])), { code: "policy_denied" });
  await f.service.approve(id, password, digest(review.records[0]));
  assert.equal((await f.service.send("transfer", input)).status, "submitted");
  assert.equal(f.builds(), 1);
});

test("release gate, failed simulation, changed nonce and inadequate gas balance never submit", async t => {
  for (const scenario of ["release", "simulation", "nonce", "balance"]) await t.test(scenario, async t => {
    const f = await fixture(t, { releaseApproved: scenario !== "release" });
    if (scenario === "simulation") f.chain.simulate = async () => { throw new Error("SECRET_CANARY"); };
    if (scenario === "balance") f.chain.balances = async () => ({ native: "1100" });
    if (scenario === "nonce") { const state = f.chain.state; let count = 0; f.chain.state = async () => ({ ...await state(), nonce: count++ ? 1n : 0n }); }
    if (scenario === "release") {
      const prepared = await f.service.send("transfer", args(randomUUID()));
      assert.equal(prepared.status, "approval_required");
      assert.deepEqual(prepared.reasons, ["release_test_approval_required"]);
    } else await assert.rejects(f.service.send("transfer", args(randomUUID())), error => !error.message.includes("SECRET_CANARY"));
    assert.equal(f.submissions.length, 0);
  });
});

test("disable during simulation prevents signing and concurrent sends cannot allocate another nonce", async t => {
  const f = await fixture(t);
  f.chain.simulate = () => f.store.disable();
  await assert.rejects(f.service.send("transfer", args(randomUUID())), { code: "wallet_locked" });
  assert.equal(f.submissions.length, 0);
  const g = await fixture(t);
  const results = await Promise.allSettled([g.service.send("transfer", args(randomUUID())), g.service.send("transfer", args(randomUUID()))]);
  assert.equal(results.filter(r => r.status === "fulfilled").length, 1); assert.equal(g.submissions.length, 1);
});

test("journal tampering and missing history fail closed without overwriting evidence", async t => {
  const f = await fixture(t); await f.service.send("transfer", args(randomUUID()));
  const path = join(f.root, "wallet", "operations", "journal.json");
  const data = JSON.parse(await readFile(path, "utf8")); data.data.records[0].status = "confirmed";
  const corrupt = JSON.stringify(data); await writeFile(path, corrupt);
  await assert.rejects(f.service.send("transfer", args(randomUUID())), { code: "wallet_recovery_required" });
  assert.equal(await readFile(path, "utf8"), corrupt);
});

test("reviewed same-nonce replacement retains reservations until its receipt and cannot resend the original", async t => {
  const f = await fixture(t), id = randomUUID();
  await f.service.send("transfer", args(id));
  const review = await f.service.reviewReplacement(id);
  const record = review.records[0];
  assert.equal(record.replacement.operation.nonce, record.operation.nonce);
  await assert.rejects(f.service.replace(id, Buffer.from("incorrect admin"), digest(record)), { code: "policy_denied" });
  const replaced = await f.service.replace(id, password, digest(record));
  assert.equal(replaced.status, "superseding");
  assert.equal(f.submissions.length, 2);
  assert.notEqual(f.submissions[0].callData, f.submissions[1].callData);
  await f.service.send("transfer", args(id));
  assert.deepEqual(f.submissions[1], f.submissions[2]);
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "1900" }));
  f.chain.receipt = async r => r.userOpHash === record.replacement.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"44".repeat(32)}` } : undefined;
  assert.equal((await f.service.operation(id)).status, "superseded");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "400" }));
  assert.equal((await f.service.send("transfer", args(id))).status, "superseded");
  assert.equal(f.submissions.length, 3);
});

test("encrypted backup restores identity, spend history and request IDs, starts disabled and refuses overwrite", async t => {
  const f = await fixture(t), id = randomUUID(), recovery = Buffer.from("PUBLIC_RECOVERY_CANARY_2026");
  await f.service.send("transfer", args(id));
  const out = join(f.parent, "backup.json");
  await assert.rejects(backupWallet(MAINNET, f.store, out, password, recovery), { code: "operation_pending" });
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"33".repeat(32)}` }); await f.service.operation(id);
  await backupWallet(MAINNET, f.store, out, password, recovery);
  const encrypted = await readFile(out, "utf8"); assert.ok(!encrypted.includes(recovery.toString())); assert.ok(!encrypted.includes(password.toString())); assert.ok(!encrypted.includes(id));
  const restored = new WalletStore(MAINNET, { ...f.deps, root: join(f.parent, "restored") });
  await assert.rejects(restoreWallet(MAINNET, restored, out, Buffer.from("incorrect recovery")), { code: "backup_authentication_failed" });
  const result = await restoreWallet(MAINNET, restored, out, recovery);
  assert.equal(result.account, (await f.service.get()).account);
  await restored.session(async s => {
    assert.equal(s.envelope.policy.enabled, false); assert.equal(s.envelope.policy.restored, true); assert.equal(await s.disabled(), true);
    const journal = await Journal.open(s); assert.equal(journal.data.records[0].requestId, id); assert.deepEqual(journal.used(), { native: "1200" });
  });
  await assert.rejects(restoreWallet(MAINNET, restored, out, recovery), { code: "wallet_recovery_required" });
  const restoredService = new (await import("../src/wallet/service.ts")).WalletService(f.service.ctx, restored, f.chain, true);
  const review = await restoredService.review();
  await assert.rejects(restoredService.configure(limits, password, false, digest(review.records)), { code: "policy_denied" });
  await restoredService.configure(limits, password, true, digest(review.records));
  assert.equal((await restoredService.get()).policy.enabled, true);
  const original = await readFile(join(f.root, "wallet", "wallet.json"));
  await assert.rejects(migrateWallet(f.store, 2), { code: "unsupported_wallet_version" });
  assert.deepEqual(await readFile(join(f.root, "wallet", "wallet.json")), original);
  assert.equal((await migrateWallet(f.store, 1)).status, "already_current");
});
