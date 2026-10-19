import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { fixture, args, password } from "../scripts/wallet-pipeline-fixture.mjs";
import { Journal, digest } from "../src/wallet/journal.ts";

async function approve(f, id) {
  const review = await f.service.review(id);
  await f.service.approve(id, password, digest(review.records[0]), true);
}
async function edit(f, change) {
  await f.store.session(async s => {
    const journal = await Journal.open(s);
    await change(journal.data.records, s);
    await journal.save();
  });
}

test("funded test signs one reviewed transfer while the general release gate remains closed", async t => {
  const f = await fixture(t, { releaseApproved: false }), id = randomUUID();
  const pending = await f.service.send("transfer", args(id));
  assert.equal(pending.status, "approval_required");
  assert.deepEqual(pending.reasons, ["release_test_approval_required"]);
  let review = await f.service.review(id);
  assert.equal(review.records[0].operation.signature, "0x");
  await assert.rejects(f.service.approve(id, password, digest(review.records[0])), { code: "wallet_release_unreviewed" });
  await assert.rejects(f.service.approve(id, Buffer.from("incorrect password"), digest(review.records[0]), true), { code: "policy_denied" });
  assert.equal(f.submissions.length, 0);
  await approve(f, id);
  // Reopening the local review must never sign an existing approved request.
  assert.equal((await f.service.send("transfer", args(id), true)).status, "approval_required");
  assert.equal(f.submissions.length, 0);
  assert.equal((await f.service.send("transfer", args(id))).status, "submitted");
  assert.equal(f.builds(), 1);
  assert.notEqual(f.submissions[0].signature, "0x");
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"77".repeat(32)}` });
  const confirmed = await f.service.operation(id);
  assert.equal(confirmed.status, "confirmed");
  assert.equal(confirmed.reasons, undefined);
  assert.equal(confirmed.actual_native_gas_cost_wei, "200");
  assert.equal((await f.service.send("transfer", args(id))).status, "confirmed");
  assert.equal(f.submissions.length, 1);
  f.setReceipt(undefined);
  const other = await f.service.send("transfer", args(randomUUID()));
  assert.equal(other.status, "approval_required");
  assert.equal((await f.service.get()).release_approved, false);
  assert.equal(f.submissions.length, 1);
});

test("live test approval cannot be copied, changed, expired, or used after a policy change", async t => {
  for (const scenario of ["request", "gas", "recipient", "amount", "expired", "policy", "disable"]) await t.test(scenario, async t => {
    const f = await fixture(t, { releaseApproved: false }), id = randomUUID();
    await f.service.send("transfer", args(id)); await approve(f, id);
    if (scenario === "request") await edit(f, records => { records[0].approval.liveTest.requestId = randomUUID(); });
    if (scenario === "gas") await edit(f, records => { records[0].operation.maxFeePerGas = "0x2"; });
    if (scenario === "recipient") await edit(f, records => { records[0].intent.to = "0x0000000000000000000000000000000000000003"; records[0].intentHash = digest(records[0].intent); });
    if (scenario === "amount") await edit(f, records => { records[0].intent.amount = "1001"; records[0].intentHash = digest(records[0].intent); });
    if (scenario === "expired") await edit(f, records => { records[0].approval.expiresAt = 1; });
    if (scenario === "policy") await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, maxGasUnits: "999999" } }));
    if (scenario === "disable") await f.store.disable();
    await f.service.send("transfer", args(id)).catch(() => {});
    assert.equal(f.submissions.length, 0);
    const review = await f.service.review(id);
    assert.equal(review.records[0].operation.signature, "0x");
  });
});

test("funded approval cannot override spending limits, simulation, or a stale review", async t => {
  for (const scenario of ["limit", "simulation", "review", "balance", "nonce"]) await t.test(scenario, async t => {
    const f = await fixture(t, { releaseApproved: false }), id = randomUUID();
    const input = scenario === "limit" ? { ...args(id), amount: "0.00000000000002" } : args(id);
    await f.service.send("transfer", input);
    const review = await f.service.review(id);
    if (scenario === "simulation") f.chain.simulate = async () => { throw new Error("simulation failed"); };
    if (scenario === "balance") f.chain.balances = async () => ({ native: "1000" });
    if (scenario === "nonce") { const state = f.chain.state; f.chain.state = async () => ({ ...await state(), nonce: 1n }); }
    await assert.rejects(f.service.approve(id, password, scenario === "review" ? digest({}) : digest(review.records[0]), true));
    assert.equal(f.submissions.length, 0);
    assert.equal((await f.service.review(id)).records[0].approval, undefined);
  });
});

test("test retry retains exact signed bytes, needs fresh approval after expiry, and cannot authorize a replacement", async t => {
  const f = await fixture(t, { releaseApproved: false }), id = randomUUID(), relay = f.chain.relay;
  await f.service.send("transfer", args(id)); await approve(f, id);
  f.chain.relay = async wire => { await relay(wire); throw new Error("lost response"); };
  assert.equal((await f.service.send("transfer", args(id))).status, "submission_unknown");
  await edit(f, records => { records[0].approval.expiresAt = 1; });
  await assert.rejects(f.service.send("transfer", args(id)), { code: "wallet_release_unreviewed" });
  assert.equal(f.submissions.length, 1);
  await approve(f, id);
  assert.equal((await f.service.send("transfer", args(id), true)).status, "submission_unknown");
  assert.equal(f.submissions.length, 1);
  f.chain.relay = relay;
  assert.equal((await f.service.send("transfer", args(id))).status, "submitted");
  assert.deepEqual(f.submissions[0], f.submissions[1]);
  assert.equal(f.builds(), 1);
  await assert.rejects(f.service.send("transfer", { ...args(id), to: "0x0000000000000000000000000000000000000003" }), { code: "idempotency_conflict" });
  const review = await f.service.reviewReplacement(id);
  await assert.rejects(f.service.replace(id, password, digest(review.records[0])), { code: "wallet_release_unreviewed" });
  assert.equal(f.submissions.length, 2);
});

test("live test fails closed when policy is tightened between approval and signing", async t => {
  const f = await fixture(t, { releaseApproved: false }), id = randomUUID();
  await f.service.send("transfer", args(id)); await approve(f, id);
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, maxGasCostWei: "1" } }));
  const result = await f.service.send("transfer", args(id));
  assert.equal(result.status, "approval_required");
  assert.ok(result.reasons.includes("gas_limit"));
  assert.equal(f.submissions.length, 0);
  assert.equal((await f.service.review(id)).records[0].approval, undefined);
});
