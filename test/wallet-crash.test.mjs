import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, utimes } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fixture, args } from "../scripts/wallet-pipeline-fixture.mjs";
import { canonicalJson } from "../src/config.ts";

test("process death at journal commits or after relay acceptance never produces a second operation", async t => {
  const states = ["preparing", "approval_required", "failed", "signed", "submitting", "submission_unknown", "submitted", "confirmed", "reverted"];
  const boundaries = [...states, "relay_accepted", ...states.flatMap(status => ["temporary_flushed", "renamed", "directory_flushed"].map(point => `journal_${status}:${point}`))];
  for (const boundary of boundaries) await t.test(boundary, async t => {
    const f = await fixture(t), id = randomUUID();
    const output = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../scripts/wallet-send-worker.mjs", import.meta.url)), f.root, id, boundary], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      let text = ""; child.stdout.on("data", b => { text += b; }); child.stderr.on("data", b => { text += b; }); child.on("error", reject); child.on("exit", code => resolve({ code, text }));
    });
    assert.equal(output.code, 73, output.text);
    assert.ok(!output.text.includes("PUBLIC_TEST_ADMIN_CANARY"));
    const lockPath = join(f.root, "wallet.create.lock");
    const old = new Date(Date.now() - 120_000); await utimes(lockPath, old, old);
    const accepted = await readFile(join(f.parent, "relay.jsonl"), "utf8").catch(() => "");
    const before = accepted.trim() ? accepted.trim().split("\n").map(JSON.parse) : [];
    const input = args(id);
    if (boundary.includes("approval_required")) input.amount = "0.00000000000002";
    const result = await f.service.send("transfer", input);
    assert.ok(["submitted", "submission_unknown", "approval_required", "failed", "confirmed", "reverted"].includes(result.status));
    if (before.length && f.submissions.length) assert.deepEqual(f.submissions[0], before[0]);
    const all = [...before, ...f.submissions];
    assert.ok(new Set(all.map(canonicalJson)).size <= 1);
    if (!boundary.includes("approval_required") && !boundary.includes("failed")) assert.ok(all.length > 0);
    await f.store.session(async s => {
      const { Journal } = await import("../src/wallet/journal.ts");
      const journal = await Journal.open(s); assert.equal(journal.data.records.length, 1); assert.equal(journal.data.records[0].requestId, id);
    });
  });
});
