import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { readFile, utimes } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { fixture, args } from "../scripts/wallet-pipeline-fixture.mjs";
import { canonicalJson } from "../src/config.ts";
import { Journal } from "../src/wallet/journal.ts";

test("process death during replacement, cancellation and expiry preserves exact retry and nonce ownership", async t => {
  const states = ["superseding", "superseded", "cancelled", "expired"];
  const boundaries = [...states, "replacement_relay_accepted", ...states.flatMap(status => ["temporary_flushed", "renamed", "directory_flushed"].map(point => `journal_${status}:${point}`))];
  for (const boundary of boundaries) await t.test(boundary, async t => {
    const f = await fixture(t), id = randomUUID();
    const output = await new Promise((resolve, reject) => {
      const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../scripts/wallet-send-worker.mjs", import.meta.url)), f.root, id, boundary], { stdio: ["ignore", "pipe", "pipe"], windowsHide: true });
      let text = ""; child.stdout.on("data", b => { text += b; }); child.stderr.on("data", b => { text += b; }); child.on("error", reject); child.on("exit", code => resolve({ code, text }));
    });
    assert.equal(output.code, 73, output.text);
    assert.ok(!output.text.includes(passwordCanary));
    const old = new Date(Date.now() - 120_000); await utimes(join(f.root, "wallet.create.lock"), old, old);
    const accepted = await readFile(join(f.parent, "relay.jsonl"), "utf8").catch(() => "");
    const before = accepted.trim() ? accepted.trim().split("\n").map(JSON.parse) : [];
    const unsigned = boundary.includes("expired") || boundary.includes("cancelled");
    const input = { ...args(id), ...(unsigned ? { amount: "0.00000000000002" } : {}) };
    const result = await f.service.send("transfer", input);
    assert.ok(["approval_required", "expired", "cancelled", "submitted", "submission_unknown", "superseding", "superseded"].includes(result.status));
    await f.store.session(async s => {
      const journal = await Journal.open(s), record = journal.data.records[0];
      assert.equal(journal.data.records.length, 1); assert.equal(record.requestId, id);
      const all = [...before, ...f.submissions];
      if (unsigned) assert.equal(all.length, 0);
      else {
        const original = canonicalJson(record.operation), replacement = canonicalJson(record.replacement.operation);
        assert.notEqual(original, replacement);
        assert.equal(record.operation.nonce, record.replacement.operation.nonce);
        assert.ok(all.every(op => [original, replacement].includes(canonicalJson(op))));
        assert.ok(f.submissions.every(op => canonicalJson(op) === (record.replacement.signed ? replacement : original)));
        assert.deepEqual(journal.used(), { native: result.status === "superseded" ? "400" : record.replacement.signed ? "1900" : "1300" });
      }
    });
  });
});
const passwordCanary = "PUBLIC_TEST_ADMIN_CANARY";
