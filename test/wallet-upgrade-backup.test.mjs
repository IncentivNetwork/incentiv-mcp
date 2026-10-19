import assert from "node:assert/strict";
import test from "node:test";
import { createHash, randomUUID } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { MAINNET } from "../src/config.ts";
import { previousImplementationConfig } from "../src/account-upgrade.ts";
import { assertWalletNetwork } from "../src/network.ts";
import { backupWallet, restoreWallet, reviewImplementationBackup } from "../src/wallet/backup.ts";
import { exists } from "../src/wallet/files.ts";
import { digest, Journal } from "../src/wallet/journal.ts";
import { unlockWallet } from "../src/wallet/keystore.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { fixture, limits, password, recipient } from "../scripts/wallet-pipeline-fixture.mjs";

const recovery = Buffer.from("PUBLIC_TEST_RECOVERY_UPGRADE_2026");
const intent = { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "1000", gasToken: "native", to: recipient, slippageBps: 0, feeTier: 3000 };

async function oldBackup(t) {
  const f = await fixture(t, { existing: true });
  const previous = previousImplementationConfig(MAINNET);
  const store = new WalletStore(previous, f.deps);
  const wallet = await store.initialize(limits, password);
  const ids = [randomUUID(), randomUUID(), randomUUID()];
  await store.session(async s => {
    const journal = await Journal.open(s);
    const confirmed = await journal.create(ids[0], intent);
    confirmed.status = "confirmed";
    confirmed.consumed = { native: "1200" };
    confirmed.consumedAt = Date.now();
    await journal.create(ids[1], intent);
    const pending = await journal.create(ids[2], intent);
    pending.status = "approval_required";
    pending.approval = { intentHash: pending.intentHash, userOpHash: digest("operation"), operationDigest: digest("operation"), expiresAt: Date.now() + 300_000 };
    await journal.save();
  });
  const out = join(f.parent, "previous-backup.json");
  await backupWallet(previous, store, out, password, recovery);
  return { ...f, previous, store, wallet, ids, out };
}

async function ownerKeyDigest(store, config) {
  return store.session(async s => {
    const key = unlockWallet(config, s.envelope, s.wrappingKey);
    try { return createHash("sha256").update(key).digest("hex"); }
    finally { key.fill(0); }
  });
}

test("old backups require explicit current review, recovery and administration before restoring an implementation upgrade", async t => {
  const f = await oldBackup(t), root = join(f.parent, "restored");
  const restored = new WalletStore(MAINNET, { ...f.deps, root });
  const original = await readFile(f.out, "utf8");
  await assert.rejects(restoreWallet(MAINNET, restored, f.out, recovery), { code: "backup_authentication_failed" });
  await assert.rejects(reviewImplementationBackup(MAINNET, f.out, Buffer.from("incorrect recovery")), { code: "backup_authentication_failed" });
  const review = await reviewImplementationBackup(MAINNET, f.out, recovery);
  assert.deepEqual(await reviewImplementationBackup(MAINNET, f.out, recovery), review);
  const upgrade = { administration: password, reviewedDigest: digest(review) };
  await assert.rejects(restoreWallet(MAINNET, restored, f.out, Buffer.from("incorrect recovery"), upgrade), { code: "backup_authentication_failed" });
  await assert.rejects(restoreWallet(MAINNET, restored, f.out, recovery, { ...upgrade, administration: Buffer.from("incorrect administration") }), { code: "policy_denied" });
  await assert.rejects(restoreWallet(MAINNET, restored, f.out, recovery, { ...upgrade, reviewedDigest: digest({ stale: true }) }), { code: "policy_denied" });
  assert.equal(await exists(root), false);
  assert.equal(await readFile(f.out, "utf8"), original);

  const result = await restoreWallet(MAINNET, restored, f.out, recovery, upgrade);
  assert.equal(result.account, f.wallet.account);
  assert.equal(result.owner, f.wallet.owner);
  assert.equal(result.wallet_id, f.wallet.wallet_id);
  assert.equal(result.network_id, MAINNET.identity.networkId);
  assert.equal(result.manifest_id, MAINNET.manifest.manifestId);
  assert.equal(result.policy.enabled, false);
  assert.equal(await exists(join(root, "wallet", "disabled")), true);
  assert.equal(await ownerKeyDigest(restored, MAINNET), await ownerKeyDigest(f.store, f.previous));
  await restored.session(async s => {
    assertWalletNetwork(MAINNET, s.envelope);
    assert.equal(s.envelope.policy.restored, true);
    const journal = await Journal.open(s);
    assert.deepEqual(journal.used(), { native: "1200" });
    assert.deepEqual(journal.data.records.map(r => r.requestId), f.ids);
    assert.deepEqual(journal.data.records.map(r => r.status), ["confirmed", "cancelled", "cancelled"]);
    assert.ok(journal.data.records.every(r => !r.approval));
    assert.ok(journal.data.records.every(r => r.manifestId === f.previous.manifest.manifestId));
    assert.ok(journal.data.approvedNetworkIds.includes(MAINNET.identity.networkId));
    assert.ok(journal.data.approvedManifestIds.includes(MAINNET.manifest.manifestId));
    const key = unlockWallet(MAINNET, s.envelope, s.wrappingKey);
    try {
      const visible = JSON.stringify(review) + JSON.stringify(result);
      for (const secret of [key, s.wrappingKey, password, recovery]) for (const encoding of ["hex", "base64", "utf8"]) assert.ok(!visible.includes(secret.toString(encoding)));
    } finally { key.fill(0); }
  });

  // The upgraded identity remains restorable through the ordinary backup path.
  const nextBackup = join(f.parent, "current-backup.json");
  await backupWallet(MAINNET, restored, nextBackup, password, recovery);
  const second = new WalletStore(MAINNET, { ...f.deps, root: join(f.parent, "restored-again") });
  assert.equal((await restoreWallet(MAINNET, second, nextBackup, recovery)).account, f.wallet.account);
  await second.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "1200" }));
  await assert.rejects(reviewImplementationBackup(MAINNET, nextBackup, recovery), { code: "backup_authentication_failed" });
});

test("an old backup changed after review is rejected without creating a wallet", async t => {
  const f = await oldBackup(t), root = join(f.parent, "restored");
  const review = await reviewImplementationBackup(MAINNET, f.out, recovery);
  await f.store.session(async s => {
    const journal = await Journal.open(s);
    const record = await journal.create(randomUUID(), intent);
    await journal.transition(record, "failed");
  });
  const changed = join(f.parent, "changed-backup.json");
  await backupWallet(f.previous, f.store, changed, password, recovery);
  const restored = new WalletStore(MAINNET, { ...f.deps, root });
  await assert.rejects(restoreWallet(MAINNET, restored, changed, recovery, { administration: password, reviewedDigest: digest(review) }), { code: "policy_denied" });
  assert.equal(await exists(root), false);
});
