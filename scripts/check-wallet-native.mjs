// Isolated native custody integration. Never touches ~/.incentiv-mcp or an existing credential service.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { MAINNET } from "../src/config.ts";
import { assertWalletNetwork } from "../src/network.ts";
import { nativeCredentials } from "../src/wallet/credentials.ts";
import { WalletStore, credentialNames } from "../src/wallet/store.ts";
import { Journal } from "../src/wallet/journal.ts";
import { backupWallet, restoreWallet } from "../src/wallet/backup.ts";

const parent = await mkdtemp(join(await realpath(tmpdir()), "incentiv-native-check-"));
const root = join(parent, "state");
const credentials = await nativeCredentials(`io.incentiv.mcp.test.${randomUUID()}`);
const restoredRoot = join(parent, "restored");
const restoredCredentials = await nativeCredentials(`io.incentiv.mcp.test.${randomUUID()}`);
const password = Buffer.from("PUBLIC_DISPOSABLE_NATIVE_TEST_2026");
const recovery = Buffer.from("PUBLIC_DISPOSABLE_RECOVERY_TEST_2026");
const limits = JSON.parse(await readFile(new URL("../docs/wallet-policy.example.json", import.meta.url), "utf8"));
try {
  const store = new WalletStore(MAINNET, { root, allowFileKey: false, credentials: async () => credentials, verify: async (cfg, wallet) => { if (wallet) assertWalletNetwork(cfg, wallet); } });
  const first = await store.initialize(limits, password);
  assert.equal(first.policy.enabled, false);
  assert.equal((await store.createOrLoad()).account, first.account);
  const requestId = randomUUID();
  await store.session(async s => {
    const journal = await Journal.open(s);
    assert.equal(journal.data.records.length, 0);
    const record = await journal.create(requestId, { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "1", gasToken: "native", to: first.account.toLowerCase(), slippageBps: 0, feeTier: 3000 });
    await journal.transition(record, "failed");
    await s.savePolicy({ ...s.envelope.policy, enabled: false });
  });
  await store.disable();
  await store.session(async s => assert.equal(await s.disabled(), true));
  await assert.rejects(store.reviewOrphan(), { code: "wallet_recovery_required" });
  const backup = join(parent, "backup.json");
  await backupWallet(MAINNET, store, backup, password, recovery);
  const restored = new WalletStore(MAINNET, { root: restoredRoot, allowFileKey: false, credentials: async () => restoredCredentials, verify: async (cfg, wallet) => { if (wallet) assertWalletNetwork(cfg, wallet); } });
  await restoreWallet(MAINNET, restored, backup, recovery);
  const loaded = await restored.createOrLoad();
  assert.equal(loaded.account, first.account);
  assert.equal(loaded.owner, first.owner);
  assert.equal(loaded.policy.enabled, false);
  await restored.session(async s => {
    const records = (await Journal.open(s)).data.records;
    assert.equal(records.length, 1);
    assert.equal(records[0].requestId, requestId);
    assert.equal(records[0].status, "failed");
  });
  console.log("Native private filesystem + OS credentials + initialization/load/reseal/journal/disable/backup/restore passed.");
} finally {
  password.fill(0); recovery.fill(0);
  for (const [directory, vault] of [[root, credentials], [restoredRoot, restoredCredentials]]) {
    let binding;
    try { binding = JSON.parse(await readFile(join(directory, "wallet.binding.json"), "utf8")); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (binding) {
      for (const name of [...Object.values(credentialNames(binding)), `commit:${binding.walletId}:${binding.creationToken}`, "wallet-binding-v1"]) await vault.remove(name);
    }
  }
  // parent comes directly from mkdtemp under the resolved system temp directory.
  await rm(parent, { recursive: true, force: true });
}
