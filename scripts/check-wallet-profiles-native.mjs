// Real local factory and native credentials, exclusively in unique disposable profiles.
import assert from "node:assert/strict";
import { randomUUID } from "node:crypto";
import { lstat, mkdtemp, readFile, realpath, rm } from "node:fs/promises";
import { homedir, tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { loadConfig } from "../src/config.ts";
import { walletProfile } from "../src/wallet-profile.ts";
import { nativeCredentials } from "../src/wallet/credentials.ts";
import { credentialNames, localWalletStore } from "../src/wallet/store.ts";
import { backupWallet, restoreWallet } from "../src/wallet/backup.ts";
import { authorize } from "../src/wallet/policy.ts";

const stem = `nativecheck-${randomUUID().replaceAll("-", "").slice(0, 12)}`;
const locations = ["a", "b", "r"].map(suffix => walletProfile(`${stem}${suffix}`));
for (const location of locations) {
  assert.equal(dirname(resolve(location.root)), resolve(homedir()));
  assert.ok(location.root.endsWith(`.incentiv-mcp-profile-${location.name}`));
  await assert.rejects(lstat(location.root), { code: "ENOENT" });
}
const temporary = await mkdtemp(join(await realpath(tmpdir()), "incentiv-profile-backup-"));
const password = Buffer.from("PUBLIC_DISPOSABLE_PROFILE_ADMIN_2026");
const recovery = Buffer.from("PUBLIC_DISPOSABLE_PROFILE_RECOVERY_2026");
const config = loadConfig();
const limits = JSON.parse(await readFile(new URL("../docs/wallet-policy.example.json", import.meta.url), "utf8"));
const stores = locations.map(location => localWalletStore(config, location.name));
try {
  console.log("Native profiles: initialize first disabled wallet.");
  const first = await stores[0].initialize(limits, password);
  console.log("Native profiles: initialize second disabled wallet.");
  const second = await stores[1].initialize(limits, password);
  assert.notEqual(first.account, second.account);
  for (const [index, expected] of [[0, first], [1, second]]) {
    console.log(`Native profiles: reload and authenticate wallet ${index + 1}.`);
    const reloaded = await localWalletStore(config, locations[index].name).createOrLoad();
    assert.equal(reloaded.account, expected.account);
    assert.equal(reloaded.policy.enabled, false);
    await stores[index].session(s => authorize(s.envelope.policy, password));
  }
  const backup = join(temporary, "backup.json");
  console.log("Native profiles: write and reload encrypted backup.");
  await backupWallet(config, stores[0], backup, password, recovery);
  console.log("Native profiles: restore disabled copy into third profile.");
  await restoreWallet(config, stores[2], backup, recovery);
  console.log("Native profiles: authenticate restored copy and recheck the separate wallet.");
  const restored = await stores[2].createOrLoad();
  assert.equal(restored.account, first.account);
  assert.equal(restored.policy.enabled, false);
  await stores[2].session(s => authorize(s.envelope.policy, password));
  assert.equal((await stores[1].createOrLoad()).account, second.account);
  console.log("Passed: two isolated native profiles, new-store reloads, administration authentication, encrypted backup and disabled restore into a third profile. No funded wallet accessed.");
} finally {
  password.fill(0); recovery.fill(0);
  for (const location of locations) {
    // Only the unique, validated, previously absent test profiles above may be removed.
    assert.equal(dirname(resolve(location.root)), resolve(homedir()));
    assert.ok(location.name.startsWith(stem) && location.name !== "default");
    const vault = await nativeCredentials(location.credentialService);
    let binding;
    try { binding = JSON.parse(await readFile(join(location.root, "wallet.binding.json"), "utf8")); }
    catch (error) { if (error.code !== "ENOENT") throw error; }
    if (binding) for (const name of [...Object.values(credentialNames(binding)), `commit:${binding.walletId}:${binding.creationToken}`, "wallet-binding-v1"]) await vault.remove(name);
    await rm(location.root, { recursive: true, force: true });
  }
  // The exact parent returned by mkdtemp, under the resolved system temp directory.
  assert.ok(temporary.startsWith(join(await realpath(tmpdir()), "incentiv-profile-backup-")));
  await rm(temporary, { recursive: true, force: true });
}
