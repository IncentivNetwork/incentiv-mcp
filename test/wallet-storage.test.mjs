import assert from "node:assert/strict";
import test from "node:test";
import { spawn } from "node:child_process";
import { randomUUID } from "node:crypto";
import { chmod, link, mkdtemp, readFile, readdir, realpath, rm, symlink, unlink, utimes, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { MAINNET, configurationId } from "../src/config.ts";
import { assertWalletNetwork, NetworkError } from "../src/network.ts";
import { credentialNames, WalletStore } from "../src/wallet/store.ts";
import { WalletError } from "../src/wallet/keystore.ts";
import { exists, privateDirectory, verifyTree, writeNew } from "../src/wallet/files.ts";
import { creationLock } from "../src/wallet/lock.ts";

async function fixture(t, file = false) {
  const parent = await mkdtemp(join(await realpath(tmpdir()), "incentiv-wallet-test-"));
  const root = join(parent, "state");
  const values = new Map();
  const reads = [];
  const credentials = {
    read: async (name) => { reads.push(name); return values.has(name) ? Buffer.from(values.get(name)) : undefined; },
    create: async (name, value) => { assert.equal(values.has(name), false, "must never replace credentials"); values.set(name, Buffer.from(value)); },
    remove: async (name) => { values.get(name)?.fill(0); values.delete(name); },
  };
  const deps = {
    root, allowFileKey: file, credentials: async () => credentials, lockTimeoutMs: 10_000,
    verify: async (cfg, wallet) => { if (wallet) assertWalletNetwork(cfg, wallet); },
  };
  t.after(async () => { for (const value of values.values()) value.fill(0); await rm(parent, { recursive: true, force: true }); });
  return { root, parent, values, reads, deps, store: (overrides = {}, cfg = MAINNET) => new WalletStore(cfg, { ...deps, ...overrides }) };
}
const json = async (path) => JSON.parse(await readFile(path, "utf8"));

test("OS-backed creation is idempotent, promotes credentials and rebuilds the untrusted public cache", async (t) => {
  const f = await fixture(t);
  const first = await f.store({ checkpoint: async (point) => {
    if (point === "binding_written") {
      const binding = await json(join(f.root, "wallet.binding.json"));
      const lock = await json(join(f.root, "wallet.create.lock"));
      assert.equal(binding.creationToken, lock.token);
    }
  } }).createOrLoad();
  const keystore = join(f.root, "wallet", "wallet.json");
  const original = await readFile(keystore, "utf8");
  const binding = await json(join(f.root, "wallet.binding.json"));
  const names = credentialNames(binding);
  assert.equal(first.status, "locked");
  assert.equal(first.reason, "policy_not_configured");
  assert.deepEqual(first.policy, { schemaVersion: 1, enabled: false, configured: false });
  assert.deepEqual([...f.values.keys()].sort(), ["wallet-binding-v1", names.committed].sort());
  assert.equal(await exists(join(f.root, "wallet", "master.key")), false);
  await writeFile(join(f.root, "wallet", "public.json"), '{"account":"attacker","status":"ready"}');
  assert.deepEqual(await f.store().createOrLoad(), first);
  assert.deepEqual(await json(join(f.root, "wallet", "public.json")), first);
  assert.equal(await readFile(keystore, "utf8"), original);
  for (const secret of f.values.values()) {
    if (secret.length === 32) assert.equal(original.includes(secret.toString("base64")), false);
  }
  assert.equal(await exists(join(f.root, "wallet.create.lock")), false);
  await verifyTree(f.root);
});

test("explicit file fallback is required on every load and never replaces a missing key", async (t) => {
  const f = await fixture(t, true);
  const unavailable = async () => { throw new WalletError("wallet_locked", "Credential service unavailable"); };
  const first = await f.store({ credentials: unavailable }).createOrLoad();
  assert.match(first.warning, /copying the wallet directory/);
  const path = join(f.root, "wallet", "master.key");
  const original = await readFile(path);
  assert.equal(original.length, 32);
  assert.deepEqual(await f.store().createOrLoad(), first);
  assert.deepEqual(await readFile(path), original);
  original.fill(0);
  await assert.rejects(f.store({ allowFileKey: false }).createOrLoad(), { code: "file_key_not_allowed" });
  await unlink(path);
  await assert.rejects(f.store().createOrLoad(), { code: "wrapping_key_missing" });
  assert.equal(await exists(path), false);
});

test("network/manifest rejection happens before unlocking an existing wallet", async (t) => {
  const f = await fixture(t);
  await f.store().createOrLoad();
  f.reads.length = 0;
  const otherNetwork = structuredClone(MAINNET);
  otherNetwork.identity.genesisHash = `0x${"12".repeat(32)}`;
  otherNetwork.identity.networkId = configurationId(otherNetwork.identity, "networkId");
  otherNetwork.manifest.networkId = otherNetwork.identity.networkId;
  otherNetwork.manifest.manifestId = configurationId(otherNetwork.manifest, "manifestId");
  await assert.rejects(f.store({}, otherNetwork).createOrLoad(), { code: "wallet_network_mismatch" });
  const otherManifest = structuredClone(MAINNET);
  otherManifest.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
  otherManifest.manifest.manifestId = configurationId(otherManifest.manifest, "manifestId");
  await assert.rejects(f.store({}, otherManifest).createOrLoad(), { code: "capability_manifest_unapproved" });
  await assert.rejects(f.store({ verify: async () => { throw new NetworkError("network_verification_failed", "Rejected"); } }).createOrLoad(), { code: "network_verification_failed" });
  assert.deepEqual(f.reads, []);
});

test("failed initial verification leaves no wallet or creation binding", async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.store({ verify: async () => { throw new NetworkError("network_verification_failed", "Rejected"); } }).createOrLoad(), { code: "network_verification_failed" });
  assert.deepEqual(await readdir(f.root), []);
  assert.equal(f.values.size, 0);
});

test("incomplete, corrupt and unsupported keystores are preserved with distinct errors", async (t) => {
  const f = await fixture(t);
  await f.store().createOrLoad();
  const path = join(f.root, "wallet", "wallet.json");
  const original = await readFile(path, "utf8");
  for (const [contents, code] of [
    ["{broken", "wallet_recovery_required"],
    [JSON.stringify({ ...JSON.parse(original), schemaVersion: 2 }), "unsupported_wallet_version"],
    [JSON.stringify({ ...JSON.parse(original), owner: "0x0000000000000000000000000000000000000001" }), "keystore_authentication_failed"],
  ]) {
    await writeFile(path, contents);
    await assert.rejects(f.store().createOrLoad(), { code });
    assert.equal(await readFile(path, "utf8"), contents);
  }
  await unlink(path);
  await assert.rejects(f.store().createOrLoad(), { code: "keystore_missing" });
  assert.equal(await exists(path), false);
});

test("missing/disagreeing credentials and lost filesystem state never select a replacement wallet", async (t) => {
  const f = await fixture(t);
  await f.store().createOrLoad();
  const binding = await json(join(f.root, "wallet.binding.json"));
  const names = credentialNames(binding);
  const original = f.values.get(names.committed);
  f.values.set(names.pending, Buffer.alloc(32));
  await assert.rejects(f.store().createOrLoad(), { code: "wallet_recovery_required" });
  f.values.delete(names.pending);
  f.values.delete(names.committed);
  await assert.rejects(f.store().createOrLoad(), { code: "wrapping_key_missing" });
  f.values.set(names.committed, original);
  await rm(f.root, { recursive: true });
  for (const allowFileKey of [false, true]) {
    await assert.rejects(f.store({ allowFileKey }).createOrLoad(), { code: "wallet_recovery_required" });
    assert.equal(await exists(join(f.root, "wallet.binding.json")), false);
    assert.equal(f.values.get(names.committed), original);
  }
});

test("failures at each creation boundary preserve evidence or resume the same wallet", async (t) => {
  const points = ["binding_written", "credential_anchor_written", "pending_credential_written", "staging_created", "file_key_written", "keystore_written", "operations_created", "wallet_authenticated", "wallet_committed", "credential_promoted", "committed_wallet_verified", "pending_credential_removed", "public_cache_written"];
  for (const point of points) await t.test(point, async (t) => {
    const f = await fixture(t, point === "file_key_written");
    let hit = false;
    await assert.rejects(f.store({ checkpoint: async (p) => {
      if (p === point) { hit = true; throw new Error("SECRET_CANARY: must never escape storage errors"); }
    } }).createOrLoad(), (e) => e.code === "wallet_recovery_required" && !e.message.includes("SECRET_CANARY"));
    assert.equal(hit, true);
    const binding = await json(join(f.root, "wallet.binding.json"));
    const directory = await exists(join(f.root, "wallet")) ? join(f.root, "wallet") : join(f.root, `wallet.tmp-${binding.walletId}`);
    const path = join(directory, "wallet.json");
    if (await exists(path)) {
      const before = await readFile(path, "utf8");
      const result = await f.store().createOrLoad();
      assert.equal(result.wallet_id, binding.walletId);
      assert.equal(result.account, JSON.parse(before).account);
      assert.equal(await readFile(join(f.root, "wallet", "wallet.json"), "utf8"), before);
    } else {
      const names = [...f.values.keys()].sort();
      await assert.rejects(f.store().createOrLoad(), { code: "keystore_missing" });
      assert.deepEqual([...f.values.keys()].sort(), names);
    }
    assert.deepEqual(await json(join(f.root, "wallet.binding.json")), binding);
  });
});

test("symlinks/junctions, hard links and permissive POSIX files are rejected", async (t) => {
  const f = await fixture(t, true);
  const destination = join(f.parent, "elsewhere");
  await privateDirectory(destination);
  await symlink(destination, f.root, process.platform === "win32" ? "junction" : "dir");
  await assert.rejects(f.store().createOrLoad(), { code: "wallet_path_unsafe" });
  assert.deepEqual(await readdir(destination), []);
  await unlink(f.root);
  await f.store().createOrLoad();
  const path = join(f.root, "wallet", "wallet.json");
  const alias = join(f.parent, "alias.json");
  await link(path, alias);
  await assert.rejects(f.store().createOrLoad(), { code: "wallet_path_unsafe" });
  await unlink(alias);
  if (process.platform !== "win32") {
    await chmod(path, 0o644);
    await assert.rejects(f.store().createOrLoad(), { code: "wallet_permissions_invalid" });
  }
});

test("a stale timestamp does not authorize stealing a live process's creation lock", async (t) => {
  const f = await fixture(t);
  await privateDirectory(f.root);
  const lock = await creationLock(f.root);
  try {
    const old = new Date(Date.now() - 120_000);
    await utimes(join(f.root, "wallet.create.lock"), old, old);
    await assert.rejects(creationLock(f.root, 1), { code: "wallet_locked" });
    await lock.assertOwned();
  } finally { await lock.release(); }
  const path = join(f.root, "wallet.create.lock");
  await writeNew(path, JSON.stringify({ token: randomUUID(), pid: 1, host: "another-host", startedAt: 1 }));
  const old = new Date(Date.now() - 120_000);
  await utimes(path, old, old);
  await assert.rejects(creationLock(f.root, 1), { code: "wallet_recovery_required" });
  assert.equal(await exists(path), true);
});

function worker(root, crashAt = "") {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", fileURLToPath(new URL("../scripts/wallet-test-worker.mjs", import.meta.url)), root, crashAt], { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "", stderr = "";
    child.stdout.on("data", (b) => { stdout += b; }); child.stderr.on("data", (b) => { stderr += b; });
    const timeout = setTimeout(() => child.kill(), 90_000);
    child.on("error", (e) => { clearTimeout(timeout); reject(e); });
    child.on("close", (code) => { clearTimeout(timeout); resolve({ code, stdout, stderr }); });
  });
}

test("concurrent processes converge on one wallet; a crashed creator resumes the same encrypted file", async (t) => {
  const f = await fixture(t, true);
  const results = await Promise.all([worker(f.root), worker(f.root)]);
  for (const r of results) assert.equal(r.code, 0, r.stderr);
  assert.deepEqual(JSON.parse(results[0].stdout), JSON.parse(results[1].stdout));
  const crash = await fixture(t, true);
  const result = await worker(crash.root, "keystore_written");
  assert.equal(result.code, 73, result.stderr);
  const binding = await json(join(crash.root, "wallet.binding.json"));
  const original = await readFile(join(crash.root, `wallet.tmp-${binding.walletId}`, "wallet.json"), "utf8");
  const old = new Date(Date.now() - 120_000);
  await utimes(join(crash.root, "wallet.create.lock"), old, old);
  const recovered = await crash.store().createOrLoad();
  assert.equal(recovered.account, JSON.parse(original).account);
  assert.equal(await readFile(join(crash.root, "wallet", "wallet.json"), "utf8"), original);
});
