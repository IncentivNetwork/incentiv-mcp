import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, realpath, rm, writeFile, mkdir, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFunctionData } from "viem";
import { MAINNET } from "../src/config.ts";
import { erc20Abi, swapRouterAbi, wcentAbi } from "../src/abi.ts";
import { allowance, answer, promptPolicy, setupTargets } from "../src/setup-policy.ts";
import { connectionFor, clientConfigPath, mergeConnection, saveClientConfig, connectClient } from "../src/setup-client.ts";
import { setupWallet, checkRuntime } from "../src/setup.ts";
import { parseWalletProfileArgs } from "../src/wallet-profile.ts";
import { backupWallet, restoreWallet } from "../src/wallet/backup.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { WalletError } from "../src/wallet/errors.ts";
import { digest } from "../src/wallet/journal.ts";
import { fixture, limits, password, recipient, args } from "../scripts/wallet-pipeline-fixture.mjs";

const native = { address: "native", symbol: "CENT", name: "CENT", decimals: 18 };
const usdc = { address: MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase(), symbol: "USDC", name: "USDC", decimals: 6 };
const recoveryPassword = "PUBLIC_SEPARATE_RECOVERY_2026";

function interaction(responses, out) {
  const output = [], secrets = [], questions = [];
  const io = {
    tell: message => output.push(message),
    ask: async label => {
      questions.push(label);
      if (label.startsWith("Encrypted backup path")) return out;
      assert.ok(responses.length, `Unexpected prompt: ${label}`);
      return responses.shift();
    },
    secret: async () => { const value = Buffer.from(password); secrets.push(value); return value; },
    newSecret: async label => { const value = Buffer.from(label.includes("backup recovery") ? recoveryPassword : password); secrets.push(value); return value; },
  };
  return { io, output, secrets, questions };
}
const freshAnswers = () => ["CENT", recipient, "n", "0.01", "100", "1000", "20", "20", "n", "y", "y", "ENABLE"];

test("setup amounts are exact, support zero allowances and reject lossy or ambiguous input", () => {
  assert.equal(allowance("0", 6), "0");
  assert.equal(allowance("10.123456", 6), "10123456");
  assert.equal(allowance("0.000000000000000001", 18), "1");
  for (const value of ["1.1234567", "01", "-1", "1e3", "1,000", "NaN", "", (2n ** 256n).toString()]) assert.throws(() => allowance(value, 6));
  assert.throws(() => checkRuntime("22.17.0"));
  checkRuntime("22.18.0");
  assert.deepEqual(parseWalletProfileArgs(["--wallet-profile", "fresh", "setup"]).args, ["setup"]);
  assert.deepEqual(parseWalletProfileArgs(["--help"]).args, ["--help"]);
});

test("generated permissions match real transfer, paymaster, wrap and swap selectors", () => {
  const targets = setupTargets(MAINNET, [native, usdc], true);
  const allowed = (address, abi, functionName, args) => assert.ok(targets[address.toLowerCase()].includes(encodeFunctionData({ abi, functionName, args }).slice(0, 10)), functionName);
  allowed(usdc.address, erc20Abi, "transfer", [recipient, 1n]);
  allowed(usdc.address, erc20Abi, "approve", [MAINNET.manifest.contracts.swapRouter.address, 1n]);
  allowed(MAINNET.manifest.contracts.wcent.address, wcentAbi, "deposit", []);
  allowed(MAINNET.manifest.contracts.wcent.address, wcentAbi, "withdraw", [1n]);
  allowed(MAINNET.manifest.contracts.swapRouter.address, swapRouterAbi, "exactInputSingle", [{ tokenIn: usdc.address, tokenOut: MAINNET.manifest.contracts.wcent.address, fee: 3000, recipient, deadline: 100n, amountIn: 1n, amountOutMinimum: 1n, sqrtPriceLimitX96: 0n }]);
  allowed(MAINNET.manifest.contracts.swapRouter.address, swapRouterAbi, "exactInput", [{ path: "0x1234", recipient, deadline: 100n, amountIn: 1n, amountOutMinimum: 1n }]);
  allowed(MAINNET.manifest.contracts.swapRouter.address, swapRouterAbi, "unwrapWETH9", [1n, recipient]);
  assert.deepEqual(Object.keys(setupTargets(MAINNET, [native, usdc], false)), [usdc.address]);
});

test("guided policy requires RPC trust, corrects invalid input and includes gas in user-entered daily budgets", async () => {
  const replies = ["", "bad-address", recipient, "y", "y", "1", "0.5", "100", "1000", "20", "10.1234567", "10", "11", "100", "1", "20", "n"];
  const messages = [];
  const { limits: policy } = await promptPolicy(MAINNET, async ref => ref === "CENT" ? native : usdc, async () => { assert.ok(replies.length); return replies.shift(); }, message => messages.push(message));
  assert.equal(policy.tokens[usdc.address].daily, "11000000");
  assert.equal(policy.tokens[usdc.address].perTransaction, "10000000");
  assert.equal(policy.tokens[usdc.address].gasPayment, "1000000");
  assert.deepEqual(policy.trustedRpcOrigins, ["https://rpc.incentiv.io"]);
  assert.equal(policy.recipients.mode, "allowlist");
  assert.ok(messages.some(message => message.includes("Daily budget must cover")));
  const rejected = ["", "", "y", "n"];
  await assert.rejects(promptPolicy(MAINNET, async ref => ref === "CENT" ? native : usdc, async () => rejected.shift(), () => {}), { code: "policy_denied" });
  await assert.rejects(answer(async () => "cancel", () => {}, "test", value => value), { code: "policy_denied" });
});

test("client settings retain unrelated data, require explicit conflict handling and preserve profiles", async t => {
  const root = await mkdtemp(join(await realpath(tmpdir()), "incentiv-connect-")); t.after(() => rm(root, { recursive: true, force: true }));
  const path = join(root, "settings with spaces.json");
  const connection = connectionFor("fresh", {}, join(root, "node path"), join(root, "package path", "index.js"));
  assert.ok(connection.args.includes("--wallet-profile"));
  const original = JSON.stringify({ theme: "dark", mcpServers: { other: { command: "keep-me" }, "incentiv-wallet-fresh": { command: "old" } } });
  const merged = mergeConnection(original, "incentiv-wallet-fresh", connection, "cursor");
  assert.equal(merged.conflict, true);
  const saved = JSON.parse(merged.content);
  assert.equal(saved.theme, "dark"); assert.equal(saved.mcpServers.other.command, "keep-me");
  assert.equal(mergeConnection(merged.content, "incentiv-wallet-fresh", connection, "cursor").same, true);
  const aliased = mergeConnection(JSON.stringify({ mcpServers: { "my-old-wallet-name": { type: "stdio", ...connection } } }), "incentiv-wallet-fresh", connection, "cursor");
  assert.equal(aliased.name, "my-old-wallet-name"); assert.equal(aliased.same, true);
  assert.deepEqual(Object.keys(JSON.parse(aliased.content).mcpServers), ["my-old-wallet-name"]);
  assert.throws(() => mergeConnection("invalid", "server", connection, "claude"));
  assert.throws(() => mergeConnection('{"mcpServers":[]}', "server", connection, "claude"));
  await writeFile(path, original);
  const backup = await saveClientConfig(path, original, merged.content);
  assert.equal(await readFile(backup, "utf8"), original);
  assert.equal(await readFile(path, "utf8"), merged.content);
  await assert.rejects(saveClientConfig(path, original, "{}"), { code: "validation_failed" });
  assert.equal(clientConfigPath("claude", "linux", root, {}), undefined);
  assert.ok(clientConfigPath("claude", "darwin", root, {}).endsWith("claude_desktop_config.json"));
  assert.ok(clientConfigPath("claude", "win32", root, { APPDATA: root }).endsWith("claude_desktop_config.json"));
});

test("app connection cancellation, repeat runs, malformed files and missing Codex preserve settings and hide unrelated secrets", async t => {
  const root = await mkdtemp(join(await realpath(tmpdir()), "incentiv-client-flow-"));
  t.after(() => rm(root, { recursive: true, force: true }));
  const keys = ["HOME", "USERPROFILE", "CODEX_HOME", "PATH"], previous = Object.fromEntries(keys.map(key => [key, process.env[key]]));
  try {
    process.env.HOME = root; process.env.USERPROFILE = root; process.env.CODEX_HOME = join(root, ".codex");
    const path = clientConfigPath("cursor"); assert.equal(path, join(root, ".cursor", "mcp.json"));
    await mkdir(join(root, ".cursor"));
    const original = JSON.stringify({ mcpServers: { other: { command: "keep", env: { TOKEN: "UNRELATED_SECRET_CANARY" } }, "incentiv-wallet": { command: "old" } } });
    await writeFile(path, original);
    const connection = connectionFor("default", {}, join(root, "node path"), join(root, "index.js"));
    const messages = [];
    assert.equal(await connectClient("cursor", "default", connection, async () => "n", value => messages.push(value)), false);
    assert.equal(await readFile(path, "utf8"), original);
    assert.equal(await connectClient("cursor", "default", connection, async () => "y", value => messages.push(value)), true);
    assert.equal(JSON.parse(await readFile(path, "utf8")).mcpServers.other.env.TOKEN, "UNRELATED_SECRET_CANARY");
    assert.equal((await readdir(join(root, ".cursor"))).filter(name => name.endsWith(".bak")).length, 1);
    assert.equal(await connectClient("cursor", "default", connection, async () => { assert.fail("Repeat setup must not prompt to replace an identical connection"); }, value => messages.push(value)), true);
    await writeFile(path, "malformed JSON");
    assert.equal(await connectClient("cursor", "default", connection, async () => { assert.fail("Do not overwrite malformed configuration"); }, value => messages.push(value)), false);
    assert.equal(await readFile(path, "utf8"), "malformed JSON");
    process.env.PATH = root;
    assert.equal(await connectClient("codex", "default", connection, async () => { assert.fail("Missing Codex must produce manual configuration"); }, value => messages.push(value)), false);
    assert.ok(messages.some(value => value.includes("[mcp_servers.incentiv-wallet]")));
    assert.ok(!messages.join("\n").includes("UNRELATED_SECRET_CANARY"));
  } finally { for (const key of keys) { if (previous[key] === undefined) delete process.env[key]; else process.env[key] = previous[key]; } }
});

test("fresh setup verifies a backup before activation, does not send, and repeat setup preserves the account", async t => {
  const f = await fixture(t, { existing: true }), out = join(f.parent, "setup-backup.json");
  const interaction1 = interaction(freshAnswers(), out);
  const created = await setupWallet(f.service, f.root, interaction1.io);
  assert.equal(created.activated, true); assert.equal(f.submissions.length, 0);
  assert.equal((await f.service.review()).wallet.policy.enabled, true);
  const restored = new WalletStore(MAINNET, { ...f.deps, root: join(f.parent, "restored") });
  const backup = await restoreWallet(MAINNET, restored, out, Buffer.from(recoveryPassword));
  assert.equal(backup.account, created.account); assert.equal(backup.policy.enabled, false);
  assert.ok(interaction1.secrets.every(secret => secret.every(byte => byte === 0)));
  assert.ok(!interaction1.output.join("\n").includes(password.toString()));
  assert.ok(!interaction1.output.join("\n").includes(recoveryPassword));
  const again = interaction(["1"], "unused");
  assert.equal((await setupWallet(f.service, f.root, again.io)).account, created.account);
  assert.equal(again.secrets.length, 0); assert.equal(f.submissions.length, 0);
});

test("failed backup and interrupted activation leave new wallets disabled; resume keeps the same key", async t => {
  const f = await fixture(t, { existing: true });
  const broken = interaction(freshAnswers(), join(f.parent, "missing-parent", "backup.json"));
  await assert.rejects(setupWallet(f.service, f.root, broken.io));
  const before = (await f.service.review()).wallet;
  assert.equal(before.policy.enabled, false);
  const resumed = interaction(["", "y", "y", "y", ""], join(f.parent, "resumed.json"));
  const result = await setupWallet(f.service, f.root, resumed.io);
  assert.equal(result.account, before.account); assert.equal(result.activated, false);
  assert.equal((await f.service.review()).wallet.policy.enabled, false);
  assert.equal(f.submissions.length, 0);
  const finish = interaction(["", "y", "y", "y", "ENABLE"], join(f.parent, "finished.json"));
  assert.equal((await setupWallet(f.service, f.root, finish.io)).account, before.account);
  assert.equal((await f.service.review()).wallet.policy.enabled, true);
});

test("MCP-created wallet can establish disabled administration before backup, and cancellation never enables it", async t => {
  const f = await fixture(t, { existing: true });
  const before = await f.store.createOrLoad();
  const cancelled = interaction([...freshAnswers().slice(0, -1), "cancel"], join(f.parent, "mcp-backup.json"));
  const result = await setupWallet(f.service, f.root, cancelled.io);
  assert.equal(result.account, before.account);
  const policy = (await f.service.review()).wallet.policy;
  assert.equal(policy.configured, true); assert.equal(policy.enabled, false);
  await assert.rejects(f.service.send("transfer", args("11111111-1111-4111-8111-111111111111")), { code: "wallet_locked" });
});

test("saving disabled policy preserves restored-copy acknowledgement and existing activation behavior", async t => {
  const f = await fixture(t), out = join(f.parent, "restored.json");
  await backupWallet(MAINNET, f.store, out, password, Buffer.from(recoveryPassword));
  const restored = new WalletStore(MAINNET, { ...f.deps, root: join(f.parent, "restored-copy") });
  await restoreWallet(MAINNET, restored, out, Buffer.from(recoveryPassword));
  const { WalletService } = await import("../src/wallet/service.ts");
  const service = new WalletService(f.service.ctx, restored, f.chain);
  let review = await service.review();
  await service.configure(limits, password, false, digest(review.records), false);
  review = await service.review();
  await assert.rejects(service.configure(limits, password, false, digest(review.records)), { code: "policy_denied" });
  await service.configure(limits, password, true, digest(review.records));
  assert.equal((await service.review()).wallet.policy.enabled, true);
});
