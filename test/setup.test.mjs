import assert from "node:assert/strict";
import test from "node:test";
import { mkdtemp, readFile, realpath, rm, writeFile, mkdir, readdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFunctionData, toFunctionSelector } from "viem";
import { MAINNET, withoutAgentRegistry } from "../src/config.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { erc20Abi, swapRouterAbi, wcentAbi } from "../src/abi.ts";
import { linkGasWarning, promptAgentRegistry, allowance, answer, promptPolicy, setupTargets, technicalLimits } from "../src/setup-policy.ts";
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
const freshAnswers = () => ["CENT", recipient, "n", "0.01", "100", "1000", "20", "20", "n", "n", "y", "y", "ENABLE"];

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
  const replies = ["", "bad-address", recipient, "y", "y", "1", "0.5", "100", "1000", "20", "10.1234567", "10", "11", "100", "1", "20", "n", "n"];
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
  const resumed = interaction(["", "y", "", "y", "y", ""], join(f.parent, "resumed.json"));
  const result = await setupWallet(f.service, f.root, resumed.io);
  assert.equal(result.account, before.account); assert.equal(result.activated, false);
  assert.equal((await f.service.review()).wallet.policy.enabled, false);
  assert.equal(f.submissions.length, 0);
  const finish = interaction(["", "y", "", "y", "y", "ENABLE"], join(f.parent, "finished.json"));
  assert.equal((await setupWallet(f.service, f.root, finish.io)).account, before.account);
  assert.equal((await f.service.review()).wallet.policy.enabled, true);
});

test("keeping current permissions still offers the registry once approved, and only points to approval before that", async t => {
  const base = withoutAgentRegistry(MAINNET), old = await fixture(t, { config: base }), f = await fixture(t, { root: old.root, existing: true }), portal = "0x0000000000000000000000000000000000000002";
  await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, enabled: false }));
  const pending = interaction(["", "y", "y", "y", ""], join(old.parent, "unapproved.json"));
  await setupWallet(f.service, f.root, pending.io);
  assert.ok(!pending.questions.some(q => q.startsWith("Allow this agent")));
  assert.ok(pending.output.some(line => line.includes("wallet capabilities approve")));
  assert.equal((await f.service.review()).wallet.manifest_id, base.manifest.manifestId);

  await approveCapabilities(f.store, base, MAINNET, password, digest(await reviewCapabilities(f.store, base, MAINNET)));
  const approved = interaction(["", "y", "y", portal, "y", "y", "ENABLE"], join(old.parent, "approved.json"));
  await setupWallet(f.service, f.root, approved.io);
  const { limits: saved, enabled } = (await f.service.review()).wallet.policy;
  assert.equal(enabled, true);
  assert.deepEqual(saved.agentRegistry, { parents: [portal], allowUnlink: false });
  assert.equal(saved.targets[MAINNET.manifest.agentRegistry.proxy.address.toLowerCase()].length, 1, "link only: connections are permanent");
  assert.deepEqual(saved.tokens, limits.tokens);
});

test("replacing permissions on a wallet that has not approved the registry does not ask for Portal accounts", async t => {
  const base = withoutAgentRegistry(MAINNET), old = await fixture(t, { config: base }), f = await fixture(t, { root: old.root, existing: true });
  await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, enabled: false }));
  const replaced = interaction(["", "n", "CENT", recipient, "n", "0.01", "100", "1000", "20", "20", "n", "y", "y", ""], join(old.parent, "replaced.json"));
  await setupWallet(f.service, f.root, replaced.io);
  assert.ok(!replaced.questions.some(q => /Portal accounts/.test(q)), "setup passes the wallet's approval state to promptPolicy");
  assert.ok(replaced.output.some(line => line.includes("run wallet capabilities approve, then rerun setup")));
  assert.equal((await f.service.review()).wallet.policy.limits.agentRegistry, undefined);
});

test("keeping a policy from an earlier build drops its unlink permission before the review", async t => {
  const old = await fixture(t), f = await fixture(t, { root: old.root, existing: true }), portal = "0x0000000000000000000000000000000000000002";
  const registry = MAINNET.manifest.agentRegistry.proxy.address.toLowerCase(), link = toFunctionSelector("link(address,address,uint256,bytes,uint256,bytes)"), unlink = toFunctionSelector("unlink()");
  await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, enabled: false, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [portal], allowUnlink: true }, targets: { ...s.envelope.policy.limits.targets, [registry]: [link, unlink] } } }));
  const kept = interaction(["", "y", "y", "y", "ENABLE"], join(old.parent, "kept.json"));
  await setupWallet(f.service, f.root, kept.io);
  assert.ok(kept.output.some(line => line.includes("unlink permission an earlier version saved is left out below")));
  const summary = kept.output.find(line => line.includes("Contract permissions"));
  assert.ok(summary && !summary.includes(unlink), "the reviewed summary no longer lists unlink()");
  const { limits: saved } = (await f.service.review()).wallet.policy;
  assert.deepEqual(saved.agentRegistry, { parents: [portal], allowUnlink: false });
  assert.deepEqual(saved.targets[registry], [link]);
});

test("keeping permissions after the registry moves offers its link permission, keeping parents and limits", async t => {
  const registry = MAINNET.manifest.agentRegistry.proxy.address.toLowerCase(), link = toFunctionSelector("link(address,address,uint256,bytes,uint256,bytes)");
  const earlier = "0x00000000000000000000000000000000000000aa", portal = "0x0000000000000000000000000000000000000002";
  for (const accept of [true, false]) {
    const old = await fixture(t), f = await fixture(t, { root: old.root, existing: true });
    // The policy was saved when the approved registry lived at an earlier proxy.
    await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, enabled: false, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [portal], allowUnlink: false }, targets: { ...s.envelope.policy.limits.targets, [earlier]: [link] } } }));
    const kept = interaction(["", "y", accept ? "y" : "n", "y", "y", "ENABLE"], join(old.parent, `moved-${accept}.json`));
    await setupWallet(f.service, f.root, kept.io);
    assert.ok(kept.questions.some(q => q.includes(`Agent Registry is now at ${registry}`) && q.includes(portal)));
    assert.ok(!kept.questions.some(q => q.startsWith("Allow this agent")), "the parent list is kept, not asked again");
    const { limits: saved } = (await f.service.review()).wallet.policy;
    assert.deepEqual(saved.agentRegistry, { parents: [portal], allowUnlink: false });
    assert.deepEqual(saved.tokens, limits.tokens);
    assert.deepEqual(saved.targets[earlier], [link]);
    if (accept) assert.deepEqual(saved.targets[registry], [link]);
    else { assert.equal(saved.targets[registry], undefined); assert.ok(kept.output.some(line => line.includes("terminal approval"))); }
  }
});

test("registry permission merges with a differently cased target, and unlink is dropped from a moved registry", async t => {
  const { withLinkPermission, withoutUnlink } = await import("../src/setup-policy.ts");
  const registry = MAINNET.manifest.agentRegistry.proxy.address, link = toFunctionSelector("link(address,address,uint256,bytes,uint256,bytes)"), unlink = toFunctionSelector("unlink()");
  const merged = withLinkPermission(MAINNET, { ...limits, targets: { ...limits.targets, [registry]: [] } });
  assert.deepEqual(Object.keys(merged.targets).filter(key => key.toLowerCase() === registry.toLowerCase()), [registry]);
  assert.deepEqual(merged.targets[registry], [link]);
  assert.equal(withLinkPermission(MAINNET, merged), merged);
  const earlier = "0x00000000000000000000000000000000000000aa";
  const cleaned = withoutUnlink(MAINNET, { ...limits, agentRegistry: { parents: [], allowUnlink: true }, targets: { ...limits.targets, [earlier]: [link, unlink] } });
  assert.deepEqual(cleaned.targets[earlier], [link]); assert.equal(cleaned.agentRegistry.allowUnlink, false);
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


test("registry setup deduplicates parent addresses after case normalization", async () => {
  const parent = "0x16e43840d8D79896A389a3De85aB0B0210C05685";
  const replies = ["", recipient, "y", "y", "1", "100", "1000", "20", "10", "100", "1000", "20", "20", "n", "y", `${parent.toLowerCase()},${parent}`, "y"];
  const { limits: policy } = await promptPolicy(MAINNET, async ref => ref === "CENT" ? native : usdc, async () => { assert.ok(replies.length); return replies.shift(); }, () => {});
  assert.deepEqual(policy.agentRegistry.parents, [parent]);
});

test("setup's default gas-unit limit admits a token-paid first operation that deploys and links an agent", async () => {
  // Declared on mainnet by a USDC-paid deploy + link (2026-11-10, tx 0x3a6e14f9…): 382,120 verification, 327,100 call,
  // 55,717 pre-verification, and the paymaster's 300,000 verification and 50,000 post-operation limits.
  const firstLink = 382_120n + 327_100n + 55_717n + 300_000n + 50_000n;
  assert.ok(BigInt(technicalLimits.maxGasUnits) >= firstLink * 13n / 10n, "the default keeps at least 30% headroom over a measured first link");
  const told = [];
  const asked = [];
  const answers = ["", "", "n", "1", "1", "1", "1", "1", "1", "1", "1", "1", "n", "n"];
  await promptPolicy(MAINNET, async ref => ({ address: ref === "CENT" ? "native" : MAINNET.manifest.canonicalTokens.USDC.address, symbol: ref, name: ref, decimals: ref === "CENT" ? 18 : 6 }), async q => { asked.push(q); return answers.shift() ?? "n"; }, m => told.push(m)).catch(() => {});
  assert.ok(told.some(m => m.includes("1,500,000 gas units") && m.includes("100,000 gwei fee ceiling")), "setup states the defaults it applies");
});

test("setup does not ask for Portal accounts on a wallet that has not approved the registry yet", async () => {
  // The same answers as the registry case above, without the registry prompt: nothing is left unanswered or saved.
  const replies = ["", recipient, "y", "y", "1", "100", "1000", "20", "10", "100", "1000", "20", "20", "n"], asked = [], told = [];
  const { limits: policy } = await promptPolicy(MAINNET, async ref => ref === "CENT" ? native : usdc, async q => { asked.push(q); assert.ok(replies.length); return replies.shift(); }, m => told.push(m), false);
  assert.equal(policy.agentRegistry, undefined); assert.equal(replies.length, 0);
  assert.ok(!asked.some(q => /Portal accounts/.test(q)));
  assert.ok(told.some(m => /run wallet capabilities approve, then rerun setup/.test(m)));
});

test("kept permissions below the default gas unit cap are flagged when a link is added", () => {
  assert.match(linkGasWarning({ maxGasUnits: "1000000" }), /1,000,000 is below the 1,500,000.*terminal approval/);
  assert.equal(linkGasWarning({ maxGasUnits: technicalLimits.maxGasUnits }), undefined);
  // A fresh setup that lowered the cap is told how to raise it there.
  const fresh = linkGasWarning({ maxGasUnits: "1000000" }, false);
  assert.match(fresh, /^The gas unit cap of 1,000,000.*edit the advanced limits/); assert.doesNotMatch(fresh, /kept|without keeping/);
});

test("setup refuses the agent's own account as its Portal parent", async () => {
  const agent = "0x00000000000000000000000000000000000000a1", other = "0x00000000000000000000000000000000000000b2", told = [];
  const replies = ["y", `${other},${agent}`, other];
  const registry = await promptAgentRegistry(MAINNET, async () => replies.shift(), m => told.push(m), agent);
  assert.equal(replies.length, 0);
  assert.deepEqual(registry.agentRegistry.parents.map(p => p.toLowerCase()), [other]);
  assert.ok(told.some(m => /own account, which cannot be its own parent/.test(m)));
});
