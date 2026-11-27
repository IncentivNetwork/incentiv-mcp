import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { writeFile } from "node:fs/promises";
import { createPublicClient, custom, encodeAbiParameters, encodeEventTopics, HttpRequestError, recoverMessageAddress, decodeFunctionData, encodeFunctionData, encodeErrorResult } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { MAINNET, configurationId, loadConfig, parseConfig, withoutAgentRegistry } from "../src/config.ts";
import { deriveSmartAccount } from "../src/network.ts";
import { agentLinkDigest, agentRegistryAbi, assertAgentSignature, hasRegistryEvent, linkBlocker, parentBlocker, readAgentLinkDigest, registryApprovalSchema, registryCall, registryRevertCode, verifyRegistryDeployment, verifyRegistryIntent } from "../src/agent-registry.ts";
import { intentSchema, Journal, digest, ownsNonce } from "../src/wallet/journal.ts";
import { validateOperation } from "../src/wallet/validate.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { limitsSchema, policyViolations } from "../src/wallet/policy.ts";
import { isTransportFailure, replacementFees, WalletChain } from "../src/wallet/chain.ts";
import { Ctx } from "../src/context.ts";
import { buildUserOpUnsigned, computeUserOpHash, encodeExecuteBatch, userOpToJson } from "../src/userop.ts";
import { args as transfer, fixture, limits, password, unsigned } from "../scripts/wallet-pipeline-fixture.mjs";
import { join } from "node:path";
import { previousImplementationConfig } from "../src/account-upgrade.ts";
import { approveImplementation, reviewImplementation } from "../src/wallet/implementation.ts";
import { backupWallet, restoreWallet } from "../src/wallet/backup.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { RpcDisagreementError, WalletError } from "../src/wallet/errors.ts";
import { WalletService } from "../src/wallet/service.ts";
import { reviewUpgrade } from "../src/wallet/cli.ts";

const zero = `0x${"00".repeat(20)}`, parent = "0x0000000000000000000000000000000000000002";
const owner = privateKeyToAccount(`0x${"01".padStart(64, "0")}`), agent = deriveSmartAccount(MAINNET, owner.address);
const digestToSign = `0x${"ab".repeat(32)}`;
const code = JSON.parse(readFileSync(new URL("./fixtures/agent-registry-code.json", import.meta.url)));
const cap = MAINNET.manifest.agentRegistry;
async function approval(overrides = {}) {
  return { version: 1, chain_id: 24101, registry: cap.proxy.address, parent, agent, parent_nonce: "0", parent_deadline: String(Math.floor(Date.now() / 1000) + 900), parent_signature: await owner.signMessage({ message: { raw: digestToSign } }), ...overrides };
}
const intent = a => ({ intentSchemaVersion: 1, kind: "link_agent", token: "native", gasToken: "native", amount: "0", slippageBps: 0, feeTier: 3000, registryParent: a.parent.toLowerCase(), registryApproval: a });
const state = () => ({ block: 123n, timestamp: Math.floor(Date.now() / 1000), deployed: false });
function client(overrides = {}) {
  const c = {
    getCode: async ({ address }) => address.toLowerCase() === cap.proxy.address.toLowerCase() ? code.proxy : code.implementation,
    getStorageAt: async () => code.implementationSlot,
    readContract: async ({ functionName, args, blockNumber }) => {
      assert.equal(blockNumber, 123n);
      if (functionName === "eip712Domain") return ["0x0f", "Incentiv Agent Registry", "1", 24101n, cap.proxy.address, `0x${"00".repeat(32)}`, []];
      if (functionName === "parentOf") return zero;
      if (functionName === "isIncentivAccount") return args[0].toLowerCase() === parent.toLowerCase();
      if (functionName === "isAccountFactory") return true;
      if (functionName === "maxAgentsPerParent") return 5n;
      if (functionName === "agentCount" || functionName === "nonces") return 0n;
      if (functionName === "parentLinkDigest") return digestToSign;
      if (functionName === "agentLinkDigest") return agentLinkDigest(MAINNET, args[1], args[0], 0n, args[2]);
      if (functionName === "isValidSignature") return (await recoverMessageAddress({ message: { raw: args[0] }, signature: args[1] })) === owner.address ? "0x1626ba7e" : "0xffffffff";
      assert.fail(functionName);
    },
  };
  return Object.assign(c, overrides);
}

test("approval handoff is strict, bounded and signs bytes with EIP-191", async () => {
  const a = await approval(); assert.deepEqual(registryApprovalSchema.parse(a), a);
  for (const change of [{ version: 2 }, { parent_nonce: "01" }, { parent_deadline: "9007199254740992" }, { parent_signature: "0x" }, { parent: zero }, { private_key: "CANARY" }]) assert.throws(() => registryApprovalSchema.parse({ ...a, ...change }));
  await verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(a), state());
});

test("deployment verification refuses each registry pin on its own", async () => {
  const c = client(), good = c.readContract, domain = ["0x0f", "Incentiv Agent Registry", "1", 24101n, cap.proxy.address, `0x${"00".repeat(32)}`, []];
  const withDomain = changed => client({ readContract: async args => args.functionName === "eip712Domain" ? changed : good(args) });
  const changedCode = which => client({ getCode: async ({ address }) => {
    const isProxy = address.toLowerCase() === cap.proxy.address.toLowerCase();
    return (isProxy ? which === "proxy" : which === "implementation") ? "0x6000" : c.getCode({ address });
  } });
  for (const [label, changed] of [["proxy code", changedCode("proxy")], ["implementation code", changedCode("implementation")], ["domain chain", withDomain(domain.with(3, 1n))], ["domain contract", withDomain(domain.with(4, parent))], ["domain version", withDomain(domain.with(2, "2"))], ["domain fields", withDomain(domain.with(0, "0x1f"))]]) {
    await assert.rejects(verifyRegistryDeployment(changed, MAINNET, 123n), /implementation|domain/, label);
  }
  await verifyRegistryDeployment(withDomain(domain.with(4, cap.proxy.address.toUpperCase().replace("0X", "0x"))), MAINNET, 123n);
});

test("deployment verification checks code, implementation slot and signing domain", async () => {
  await verifyRegistryDeployment(client(), MAINNET, 123n);
  await assert.rejects(verifyRegistryDeployment(client({ getStorageAt: async () => `0x${"00".repeat(32)}` }), MAINNET, 123n), /implementation/);
  await assert.rejects(verifyRegistryDeployment(client({ getCode: async () => "0x6000" }), MAINNET, 123n), /implementation/);
  const c = client(), good = c.readContract;
  c.readContract = async args => args.functionName === "eip712Domain" ? ["0x0f", "Wrong Registry", "1", 24101n, cap.proxy.address] : good(args);
  await assert.rejects(verifyRegistryDeployment(c, MAINNET, 123n), /domain/);
});

test("preflight permits first-operation deployment but rejects stale approvals, roles and limits", async () => {
  const a = await approval();
  await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(a), { ...state(), deployed: true }), { code: "registry_ineligible" });
  for (const [functionName, answer, expected] of [["nonces", 1n, "registry_approval_stale"], ["agentCount", 5n, "registry_limit_reached"], ["isAccountFactory", false, "registry_factory_not_allowed"], ["parentOf", parent, "registry_already_linked"], ["isValidSignature", "0xffffffff", "registry_approval_invalid"]]) {
    const c = client(), good = c.readContract;
    // agentCount is per address: a full parent, not an agent that is itself a parent.
    c.readContract = args => args.functionName === functionName && (functionName !== "agentCount" || args.args[0].toLowerCase() === parent.toLowerCase()) ? Promise.resolve(answer) : good(args);
    await assert.rejects(verifyRegistryIntent(c, MAINNET, { account: agent }, intent(a), state()), { code: expected });
  }
  await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(await approval({ parent_deadline: "1" })), state()), { code: "registry_approval_expired" });
});

test("semantic validation binds registry, parent, agent, zero value, deadline and complete batch", async () => {
  const a = await approval(), i = intentSchema.parse(intent(a));
  const wallet = { account: agent, owner: owner.address, approvedCapabilityManifestId: MAINNET.manifest.manifestId };
  const built = unsigned(wallet, { to: parent, amount: "0" }, { deployed: false, nonce: 0n });
  const expectedCall = registryCall(MAINNET, agent, i);
  const check = calls => {
    built.op.callData = encodeExecuteBatch(calls);
    const hash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return validateOperation(MAINNET, wallet, i, userOpToJson(built.op), { nonce: 0n, deployed: false, hash, deadline: Number(a.parent_deadline) });
  };
  assert.deepEqual(check([expectedCall]).spend, { native: "300" });
  assert.equal(decodeFunctionData({ abi: agentRegistryAbi, data: expectedCall.data }).args[4], 0n);
  for (const calls of [[{ ...expectedCall, value: 1n }], [{ ...expectedCall, to: parent }], [expectedCall, expectedCall], [{ ...expectedCall, data: `${expectedCall.data}00` }]]) assert.throws(() => check(calls), { code: "validation_failed" });
  for (const changed of [{ chain_id: 1 }, { registry: parent }, { agent: parent }, { parent: agent }]) assert.throws(() => registryCall(MAINNET, agent, intent({ ...a, ...changed })), { code: "validation_failed" });
  assert.throws(() => intentSchema.parse({ ...i, amount: "1" }));
  assert.throws(() => intentSchema.parse({ ...i, kind: "transfer" }));
});

test("registry policy defaults deny connection, never allow unlink, and gas budgets still apply", () => {
  const base = { token: "native", amount: "0", swap: false, slippage: 0, spend: { native: "300" }, used: {}, balances: { native: "1000000" }, gasCost: 300n, fee: 1n, gasUnits: 300n, gasToken: "native", gasCharge: 300n, calls: [], registryKind: "link_agent", registryParent: parent };
  assert.ok(policyViolations(limits, base).includes("registry_parent_not_allowed"));
  const configured = limitsSchema.parse({ ...limits, agentRegistry: { parents: [parent], allowUnlink: true } });
  assert.deepEqual(policyViolations(configured, base), []);
  assert.ok(policyViolations(limits, { ...base, registryKind: "unlink_agent" }).includes("registry_unlink_not_allowed"));
  // An older stored policy that allowed unlinking no longer permits it.
  assert.ok(policyViolations(configured, { ...base, registryKind: "unlink_agent" }).includes("registry_unlink_not_allowed"));
  assert.ok(policyViolations(configured, { ...base, gasCharge: 10001n }).includes("gas_payment_limit"));
});

async function registryFixture(t, allowed = true, options = {}) {
  const f = await fixture(t, options);
  const wallet = await f.store.createOrLoad(), a = await approval({ agent: wallet.smart_account_address ?? wallet.account });
  // publicWallet uses account; obtain the exact address from the authenticated envelope.
  await f.store.session(async s => { a.agent = s.envelope.account; if (allowed) await s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false }, targets: { [cap.proxy.address.toLowerCase()]: ["0x" + registryCall(MAINNET, a.agent, intent(a)).data.slice(2, 10)] } } }); });
  f.chain.verifyRegistry = async () => {};
  f.chain.build = async (w, i, s) => {
    const built = unsigned(w, { to: parent, amount: "0" }, s);
    built.op.callData = encodeExecuteBatch([registryCall(MAINNET, w.account, i)]);
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return built;
  };
  return { ...f, approval: a };
}

test("link uses durable wallet signing, identical retry bytes and gas-only accounting", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval };
  const relay = f.chain.relay;
  f.chain.relay = async (...a) => { await relay(...a); throw new Error('lost response'); };
  assert.equal((await f.service.send("link_agent", args)).status, "submission_unknown");
  f.chain.relay = relay;
  assert.equal((await f.service.send("link_agent", args)).status, "submitted");
  assert.deepEqual(f.submissions[0], f.submissions[1]);
  await assert.rejects(f.service.send("link_agent", { ...args, approval: { ...f.approval, parent_nonce: "1" } }), { code: "idempotency_conflict" });
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}` });
  const settled = await f.service.operation(id);
  assert.equal(settled.status, "confirmed"); assert.equal(settled.intent.registryApproval.parent_signature, "[redacted]");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "200" }));
});

test("unconfigured registry permission needs existing exact-operation local approval", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval };
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  assert.equal(f.submissions.length, 0);
  const review = await f.service.review(id);
  await f.service.approve(id, password, digest(review.records[0]));
  assert.equal((await f.service.send("link_agent", args)).status, "submitted");
});

test("connections are permanent: an unlink request is refused before any read, record or submission", async t => {
  const f = await registryFixture(t), id = randomUUID();
  f.chain.verifyRegistry = WalletChain.prototype.verifyRegistry; // the real check
  await assert.rejects(f.service.send("unlink_agent", { request_id: id, parent }), { code: "registry_unlink_unsupported" });
  assert.equal(f.submissions.length, 0);
  await assert.rejects(f.service.operation(id), { code: "operation_not_found" });
  const reads = [], c = client({ readContract: async opts => { reads.push(opts.functionName); throw new Error("unexpected read"); } });
  await assert.rejects(verifyRegistryIntent(c, MAINNET, { account: agent }, { ...intent(await approval()), kind: "unlink_agent", registryApproval: undefined }, state()), { code: "registry_unlink_unsupported" });
  assert.deepEqual(reads, []);
});

const registryLog = (eventName, by = agent) => ({ address: cap.proxy.address, topics: encodeEventTopics({ abi: agentRegistryAbi, eventName, args: { parent, agent, ...(eventName === "AgentUnlinked" ? { by } : {}) } }), data: "0x" });
test("confirmation requires the right proxy, parent, agent and unlinking side", async () => {
  const i = intent(await approval()), log = registryLog("AgentLinked");
  assert.equal(hasRegistryEvent(MAINNET, i, agent, [log]), true);
  assert.equal(hasRegistryEvent(MAINNET, i, agent, [{ ...log, address: parent }]), false);
  assert.equal(hasRegistryEvent(MAINNET, i, parent, [log]), false);
  const unlink = { ...i, kind: "unlink_agent" };
  assert.equal(hasRegistryEvent(MAINNET, unlink, agent, [registryLog("AgentUnlinked")]), true);
  assert.equal(hasRegistryEvent(MAINNET, unlink, agent, [registryLog("AgentUnlinked", parent)]), false);
  // Reconciling under a manifest without the registry reports the event as missing instead of throwing.
  assert.equal(hasRegistryEvent(withoutAgentRegistry(MAINNET), i, agent, [log]), false);
});

test("receipt cannot borrow a registry event from another user operation in the same bundle", async t => {
  const chain = new WalletChain(new Ctx(MAINNET)), hash = `0x${"11".repeat(32)}`, tx = `0x${"22".repeat(32)}`, blockHash = `0x${"33".repeat(32)}`;
  const operationEvent = (await import('viem')).parseAbiItem('event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)');
  const opLog = h => ({ address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: [operationEvent], eventName: "UserOperationEvent", args: { userOpHash: h, sender: agent, paymaster: zero } }), data: encodeAbiParameters([{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }], [0n, true, 200n, 100n]) });
  const beforeExecution = { address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: (await import("viem")).parseAbi(["event BeforeExecution()"]), eventName: "BeforeExecution" }), data: "0x" };
  let logs = [beforeExecution, registryLog("AgentLinked"), opLog(`0x${"44".repeat(32)}`), opLog(hash)];
  chain.clients.splice(0, chain.clients.length, { getTransactionReceipt: async () => ({ status: "success", transactionHash: tx, blockNumber: 10n, blockHash, logs }), getBlock: async () => ({ hash: blockHash }), getBlockNumber: async () => 12n });
  t.mock.method(globalThis, "fetch", async () => Response.json({ result: { receipt: { transactionHash: tx } } }));
  const record = { userOpHash: hash, nonce: "0", operation: { sender: agent }, intent: intent(await approval()) };
  assert.equal((await chain.receipt(record)).registryError, "registry_event_missing");
  logs = [registryLog("AgentLinked"), beforeExecution, opLog(hash)];
  assert.equal((await chain.receipt(record)).registryError, "registry_event_missing");
  // Without an execution boundary the operation's logs cannot be isolated, but the nonce still settles.
  logs = [registryLog("AgentLinked"), opLog(hash)];
  assert.equal((await chain.receipt(record)).registryError, "registry_event_missing");
  logs = [beforeExecution, registryLog("AgentLinked"), opLog(hash)];
  const settled = await chain.receipt(record);
  assert.equal(settled.success, true); assert.equal(settled.registryError, undefined);
});

test("registry capability approval preserves wallet identity and legacy journal MACs", async t => {
  const previous = structuredClone(MAINNET); delete previous.manifest.agentRegistry; previous.manifest.manifestId = configurationId(previous.manifest, "manifestId"); parseConfig(previous);
  const f = await fixture(t, { config: previous });
  const before = await f.store.createOrLoad();
  const proposedStore = new (await import('../src/wallet/store.ts')).WalletStore(MAINNET, f.deps);
  const review = await reviewCapabilities(proposedStore, previous, MAINNET);
  await approveCapabilities(proposedStore, previous, MAINNET, password, digest(review));
  const after = await proposedStore.createOrLoad();
  assert.equal(after.account, before.account); assert.equal(after.owner, before.owner); assert.equal(after.wallet_id, before.wallet_id);
  await proposedStore.session(async s => { assert.equal(s.envelope.policy.enabled, false); await Journal.open(s); });
});


test("derived configurations reproduce the manifest IDs that released wallets approved", () => {
  assert.equal(withoutAgentRegistry(MAINNET).manifest.manifestId, "0x46e12b725e59f3f5c3fc3f39c48eb6e4301a5cfdb5f06b7df2a5c02cf65d77b4");
  assert.equal(previousImplementationConfig(MAINNET).manifest.manifestId, "0x6fe24377ccfc78465ee7febb06cbc71eb0a975285432b5f15531438dbc2877c4");
});

test("a released default-config wallet approves the registry without a previous configuration file", async t => {
  const base = withoutAgentRegistry(MAINNET), f = await fixture(t, { config: base }), before = await f.store.createOrLoad();
  const store = new WalletStore(MAINNET, f.deps);
  assert.equal((await store.createOrLoad()).manifest_id, base.manifest.manifestId);
  const review = await reviewCapabilities(store, base, MAINNET);
  assert.equal(review.note, undefined);
  await approveCapabilities(store, base, MAINNET, password, digest(review));
  const after = await store.createOrLoad();
  assert.equal(after.account, before.account); assert.equal(after.manifest_id, MAINNET.manifest.manifestId);
});

test("a previous-implementation wallet upgrades, then approves the registry as a separate step", async t => {
  const base = withoutAgentRegistry(MAINNET), f = await fixture(t, { config: previousImplementationConfig(MAINNET) }), before = await f.store.createOrLoad();
  const full = new WalletStore(MAINNET, f.deps), upgrade = full.withConfig(base);
  await assert.rejects(approveImplementation(full, MAINNET, password, digest(await reviewImplementation(full, MAINNET))), { code: "policy_denied" });
  await approveImplementation(upgrade, base, password, digest(await reviewImplementation(upgrade, base)));
  await upgrade.session(async s => { assert.equal(s.envelope.approvedCapabilityManifestId, base.manifest.manifestId); assert.equal(s.envelope.networkIdentity.networkId, MAINNET.identity.networkId); });
  assert.equal((await full.createOrLoad()).manifest_id, base.manifest.manifestId);
  await approveCapabilities(full, base, MAINNET, password, digest(await reviewCapabilities(full, base, MAINNET)));
  const after = await full.createOrLoad();
  assert.equal(after.account, before.account); assert.equal(after.owner, before.owner);
});

test("a backup from before the registry restores without approving it, then approves the registry", async t => {
  const base = withoutAgentRegistry(MAINNET), source = await fixture(t, { config: base }), target = await fixture(t, { existing: true });
  const recovery = Buffer.from("recovery passphrase for test"), before = await source.store.createOrLoad();
  const out = join(source.parent, "pre-registry-backup.json");
  await backupWallet(base, source.store, out, password, recovery);
  const store = new WalletStore(MAINNET, target.deps);
  await restoreWallet(MAINNET, store, out, recovery);
  assert.equal((await store.createOrLoad()).manifest_id, base.manifest.manifestId);
  await approveCapabilities(store, base, MAINNET, password, digest(await reviewCapabilities(store, base, MAINNET)));
  assert.equal((await store.createOrLoad()).account, before.account);
  await assert.rejects(restoreWallet(MAINNET, store, out, Buffer.from("wrong recovery passphrase")), { code: "backup_authentication_failed" });
});

test("a rejected link request leaves no journal record and oversized signatures are refused", async t => {
  const f = await registryFixture(t), id = randomUUID();
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: { ...f.approval, parent_signature: `0x${"ab".repeat(4097)}` } }));
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_approval_invalid", "Parent signature is invalid"); };
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: { ...f.approval, parent_signature: `0x${"ab".repeat(4096)}` } }), { code: "registry_approval_invalid" });
  await f.store.session(async s => assert.equal((await Journal.open(s)).data.records.length, 0));
});

test("bad consent closes an existing link record on retry", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval };
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_approval_expired", "Portal approval expired"); };
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_approval_expired" });
  const closed = await f.service.operation(id);
  assert.equal(closed.status, "failed"); assert.equal(closed.last_error, "registry_approval_expired");
  assert.equal((await f.service.send("link_agent", args)).status, "failed");

  // A record left in preparing by a crash closes the same way.
  const crashed = randomUUID(), crashedArgs = { request_id: crashed, approval: { ...f.approval, parent_nonce: "1" } };
  f.chain.verifyRegistry = async () => {};
  assert.equal((await f.service.send("link_agent", crashedArgs)).status, "approval_required");
  await f.store.session(async s => { const journal = await Journal.open(s); await journal.transition(journal.data.records.find(r => r.requestId === crashed), "preparing"); });
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_already_linked", "Already linked"); };
  await assert.rejects(f.service.send("link_agent", crashedArgs), { code: "registry_already_linked" });
  assert.equal((await f.service.operation(crashed)).status, "failed");
});

test("an expired terminal approval still expires its link record", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval }, now = Date.now();
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  await f.service.approve(id, password, digest((await f.service.review(id)).records[0]));
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_approval_expired", "Portal approval expired"); };
  t.mock.method(Date, "now", () => now + 3_600_000);
  assert.equal((await f.service.send("link_agent", args)).status, "expired");
});

async function preRegistryWallet(t) {
  const base = withoutAgentRegistry(MAINNET), old = await fixture(t, { config: base });
  return { ...(await fixture(t, { root: old.root, existing: true })), base, parent: old.parent };
}

test("a wallet that has not approved the registry can resolve a pending operation, then approve", async t => {
  const f = await preRegistryWallet(t), id = randomUUID();
  assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted");
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  assert.equal((await f.service.review(id)).records.length, 1);
  await assert.rejects(approveCapabilities(f.store, f.base, MAINNET, password, digest(await reviewCapabilities(f.store, f.base, MAINNET))), { code: "operation_pending" });
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}` });
  assert.equal((await f.service.operation(id)).status, "confirmed");
  await approveCapabilities(f.store, f.base, MAINNET, password, digest(await reviewCapabilities(f.store, f.base, MAINNET)));
  assert.equal((await f.store.createOrLoad()).manifest_id, MAINNET.manifest.manifestId);
  f.chain.clients.splice(0, f.chain.clients.length);
  assert.equal((await f.service.registryStatus()).deployed, false);
});

test("an upgraded previous-implementation wallet can still check its pending operation", async t => {
  const base = withoutAgentRegistry(MAINNET), old = await fixture(t, { config: previousImplementationConfig(MAINNET) }), id = randomUUID();
  assert.equal((await old.service.send("transfer", transfer(id))).status, "submitted");
  const upgrade = new WalletStore(base, old.deps);
  await approveImplementation(upgrade, base, password, digest(await reviewImplementation(upgrade, base)));
  const f = await fixture(t, { root: old.root, existing: true });
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  await assert.rejects(approveCapabilities(f.store, base, MAINNET, password, digest(await reviewCapabilities(f.store, base, MAINNET))), { code: "operation_pending" });
});

test("registry use stays blocked until approval and nothing but approval grants it", async t => {
  const f = await preRegistryWallet(t), wallet = await f.store.createOrLoad(), id = randomUUID(), code = "capability_manifest_unapproved", a = await approval({ agent: wallet.account });
  await assert.rejects(f.service.registryStatus(), { code });
  assert.equal((await f.service.prepareAgentLink()).link_blocked, code);
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: a }), { code });
  // Unlink is refused for every wallet, before the approval check.
  await assert.rejects(f.service.send("unlink_agent", { request_id: id, parent }), { code: "registry_unlink_unsupported" });
  await f.store.session(async s => {
    assert.equal((await Journal.open(s)).data.records.length, 0);
    assert.throws(() => validateOperation(MAINNET, s.envelope, intent(a), {}, { nonce: 0n, deployed: false, hash: digestToSign }), { code });
  });

  // Saving a policy reseals the wallet, even one that lists registry permissions.
  await f.service.configure({ ...limits, agentRegistry: { parents: [parent], allowUnlink: true } }, password, false, digest([]));
  assert.equal((await f.store.createOrLoad()).manifest_id, f.base.manifest.manifestId);
  await assert.rejects(f.service.registryStatus(), { code });

  // So does restoring a backup.
  const recovery = Buffer.from("recovery passphrase for test"), out = join(f.parent, "backup.json"), target = await fixture(t, { existing: true }), restored = new WalletStore(MAINNET, target.deps);
  await backupWallet(MAINNET, f.store, out, password, recovery);
  await restoreWallet(MAINNET, restored, out, recovery);
  assert.equal((await restored.createOrLoad()).manifest_id, f.base.manifest.manifestId);

  // A transition must start from the manifest the wallet actually approved.
  const other = structuredClone(f.base);
  other.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
  other.manifest.manifestId = configurationId(other.manifest, "manifestId");
  await assert.rejects(reviewCapabilities(f.store, other, MAINNET), { code });
});

test("an RPC failure keeps a link request and its local approval retryable", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval }, down = async () => { throw new WalletError("registry_rpc_unavailable", "RPC down"); };
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  await f.service.approve(id, password, digest((await f.service.review(id)).records[0]));
  f.chain.verifyRegistry = down;
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_rpc_unavailable" });
  const interrupted = await f.service.operation(id);
  assert.equal(interrupted.status, "approval_required"); assert.equal(interrupted.last_error, "registry_rpc_unavailable");
  assert.ok(interrupted.reasons.length, "a real policy exception keeps its reasons");
  assert.doesNotMatch(interrupted.next_action, /not needed/);
  f.chain.verifyRegistry = async () => {};
  const recovered = await f.service.send("link_agent", args);
  assert.equal(recovered.status, "submitted"); assert.equal(recovered.last_error, undefined); assert.equal(recovered.next_action, undefined);

  const g = await registryFixture(t), fresh = randomUUID(), freshArgs = { request_id: fresh, approval: g.approval };
  let checks = 0;
  g.chain.verifyRegistry = async () => { if (++checks === 2) await down(); };
  await assert.rejects(g.service.send("link_agent", freshArgs), { code: "registry_rpc_unavailable" });
  const permitted = await g.service.operation(fresh);
  assert.equal(permitted.status, "approval_required"); assert.equal(permitted.reasons, undefined); assert.equal(permitted.last_error, "registry_rpc_unavailable");
  assert.match(permitted.next_action, /same request ID.*not needed/);
  const review = await g.service.review(fresh);
  await assert.rejects(g.service.approve(fresh, password, digest(review.records[0])), { code: "validation_failed" });
  const sent = await g.service.send("link_agent", freshArgs);
  assert.equal(sent.status, "submitted"); assert.equal(sent.last_error, undefined);
});

test("an RPC failure after an unapproved request is rebuilt drops reasons that may no longer describe it", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval }, simulate = f.chain.simulate;
  assert.ok((await f.service.send("link_agent", args)).reasons.length);
  // The retry rebuilds the operation, then the RPC fails before its policy is evaluated.
  f.chain.simulate = async () => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); };
  await assert.rejects(f.service.send("link_agent", args), { code: "rpc_unavailable" });
  const interrupted = await f.service.operation(id);
  assert.equal(interrupted.status, "approval_required"); assert.equal(interrupted.reasons, undefined); assert.match(interrupted.next_action, /not needed/);
  await assert.rejects(f.service.approve(id, password, digest((await f.service.review(id)).records[0])), { code: "validation_failed" });
  // Retrying evaluates the rebuilt operation and reports its own reasons.
  f.chain.simulate = simulate;
  const retried = await f.service.send("link_agent", args);
  assert.equal(retried.status, "approval_required"); assert.ok(retried.reasons.includes("registry_parent_not_allowed"));
});

test("a signed link the registry no longer accepts names the replacement that frees its nonce", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
  f.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await f.service.send("link_agent", args)).status, "signed");
  f.service.submit = submit;
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_approval_stale", "Parent nonce changed; obtain a fresh Portal approval"); };
  const replace = new RegExp(`wallet operation resolve ${id} --replace.*fresh Portal approval with a new request ID`);
  await assert.rejects(f.service.send("link_agent", args), error => error.code === "registry_approval_stale" && /^registry_approval_stale: Parent nonce changed; obtain a fresh Portal approval\. Signed request/.test(error.message) && replace.test(error.message));
  await assert.rejects(f.service.resolve(id, password), error => error.code === "registry_approval_stale" && replace.test(error.message));
  assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
  // Refusals that can clear, such as a temporary RPC failure, an unverifiable read, a full parent or a policy shortened after signing, are not a reason to replace anything.
  for (const [code, message] of [["registry_rpc_unavailable", "RPC down"], ["registry_verification_failed", "Registry state could not be verified"], ["registry_limit_reached", "Parent has reached its agent limit; unlink an agent in Portal first"], ["registry_approval_outlasts_policy", "Portal approval lasts past the local wallet policy's expiry; renew the policy with incentiv-mcp setup in your local terminal, or obtain a fresh approval"]]) {
    f.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
    await assert.rejects(f.service.send("link_agent", args), error => error.code === code && error.message === `${code}: ${message}`);
  }
  assert.equal((await f.service.operation(id)).status, "signed");
});

test("a signed registry request names the replacement that frees its nonce after a release drops the registry", async t => {
  const id = randomUUID(), old = await registryFixture(t), submit = old.service.submit;
  old.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await old.service.send("link_agent", { request_id: id, approval: old.approval })).status, "signed");
  old.service.submit = submit;
  const f = await fixture(t, { root: old.root, existing: true, config: withoutAgentRegistry(MAINNET) });
  await assert.rejects(f.service.resolve(id, password), error => error.code === "registry_unavailable" && new RegExp(`does not include the Agent Registry.*wallet operation resolve ${id} --replace`).test(error.message));
  assert.equal(f.submissions.length, 0);
});

test("a wallet that approved older registry pins keeps working and approves new pins without a config file", async t => {
  const next = structuredClone(MAINNET), code = "capability_manifest_unapproved", id = randomUUID(), base = withoutAgentRegistry(MAINNET);
  next.manifest.agentRegistry.implementation.codeHash = `0x${"12".repeat(32)}`;
  next.manifest.manifestId = configurationId(next.manifest, "manifestId");
  const old = await fixture(t);
  assert.equal((await old.service.send("transfer", transfer(id))).status, "submitted");
  const f = await fixture(t, { root: old.root, existing: true, config: next }), approval = store => store.session(async s => [s.envelope.approvedCapabilityManifestId, s.envelope.registryFreeManifestId]);
  const held = [MAINNET.manifest.manifestId, base.manifest.manifestId];

  // The pending operation stays reachable, and resolves, under the new release.
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  await assert.rejects(f.service.registryStatus(), { code });
  const previous = withoutAgentRegistry(next);
  await assert.rejects(approveCapabilities(f.store, previous, next, password, digest(await reviewCapabilities(f.store, previous, next))), { code: "operation_pending" });
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}` });
  assert.equal((await f.service.operation(id)).status, "confirmed");
  assert.equal((await f.service.send("transfer", transfer(randomUUID()))).status, "submitted");
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"22".repeat(32)}` });
  await f.service.review();

  // Neither saving a policy nor restoring a backup approves the new pins.
  await f.service.configure(limits, password, false, digest([]));
  assert.deepEqual(await approval(f.store), held);
  await assert.rejects(f.service.registryStatus(), { code });
  const recovery = Buffer.from("recovery passphrase for test"), out = join(old.parent, "backup.json"), target = await fixture(t, { existing: true, config: next });
  await backupWallet(next, f.store, out, password, recovery);
  await restoreWallet(next, target.store, out, recovery);
  assert.deepEqual(await approval(target.store), held);

  // An unrelated previous manifest is still refused; the derived one is the reviewed route.
  const other = structuredClone(previous);
  other.manifest.contracts.swapRouter.codeHash = `0x${"34".repeat(32)}`;
  other.manifest.manifestId = configurationId(other.manifest, "manifestId");
  await assert.rejects(reviewCapabilities(f.store, other, next), { code });
  // The review says these pins replace older ones; once approved there is nothing left to say.
  const pinReview = await reviewCapabilities(f.store, previous, next);
  assert.match(pinReview.note, /previously approved different Agent Registry pins/);
  await approveCapabilities(f.store, previous, next, password, digest(pinReview));
  assert.deepEqual(await approval(f.store), [next.manifest.manifestId, base.manifest.manifestId]);
  assert.equal((await reviewCapabilities(f.store, previous, next)).note, undefined);
  f.chain.clients.splice(0, f.chain.clients.length);
  assert.equal((await f.service.registryStatus()).deployed, false);
});

test("a registry request signed under older pins names the replacement that clears it after a pin update", async t => {
  const next = structuredClone(MAINNET), id = randomUUID(), replace = new RegExp(`wallet operation resolve ${id} --replace`);
  next.manifest.agentRegistry.implementation.codeHash = `0x${"12".repeat(32)}`;
  next.manifest.manifestId = configurationId(next.manifest, "manifestId");
  const old = await registryFixture(t), submit = old.service.submit;
  old.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await old.service.send("link_agent", { request_id: id, approval: old.approval })).status, "signed");
  old.service.submit = submit;

  // Under the new release the signed link can't be sent, and approving the new pins waits for its nonce: both name the way out.
  const f = await fixture(t, { root: old.root, existing: true, config: next }), previous = withoutAgentRegistry(next);
  await assert.rejects(f.service.resolve(id, password), error => error.code === "capability_manifest_unapproved" && replace.test(error.message));
  await assert.rejects(approveCapabilities(f.store, previous, next, password, digest(await reviewCapabilities(f.store, previous, next))), error => error.code === "operation_pending" && replace.test(error.message));
  assert.equal(f.submissions.length, 0);

  // That replacement goes through, and then the new pins can be approved.
  const record = (await f.service.reviewReplacement(id, true)).records[0];
  assert.equal((await f.service.replace(id, password, digest(record))).status, "superseding");
  f.chain.receipt = async r => r.userOpHash === record.replacement.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"44".repeat(32)}` } : undefined;
  assert.equal((await f.service.operation(id)).status, "superseded");
  await approveCapabilities(f.store, previous, next, password, digest(await reviewCapabilities(f.store, previous, next)));
  assert.equal((await f.store.createOrLoad()).manifest_id, next.manifest.manifestId);
});

test("a changed base manifest is still refused even with a registry-free approval on record", async t => {
  const f = await fixture(t), changed = structuredClone(MAINNET);
  changed.manifest.contracts.swapRouter.codeHash = `0x${"56".repeat(32)}`;
  changed.manifest.manifestId = configurationId(changed.manifest, "manifestId");
  await assert.rejects(new WalletStore(changed, f.deps).createOrLoad(), { code: "capability_manifest_unapproved" });
});

test("a mined link with no registry event settles and says so instead of holding the nonce", async t => {
  const f = await registryFixture(t), id = randomUUID();
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "submitted");
  f.chain.receipt = async () => ({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}`, registryError: "registry_event_missing" });
  const settled = await f.service.operation(id);
  assert.equal(settled.status, "confirmed"); assert.equal(settled.registry_error, "registry_event_missing");
  assert.match(settled.next_action, /get_agent_registry_status/);
  await f.store.session(async s => assert.ok(!(await Journal.open(s)).data.records.some(r => ownsNonce(r.status))));
});

test("one Portal approval cannot fill the journal under new request IDs", async t => {
  const f = await registryFixture(t, false), args = id => ({ request_id: id, approval: f.approval }), first = randomUUID();
  assert.equal((await f.service.send("link_agent", args(first))).status, "approval_required");
  await assert.rejects(f.service.send("link_agent", args(randomUUID())), error => error.code === "operation_pending" && error.message.includes(first));
  const close = () => f.store.session(async s => { const journal = await Journal.open(s), open = journal.data.records.find(r => r.status === "approval_required"); await journal.transition(open, "preparing"); await journal.transition(open, "failed"); });
  await close();
  for (let i = 1; i < 8; i++) { assert.equal((await f.service.send("link_agent", args(randomUUID()))).status, "approval_required"); await close(); }
  await assert.rejects(f.service.send("link_agent", args(randomUUID())), { code: "policy_denied" });
  await f.store.session(async s => assert.equal((await Journal.open(s)).data.records.length, 8));
  // A different gas token does not make the same approval count as new.
  const token = f.chain.token, usdc = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase();
  f.chain.token = async ref => ref === "USDC" ? { address: usdc, decimals: 6, symbol: "USDC", name: "test" } : token.call(f.chain, ref);
  await assert.rejects(f.service.send("link_agent", { ...args(randomUUID()), gas_token: "USDC" }), error => error.code === "policy_denied" && /tried too many times/.test(error.message));
  f.chain.token = token;
  const fresh = { ...f.approval, parent_deadline: String(Number(f.approval.parent_deadline) + 60) };
  assert.equal((await f.service.send("link_agent", { request_id: randomUUID(), approval: fresh })).status, "approval_required");
});

test("an RPC outage elsewhere in preparation keeps a request retryable; other errors still close it", async t => {
  const f = await fixture(t), id = randomUUID(), balances = f.chain.balances;
  f.chain.balances = async () => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); };
  await assert.rejects(f.service.send("transfer", transfer(id)), { code: "rpc_unavailable" });
  const interrupted = await f.service.operation(id);
  assert.equal(interrupted.status, "approval_required"); assert.equal(interrupted.last_error, "rpc_unavailable"); assert.match(interrupted.next_action, /same request ID/);
  f.chain.balances = balances;
  const sent = await f.service.send("transfer", transfer(id));
  assert.equal(sent.status, "submitted"); assert.equal(sent.last_error, undefined);

  // Configured RPCs that disagree, one lagging behind say, are an outage too.
  for (const stage of ["state", "balances"]) {
    const h = await fixture(t), lagging = randomUUID(), original = h.chain[stage];
    h.chain[stage] = async () => { throw new RpcDisagreementError(`RPC ${stage} disagree`); };
    await assert.rejects(h.service.send("transfer", transfer(lagging)), { code: "rpc_unavailable" });
    assert.equal((await h.service.operation(lagging)).status, "approval_required", stage);
    h.chain[stage] = original;
    assert.equal((await h.service.send("transfer", transfer(lagging))).status, "submitted", stage);
  }

  const g = await fixture(t), other = randomUUID();
  g.chain.balances = async () => { throw new Error("local bug"); };
  await assert.rejects(g.service.send("transfer", transfer(other)), { code: "validation_failed" });
  assert.equal((await g.service.operation(other)).status, "failed");
});

test("an agent that is itself a parent is ineligible, judged by its agent count", async () => {
  const a = await approval(), good = client();
  const isParent = client({ readContract: async opts => opts.functionName === "agentCount" && opts.args[0].toLowerCase() === agent.toLowerCase() ? 1n : good.readContract(opts) });
  await assert.rejects(verifyRegistryIntent(isParent, MAINNET, { account: agent }, intent(a), state()), { code: "registry_ineligible" });
});

test("mixed registry verdicts preserve an exact local approval until the RPCs agree", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval };
  const good = client();
  const stale = client({ readContract: async call => call.functionName === "nonces" ? 1n : good.readContract(call) });
  f.chain.verifyRegistry = WalletChain.prototype.verifyRegistry;
  const currentState = f.chain.state.bind(f.chain);
  f.chain.state = async wallet => ({ ...await currentState(wallet), block: 123n });
  f.chain.clients.splice(0, f.chain.clients.length, good, good);
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  await f.service.approve(id, password, digest((await f.service.review(id)).records[0]));
  const approved = (await f.service.review(id)).records[0].approval;

  f.chain.clients.splice(0, 2, stale, good);
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_rpc_unavailable" });
  const interrupted = (await f.service.review(id)).records[0];
  assert.equal(interrupted.status, "approval_required");
  assert.deepEqual(interrupted.approval, approved);
  assert.equal(f.submissions.length, 0);

  f.chain.clients.splice(0, 2, good, good);
  assert.equal((await f.service.send("link_agent", args)).status, "submitted");
  f.chain.clients.splice(0, 2, stale, stale);
  await assert.rejects(f.store.session(s => f.chain.verifyRegistry(s.envelope, intent(f.approval))), { code: "registry_approval_stale" });
});

test("a temporary RPC error does not outlive the record state it explained", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval }, now = Date.now();
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  await f.service.approve(id, password, digest((await f.service.review(id)).records[0]));
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_rpc_unavailable", "RPC down"); };
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_rpc_unavailable" });
  t.mock.method(Date, "now", () => now + 3_600_000);
  const expired = await f.service.send("link_agent", args);
  assert.equal(expired.status, "expired"); assert.equal(expired.last_error, undefined);
});

test("registry reads report RPC failures as temporary", async t => {
  const f = await fixture(t), code = "registry_rpc_unavailable";
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  f.chain.state = async () => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); };
  await assert.rejects(f.service.registryStatus(), { code });
  await assert.rejects(f.service.prepareAgentLink(), { code });
  const a = await approval(), stale = Math.floor(Date.now() / 1000) - 120;
  await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(a), { ...state(), timestamp: stale }), { code });
});

test("prepare_agent_link only sends the user to Portal when linking can succeed", async t => {
  const f = await fixture(t), linkable = { parent: zero, agent_is_parent: false, agent_eligible: false, factory_allowed: true, deployed: false };
  const prepared = async status => { f.chain.registryStatus = async () => ({ ...linkable, ...status }); return f.service.prepareAgentLink(); };
  // A policy that allows no Portal account could not use the approval.
  const noParent = await prepared({});
  assert.equal(noParent.link_blocked, "registry_parent_not_allowed"); assert.equal(noParent.portal_url, undefined); assert.match(noParent.next_action, /allows no Portal account/);
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  const ready = await prepared({});
  assert.ok(ready.portal_url); assert.equal(ready.link_blocked, undefined);
  for (const [status, code] of [[{ parent }, "registry_already_linked"], [{ agent_is_parent: true }, "registry_ineligible"], [{ factory_allowed: false }, "registry_factory_not_allowed"], [{ deployed: true }, "registry_ineligible"], [{ deployed: true, factory_allowed: false }, "registry_factory_not_allowed"]]) {
    const blocked = await prepared(status);
    assert.equal(blocked.link_blocked, code); assert.equal(blocked.portal_url, undefined); assert.match(blocked.next_action, /Do not ask the user to sign/);
  }
});

test("a disallowed factory refuses an undeployed agent, and a deployed one only once the registry no longer counts it", async () => {
  const a = await approval(), good = client();
  const registry = eligible => client({ readContract: async opts => opts.functionName === "isAccountFactory" ? false : opts.functionName === "isIncentivAccount" && opts.args[0].toLowerCase() === agent.toLowerCase() ? eligible : good.readContract(opts) });
  await verifyRegistryIntent(registry(true), MAINNET, { account: agent }, intent(a), { ...state(), deployed: true });
  await assert.rejects(verifyRegistryIntent(registry(true), MAINNET, { account: agent }, intent(a), state()), { code: "registry_factory_not_allowed" });
  // The registry counts a deployed agent through its factory, so removing that factory is the same temporary refusal, not a paid replacement.
  await assert.rejects(verifyRegistryIntent(registry(false), MAINNET, { account: agent }, intent(a), { ...state(), deployed: true }), { code: "registry_factory_not_allowed" });
  assert.deepEqual(linkBlocker({ parent: zero, agent_is_parent: false, agent_eligible: false, factory_allowed: true }, true)?.[0], "registry_ineligible");
});

test("the upgrade command only points a current wallet to capability approval when it is pending", async t => {
  const base = withoutAgentRegistry(MAINNET), f = await fixture(t, { config: base }), store = new WalletStore(MAINNET, f.deps);
  await f.store.createOrLoad();
  assert.equal((await reviewUpgrade(f.store, base)).registryPending, false);
  const pending = await reviewUpgrade(store, MAINNET);
  assert.equal(pending.review.wallet.network_id, MAINNET.identity.networkId); assert.equal(pending.registryPending, true);
  await approveCapabilities(store, base, MAINNET, password, digest(await reviewCapabilities(store, base, MAINNET)));
  const approved = await reviewUpgrade(store, MAINNET);
  assert.equal(approved.review.wallet.network_id, MAINNET.identity.networkId); assert.equal(approved.registryPending, false);
});

test("an RPC failure during signature validation is not reported as an invalid signature", async () => {
  const a = await approval(), good = client();
  const parentCall = respond => client({ readContract: async opts => {
    if (opts.functionName !== "isValidSignature") return good.readContract(opts);
    return createPublicClient({ transport: custom({ request: async () => respond() }, { retryCount: 0 }) }).readContract(opts);
  } });
  const check = c => verifyRegistryIntent(c, MAINNET, { account: agent }, intent(a), state());
  await assert.rejects(check(parentCall(() => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); })), error => !(error instanceof WalletError) && /429|HTTP/.test(error.message));
  await assert.rejects(check(parentCall(() => { throw Object.assign(new Error("execution reverted"), { code: 3, data: "0x" }); })), { code: "registry_approval_invalid" });
  for (const message of ["internal error", "missing trie node"]) await assert.rejects(check(parentCall(() => { throw Object.assign(new Error(message), { code: -32603 }); })), error => !(error instanceof WalletError));
  await assert.rejects(check(parentCall(() => { throw Object.assign(new Error("execution reverted"), { code: -32603 }); })), { code: "registry_approval_invalid" });
  await assert.rejects(check(parentCall(() => "0x")), { code: "registry_approval_invalid" });
  const chain = new WalletChain(new Ctx(MAINNET));
  chain.clients.splice(0, chain.clients.length, parentCall(() => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); }));
  const approved = { account: agent, approvedCapabilityManifestId: MAINNET.manifest.manifestId };
  await assert.rejects(chain.verifyRegistry(approved, intent(a), state()), { code: "registry_rpc_unavailable" });

  // A contract that refuses a read will keep refusing, so "retry" would be wrong.
  const domainCall = respond => client({ readContract: async opts => opts.functionName !== "eip712Domain" ? good.readContract(opts) : createPublicClient({ transport: custom({ request: async () => respond() }, { retryCount: 0 }) }).readContract(opts) });
  chain.clients.splice(0, 1, domainCall(() => { throw Object.assign(new Error("execution reverted"), { code: 3, data: "0x" }); }));
  await assert.rejects(chain.verifyRegistry(approved, intent(a), state()), { code: "registry_verification_failed" });
  chain.clients.splice(0, 1, domainCall(() => { throw Object.assign(new Error("internal error"), { code: -32603 }); }));
  await assert.rejects(chain.verifyRegistry(approved, intent(a), state()), { code: "registry_rpc_unavailable" });
  chain.clients.splice(0, 1, domainCall(() => { throw Object.assign(new Error("header not found"), { code: -32000 }); }));
  await assert.rejects(chain.verifyRegistry(approved, intent(a), state()), { code: "registry_rpc_unavailable" });
  // Malformed return data repeats on every retry, so it is not reported as temporary.
  chain.clients.splice(0, 1, domainCall(() => "0x01"));
  await assert.rejects(chain.verifyRegistry(approved, intent(a), state()), { code: "registry_verification_failed" });
});

test("a revert reported as -32603 is not a transport failure", async () => {
  const read = respond => createPublicClient({ transport: custom({ request: async () => respond() }, { retryCount: 0 }) })
    .readContract({ address: cap.proxy.address, abi: agentRegistryAbi, functionName: "eip712Domain" }).then(() => assert.fail("expected a rejection"), error => error);
  assert.equal(isTransportFailure(await read(() => { throw Object.assign(new Error("execution reverted"), { code: -32603 }); })), false);
  assert.equal(isTransportFailure(await read(() => { throw Object.assign(new Error("internal error"), { code: -32603 }); })), true);
  assert.equal(isTransportFailure(await read(() => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 429 }); })), true);
  // A lagging node's -32000 is temporary; a -32000 revert without data is the contract's answer.
  for (const message of ["header not found", "missing trie node"]) assert.equal(isTransportFailure(await read(() => { throw Object.assign(new Error(message), { code: -32000 }); })), true, message);
  assert.equal(isTransportFailure(await read(() => { throw Object.assign(new Error("execution reverted"), { code: -32000 }); })), false);
});

test("a link retried near its deadline gets recovery guidance instead of a tampering error", async t => {
  const f = await registryFixture(t), id = randomUUID(), now = Date.now(), relay = f.chain.relay;
  f.chain.verifyRegistry = async () => {};
  const args = { request_id: id, approval: { ...f.approval, parent_deadline: String(Math.floor(now / 1000) + 15) } };
  f.chain.relay = async () => { throw new Error("lost response"); };
  assert.equal((await f.service.send("link_agent", args)).status, "submission_unknown");
  f.chain.relay = relay;
  t.mock.method(Date, "now", () => now + 8_000);
  await assert.rejects(f.service.send("link_agent", args), { code: "operation_pending" });
});

test("registry errors produce bounded actionable codes without forwarding raw revert data", () => {
  for (const [errorName, args, expected] of [["NotLinked", [agent], "registry_link_changed"], ["SelfLink", [], "registry_ineligible"], ["InvalidAgentSignature", [], "registry_agent_signature_invalid"], ["InvalidParentSignature", [], "registry_approval_invalid"], ["SignatureExpired", [1n], "registry_approval_expired"], ["AgentLimitReached", [parent, 5n], "registry_limit_reached"]]) {
    assert.equal(registryRevertCode(encodeErrorResult({ abi: agentRegistryAbi, errorName, args })), expected);
  }
  assert.equal(registryRevertCode("0x1234"), undefined);
});

test("token-paid linking reserves only the exact paymaster transfer and rejects a hidden extra payment", async () => {
  const token = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase(), a = await approval();
  const i = { ...intent(a), token, gasToken: token }, wallet = { account: agent, owner: owner.address, approvedCapabilityManifestId: MAINNET.manifest.manifestId };
  const built = unsigned(wallet, { to: parent, amount: "0" }, { deployed: false, nonce: 0n });
  Object.assign(built.op, { paymaster: MAINNET.manifest.contracts.unifiedTokenPaymaster.address, paymasterData: "0x", paymasterVerificationGasLimit: 100n, paymasterPostOpGasLimit: 100n });
  const erc20 = (await import('../src/abi.ts')).erc20Abi;
  const gasCall = { to: token, value: 0n, data: encodeFunctionData({ abi: erc20, functionName: "transfer", args: [built.op.paymaster, 123n] }) };
  const check = calls => {
    built.op.callData = encodeExecuteBatch(calls);
    const hash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return validateOperation(MAINNET, wallet, i, userOpToJson(built.op), { nonce: 0n, deployed: false, hash, deadline: Number(a.parent_deadline) });
  };
  assert.deepEqual(check([gasCall, registryCall(MAINNET, agent, i)]).spend, { [token]: "123" });
  assert.throws(() => check([gasCall, gasCall, registryCall(MAINNET, agent, i)]), { code: "validation_failed" });
});

test("expired signed links keep nonce ownership and reservations until resolved", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval };
  await f.service.send("link_agent", args);
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].deadline = 1; await journal.save(); });
  await assert.rejects(f.service.send("link_agent", args), { code: "operation_pending" });
  assert.equal(f.submissions.length, 1);
  await f.store.session(async s => { const r = (await Journal.open(s)).data.records[0]; assert.ok(ownsNonce(r.status)); assert.deepEqual(r.reservation, { native: "300" }); });
});

async function tokenRegistryFixture(t) {
  const f = await registryFixture(t), token = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase();
  await f.store.session(async s => {
    const policy = s.envelope.policy;
    await s.savePolicy({ ...policy, limits: { ...policy.limits, tokens: { ...policy.limits.tokens, [token]: { perTransaction: "10000", daily: "1000000", exposure: "10000000", gasPayment: "10000" } }, targets: { ...policy.limits.targets, [token]: ["0xa9059cbb"] } } });
  });
  f.chain.token = async ref => ({ address: ref === "USDC" || ref === token ? token : "native", decimals: 6, symbol: ref === "USDC" || ref === token ? "USDC" : "CENT", name: "test" });
  f.chain.balances = async (_wallet, tokens) => Object.fromEntries(tokens.map(id => [id.toLowerCase(), id.toLowerCase() === token ? "1000000" : "0"]));
  const erc20 = (await import('../src/abi.ts')).erc20Abi;
  const build = (wallet, i, state, replacing = false) => {
    const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
    const payment = replacing ? 150n : 123n;
    Object.assign(built.op, { paymaster: MAINNET.manifest.contracts.unifiedTokenPaymaster.address, paymasterData: "0x", paymasterVerificationGasLimit: 100n, paymasterPostOpGasLimit: 100n });
    if (replacing) { built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n; }
    built.op.callData = encodeExecuteBatch([
      { to: token, value: 0n, data: encodeFunctionData({ abi: erc20, functionName: "transfer", args: [built.op.paymaster, payment] }) },
      replacing ? { to: wallet.account, value: 0n, data: "0x" } : registryCall(MAINNET, wallet.account, i),
    ]);
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return built;
  };
  f.chain.build = (wallet, i, state) => build(wallet, i, state);
  f.chain.buildReplacement = (wallet, original, state) => build(wallet, original.intent, state, true);
  return { ...f, token };
}

test("a stale link can be replaced and retried with USDC and zero native CENT", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID();
  let checks = 0;
  f.chain.verifyRegistry = async () => { if (++checks >= 3) throw new (await import('../src/wallet/errors.ts')).WalletError("registry_approval_stale", "Parent nonce changed"); };
  const args = { request_id: id, approval: f.approval, gas_token: "USDC" };
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_approval_stale" });
  assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
  await assert.rejects(f.service.send("link_agent", { ...args, request_id: randomUUID() }), { code: "operation_pending" });
  const buildReplacement = f.chain.buildReplacement, simulate = f.chain.simulate;
  f.chain.buildReplacement = () => { throw new Error("paymaster quote failed"); };
  await assert.rejects(f.service.reviewReplacement(id), error => error.code === "validation_failed" && /--native-gas/.test(error.message));
  await assert.rejects(f.service.reviewReplacement(id, true), error => error.code === "validation_failed" && !/--native-gas/.test(error.message));
  f.chain.buildReplacement = buildReplacement;
  f.chain.simulate = async () => { throw new WalletError("simulation_failed", "Simulation failed"); };
  await assert.rejects(f.service.reviewReplacement(id), error => error.code === "simulation_failed" && /Simulation failed\..*--native-gas/.test(error.message));
  f.chain.simulate = simulate;
  const review = await f.service.reviewReplacement(id), record = review.records[0];
  assert.equal(record.replacement.gasToken, f.token); assert.equal(record.replacement.gasCharge, "150");
  assert.equal(record.replacement.operation.paymaster, MAINNET.manifest.contracts.unifiedTokenPaymaster.address);
  assert.equal(record.replacement.operation.nonce, record.operation.nonce);
  const balances = f.chain.balances;
  f.chain.balances = async () => ({ [f.token]: "0" });
  await assert.rejects(f.service.replace(id, password, digest(record)), error => error.code === "policy_denied" && /--native-gas/.test(error.message));
  f.chain.balances = balances;
  assert.equal((await f.service.replace(id, password, digest(record))).status, "superseding");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "273" }));
  f.chain.receipt = async r => r.userOpHash === record.replacement.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"44".repeat(32)}` } : undefined;
  assert.equal((await f.service.operation(id)).status, "superseded");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "150" }));
  f.chain.receipt = async () => undefined; f.chain.verifyRegistry = async () => {};
  const state = f.chain.state;
  f.chain.state = async (...a) => ({ ...await state(...a), nonce: 1n });
  assert.equal((await f.service.send("link_agent", { ...args, request_id: randomUUID(), approval: { ...f.approval, parent_nonce: "1" } })).status, "submitted");
});

test("when the original token-paid link wins, only its gas payment is consumed", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID();
  await f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" });
  const review = await f.service.reviewReplacement(id), record = review.records[0];
  await f.service.replace(id, password, digest(record));
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "273" }));
  f.chain.receipt = async r => r.userOpHash === record.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"55".repeat(32)}` } : undefined;
  assert.equal((await f.service.operation(id)).status, "confirmed");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "123" }));
});

test("uncertain token-paid replacement retries exact signed bytes and retains both reservations", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval, gas_token: "USDC" };
  await f.service.send("link_agent", args);
  const review = await f.service.reviewReplacement(id), relay = f.chain.relay;
  f.chain.relay = async (...a) => { await relay(...a); throw new Error("lost replacement response"); };
  await f.service.replace(id, password, digest(review.records[0]));
  f.chain.relay = relay;
  await f.service.send("link_agent", args);
  assert.deepEqual(f.submissions[1], f.submissions[2]);
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "273" }));
});

test("a stuck token-paid link can be replaced with native gas when requested", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID(), balances = f.chain.balances;
  await f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" });
  f.chain.balances = async (...a) => ({ ...await balances(...a), native: "1000000" });
  f.chain.buildReplacement = (wallet, original, state, gasToken) => {
    assert.equal(gasToken, "native");
    const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
    built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n;
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return built;
  };
  const record = (await f.service.reviewReplacement(id, true)).records[0];
  assert.equal(record.replacement.gasToken, undefined); assert.equal(record.replacement.operation.paymaster, undefined);
  assert.equal(record.replacement.operation.nonce, record.operation.nonce);
  assert.equal((await f.service.replace(id, password, digest(record))).status, "superseding");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "123", native: record.replacement.maxGasCost }));
  f.chain.receipt = async r => r.userOpHash === record.replacement.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"66".repeat(32)}` } : undefined;
  assert.equal((await f.service.operation(id)).status, "superseded");
  await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { native: "400" }));
});

test("replacement validation rejects a changed token payment before signing", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID();
  await f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" });
  await f.service.reviewReplacement(id);
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].replacement.gasCharge = "151"; await journal.save(); });
  const review = await f.service.review(id);
  await assert.rejects(f.service.replace(id, password, digest(review.records[0])), { code: "validation_failed" });
  assert.equal(f.submissions.length, 1);
  await f.store.session(async s => { const record = (await Journal.open(s)).data.records[0]; assert.equal(record.replacement.signed, false); assert.deepEqual(record.reservation, { [f.token]: "123" }); });
});


test("registry reverts expose actionable error and fresh-consent guidance through the wallet service", async t => {
  const f = await registryFixture(t), id = randomUUID();
  await f.service.send("link_agent", { request_id: id, approval: f.approval });
  f.setReceipt({ success: false, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}`, registryError: "registry_approval_invalid" });
  const result = await f.service.operation(id);
  assert.equal(result.status, "reverted");
  assert.equal(result.registry_error, "registry_approval_invalid");
  assert.match(result.next_action, /fresh approval in Portal/);
});

// Builds an unlink record the way an earlier build did: the stubbed check lets it through, the user approved it in the
// terminal, reconcile did not yet cancel unlinks awaiting approval, and submission did not yet refuse them.
async function legacyUnlink(f, id, { approve = true } = {}) {
  const { reconcile, refuseUnlink } = f.service;
  f.service.reconcile = async () => {};
  f.service.refuseUnlink = () => {};
  try {
    assert.equal((await f.service.send("unlink_agent", { request_id: id, parent })).status, "approval_required");
    if (!approve) return;
    await f.service.approve(id, password, digest((await f.service.review(id)).records[0]));
    return await f.service.send("unlink_agent", { request_id: id, parent });
  } finally { f.service.reconcile = reconcile; f.service.refuseUnlink = refuseUnlink; }
}

test("an unlink an earlier build left awaiting approval is cancelled and never warned about", async t => {
  const f = await signedLinkFixture(t), id = randomUUID();
  await legacyUnlink(f, id, { approve: false });
  const signed = await f.service.signAgentLink(parent);
  assert.equal(signed.agent_signed, true); assert.equal(signed.warning, undefined);
  const record = await f.service.operation(id);
  assert.equal(record.status, "cancelled"); assert.equal(record.last_error, "registry_unlink_unsupported");
  assert.equal(f.submissions.length, 0);
});

test("sign_agent_link points a signed or unconfirmed legacy unlink to a replacement, not to a removed tool", async t => {
  for (const lost of [false, true]) {
    const f = await signedLinkFixture(t), id = randomUUID(), relay = f.chain.relay, revalidate = f.service.revalidate;
    // Lost in flight it is submission_unknown; refused before sending it stays signed.
    if (lost) f.chain.relay = async () => { throw new Error("lost response"); };
    else f.service.revalidate = async () => { throw new WalletError("rpc_unavailable", "down"); };
    await legacyUnlink(f, id).catch(() => {});
    f.chain.relay = relay; f.service.revalidate = revalidate;
    assert.equal((await f.service.operation(id)).status, lost ? "submission_unknown" : "signed");
    const refused = await f.service.signAgentLink(parent);
    assert.equal(refused.link_blocked, "operation_pending");
    assert.match(refused.next_action, new RegExp(`wallet operation resolve ${id} --replace`));
    assert.doesNotMatch(refused.next_action, /Retry unlink_agent/);
    assert.deepEqual(f.calls, []);
  }
});

test("an unlink recorded by an earlier build still reconciles, and is never retried or sent to Portal", async t => {
  const f = await registryFixture(t), id = randomUUID();
  await legacyUnlink(f, id);
  assert.equal(f.submissions.length, 1);
  f.setReceipt({ success: false, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}`, registryError: "registry_link_changed" });
  const unlinked = await f.service.operation(id);
  assert.equal(unlinked.status, "reverted"); assert.equal(unlinked.registry_error, "registry_link_changed");
  assert.match(unlinked.next_action, /no longer linked.*no Portal approval is needed/); assert.doesNotMatch(unlinked.next_action, /fresh approval|retry/i);

  const g = await registryFixture(t), linkId = randomUUID();
  await g.service.send("link_agent", { request_id: linkId, approval: g.approval });
  g.setReceipt({ success: false, actualGasCost: 200n, transactionHash: `0x${"22".repeat(32)}`, registryError: "registry_limit_reached" });
  const limited = await g.service.operation(linkId);
  assert.equal(limited.registry_error, "registry_limit_reached"); assert.match(limited.next_action, /refused this link \(registry_limit_reached\).*get_agent_registry_status/);
});

test("a signed unlink from an earlier build is never resent and points to a same-nonce replacement", async t => {
  const f = await registryFixture(t), id = randomUUID(), relay = f.chain.relay;
  f.chain.relay = async () => { throw new Error("lost response"); };
  await legacyUnlink(f, id).catch(() => {});
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  f.chain.relay = relay;
  f.chain.verifyRegistry = WalletChain.prototype.verifyRegistry; // the real check
  await assert.rejects(f.service.send("unlink_agent", { request_id: id, parent }), e => e.code === "registry_unlink_unsupported" && e.message.includes(`wallet operation resolve ${id} --replace`));
  // wallet operation resolve <id> without --replace, once the terminal approval has expired: refused before policy,
  // with the same guidance rather than a bare policy denial.
  await f.store.session(async s => { const journal = await Journal.open(s), r = journal.data.records.find(r => r.requestId === id); r.approval.expiresAt = 1; await journal.save(); });
  await assert.rejects(f.service.resolve(id, password), e => e.code === "registry_unlink_unsupported" && e.message.includes(`wallet operation resolve ${id} --replace`));
  // A disabled wallet does not hide that guidance either.
  await f.store.disable();
  await assert.rejects(f.service.resolve(id, password), e => e.code === "registry_unlink_unsupported" && e.message.includes(`wallet operation resolve ${id} --replace`));
  assert.equal(f.submissions.length, 0);
});

test("the agent-link digest matches the mainnet registry", () => {
  // agentLinkDigest(0x…02, 0x…03, 1900000000) read from the mainnet proxy, where 0x…03 has nonce 0.
  assert.equal(agentLinkDigest(MAINNET, "0x0000000000000000000000000000000000000003", parent, 0n, 1900000000n), "0xb6e5540180a89bd960609763d2464a49209c61af3b0bb2c11766dad62dee249b");
});

test("the agent signs only a locally computed digest that the registry agrees with", async () => {
  const read = await readAgentLinkDigest(client(), MAINNET, agent, parent, 1900000000n, 123n);
  assert.deepEqual(read, { nonce: 0n, digest: agentLinkDigest(MAINNET, agent, parent, 0n, 1900000000n) });
  const c = client(), good = c.readContract;
  c.readContract = args => args.functionName === "agentLinkDigest" ? Promise.resolve(digestToSign) : good(args);
  await assert.rejects(readAgentLinkDigest(c, MAINNET, agent, parent, 1900000000n, 123n), { code: "registry_verification_failed" });
  const signed = await owner.signMessage({ message: { raw: read.digest } });
  await assertAgentSignature(client(), agent, read.digest, signed, 123n);
  const stranger = privateKeyToAccount(`0x${"02".padStart(64, "0")}`);
  await assert.rejects(assertAgentSignature(client(), agent, read.digest, await stranger.signMessage({ message: { raw: read.digest } }), 123n), { code: "registry_agent_signature_invalid" });
});

async function signedLinkFixture(t, allowed = true, status = {}, policy = {}, options = {}) {
  const f = await registryFixture(t, allowed, options), calls = [];
  if (Object.keys(policy).length) await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, ...policy } }));
  f.chain.agentLinkConsent = async (_wallet, requested, notAfter) => {
    calls.push(["consent", requested, notAfter]);
    const current = { parent: zero, agent: f.approval.agent, agent_is_parent: false, agent_eligible: true, factory_allowed: true, max_agents: "5", requested_parent: requested, parent_eligible: true, parent_is_agent: false, parent_agent_count: "0", parent_nonce: "0", deployed: true, ...status };
    const soon = current.deployed && notAfter !== undefined && notAfter < Math.floor(Date.now() / 1000) + 15 * 60;
    const blocked = linkBlocker(current, current.deployed) ?? parentBlocker(current, requested) ?? (soon ? ["policy_expired", "Local wallet policy has expired or expires too soon"] : undefined);
    return blocked || !current.deployed ? { status: current, blocked } : { status: current, consent: { nonce: 4n, digest: digestToSign, deadline: 1900000000n, block: 7n } };
  };
  f.chain.verifyAgentLinkSignature = async (_wallet, digest, signature, block) => { calls.push(["verify", digest, signature, block]); };
  return { ...f, calls };
}

test("agent links open the configured Portal URL, which an endpoint override changes without re-approval", async t => {
  const config = loadConfig({ INCENTIV_PORTAL_URL: "https://portal-override.example.incentiv.io/agents" });
  const f = await signedLinkFixture(t, true, {}, {}, { config });
  const url = new URL((await f.service.signAgentLink(parent)).portal_url);
  assert.equal(url.origin + url.pathname, "https://portal-override.example.incentiv.io/agents");
  assert.equal(url.searchParams.get("parent"), parent); assert.ok(url.searchParams.get("agent_signature"));
  // Same manifest, so a wallet approved under the default Portal keeps working under the override.
  assert.equal(config.manifest.manifestId, MAINNET.manifest.manifestId);
  const standard = await signedLinkFixture(t);
  assert.equal(new URL((await standard.service.signAgentLink(parent)).portal_url).host, "portal.incentiv.io");
});

test("sign_agent_link signs this agent's consent for Portal to submit", async t => {
  const f = await signedLinkFixture(t);
  const prepared = await f.service.signAgentLink(parent);
  assert.equal(prepared.agent_signed, true); assert.equal(prepared.link_blocked, undefined);
  const url = new URL(prepared.portal_url), signature = url.searchParams.get("agent_signature");
  assert.equal(url.searchParams.get("agent").toLowerCase(), f.approval.agent.toLowerCase());
  assert.equal(url.searchParams.get("parent"), parent);
  assert.equal(url.searchParams.get("agent_nonce"), "4");
  assert.equal(url.searchParams.get("agent_deadline"), "1900000000");
  const ownerAddress = await f.store.session(async s => s.envelope.owner);
  assert.equal(await recoverMessageAddress({ message: { raw: digestToSign }, signature }), ownerAddress);
  assert.deepEqual(f.calls, [["consent", parent, undefined], ["verify", digestToSign, signature, 7n]]);
  assert.match(prepared.next_action, /Do not call link_agent/);
});

test("sign_agent_link caps the consent at local policy expiry and refuses a policy about to expire", async t => {
  const expiresAt = Date.now() + 2 * 60 * 60 * 1000;
  const f = await signedLinkFixture(t, true, {}, { expiresAt });
  assert.equal((await f.service.signAgentLink(parent)).agent_signed, true);
  assert.deepEqual(f.calls[0], ["consent", parent, Math.floor(expiresAt / 1000)]);
  const soonAt = Date.now() + 60_000, soon = await signedLinkFixture(t, true, {}, { expiresAt: soonAt });
  const refused = await soon.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "policy_expired"); assert.match(refused.next_action, /Do not ask the user to sign/); assert.equal(refused.portal_url, undefined);
  assert.deepEqual(soon.calls, [["consent", parent, Math.floor(soonAt / 1000)]]);
});

test("a release with candidate signing disabled refuses to sign link consent before any registry read", async t => {
  const f = await signedLinkFixture(t), service = new WalletService(f.service.ctx, f.store, f.chain, false);
  const refused = await service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "wallet_release_unreviewed"); assert.match(refused.next_action, /release with signing enabled/); assert.doesNotMatch(refused.next_action, /prepare_agent_link/); assert.deepEqual(f.calls, []);
  // link_agent cannot sign in such a release either, so prepare_agent_link does not ask for a Portal approval.
  f.chain.registryStatus = async () => assert.fail("a release that cannot sign needs no registry read");
  const prepared = await service.prepareAgentLink();
  assert.equal(prepared.link_blocked, "wallet_release_unreviewed"); assert.equal(prepared.portal_url, undefined);
});

test("sign_agent_link signs nothing for a parent that local policy or the registry refuses", async t => {
  const denied = await signedLinkFixture(t, false);
  const refused = await denied.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "registry_parent_not_allowed"); assert.equal(refused.portal_url, undefined); assert.deepEqual(denied.calls, []);
  // The refusal's code is in link_blocked; next_action is the plain instruction.
  assert.match(refused.next_action, /^Local wallet policy does not allow this parent\./);
  for (const [status, code] of [[{ parent_agent_count: "5" }, "registry_limit_reached"], [{ parent_eligible: false }, "registry_parent_not_eligible"], [{ parent_is_agent: true }, "registry_ineligible"], [{ parent }, "registry_already_linked"]]) {
    const f = await signedLinkFixture(t, true, status);
    const blocked = await f.service.signAgentLink(parent);
    assert.equal(blocked.link_blocked, code); assert.equal(blocked.portal_url, undefined); assert.deepEqual(f.calls, [["consent", parent, undefined]]);
  }
});

test("a disabled wallet gets a structured refusal, and one disabled while signing returns no signature", async t => {
  const f = await signedLinkFixture(t);
  await f.store.disable();
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "wallet_locked"); assert.match(refused.next_action, /Do not ask the user to sign/); assert.deepEqual(f.calls, []);
  const g = await signedLinkFixture(t), verify = g.chain.verifyAgentLinkSignature;
  g.chain.verifyAgentLinkSignature = async (...a) => { await verify(...a); await g.store.disable(); };
  await assert.rejects(g.service.signAgentLink(parent), { code: "wallet_locked" });
});

test("sign_agent_link waits for an unresolved link or unlink, which would void any consent signed now", async t => {
  const f = await signedLinkFixture(t), id = randomUUID();
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "submitted");
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "operation_pending"); assert.match(refused.next_action, new RegExp(id)); assert.deepEqual(f.calls, []);
});

test("a signed but unsent registry request is named with the retry that clears it", async t => {
  const f = await signedLinkFixture(t), id = randomUUID(), submit = f.service.submit;
  f.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "signed");
  f.service.submit = submit;
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "operation_pending"); assert.match(refused.next_action, new RegExp(`Retry link_agent with that request_id.*${id}|${id}.*Retry link_agent with that request_id`)); assert.deepEqual(f.calls, []);
  // Once its deadline passes, a retry cannot send it, so the refusal names the resolve command instead.
  const now = Date.now;
  Date.now = () => now() + 60 * 60 * 1000;
  try {
    const stale = await f.service.signAgentLink(parent);
    assert.equal(stale.link_blocked, "operation_pending"); assert.match(stale.next_action, new RegExp(`wallet operation resolve ${id} --replace`));
  } finally { Date.now = now; }
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "submitted");
});

test("a registry request the network may have dropped is named with the resend that settles it", async t => {
  const f = await signedLinkFixture(t), id = randomUUID(), relay = f.chain.relay;
  f.chain.relay = async (...a) => { await relay(...a); throw new Error("lost response"); };
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "submission_unknown");
  f.chain.relay = relay;
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "operation_pending"); assert.match(refused.next_action, new RegExp(`${id}.*Retry link_agent with that request_id to send it again`)); assert.doesNotMatch(refused.next_action, /until it settles/);
  const now = Date.now;
  Date.now = () => now() + 60 * 60 * 1000;
  try { assert.match((await f.service.signAgentLink(parent)).next_action, new RegExp(`never confirmed.*wallet operation resolve ${id} --replace`)); }
  finally { Date.now = now; }
  assert.deepEqual(f.calls, []);
});

test("an expired policy is refused before any registry read, deployed or not", async t => {
  for (const status of [{}, { deployed: false, agent_eligible: false }]) {
    const f = await signedLinkFixture(t, true, status, { expiresAt: Date.now() - 1000 });
    const refused = await f.service.signAgentLink(parent);
    assert.equal(refused.link_blocked, "policy_expired"); assert.deepEqual(f.calls, []);
  }
});

test("a damaged journal stays an error rather than becoming a link refusal", async t => {
  const f = await signedLinkFixture(t);
  await f.store.session(async s => writeFile(join(s.directory, "operations", "journal.json"), "{}"));
  await assert.rejects(f.service.signAgentLink(parent), { code: "wallet_recovery_required" });
  assert.deepEqual(f.calls, []);
});

test("a registry request still awaiting local approval does not block consent but is named in a warning", async t => {
  const f = await signedLinkFixture(t, false), id = randomUUID();
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "approval_required");
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  const signed = await f.service.signAgentLink(parent);
  assert.equal(signed.agent_signed, true); assert.match(signed.warning, new RegExp(id));
  assert.equal((await (await signedLinkFixture(t)).service.signAgentLink(parent)).warning, undefined);
});

test("sign_agent_link refuses an unapproved registry capability in the same shape as other local refusals", async t => {
  const f = await preRegistryWallet(t);
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "capability_manifest_unapproved"); assert.match(refused.next_action, /Do not ask the user to sign/);
  // prepare_agent_link answers the same state in the same shape, with no Portal URL.
  const prepared = await f.service.prepareAgentLink();
  assert.equal(prepared.link_blocked, "capability_manifest_unapproved"); assert.equal(prepared.portal_url, undefined);
});

test("an undeployed agent signs nothing and is sent to prepare_agent_link, since the registry cannot check its signature", async t => {
  const f = await signedLinkFixture(t, true, { deployed: false, agent_eligible: false });
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "registry_agent_not_deployed"); assert.equal(refused.portal_url, undefined); assert.equal(refused.agent_signed, undefined);
  assert.match(refused.next_action, /prepare_agent_link/); assert.deepEqual(f.calls, [["consent", parent, undefined]]);
  // An expired policy no longer yields an approval URL for an undeployed agent either.
  const expired = await signedLinkFixture(t, true, { deployed: false, agent_eligible: false }, { expiresAt: Date.now() + 1000 });
  assert.equal((await expired.service.signAgentLink(parent)).portal_url, undefined);
});

function consentChain(clients, timestamp = Math.floor(Date.now() / 1000), deployed = true) {
  const chain = new WalletChain(new Ctx(MAINNET));
  chain.clients.splice(0, chain.clients.length, ...clients);
  chain.state = async () => ({ ...state(), timestamp, deployed });
  return chain;
}
// A deployed agent is itself an Incentiv account.
const deployedAgent = (overrides = {}) => {
  const c = client(overrides), good = c.readContract;
  c.readContract = args => args.functionName === "isIncentivAccount" && args.args[0].toLowerCase() === agent.toLowerCase() ? Promise.resolve(true) : good(args);
  return c;
};
const consentWallet = { account: agent, approvedCapabilityManifestId: MAINNET.manifest.manifestId };

test("the chain reads status and digest at one block, with a deadline capped by policy expiry", async () => {
  const now = Math.floor(Date.now() / 1000);
  const full = await consentChain([deployedAgent(), deployedAgent()], now).agentLinkConsent(consentWallet, parent);
  assert.equal(full.blocked, undefined); assert.equal(full.consent.block, 123n);
  assert.ok(full.consent.deadline >= BigInt(now + 24 * 60 * 60) && full.consent.deadline <= BigInt(now + 24 * 60 * 60 + 5));
  assert.equal(full.consent.digest, agentLinkDigest(MAINNET, agent, parent, 0n, full.consent.deadline));
  const capped = await consentChain([deployedAgent()], now).agentLinkConsent(consentWallet, parent, now + 3600);
  assert.equal(capped.consent.deadline, BigInt(now + 3600));
  // A policy ending within 15 minutes of the block's time is refused like the registry's own blockers, and nothing is read for signing.
  const soon = await consentChain([deployedAgent()], now).agentLinkConsent(consentWallet, parent, now + 60);
  assert.equal(soon.blocked[0], "policy_expired"); assert.equal(soon.consent, undefined);
  const ahead = await consentChain([deployedAgent()], now + 20).agentLinkConsent(consentWallet, parent, now + 15 * 60 + 10);
  assert.equal(ahead.blocked[0], "policy_expired");
  // A registry blocker is reported ahead of an expiring policy, since renewing the policy would not clear it.
  const linked = deployedAgent(), linkedRead = linked.readContract;
  linked.readContract = args => args.functionName === "parentOf" && args.args[0].toLowerCase() === agent.toLowerCase() ? Promise.resolve(parent) : linkedRead(args);
  assert.equal((await consentChain([linked], now).agentLinkConsent(consentWallet, parent, now + 60)).blocked[0], "registry_already_linked");
});

test("the chain signs nothing from a stale block, a blocked parent or disagreeing RPCs", async () => {
  await assert.rejects(consentChain([deployedAgent()], Math.floor(Date.now() / 1000) - 600).agentLinkConsent(consentWallet, parent), { code: "registry_rpc_unavailable" });
  // A block from the future would stretch the consent deadline past AGENT_LINK_REQUEST_SECONDS.
  await assert.rejects(consentChain([deployedAgent()], Math.floor(Date.now() / 1000) + 3600).agentLinkConsent(consentWallet, parent), { code: "registry_rpc_unavailable" });
  const full = consentChain([deployedAgent()]), c = full.clients[0], good = c.readContract;
  c.readContract = args => args.functionName === "agentCount" && args.args[0].toLowerCase() === parent.toLowerCase() ? Promise.resolve(5n) : good(args);
  // A blocked link reads no digest, so a digest read that would fail cannot hide the registry's reason.
  const reads = c.readContract;
  c.readContract = args => args.functionName === "agentLinkDigest" ? assert.fail("digest read for a blocked link") : reads(args);
  const blocked = await full.agentLinkConsent(consentWallet, parent);
  assert.equal(blocked.blocked[0], "registry_limit_reached"); assert.equal(blocked.consent, undefined);
  const undeployed = await consentChain([client()], undefined, false).agentLinkConsent(consentWallet, parent);
  assert.equal(undeployed.blocked, undefined); assert.equal(undeployed.consent, undefined);
  const other = deployedAgent(), otherRead = other.readContract;
  // This RPC reports a different agent nonce, and a registry digest consistent with it.
  other.readContract = async args => args.functionName === "nonces" && args.args[0].toLowerCase() === agent.toLowerCase() ? 1n
    : args.functionName === "agentLinkDigest" ? agentLinkDigest(MAINNET, args.args[1], args.args[0], 1n, args.args[2]) : otherRead(args);
  await assert.rejects(consentChain([deployedAgent(), other]).agentLinkConsent(consentWallet, parent), { code: "registry_rpc_unavailable", message: /disagrees/ });
});

test("a policy that expires during the last registry read stops the broadcast", async t => {
  const f = await registryFixture(t), id = randomUUID(), now = Date.now;
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt: now() + 60_000 } }));
  let checks = 0, offset = 0;
  Date.now = () => now() + offset;
  t.after(() => { Date.now = now; });
  // The fourth check is the one at the broadcast boundary; the policy expires while it reads.
  f.chain.verifyRegistry = async () => { if (++checks === 4) offset = 120_000; };
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: f.approval }), { code: "policy_denied" });
  assert.equal(checks, 4); assert.equal(f.submissions.length, 0);
  assert.equal((await f.service.operation(id)).status, "signed");
});

test("a stale approval at the broadcast boundary keeps its replacement guidance and the signed state", async t => {
  const f = await registryFixture(t), id = randomUUID();
  let checks = 0;
  f.chain.verifyRegistry = async () => { if (++checks === 4) throw new WalletError("registry_approval_stale", "Parent nonce changed; obtain a fresh Portal approval"); };
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: f.approval }), error => error.code === "registry_approval_stale" && new RegExp(`wallet operation resolve ${id} --replace`).test(error.message));
  const record = (await f.service.review(id)).records[0];
  assert.equal(record.status, "signed"); assert.equal(record.attempts, 0); assert.equal(record.lastError, undefined);
  assert.equal(f.submissions.length, 0);
});

test("a signed link to an agent that is already linked, or ineligible, names the replacement that frees its nonce", async t => {
  for (const [code, message] of [["registry_already_linked", "Agent is already permanently connected to a Portal account"], ["registry_ineligible", "Account roles or allowed factories do not permit this link"]]) {
    const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
    f.service.submit = async () => {}; // The process stops between signing and submission.
    assert.equal((await f.service.send("link_agent", args)).status, "signed");
    f.service.submit = submit;
    f.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
    await assert.rejects(f.service.send("link_agent", args), error => error.code === code && new RegExp(`wallet operation resolve ${id} --replace`).test(error.message));
    assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
  }
});

test("a replacement whose gas token the paymaster refuses points to native gas for the same request, not a new one", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID();
  let checks = 0;
  f.chain.verifyRegistry = async () => { if (++checks >= 3) throw new WalletError("registry_approval_stale", "Parent nonce changed"); };
  await assert.rejects(f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" }), { code: "registry_approval_stale" });
  f.chain.buildReplacement = () => { throw new WalletError("gas_token_unavailable", "The paymaster does not accept USDC for gas. Use a new request ID with gas in CENT, USDC or another token get_gas_payment_options lists"); };
  await assert.rejects(f.service.reviewReplacement(id), error => error.code === "gas_token_unavailable" && /^gas_token_unavailable: The paymaster does not accept USDC for gas\. /.test(error.message)
    && error.message.includes(`wallet operation resolve ${id} --replace --native-gas`) && !/Use a new request ID/.test(error.message));
});

test("a link mined against an earlier registry proxy is confirmed by that proxy's event", async t => {
  const chain = new WalletChain(new Ctx(MAINNET)), hash = `0x${"11".repeat(32)}`, tx = `0x${"22".repeat(32)}`, blockHash = `0x${"33".repeat(32)}`, earlier = "0x00000000000000000000000000000000000000aa";
  const operationEvent = (await import('viem')).parseAbiItem('event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)');
  const opLog = { address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: [operationEvent], eventName: "UserOperationEvent", args: { userOpHash: hash, sender: agent, paymaster: zero } }), data: encodeAbiParameters([{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }], [0n, true, 200n, 100n]) };
  const beforeExecution = { address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: (await import("viem")).parseAbi(["event BeforeExecution()"]), eventName: "BeforeExecution" }), data: "0x" };
  let logs;
  chain.clients.splice(0, chain.clients.length, { getTransactionReceipt: async () => ({ status: "success", transactionHash: tx, blockNumber: 10n, blockHash, logs }), getBlock: async () => ({ hash: blockHash }), getBlockNumber: async () => 12n });
  t.mock.method(globalThis, "fetch", async () => Response.json({ result: { receipt: { transactionHash: tx } } }));
  const i = intent(await approval()), signedFor = { ...registryCall(MAINNET, agent, i), to: earlier };
  const record = { userOpHash: hash, nonce: "0", operation: { sender: agent, callData: encodeExecuteBatch([signedFor]) }, intent: i };
  logs = [beforeExecution, { ...registryLog("AgentLinked"), address: earlier }, opLog];
  assert.equal((await chain.receipt(record)).registryError, undefined);
  // An event from the current proxy is not this operation's.
  logs = [beforeExecution, registryLog("AgentLinked"), opLog];
  assert.equal((await chain.receipt(record)).registryError, "registry_event_missing");
  assert.equal(hasRegistryEvent(MAINNET, i, agent, [{ ...registryLog("AgentLinked"), address: earlier }], earlier), true);
});

test("sign_agent_link settles a link that already landed instead of calling it unresolved", async t => {
  const f = await signedLinkFixture(t, true, { parent }), id = randomUUID();
  assert.equal((await f.service.send("link_agent", { request_id: id, approval: f.approval })).status, "submitted");
  f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"11".repeat(32)}` });
  const refused = await f.service.signAgentLink(parent);
  assert.equal(refused.link_blocked, "registry_already_linked");
  assert.equal((await f.service.operation(id)).status, "confirmed");
});

test("the upgrade command calls a current wallet current after the registry moves, with its approval pending", async t => {
  const base = withoutAgentRegistry(MAINNET), f = await fixture(t, { config: base }), store = new WalletStore(MAINNET, f.deps);
  await f.store.createOrLoad();
  await approveCapabilities(store, base, MAINNET, password, digest(await reviewCapabilities(store, base, MAINNET)));
  // A later release pins the registry at a new proxy.
  const moved = structuredClone(MAINNET);
  moved.manifest.agentRegistry.proxy.address = "0x00000000000000000000000000000000000000aa";
  moved.manifest.manifestId = configurationId(moved.manifest, "manifestId");
  const config = parseConfig(moved), upgrade = await reviewUpgrade(new WalletStore(config, f.deps), config);
  assert.equal(upgrade.review, undefined); assert.equal(upgrade.registryPending, true);
});

test("a signed link refused while the factory is disallowed keeps its request retryable instead of advising a paid replacement", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
  f.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await f.service.send("link_agent", args)).status, "signed");
  f.service.submit = submit;
  const [code, message] = linkBlocker({ parent: zero, agent_is_parent: false, agent_eligible: false, factory_allowed: false }, false);
  f.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
  await assert.rejects(f.service.send("link_agent", args), error => error.code === "registry_factory_not_allowed" && /retry once it does/.test(error.message) && !/--replace/.test(error.message));
  assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
  // Once the registry allows the factory again, the same signed request goes through.
  f.chain.verifyRegistry = async () => {};
  assert.equal((await f.service.send("link_agent", args)).status, "submitted"); assert.equal(f.submissions.length, 1);
});

test("an expired signed link names its own request ID in the replacement command", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
  f.service.submit = async () => {};
  assert.equal((await f.service.send("link_agent", args)).status, "signed");
  f.service.submit = submit;
  const deadline = (await f.service.review(id)).records[0].deadline, now = Date.now;
  Date.now = () => deadline * 1000 + 1000;
  try {
    await assert.rejects(f.service.send("link_agent", args), error => error.code === "operation_pending" && new RegExp(`wallet operation resolve ${id} --replace`).test(error.message));
  } finally { Date.now = now; }
  assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
});

test("a signed token-paid request that no longer simulates points to a native-gas replacement", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval, gas_token: "USDC" }, submit = f.service.submit;
  f.service.submit = async () => {};
  assert.equal((await f.service.send("link_agent", args)).status, "signed");
  f.service.submit = submit;
  const simulate = f.chain.simulate;
  // The paymaster's schedule moved after signing, so the same bytes no longer pass simulation.
  f.chain.simulate = async () => { throw new WalletError("simulation_failed", "The exact validated operation failed simulation or exceeds its gas allocation"); };
  await assert.rejects(f.service.send("link_agent", args), error => error.code === "simulation_failed" && new RegExp(`wallet operation resolve ${id} --replace --native-gas`).test(error.message));
  assert.equal((await f.service.operation(id)).status, "signed"); assert.equal(f.submissions.length, 0);
  f.chain.simulate = simulate;
});

test("a bundler outage during simulation keeps the request retryable, while a bundler rejection fails it", async () => {
  const chain = new WalletChain(new Ctx(MAINNET)), fetch = globalThis.fetch;
  const validated = { calls: [], hash: `0x${"11".repeat(32)}`, op: { sender: agent, nonce: 0n, callData: "0x", callGasLimit: 100_000n, verificationGasLimit: 100_000n, preVerificationGas: 50_000n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, signature: "0x" } };
  try {
    for (const answer of [
      () => { throw new TypeError("fetch failed"); },
      () => new Response("busy", { status: 503 }),
      () => new Response("slow down", { status: 429 }),
      () => new Response("<html>", { status: 200 }),
      () => Response.json(null),
      () => Response.json({}),
      () => Response.json({ error: { message: "proxy could not reach upstream" } }),
      () => Response.json({ result: {} }),
      () => Response.json({ result: { callGasLimit: "oops", verificationGasLimit: "0x100", preVerificationGas: "0x100" } }),
    ]) {
      globalThis.fetch = async () => answer();
      await assert.rejects(chain.simulate(validated), { code: "rpc_unavailable" });
    }
    globalThis.fetch = async () => Response.json({ result: { callGasLimit: "256", verificationGas: 256, preVerificationGas: "0x100" } });
    await chain.simulate(validated);
    globalThis.fetch = async () => Response.json({ result: { callGasLimit: "100001", verificationGasLimit: "0x100", preVerificationGas: "0x100" } });
    await assert.rejects(chain.simulate(validated), { code: "simulation_failed" });
    globalThis.fetch = async () => Response.json({ jsonrpc: "2.0", id: 1, error: { code: -32500, message: "AA23 reverted" } });
    await assert.rejects(chain.simulate(validated), { code: "simulation_failed" });
    globalThis.fetch = async () => new Response("bad request", { status: 400 });
    await assert.rejects(chain.simulate(validated), { code: "simulation_failed" });
  } finally { globalThis.fetch = fetch; }
});

test("a build interrupted by an incomplete bundler estimate keeps its request ID usable", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, build = f.chain.build;
  t.mock.method(globalThis, "fetch", async () => Response.json({ result: { callGasLimit: "0x100", verificationGasLimit: "0x100" } }));
  f.chain.build = (wallet, intent, state) => buildUserOpUnsigned(new Ctx(MAINNET), {
    account: wallet.account, calls: [registryCall(MAINNET, wallet.account, intent)], state: { ...state, deployed: true },
  });
  await assert.rejects(f.service.send("link_agent", args), { code: "rpc_unavailable" });
  assert.equal((await f.service.operation(id)).status, "approval_required");
  f.chain.build = build;
  assert.equal((await f.service.send("link_agent", args)).status, "submitted");
});

test("the upgrade command points to registry approval only when the configuration includes the registry", async t => {
  const base = withoutAgentRegistry(MAINNET), f = await fixture(t, { config: base }), store = new WalletStore(MAINNET, f.deps);
  await f.store.createOrLoad();
  await approveCapabilities(store, base, MAINNET, password, digest(await reviewCapabilities(store, base, MAINNET)));
  const moved = structuredClone(MAINNET);
  moved.manifest.agentRegistry.proxy.address = "0x00000000000000000000000000000000000000aa";
  moved.manifest.manifestId = configurationId(moved.manifest, "manifestId");
  const config = parseConfig(moved), registryFree = withoutAgentRegistry(config);
  const upgrade = await reviewUpgrade(new WalletStore(registryFree, f.deps), registryFree);
  assert.equal(upgrade.registryPending, false);
});

test("an unsigned link refused while the factory is disallowed stays open under its request ID", async t => {
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval };
  const [code, message] = linkBlocker({ parent: zero, agent_is_parent: false, agent_eligible: false, factory_allowed: false }, false);
  // The first check precedes the journal; the check right before signing refuses.
  let checks = 0;
  f.chain.verifyRegistry = async () => { if (++checks === 2) throw new WalletError(code, message); };
  await assert.rejects(f.service.send("link_agent", args), { code });
  const waiting = await f.service.operation(id);
  assert.equal(waiting.status, "approval_required"); assert.equal(waiting.last_error, code);
  assert.match(waiting.next_action, /does not currently allow this account's factory\. Retry with the same request ID once it does/);
  // Retried while still refused (the check of an existing record), the record still stays open.
  f.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
  await assert.rejects(f.service.send("link_agent", args), { code });
  assert.equal((await f.service.operation(id)).status, "approval_required");
  f.chain.verifyRegistry = async () => {};
  assert.equal((await f.service.send("link_agent", args)).status, "submitted"); assert.equal(f.submissions.length, 1);
});

test("an RPC or bundler outage while rechecking a signed request keeps it signed and retryable", async t => {
  const { BundlerUnavailableError } = await import("../src/userop.ts");
  for (const [where, outage] of [["first recheck", new HttpRequestError({ url: "https://rpc.example.test", status: 503 })], ["broadcast boundary", new HttpRequestError({ url: "https://rpc.example.test", status: 503 })], ["broadcast boundary", new BundlerUnavailableError("Bundler HTTP 503")]]) {
    const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
    f.service.submit = async () => {};
    assert.equal((await f.service.send("link_agent", args)).status, "signed");
    f.service.submit = submit;
    const relay = f.chain.relay, state = f.chain.state;
    let boundary = false, failed = false;
    f.chain.relay = (operation, before) => relay(operation, async () => { boundary = true; try { await before(); } finally { boundary = false; } });
    f.chain.state = async (...a) => {
      if (!failed && (where === "first recheck" || boundary)) { failed = true; throw outage; }
      return state(...a);
    };
    await assert.rejects(f.service.send("link_agent", args), { code: "rpc_unavailable" }, where);
    const record = (await f.service.review(id)).records[0];
    assert.equal(record.status, "signed", where); assert.equal(record.attempts, 0); assert.equal(f.submissions.length, 0);
    assert.equal((await f.service.send("link_agent", args)).status, "submitted", where); assert.equal(f.submissions.length, 1);
  }
});

test("a TransferGate read that cannot reach the RPC is an outage, not a failed simulation", async () => {
  const chain = new WalletChain(new Ctx(MAINNET));
  const validated = { calls: [{ to: parent, value: 0n, data: "0x" }], hash: `0x${"11".repeat(32)}`, op: { sender: agent, nonce: 0n, callData: "0x", callGasLimit: 1n, verificationGasLimit: 1n, preVerificationGas: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, signature: "0x" } };
  chain.clients.splice(0, chain.clients.length, { readContract: async () => { throw new HttpRequestError({ url: "https://rpc.example.test", status: 503 }); } });
  await assert.rejects(chain.simulate(validated), { code: "rpc_unavailable" });
  chain.clients.splice(0, chain.clients.length, { readContract: async () => ({ reject: 1 }) });
  await assert.rejects(chain.simulate(validated), { code: "simulation_failed" });
});

test("prepare_agent_link gives no Portal URL to a wallet that cannot sign the link", async t => {
  const f = await fixture(t);
  f.chain.registryStatus = async () => assert.fail("a refused wallet reads nothing");
  await f.store.disable();
  const refused = await f.service.prepareAgentLink();
  assert.equal(refused.link_blocked, "wallet_locked"); assert.equal(refused.portal_url, undefined); assert.match(refused.next_action, /Do not ask the user to sign/);
});

test("prepare_agent_link refuses an expired local policy before and after reading the registry", async t => {
  const f = await fixture(t), now = Date.now, expiresAt = now() + 16 * 60_000;
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  f.chain.registryStatus = async () => {
    t.mock.method(Date, "now", () => expiresAt);
    return { parent: zero, agent_is_parent: false, agent_eligible: false, factory_allowed: true, deployed: false };
  };

  const expiredDuringRead = await f.service.prepareAgentLink();
  assert.equal(expiredDuringRead.link_blocked, "policy_expired");
  assert.equal(expiredDuringRead.portal_url, undefined);
  assert.match(expiredDuringRead.next_action, /Renew it with incentiv-mcp setup/);

  f.chain.registryStatus = async () => assert.fail("an expired policy needs no registry read");
  assert.deepEqual(await f.service.prepareAgentLink(), expiredDuringRead);
});

test("a token-paid replacement the bundler keeps refusing can be replaced once more with native gas, and either may still win", async t => {
  for (const winner of ["prior", "native", "original"]) {
    const f = await tokenRegistryFixture(t), id = randomUUID(), balances = f.chain.balances, args = { request_id: id, approval: f.approval, gas_token: "USDC" };
    await f.service.send("link_agent", args);
    f.chain.balances = async (...a) => ({ ...await balances(...a), native: "1000000" });
    const token = (await f.service.reviewReplacement(id)).records[0];
    // The paymaster's terms moved: the bundler refuses the signed token-paid bytes every time.
    const relay = f.chain.relay;
    f.chain.relay = async () => { throw new Error("paymaster: insufficient token payment"); };
    assert.equal((await f.service.replace(id, password, digest(token))).status, "superseding");
    assert.equal((await f.service.resolve(id, password)).status, "superseding");
    await assert.rejects(f.service.send("link_agent", { ...args, request_id: randomUUID() }), { code: "operation_pending" });
    // Only native gas may follow it, once.
    await assert.rejects(f.service.reviewReplacement(id), e => e.code === "operation_pending" && /--native-gas/.test(e.message));
    f.chain.buildReplacement = (wallet, original, state, gasToken) => {
      assert.equal(gasToken, "native");
      const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
      built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n;
      built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
      return built;
    };
    const native = (await f.service.reviewReplacement(id, true)).records[0];
    assert.equal(native.priorReplacement.userOpHash, token.replacement.userOpHash);
    // A resend while the native one awaits signing sends the signed token-paid bytes, never the unsigned ones.
    const resent = [];
    f.chain.relay = async (operation, beforeSubmit) => { await beforeSubmit?.(); resent.push(operation); throw new Error("paymaster: insufficient token payment"); };
    assert.equal((await f.service.resolve(id, password)).status, "superseding");
    const [held] = await f.store.session(async s => (await Journal.open(s)).data.records);
    assert.deepEqual(resent, [held.priorReplacement.operation]);
    assert.notEqual(held.priorReplacement.operation.signature, "0x");
    await assert.rejects(f.service.reviewReplacement(id), e => e.code === "operation_pending" && /--native-gas/.test(e.message));
    f.chain.relay = relay;
    const sent = await f.service.replace(id, password, digest(held));
    assert.equal(sent.status, "superseding"); assert.equal(sent.prior_replacement_user_op_hash, token.replacement.userOpHash);
    // Every signed operation keeps its reservation until a receipt shows which one won.
    await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { [f.token]: "273", native: native.replacement.maxGasCost }));
    await assert.rejects(f.service.reviewReplacement(id, true), { code: "operation_pending" });
    const landed = { prior: token.replacement.userOpHash, native: native.replacement.userOpHash, original: token.userOpHash }[winner];
    f.chain.receipt = async r => {
      if (r.userOpHash === landed) return { success: true, actualGasCost: 400n, transactionHash: `0x${"77".repeat(32)}` };
      // A stale hint for the original or the newer replacement must not hide a verified winner.
      throw new Error("Receipt is not in the canonical chain");
    };
    const settled = await f.service.operation(id);
    assert.equal(settled.status, winner === "original" ? "confirmed" : "superseded");
    for (const hash of [token.userOpHash, token.replacement.userOpHash, native.replacement.userOpHash]) {
      assert.deepEqual(await f.service.operation(hash), settled);
    }
    // The original releases both replacements' gas reservations; a replacement consumes only its own gas.
    await f.store.session(async s => assert.deepEqual((await Journal.open(s)).used(), { prior: { [f.token]: "150" }, native: { native: "400" }, original: { [f.token]: "123" } }[winner]));
  }
});

test("a receipt lookup error for the native replacement preserves its progress and checks the prior replacement", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID(), balances = f.chain.balances;
  await f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" });
  f.chain.balances = async (...params) => ({ ...await balances(...params), native: "1000000" });
  const [token] = (await f.service.reviewReplacement(id)).records;
  const relay = f.chain.relay;
  f.chain.relay = async () => { throw new Error("paymaster: insufficient token payment"); };
  await f.service.replace(id, password, digest(token));
  f.chain.buildReplacement = (wallet, _original, state) => {
    const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
    built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n;
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return built;
  };
  const [native] = (await f.service.reviewReplacement(id, true)).records;
  f.chain.relay = relay;
  await f.service.replace(id, password, digest(native));

  const lookups = [];
  f.chain.receipt = async r => {
    lookups.push(r.userOpHash);
    if (r.userOpHash === native.replacement.userOpHash) {
      r.searchedBlock = "123";
      throw new Error("receipt lookup unavailable");
    }
    if (r.userOpHash === token.replacement.userOpHash) return { success: true, actualGasCost: 400n, transactionHash: `0x${"77".repeat(32)}` };
  };
  assert.equal((await f.service.operation(id)).status, "superseded");
  assert.deepEqual(lookups, [token.userOpHash, native.replacement.userOpHash, token.replacement.userOpHash]);
  await f.store.session(async s => {
    const [record] = (await Journal.open(s)).data.records;
    assert.equal(record.replacement.searchedBlock, "123");
    assert.equal(record.priorReplacement.searchedBlock, undefined);
    assert.deepEqual(record.consumed, { [f.token]: "150" });
  });
});

test("a native replacement is priced above every operation signed at its nonce", () => {
  const current = { baseFeePerGas: 1n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n };
  const op = (maxFeePerGas, maxPriorityFeePerGas) => userOpToJson({ sender: `0x${"11".repeat(20)}`, nonce: 0n, callData: "0x", callGasLimit: 1n, verificationGasLimit: 1n, preVerificationGas: 1n, maxFeePerGas, maxPriorityFeePerGas, signature: "0x" });
  const original = { operation: op(100n, 10n) };
  assert.deepEqual(replacementFees(current, original), { ...current, maxFeePerGas: 121n, maxPriorityFeePerGas: 13n });
  // The token-paid replacement outbid the original; the native one must outbid it too, signed or kept as prior.
  const token = { operation: op(121n, 13n), signed: true };
  for (const record of [{ ...original, replacement: token }, { ...original, priorReplacement: token, replacement: { operation: op(1n, 1n), signed: false } }]) {
    assert.deepEqual(replacementFees(current, record), { ...current, maxFeePerGas: 146n, maxPriorityFeePerGas: 16n });
  }
  // Current fees above the bump are kept.
  assert.deepEqual(replacementFees({ ...current, maxFeePerGas: 500n, maxPriorityFeePerGas: 50n }, { ...original, replacement: token }), { ...current, maxFeePerGas: 500n, maxPriorityFeePerGas: 50n });
});

test("the replacement builder prices above every signed operation and ignores an unsigned draft", async t => {
  const fetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = fetch; });
  globalThis.fetch = async () => Response.json({ jsonrpc: "2.0", id: 1, result: { callGasLimit: "0x1", verificationGasLimit: "0x1", preVerificationGas: "0x1" } });
  const chain = new WalletChain(new Ctx(MAINNET)), account = `0x${"11".repeat(20)}`, wallet = { account, owner: `0x${"22".repeat(20)}` };
  const op = (maxFeePerGas, maxPriorityFeePerGas) => userOpToJson({ sender: account, nonce: 7n, callData: "0x", callGasLimit: 1n, verificationGasLimit: 1n, preVerificationGas: 1n, maxFeePerGas, maxPriorityFeePerGas, signature: "0x" });
  const state = { block: 1n, nonce: 7n, deployed: true, fees: { baseFeePerGas: 1n, maxFeePerGas: 10n, maxPriorityFeePerGas: 1n } };
  // The draft outbids both signed operations; a re-review must not compound its price.
  const record = { intent: {}, operation: op(100n, 10n), priorReplacement: { operation: op(121n, 13n), signed: true }, replacement: { operation: op(10_000n, 1_000n), signed: false } };
  const built = await chain.buildReplacement(wallet, record, state, "native");
  assert.equal(built.op.maxFeePerGas, 146n);
  assert.equal(built.op.maxPriorityFeePerGas, 16n);
});

test("only a token-paid replacement can be followed by a native one", async t => {
  const f = await tokenRegistryFixture(t), id = randomUUID(), balances = f.chain.balances;
  await f.service.send("link_agent", { request_id: id, approval: f.approval, gas_token: "USDC" });
  f.chain.balances = async (...a) => ({ ...await balances(...a), native: "1000000" });
  f.chain.buildReplacement = (wallet, _original, state) => {
    const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
    built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n;
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, 24101);
    return built;
  };
  const native = (await f.service.reviewReplacement(id, true)).records[0];
  assert.equal(native.replacement.gasToken, undefined);
  assert.equal((await f.service.replace(id, password, digest(native))).status, "superseding");
  // A signed native replacement leaves nothing a second native one could fix, so no follower is offered.
  await assert.rejects(f.service.reviewReplacement(id, true), e => e.code === "operation_pending" && !/--native-gas/.test(e.message));
  const [record] = await f.store.session(async s => (await Journal.open(s)).data.records);
  assert.equal(record.priorReplacement, undefined);
});

test("a Portal approval lasting past 24 hours or the local policy's expiry is refused before signing", async () => {
  const now = Math.floor(Date.now() / 1000);
  for (const deadline of [now + 86_400 + 60, Number.MAX_SAFE_INTEGER]) {
    await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(await approval({ parent_deadline: String(deadline) })), state()), e => e.code === "registry_approval_invalid" && /24 hours/.test(e.message));
  }
  // Within 24 hours but past the policy's expiry.
  await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(await approval({ parent_deadline: String(now + 3_600) })), state(), now + 1_800), e => e.code === "registry_approval_outlasts_policy" && /policy's expiry/.test(e.message));
  // The wallet's own policy supplies that expiry.
  const chain = new WalletChain(new Ctx(MAINNET));
  chain.clients.splice(0, chain.clients.length, client());
  const wallet = { account: agent, approvedCapabilityManifestId: MAINNET.manifest.manifestId, policy: { schemaVersion: 1, configured: true, enabled: true, limits: { ...limits, expiresAt: (now + 1_800) * 1000 } } };
  await assert.rejects(chain.verifyRegistry(wallet, intent(await approval({ parent_deadline: String(now + 3_600) })), state()), { code: "registry_approval_outlasts_policy" });
});

test("an RPC or bundler outage while replacing reports rpc_unavailable and keeps the record", async t => {
  const f = await fixture(t), id = randomUUID(), outage = () => new HttpRequestError({ url: "https://rpc.incentiv.io", status: 503 });
  assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted");
  const state = f.chain.state, balances = f.chain.balances, build = f.chain.buildReplacement;
  f.chain.state = async () => { throw outage(); };
  await assert.rejects(f.service.reviewReplacement(id), { code: "rpc_unavailable" });
  f.chain.state = state;
  f.chain.buildReplacement = async () => { throw outage(); };
  await assert.rejects(f.service.reviewReplacement(id), e => e.code === "rpc_unavailable" && !/native-gas|CENT/.test(e.message));
  f.chain.buildReplacement = build;
  const review = await f.service.reviewReplacement(id);
  f.chain.state = async () => { throw outage(); };
  await assert.rejects(f.service.replace(id, password, digest(review.records[0])), { code: "rpc_unavailable" });
  f.chain.state = state;
  f.chain.balances = async () => { throw outage(); };
  await assert.rejects(f.service.replace(id, password, digest(review.records[0])), { code: "rpc_unavailable" });
  f.chain.balances = balances;
  assert.equal((await f.service.replace(id, password, digest(review.records[0]))).status, "superseding");
});

test("a bundler's internal or limit error during simulation keeps a new request ID retryable", async t => {
  for (const status of [200, 408]) for (const [code, data] of status === 200 ? [[-32603], [-32005], [-32603, { stack: "at handler" }]] : [[undefined]]) {
    const f = await fixture(t), id = randomUUID(), simulate = f.chain.simulate;
    f.chain.clients.splice(0, f.chain.clients.length, { readContract: async () => ({ reject: 0 }) });
    f.chain.simulate = WalletChain.prototype.simulate;
    const fetch = t.mock.method(globalThis, "fetch", async () => status === 200 ? Response.json({ jsonrpc: "2.0", id: 1, error: { code, message: "busy", ...(data ? { data } : {}) } }) : new Response("", { status }));
    await assert.rejects(f.service.send("transfer", transfer(id)), { code: "rpc_unavailable" });
    fetch.mock.restore();
    assert.notEqual((await f.service.operation(id).catch(() => ({ status: "none" }))).status, "failed", `${status} ${code}`);
    f.chain.simulate = simulate;
    assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted", `${status} ${code}`);
  }
  // A busy HTTP status is an outage unless it carries a rejection: some bundlers answer a revert with HTTP 500.
  // An endpoint that is unusable (a wrong URL or an expired key) is an outage too, with or without an RPC error,
  // and a rejection that carries "result": null is still a rejection.
  const rpc = (body, status = 200) => () => Response.json({ jsonrpc: "2.0", id: 1, ...body }, { status });
  for (const [answer, expected, label] of [
    [rpc({ error: { code: -32500, message: "AA23 reverted" } }, 500), "simulation_failed", "500 rejection"],
    [rpc({ error: { code: -32603, message: "busy" } }, 500), "rpc_unavailable", "500 busy"],
    [() => new Response("<html>bad gateway</html>", { status: 502 }), "rpc_unavailable", "502 html"],
    [() => new Response("not found", { status: 404 }), "rpc_unavailable", "404"],
    [rpc({ error: { code: -32001, message: "unauthorized" } }, 401), "rpc_unavailable", "401 rpc error"],
    [rpc({ result: null, error: { code: -32500, message: "AA23 reverted" } }), "simulation_failed", "result null"],
  ]) {
    const f = await fixture(t), id = randomUUID();
    f.chain.clients.splice(0, f.chain.clients.length, { readContract: async () => ({ reject: 0 }) });
    f.chain.simulate = WalletChain.prototype.simulate;
    const fetch = t.mock.method(globalThis, "fetch", async () => answer());
    await assert.rejects(f.service.send("transfer", transfer(id)), { code: expected }, label);
    fetch.mock.restore();
  }
  // A success that carries "error": null is still a success.
  {
    const f = await fixture(t), id = randomUUID(), simulate = f.chain.simulate;
    f.chain.clients.splice(0, f.chain.clients.length, { readContract: async () => ({ reject: 0 }) });
    f.chain.simulate = WalletChain.prototype.simulate;
    const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({ jsonrpc: "2.0", id: 1, result: { callGasLimit: "0x1", verificationGasLimit: "0x1", preVerificationGas: "0x1" }, error: null }));
    assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted");
    fetch.mock.restore();
    f.chain.simulate = simulate;
  }
  // A bundler that rejects the operation still fails it, including a revert some bundlers report as -32603.
  for (const error of [{ code: -32500, message: "AA23 reverted" }, { code: -32603, message: "execution reverted" }, { code: -32603, message: "AA23 reverted (or OOG)" }, { code: -32603, message: "internal error", data: "0x08c379a0" }]) {
    const f = await fixture(t), id = randomUUID();
    f.chain.clients.splice(0, f.chain.clients.length, { readContract: async () => ({ reject: 0 }) });
    f.chain.simulate = WalletChain.prototype.simulate;
    const fetch = t.mock.method(globalThis, "fetch", async () => Response.json({ jsonrpc: "2.0", id: 1, error }));
    await assert.rejects(f.service.send("transfer", transfer(id)), { code: "simulation_failed" }, JSON.stringify(error));
    fetch.mock.restore();
  }
});

test("a parent the registry does not currently accept keeps a link retryable instead of advising a paid replacement", async t => {
  const [code, message] = parentBlocker({ agent, parent_eligible: false, parent_is_agent: false, parent_agent_count: "0", max_agents: "5" }, parent);
  assert.equal(code, "registry_parent_not_eligible");
  // A self-link, or a parent that is itself an agent, stays permanent.
  assert.equal(parentBlocker({ agent, parent_eligible: true, parent_is_agent: true, max_agents: "5" }, parent)?.[0], "registry_ineligible");
  assert.equal(parentBlocker({ agent, parent_eligible: true, max_agents: "5" }, agent)?.[0], "registry_ineligible");
  // Signed: the same bytes stay sendable.
  const f = await registryFixture(t), id = randomUUID(), args = { request_id: id, approval: f.approval }, submit = f.service.submit;
  f.service.submit = async () => {}; // The process stops between signing and submission.
  assert.equal((await f.service.send("link_agent", args)).status, "signed");
  f.service.submit = submit;
  f.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
  await assert.rejects(f.service.send("link_agent", args), error => error.code === code && /retry once it does/.test(error.message) && !/--replace/.test(error.message));
  assert.equal((await f.service.operation(id)).status, "signed");
  f.chain.verifyRegistry = async () => {};
  assert.equal((await f.service.send("link_agent", args)).status, "submitted");
  // Unsigned: an existing request keeps its ID instead of failing.
  const g = await registryFixture(t, false), other = randomUUID(), retry = { request_id: other, approval: g.approval };
  assert.equal((await g.service.send("link_agent", retry)).status, "approval_required");
  g.chain.verifyRegistry = async () => { throw new WalletError(code, message); };
  await assert.rejects(g.service.send("link_agent", retry), { code });
  const waiting = await g.service.operation(other);
  assert.equal(waiting.status, "approval_required"); assert.equal(waiting.last_error, code);
  assert.match(waiting.next_action, /does not currently accept this Portal account as a parent/);
});

test("an unsigned link refused because its approval outlasts local policy keeps its request ID", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval };
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_approval_outlasts_policy", "Portal approval lasts past the local wallet policy's expiry; renew the policy with incentiv-mcp setup in your local terminal, or obtain a fresh approval"); };
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_approval_outlasts_policy" });
  const waiting = await f.service.operation(id);
  assert.equal(waiting.status, "approval_required"); assert.equal(waiting.last_error, "registry_approval_outlasts_policy");
  assert.match(waiting.next_action, /renews the policy.*same request ID/);
});

test("a retry whose reconciliation confirms the request returns it instead of preparing it again", async t => {
  const f = await fixture(t), id = randomUUID();
  const sent = await f.service.send("transfer", transfer(id));
  assert.equal(sent.status, "submitted");
  const [before] = await f.store.session(async s => (await Journal.open(s)).data.records);
  f.setReceipt({ success: true, actualGasCost: 100n, transactionHash: `0x${"12".repeat(32)}` });
  const builds = f.builds();
  const retried = await f.service.send("transfer", transfer(id));
  assert.equal(retried.status, "confirmed");
  assert.equal(f.builds(), builds);
  const [after] = await f.store.session(async s => (await Journal.open(s)).data.records);
  assert.equal(after.userOpHash, before.userOpHash); assert.deepEqual(after.reservation, before.reservation); assert.equal(after.nonce, before.nonce);
});

test("prepare_agent_link refuses locally, before any registry read, when no parent is allowed or another operation holds the nonce", async t => {
  const f = await fixture(t);
  f.chain.registryStatus = async () => assert.fail("a local refusal needs no registry read");
  const noParent = await f.service.prepareAgentLink();
  assert.equal(noParent.link_blocked, "registry_parent_not_allowed"); assert.equal(noParent.portal_url, undefined);
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  const id = randomUUID();
  assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted");
  const pending = await f.service.prepareAgentLink();
  assert.equal(pending.link_blocked, "operation_pending"); assert.equal(pending.portal_url, undefined);
  assert.match(pending.next_action, new RegExp(`Request ${id} owns the account nonce`));
});

test("a signed unlink from an earlier build names the replacement that frees the nonce to every new request", async t => {
  const f = await registryFixture(t), id = randomUUID(), relay = f.chain.relay;
  await legacyUnlink(f, id).catch(() => {});
  await f.store.session(async s => { const j = await Journal.open(s); j.data.records.find(r => r.requestId === id).status = "signed"; await j.save(); });
  f.chain.relay = relay;
  await assert.rejects(f.service.send("transfer", transfer(randomUUID())), e => e.code === "operation_pending" && e.message.includes(`wallet operation resolve ${id} --replace`) && /no longer sends/.test(e.message));
});

test("prepare_agent_link refuses a policy that ends before a Portal approval would", async t => {
  const f = await fixture(t), expiresAt = Date.now() + 10 * 60_000;
  await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt, agentRegistry: { parents: [parent], allowUnlink: false } } }));
  f.chain.registryStatus = async () => assert.fail("a policy that ends too soon needs no registry read");
  const refused = await f.service.prepareAgentLink();
  assert.equal(refused.link_blocked, "policy_expired"); assert.equal(refused.portal_url, undefined);
  assert.match(refused.next_action, /expires within 15 minutes.*Renew it with incentiv-mcp setup/);
});

test("a link request that waits on a full parent keeps its request ID", async t => {
  const f = await registryFixture(t, false), id = randomUUID(), args = { request_id: id, approval: f.approval };
  assert.equal((await f.service.send("link_agent", args)).status, "approval_required");
  f.chain.verifyRegistry = async () => { throw new WalletError("registry_limit_reached", "This Portal account has reached its agent limit"); };
  await assert.rejects(f.service.send("link_agent", args), { code: "registry_limit_reached" });
  const waiting = await f.service.operation(id);
  assert.equal(waiting.status, "approval_required"); assert.equal(waiting.last_error, "registry_limit_reached");
  assert.match(waiting.next_action, /reached its agent limit.*same request ID/);
});

test("a bundler's HTTP 400 keeps its RPC error's reason", async t => {
  const { bundlerRpc, BundlerUnavailableError } = await import("../src/userop.ts");
  const ctx = new Ctx(MAINNET);
  t.mock.method(globalThis, "fetch", async () => Response.json({ jsonrpc: "2.0", id: 1, error: { code: -32500, message: "AA21 didn't pay prefund" } }, { status: 400 }));
  await assert.rejects(bundlerRpc(ctx, "eth_estimateUserOperationGas", []), e => !(e instanceof BundlerUnavailableError) && /AA21 didn't pay prefund/.test(e.message));
  t.mock.restoreAll();
  t.mock.method(globalThis, "fetch", async () => new Response("bad request", { status: 400 }));
  await assert.rejects(bundlerRpc(ctx, "eth_estimateUserOperationGas", []), e => !(e instanceof BundlerUnavailableError) && /Bundler HTTP 400/.test(e.message));
  t.mock.restoreAll();
});
