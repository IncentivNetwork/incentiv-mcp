import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { encodeAbiParameters, encodeEventTopics, recoverMessageAddress, decodeFunctionData, encodeFunctionData, encodeErrorResult } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { MAINNET, configurationId, parseConfig } from "../src/config.ts";
import { deriveSmartAccount } from "../src/network.ts";
import { agentRegistryAbi, hasRegistryEvent, registryApprovalSchema, registryCall, registryRevertCode, verifyRegistryDeployment, verifyRegistryIntent } from "../src/agent-registry.ts";
import { intentSchema, Journal, digest, ownsNonce } from "../src/wallet/journal.ts";
import { validateOperation } from "../src/wallet/validate.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { limitsSchema, policyViolations } from "../src/wallet/policy.ts";
import { WalletChain } from "../src/wallet/chain.ts";
import { Ctx } from "../src/context.ts";
import { computeUserOpHash, encodeExecuteBatch, userOpToJson } from "../src/userop.ts";
import { fixture, limits, password, unsigned } from "../scripts/wallet-pipeline-fixture.mjs";

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
      if (functionName === "agentsOf") return [];
      if (functionName === "isIncentivAccount") return args[0].toLowerCase() === parent.toLowerCase();
      if (functionName === "isAccountFactory") return true;
      if (functionName === "maxAgentsPerParent") return 5n;
      if (functionName === "agentCount" || functionName === "nonces") return 0n;
      if (functionName === "parentLinkDigest") return digestToSign;
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
  for (const [functionName, answer, expected] of [["nonces", 1n, "registry_approval_stale"], ["agentCount", 5n, "registry_limit_reached"], ["isAccountFactory", false, "registry_ineligible"], ["parentOf", parent, "registry_already_linked"], ["isValidSignature", "0xffffffff", "registry_approval_invalid"]]) {
    const c = client(), good = c.readContract;
    c.readContract = args => args.functionName === functionName ? Promise.resolve(answer) : good(args);
    await assert.rejects(verifyRegistryIntent(c, MAINNET, { account: agent }, intent(a), state()), { code: expected });
  }
  await assert.rejects(verifyRegistryIntent(client(), MAINNET, { account: agent }, intent(await approval({ parent_deadline: "1" })), state()), { code: "registry_approval_expired" });
});

test("semantic validation binds registry, parent, agent, zero value, deadline and complete batch", async () => {
  const a = await approval(), i = intentSchema.parse(intent(a));
  const wallet = { account: agent, owner: owner.address };
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

test("registry policy defaults deny connection and unlink while gas budgets still apply", () => {
  const base = { token: "native", amount: "0", swap: false, slippage: 0, spend: { native: "300" }, used: {}, balances: { native: "1000000" }, gasCost: 300n, fee: 1n, gasUnits: 300n, gasToken: "native", gasCharge: 300n, calls: [], registryKind: "link_agent", registryParent: parent };
  assert.ok(policyViolations(limits, base).includes("registry_parent_not_allowed"));
  const configured = limitsSchema.parse({ ...limits, agentRegistry: { parents: [parent], allowUnlink: true } });
  assert.deepEqual(policyViolations(configured, base), []);
  assert.ok(policyViolations(limits, { ...base, registryKind: "unlink_agent" }).includes("registry_unlink_not_allowed"));
  assert.ok(policyViolations(configured, { ...base, gasCharge: 10001n }).includes("gas_payment_limit"));
});

async function registryFixture(t, allowed = true) {
  const f = await fixture(t);
  const wallet = await f.store.createOrLoad(), a = await approval({ agent: wallet.smart_account_address ?? wallet.account });
  // publicWallet uses account; obtain the exact address from the authenticated envelope.
  await f.store.session(async s => { a.agent = s.envelope.account; if (allowed) await s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, agentRegistry: { parents: [parent], allowUnlink: true }, targets: { [cap.proxy.address.toLowerCase()]: ["0x" + registryCall(MAINNET, a.agent, intent(a)).data.slice(2, 10), encodeFunctionData({ abi: agentRegistryAbi, functionName: "unlink" }).slice(0, 10)] } } }); });
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

test("unlink validates the expected parent and uses the same pipeline", async t => {
  const f = await registryFixture(t), id = randomUUID();
  const result = await f.service.send("unlink_agent", { request_id: id, parent });
  assert.equal(result.status, "submitted");
  assert.equal(decodeFunctionData({ abi: agentRegistryAbi, data: decodeFunctionData({ abi: (await import('../src/abi.ts')).accountAbi, data: f.submissions[0].callData }).args[2][0] }).functionName, "unlink");
  const c = client();
  await assert.rejects(verifyRegistryIntent(c, MAINNET, { account: agent }, { ...intent(await approval()), kind: "unlink_agent", registryApproval: undefined }, state()), { code: "registry_link_changed" });
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
});

test("receipt cannot borrow a registry event from another user operation in the same bundle", async t => {
  const chain = new WalletChain(new Ctx(MAINNET)), hash = `0x${"11".repeat(32)}`, tx = `0x${"22".repeat(32)}`, blockHash = `0x${"33".repeat(32)}`;
  const operationEvent = (await import('viem')).parseAbiItem('event UserOperationEvent(bytes32 indexed userOpHash,address indexed sender,address indexed paymaster,uint256 nonce,bool success,uint256 actualGasCost,uint256 actualGasUsed)');
  const opLog = h => ({ address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: [operationEvent], eventName: "UserOperationEvent", args: { userOpHash: h, sender: agent, paymaster: zero } }), data: encodeAbiParameters([{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }], [0n, true, 200n, 100n]) });
  let logs = [registryLog("AgentLinked"), opLog(`0x${"44".repeat(32)}`), opLog(hash)];
  chain.clients.splice(0, chain.clients.length, { getTransactionReceipt: async () => ({ status: "success", transactionHash: tx, blockNumber: 10n, blockHash, logs }), getBlock: async () => ({ hash: blockHash }), getBlockNumber: async () => 12n });
  t.mock.method(globalThis, "fetch", async () => Response.json({ result: { receipt: { transactionHash: tx } } }));
  const record = { userOpHash: hash, nonce: "0", operation: { sender: agent }, intent: intent(await approval()) };
  await assert.rejects(chain.receipt(record), /Registry event missing/);
  logs = [registryLog("AgentLinked"), opLog(hash)];
  assert.equal((await chain.receipt(record)).success, true);
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


test("registry errors produce bounded actionable codes without forwarding raw revert data", () => {
  for (const [errorName, args, expected] of [["InvalidParentSignature", [], "registry_approval_invalid"], ["SignatureExpired", [1n], "registry_approval_expired"], ["AgentLimitReached", [parent, 5n], "registry_limit_reached"]]) {
    assert.equal(registryRevertCode(encodeErrorResult({ abi: agentRegistryAbi, errorName, args })), expected);
  }
  assert.equal(registryRevertCode("0x1234"), undefined);
});

test("token-paid linking reserves only the exact paymaster transfer and rejects a hidden extra payment", async () => {
  const token = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase(), a = await approval();
  const i = { ...intent(a), token, gasToken: token }, wallet = { account: agent, owner: owner.address };
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
  const review = await f.service.reviewReplacement(id), record = review.records[0];
  assert.equal(record.replacement.gasToken, f.token); assert.equal(record.replacement.gasCharge, "150");
  assert.equal(record.replacement.operation.paymaster, MAINNET.manifest.contracts.unifiedTokenPaymaster.address);
  assert.equal(record.replacement.operation.nonce, record.operation.nonce);
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
