import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encodeAbiParameters, encodeEventTopics, keccak256, parseAbiItem } from "viem";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { computeUserOpHash, encodeExecuteBatch } from "../src/userop.ts";
import { buildSwapCalls, planRoute } from "../src/swap.ts";
import { WalletChain } from "../src/wallet/chain.ts";
import { authenticateWallet, parseEnvelope, sealWallet, walletAad } from "../src/wallet/keystore.ts";
import { limitsSchema, newAdministration } from "../src/wallet/policy.ts";
import { Journal, digest } from "../src/wallet/journal.ts";
import { WalletService } from "../src/wallet/service.ts";
import { args, fixture, limits, password, recipient, unsigned } from "../scripts/wallet-pipeline-fixture.mjs";

test("default local candidate signs within policy without implying publication approval", async t => {
  const f = await fixture(t);
  const service = new WalletService(new Ctx(MAINNET), f.store, f.chain);
  const state = await service.get();
  assert.equal(state.candidate_signing_enabled, true);
  assert.equal((await service.send("transfer", args(randomUUID()))).status, "submitted");
  assert.equal(f.submissions.length, 1);
});

test("trusted RPC policy is explicit, authenticated, and leaves legacy AAD unchanged", async () => {
  const key = Buffer.alloc(32, 1), wrapping = Buffer.alloc(32, 2);
  const binding = { schemaVersion: 1, walletId: randomUUID(), creationToken: randomUUID(), storage: "file" };
  const policy = { schemaVersion: 1, configured: true, enabled: true, limits, administration: await newAdministration(password) };
  const legacy = sealWallet(MAINNET, binding, key, wrapping, policy);
  const parsed = parseEnvelope(JSON.parse(JSON.stringify(legacy)));
  assert.deepEqual(walletAad(parsed), walletAad(legacy));
  assert.equal(Object.hasOwn(parsed.policy.limits, "trustedRpcOrigins"), false);
  authenticateWallet(MAINNET, parsed, wrapping);
  const trusted = { ...limits, trustedRpcOrigins: ["https://rpc.incentiv.io"] };
  const sealed = sealWallet(MAINNET, binding, key, wrapping, { ...policy, limits: trusted });
  authenticateWallet(MAINNET, parseEnvelope(sealed), wrapping);
  sealed.policy.limits.trustedRpcOrigins = ["https://malicious.test"];
  assert.throws(() => authenticateWallet(MAINNET, sealed, wrapping));
  for (const origin of ["https://rpc.incentiv.io/", "https://user:pass@rpc.incentiv.io", "https://rpc.incentiv.io/path", "file:///local"]) {
    assert.equal(limitsSchema.safeParse({ ...limits, trustedRpcOrigins: [origin] }).success, false);
  }
  key.fill(0); wrapping.fill(0);
});

test("a tightened policy or balance blocks signed retries without discarding their reservation", async t => {
  for (const scenario of ["policy", "balance"]) await t.test(scenario, async t => {
    const f = await fixture(t), id = randomUUID();
    await f.service.send("transfer", args(id));
    const original = (await f.service.review(id)).records[0];
    if (scenario === "policy") await f.store.session(s => s.savePolicy({ ...s.envelope.policy, limits: { ...limits, maxGasCostWei: "1" } }));
    else f.chain.balances = async () => ({ native: "1" });
    await assert.rejects(f.service.send("transfer", args(id)), { code: "policy_denied" });
    const current = (await f.service.review(id)).records[0];
    assert.deepEqual(current.operation, original.operation);
    assert.deepEqual(current.reservation, original.reservation);
    assert.equal(f.submissions.length, 1);
  });
});

test("the final relay callback prevents a policy change during connection from broadcasting", async t => {
  const f = await fixture(t), id = randomUUID(), relay = f.chain.relay;
  f.chain.relay = async (wire, beforeSubmit) => {
    await f.store.disable();
    return relay(wire, beforeSubmit);
  };
  assert.equal((await f.service.send("transfer", args(id))).status, "submission_unknown");
  assert.equal(f.submissions.length, 0);
  const record = (await f.service.review(id)).records[0];
  assert.notEqual(record.operation.signature, "0x");
  assert.deepEqual(record.reservation, { native: "1300" });
});

test("in-policy swaps sign automatically and recheck the route before signing and broadcast", async t => {
  for (const failAt of [0, 2, 4]) await t.test(`failAt=${failAt}`, async t => {
    const f = await fixture(t), id = randomUUID(), ctx = new Ctx(MAINNET);
    const input = { address: MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase(), decimals: 18, symbol: "USDC" };
    const output = { address: "native", decimals: 18, symbol: "CENT" };
    f.chain.token = async ref => ref === "USDC" || ref === input.address ? input : output;
    f.chain.balances = async () => ({ native: "1000000", [input.address]: "1000000" });
    let checks = 0;
    f.chain.verifySwap = async () => { if (++checks === failAt) throw new Error("quote changed"); };
    f.chain.build = async (wallet, intent, state, deadline) => {
      assert.ok(deadline <= Math.floor(Date.now() / 1000) + 60);
      const built = unsigned(wallet, { to: recipient, amount: intent.amount }, state);
      const calls = buildSwapCalls(ctx, input, output, planRoute(ctx, input, output), BigInt(intent.amount), BigInt(intent.minimumOut), wallet.account, true, BigInt(deadline));
      built.op.callData = encodeExecuteBatch(calls);
      built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, MAINNET.identity.chainId);
      return built;
    };
    await f.store.session(async s => {
      const calls = buildSwapCalls(ctx, input, output, planRoute(ctx, input, output), 1000n, 995n, s.envelope.account, true, BigInt(Math.floor(Date.now() / 1000) + 60));
      const targets = {};
      for (const call of calls) (targets[call.to.toLowerCase()] ??= []).push(call.data.slice(0, 10));
      await s.savePolicy({ ...s.envelope.policy, limits: { ...limits, swaps: true, tokens: { ...limits.tokens, [input.address]: limits.tokens.native }, targets, maxBatchCalls: 4, trustedRpcOrigins: ["https://rpc.incentiv.io"] } });
    });
    const request = { request_id: id, token_in: "USDC", token_out: "CENT", amount_in: "0.000000000000001", minimum_out: "0.000000000000000995" };
    if (failAt === 2) await assert.rejects(f.service.send("swap", request));
    else assert.equal((await f.service.send("swap", request)).status, failAt ? "submission_unknown" : "submitted");
    assert.equal(f.submissions.length, failAt ? 0 : 1);
    const record = (await f.service.review(id)).records[0];
    assert.equal(record.approval, undefined, "policy-authorized swaps need no per-operation approval");
    if (!failAt) {
      f.setReceipt({ success: true, actualGasCost: 200n, transactionHash: `0x${"55".repeat(32)}` });
      assert.equal((await f.service.operation(id)).status, "confirmed");
      assert.equal((await f.service.send("swap", request)).status, "confirmed");
      assert.equal(f.submissions.length, 1);
    }
  });
});

test("swap preflight verifies fresh blocks, contract pins, pool identity and zero allowance", async () => {
  const config = structuredClone(MAINNET), code = "0x6001";
  for (const pin of [...Object.values(config.manifest.contracts), ...Object.values(config.manifest.canonicalTokens)]) pin.codeHash = keccak256(code);
  const chain = new WalletChain(new Ctx(config)), factory = recipient;
  const input = config.manifest.canonicalTokens.USDC.address, output = config.manifest.contracts.wcent.address;
  chain.token = async ref => ({ address: ref, decimals: 18, symbol: "test" });
  chain.quote = async (_intent, _limits, block) => assert.equal(block, 123n);
  let allowance = 0n, fee = 3000, runtime = code;
  chain.clients.splice(0, chain.clients.length, {
    getCode: async ({ blockNumber }) => { assert.equal(blockNumber, 123n); return runtime; },
    readContract: async ({ functionName, blockNumber }) => {
      assert.equal(blockNumber, 123n);
      return { factory, getPool: input, token0: input, token1: output, fee, allowance }[functionName];
    },
  });
  const intent = { kind: "swap", token: input, tokenOut: output, amount: "1000", minimumOut: "995", feeTier: 3000 };
  const state = { block: 123n, timestamp: Math.floor(Date.now() / 1000) };
  await chain.verifySwap({ account: recipient }, intent, limits, state);
  allowance = 1n; await assert.rejects(chain.verifySwap({ account: recipient }, intent, limits, state), /allowance/);
  allowance = 0n; fee = 100; await assert.rejects(chain.verifySwap({ account: recipient }, intent, limits, state), /pool/);
  fee = 3000; runtime = "0x6002"; await assert.rejects(chain.verifySwap({ account: recipient }, intent, limits, state), /code/);
  await assert.rejects(chain.verifySwap({ account: recipient }, intent, limits, { ...state, timestamp: state.timestamp - 61 }), /stale/);
});

test("receipt settlement requires canonical confirmed inclusion", async t => {
  const chain = new WalletChain(new Ctx(MAINNET)), hash = `0x${"11".repeat(32)}`, tx = `0x${"22".repeat(32)}`, blockHash = `0x${"33".repeat(32)}`;
  const event = parseAbiItem("event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)");
  const zero = `0x${"00".repeat(20)}`;
  const log = { address: MAINNET.identity.entryPoint.address, topics: encodeEventTopics({ abi: [event], eventName: "UserOperationEvent", args: { userOpHash: hash, sender: recipient, paymaster: zero } }), data: encodeAbiParameters([{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }], [0n, true, 200n, 100n]) };
  let canonical = blockHash;
  chain.clients.splice(0, chain.clients.length, {
    getTransactionReceipt: async () => ({ status: "success", transactionHash: tx, blockNumber: 10n, blockHash, logs: [log] }),
    getBlock: async () => ({ hash: canonical }), getBlockNumber: async () => 12n,
  });
  t.mock.method(globalThis, "fetch", async (_url, options) => {
    const request = JSON.parse(options.body);
    return Response.json({ jsonrpc: "2.0", id: request.id, result: { receipt: { transactionHash: tx } } });
  });
  const record = { userOpHash: hash, nonce: "0", operation: { sender: recipient } };
  assert.equal((await chain.receipt(record)).actualGasCost, 200n);
  canonical = `0x${"44".repeat(32)}`;
  await assert.rejects(chain.receipt(record), /canonical/);
});
