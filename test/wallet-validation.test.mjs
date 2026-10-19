import assert from "node:assert/strict";
import test from "node:test";
import { encodeFunctionData, encodeFunctionResult } from "viem";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { erc20Abi, quoterAbi } from "../src/abi.ts";
import { computeUserOpHash, encodeExecuteBatch, userOpToJson } from "../src/userop.ts";
import { buildSwapCalls, planRoute } from "../src/swap.ts";
import { parseEnvelope } from "../src/wallet/keystore.ts";
import { validateOperation } from "../src/wallet/validate.ts";
import { exactAmount, WalletChain } from "../src/wallet/chain.ts";
import { policyViolations } from "../src/wallet/policy.ts";
import { limits, recipient, unsigned } from "../scripts/wallet-pipeline-fixture.mjs";
import { readFile } from "node:fs/promises";

const vector = JSON.parse(await readFile(new URL("./fixtures/wallet-v1.json", import.meta.url), "utf8"));
const wallet = parseEnvelope(vector.envelope);
const intent = { intentSchemaVersion: 1, kind: "transfer", token: "native", amount: "1000", gasToken: "native", to: recipient, slippageBps: 0, feeTier: 3000 };
const state = { nonce: 0n, deployed: false };
const make = () => unsigned(wallet, intent, state);
const validate = (op, hash, input = intent, deadline) => validateOperation(MAINNET, wallet, input, userOpToJson(op), { ...state, hash: hash ?? computeUserOpHash(op, MAINNET.identity.entryPoint.address, MAINNET.identity.chainId), deadline });

test("independent decoder accepts the exact transfer and rejects altered domain, amounts, recipients, extra calls and unknown fields", () => {
  assert.deepEqual(validate(make().op).spend, { native: "1300" });
  const mutations = [
    op => { op.sender = recipient; }, op => { op.nonce = 1n; },
    op => { op.factory = recipient; }, op => { op.factoryData += "00"; },
    op => { op.callData = encodeExecuteBatch([{ to: recipient, value: 1001n, data: "0x" }]); },
    op => { op.callData = encodeExecuteBatch([{ to: wallet.owner, value: 1000n, data: "0x" }]); },
    op => { op.callData = encodeExecuteBatch([{ to: recipient, value: 1000n, data: "0x" }, { to: recipient, value: 1n, data: "0x" }]); },
    op => { op.callData += "00"; }, op => { op.callData = "0xdeadbeef"; },
    op => { op.maxPriorityFeePerGas = 2n; }, op => { op.signature = "0x12"; },
    op => { op.paymaster = MAINNET.manifest.contracts.unifiedTokenPaymaster.address; },
  ];
  for (const change of mutations) { const { op } = make(); change(op); assert.throws(() => validate(op), { code: "validation_failed" }); }
  assert.throws(() => validate(make().op, `0x${"00".repeat(32)}`), { code: "validation_failed" });
  const wire = userOpToJson(make().op); wire.secret = "CANARY";
  assert.throws(() => validateOperation(MAINNET, wallet, intent, wire, { ...state, hash: make().userOpHash }), { code: "validation_failed" });
});

test("paymaster token payment must have the pinned recipient and no hidden calls", () => {
  const { op } = make(); const token = MAINNET.manifest.canonicalTokens.USDC.address;
  op.paymaster = MAINNET.manifest.contracts.unifiedTokenPaymaster.address;
  op.paymasterData = "0x"; op.paymasterVerificationGasLimit = 100n; op.paymasterPostOpGasLimit = 50n;
  const payment = to => ({ to: token, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to, 10n] }) });
  op.callData = encodeExecuteBatch([payment(op.paymaster), { to: recipient, value: 1000n, data: "0x" }]);
  assert.equal(validate(op, undefined, { ...intent, gasToken: token }).gasCharge, 10n);
  op.callData = encodeExecuteBatch([payment(recipient), { to: recipient, value: 1000n, data: "0x" }]);
  assert.throws(() => validate(op, undefined, { ...intent, gasToken: token }), { code: "validation_failed" });
});

test("independent swap decoder checks all routes, exact minimums and deadline", () => {
  const ctx = new Ctx(MAINNET), deadline = Math.floor(Date.now() / 1000) + 60;
  const native = { address: "native", decimals: 18 }, wcent = { address: MAINNET.manifest.contracts.wcent.address, decimals: 18 };
  const tokens = Object.values(MAINNET.manifest.canonicalTokens).filter(p => p.address !== wcent.address).slice(0, 2).map(p => ({ address: p.address, decimals: 18 }));
  for (const [input, output] of [[native, wcent], [wcent, native], [native, tokens[0]], [tokens[0], native], [wcent, tokens[0]], [tokens[0], tokens[1]]]) {
    const swap = { ...intent, kind: "swap", to: undefined, token: input.address, tokenOut: output.address, minimumOut: "900", slippageBps: 50 };
    const { op } = make();
    op.callData = encodeExecuteBatch(buildSwapCalls(ctx, input, output, planRoute(ctx, input, output), 1000n, 900n, wallet.account, true, BigInt(deadline)));
    validate(op, undefined, swap, deadline);
    if (input.address !== native.address || output.address !== wcent.address) {
      // Wrap/unwrap have a fixed 1:1 output, so a lower bound isn't an encoded router field.
      if (!(input.address === wcent.address && output.address === native.address)) assert.throws(() => validate(op, undefined, { ...swap, minimumOut: "901" }, deadline), { code: "validation_failed" });
    }
    assert.throws(() => validate(op, undefined, swap, 1), { code: "validation_failed" });
  }
});

test("wallet amounts never round and single-source autonomous quotes fail before reading a quote", async () => {
  assert.equal(exactAmount("1.001", 3), 1001n);
  for (const amount of ["0", "1.001", "1e5", "-1", "01", "NaN"]) assert.throws(() => exactAmount(amount, 2), { code: "validation_failed" });
  const chain = new WalletChain(new Ctx(MAINNET));
  await assert.rejects(chain.quote({ ...intent, kind: "swap" }, limits, 123n), { code: "validation_failed" });
});

test("independent quote quorum rejects a manipulating source and a weak absolute minimum", async t => {
  const config = structuredClone(MAINNET);
  config.endpoints.rpcUrls = ["https://first.test", "https://second.test"];
  const chain = new WalletChain(new Ctx(config));
  const tokenIn = MAINNET.manifest.canonicalTokens.USDC.address, tokenOut = MAINNET.manifest.contracts.wcent.address;
  chain.token = async ref => ({ address: ref, decimals: 18, symbol: "test", name: "test" });
  const original = globalThis.fetch; t.after(() => { globalThis.fetch = original; });
  let secondQuote = 1100n;
  globalThis.fetch = async (url, options) => {
    const request = JSON.parse(options.body); assert.equal(request.method, "eth_call");
    assert.equal(request.params[1], "0x7b");
    const amount = String(url).includes("second") ? secondQuote : 1000n;
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: request.id, result: encodeFunctionResult({ abi: quoterAbi, functionName: "quoteExactInputSingle", result: [amount, 0n, 0, 100000n] }) }), { status: 200, headers: { "content-type": "application/json" } });
  };
  const policy = { ...limits, independentRpcOrigins: config.endpoints.rpcUrls };
  const swap = { ...intent, kind: "swap", token: tokenIn, tokenOut, minimumOut: "995", slippageBps: 50 };
  await assert.rejects(chain.quote(swap, policy, 123n), { code: "validation_failed" });
  secondQuote = 1000n; await chain.quote(swap, policy, 123n);
  await assert.rejects(chain.quote({ ...swap, minimumOut: "900" }, policy, 123n), { code: "validation_failed" });
  config.endpoints.rpcUrls = ["https://first.test"];
  const single = new WalletChain(new Ctx(config)); single.token = chain.token;
  await assert.rejects(single.quote(swap, { ...limits, trustedRpcOrigins: [] }, 123n), { code: "validation_failed" });
  await assert.rejects(single.quote(swap, { ...limits, trustedRpcOrigins: ["https://other.test"] }, 123n), { code: "validation_failed" });
  await single.quote(swap, { ...limits, trustedRpcOrigins: ["https://first.test"] }, 123n);
  await assert.rejects(single.quote({ ...swap, minimumOut: "900" }, { ...limits, trustedRpcOrigins: ["https://first.test"] }, 123n), { code: "validation_failed" });
});

test("policy covers aggregate daily gas/input, exposure, expiry, gas caps and contract selectors", () => {
  const input = { token: "native", amount: "1000", to: recipient, swap: false, slippage: 0, spend: { native: "1300" }, used: {}, balances: { native: "1000000" }, gasCost: 300n, fee: 1n, gasUnits: 300n, gasToken: "native", gasCharge: 300n, calls: [] };
  assert.deepEqual(policyViolations(limits, input), []);
  assert.ok(policyViolations(limits, { ...input, used: { native: "999000" } }).includes("daily_limit"));
  assert.ok(policyViolations(limits, { ...input, balances: { native: "10000001" } }).includes("exposure_limit"));
  assert.ok(policyViolations({ ...limits, expiresAt: 1 }, input).includes("policy_expired"));
  assert.ok(policyViolations(limits, { ...input, gasCost: 10001n }).includes("gas_limit"));
  assert.ok(policyViolations(limits, { ...input, gasCharge: 10001n }).includes("gas_payment_limit"));
  assert.ok(policyViolations(limits, { ...input, calls: [{ to: recipient, data: "0xdeadbeef" }] }).includes("target_or_selector_not_allowed"));
  assert.ok(policyViolations({ ...limits, swaps: true }, { ...input, swap: true, tokenOut: recipient }).includes("swap_not_allowed"));
});
