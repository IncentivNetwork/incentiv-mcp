import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { HttpRequestError } from "viem";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { replacementFees, WalletChain } from "../src/wallet/chain.ts";
import { userOpToJson } from "../src/userop.ts";
import { args as transfer, fixture, password } from "../scripts/wallet-pipeline-fixture.mjs";
import { digest } from "../src/wallet/journal.ts";
import { RpcDisagreementError } from "../src/wallet/errors.ts";

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

test("an RPC or bundler outage while replacing reports rpc_unavailable and keeps the record", async t => {
  const f = await fixture(t), id = randomUUID(), outage = () => new HttpRequestError({ url: "https://rpc.incentiv.io", status: 503 });
  assert.equal((await f.service.send("transfer", transfer(id))).status, "submitted");
  const state = f.chain.state, balances = f.chain.balances, build = f.chain.buildReplacement;
  f.chain.state = async () => { throw outage(); };
  await assert.rejects(f.service.reviewReplacement(id), { code: "rpc_unavailable" });
  f.chain.state = state;
  for (const failure of [outage(), new RpcDisagreementError("Token decimals disagree")]) {
    f.chain.buildReplacement = async () => { throw failure; };
    await assert.rejects(f.service.reviewReplacement(id), e => e.code === "rpc_unavailable" && !/native-gas|CENT/.test(e.message));
  }
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
