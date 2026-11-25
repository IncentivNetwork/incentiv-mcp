import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encodeAbiParameters, encodeEventTopics, encodeFunctionData, erc20Abi, getAddress, parseAbiItem, recoverMessageAddress } from "viem";
import { decodePaymentSignatureHeader, encodePaymentRequiredHeader, encodePaymentResponseHeader } from "@x402/core/http";
import * as incentiv from "@incentiv/x402";
import { args, fixture, limits, password, recipient } from "../scripts/wallet-pipeline-fixture.mjs";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { WalletChain } from "../src/wallet/chain.ts";
import { accountFactoryAbi } from "../src/abi.ts";
import { computeUserOpHash, encodeExecuteBatch, userOpFromJson } from "../src/userop.ts";
import { Journal, digest, intentSchema } from "../src/wallet/journal.ts";
import { limitsSchema, policyViolations, x402Violations } from "../src/wallet/policy.ts";
import { checkHeaders, checkResourceUrl, isPublicAddress } from "../src/x402/http.ts";
import { parsePaymentRequired, paymentNonceKey, selectRequirements, x402Config, X402_NETWORK, X402_SCHEME } from "../src/x402/protocol.ts";
import { facilitatorUrl } from "../src/x402/discovery.ts";
import { usdcAmount, x402Request } from "../src/x402/request.ts";
import { registerX402Tools } from "../src/x402/tools.ts";
import { discoverResources } from "../src/x402/discovery.ts";
import { spawn } from "node:child_process";
import { createServer } from "node:net";
import { fileURLToPath } from "node:url";

const usdc = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase();
const entryPoint = MAINNET.identity.entryPoint.address;
const paymaster = MAINNET.manifest.contracts.unifiedTokenPaymaster.address;
const seller = "0x00000000000000000000000000000000000000aa";
const URL_ = "https://api.example.com/weather";
const requirements = { scheme: X402_SCHEME, network: X402_NETWORK, asset: usdc, amount: "50000", payTo: seller, maxTimeoutSeconds: 120, extra: { entryPoint } };
const GAS_FEE = 30_000n;
const x402Policy = { origins: { mode: "allowlist", origins: ["https://api.example.com"] }, payTo: { mode: "any" }, maxPerPayment: "100000" };

test("x402 constants, contracts and nonce lanes match @incentiv/x402", () => {
  assert.equal(X402_NETWORK, incentiv.NETWORK);
  assert.equal(X402_SCHEME, incentiv.SCHEME);
  const cfg = x402Config(MAINNET);
  for (const key of ["entryPoint", "accountFactory", "paymaster", "transferGate", "quoter", "wcent", "usdc"]) assert.equal(cfg[key].toLowerCase(), incentiv.MAINNET[key].toLowerCase(), key);
  assert.equal(cfg.chainId, incentiv.MAINNET.chainId);
  for (let i = 0; i < 4; i++) {
    const id = `0x${randomUUID().replaceAll("-", "").padEnd(64, "f")}`, until = 1_800_000_000 + i;
    assert.equal(paymentNonceKey(id, until), incentiv.paymentNonceKey(id, until));
  }
  const other = structuredClone(MAINNET); other.identity.chainId = 1;
  assert.throws(() => x402Config(other), /only on Incentiv mainnet/);
});

test("outbound x402 requests reach only public https hosts with caller-safe headers", () => {
  for (const address of ["8.8.8.8", "1.1.1.1", "2606:4700:4700::1111", "::ffff:8.8.8.8"]) assert.ok(isPublicAddress(address), address);
  for (const address of ["127.0.0.1", "10.1.2.3", "172.16.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "224.0.0.1", "::1", "::", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "2001:db8::1", "2002:7f00:1::1", "not-an-ip"]) assert.equal(isPublicAddress(address), false, address);
  for (const url of ["http://api.example.com", "https://localhost/x", "https://127.0.0.1/", "https://[::1]/", "https://10.0.0.1/", "https://169.254.169.254/latest", "https://user:pass@api.example.com/", "https://intranet/", "https://printer.local/", "https://db.internal/", "ftp://example.com", "not a url"]) assert.throws(() => checkResourceUrl(url), { code: "validation_failed" }, url);
  assert.equal(checkResourceUrl("https://api.example.com/path?q=1#frag").href, "https://api.example.com/path?q=1");
  for (const name of ["payment-signature", "Host", "X-PAYMENT", "content-length", "bad name"]) assert.throws(() => checkHeaders({ [name]: "x" }), { code: "validation_failed" }, name);
  assert.throws(() => checkHeaders({ "x-api": "a\r\nb: c" }), { code: "validation_failed" });
  assert.deepEqual(checkHeaders({ "X-Api-Key": "k" }), { "x-api-key": "k" });
  assert.throws(() => x402Request({ url: URL_, body: "{}" }), /Only a POST/);
  assert.throws(() => x402Request({ url: URL_, method: "PUT" }), /GET or POST/);
  assert.deepEqual(x402Request({ url: URL_, method: "post", body: "{}" }), { url: URL_, origin: "https://api.example.com", method: "POST", headers: {}, body: "{}" });
  for (const bad of ["0", "0.0000001", "1e3", "-1", "", "1,5"]) assert.throws(() => usdcAmount(bad), { code: "validation_failed" }, bad);
  assert.equal(usdcAmount("0.05"), 50_000n);
  assert.equal(facilitatorUrl({}), "https://x402.incentiv.io");
  assert.equal(facilitatorUrl({ INCENTIV_X402_FACILITATOR_URL: "https://pay.example.com" }), "https://pay.example.com");
  for (const value of ["https://pay.example.com/api", "http://pay.example.com", "https://127.0.0.1"]) assert.throws(() => facilitatorUrl({ INCENTIV_X402_FACILITATOR_URL: value }), { code: "validation_failed" }, value);
});

test("a 402 is read from its header or body, and only Incentiv USDC through the pinned EntryPoint is payable", () => {
  const required = { x402Version: 2, resource: { url: URL_ }, accepts: [
    { ...requirements, scheme: "exact", network: "eip155:8453" },
    { ...requirements, extra: { entryPoint: "0x0000000000000000000000000000000000000001" } },
    { ...requirements, maxTimeoutSeconds: 301 },
    { ...requirements, asset: "0x0000000000000000000000000000000000000003" },
    { ...requirements, amount: "0" },
    requirements,
  ] };
  const fromHeader = parsePaymentRequired({ status: 402, headers: { "payment-required": encodePaymentRequiredHeader(required) }, body: Buffer.alloc(0), truncated: false });
  const fromBody = parsePaymentRequired({ status: 402, headers: {}, body: Buffer.from(JSON.stringify(required)), truncated: false });
  assert.deepEqual(fromHeader, fromBody);
  assert.equal(selectRequirements(fromHeader, MAINNET), fromHeader.accepts[5]);
  assert.throws(() => selectRequirements({ ...required, accepts: required.accepts.slice(0, 5) }, MAINNET), { code: "x402_unsupported" });
  assert.throws(() => parsePaymentRequired({ status: 402, headers: {}, body: Buffer.from(JSON.stringify({ ...required, x402Version: 1 })), truncated: false }), { code: "x402_invalid_response" });
  assert.throws(() => parsePaymentRequired({ status: 402, headers: {}, body: Buffer.from("<html>"), truncated: false }), { code: "x402_invalid_response" });
});

test("x402 policy is off by default, bounds sites, sellers and price, and skips the transfer recipient allowlist", () => {
  const base = limitsSchema.parse({ ...limits, tokens: { ...limits.tokens, [usdc]: { perTransaction: "1000000", daily: "2000000", exposure: "100000000", gasPayment: "100000" } } });
  assert.deepEqual(x402Violations(base, "https://api.example.com", seller, "1"), ["x402_not_enabled"]);
  const policy = limitsSchema.parse({ ...base, x402: { ...x402Policy, payTo: { mode: "allowlist", addresses: [seller] } } });
  assert.deepEqual(x402Violations(policy, "https://api.example.com", seller, "100000"), []);
  assert.deepEqual(x402Violations(policy, "https://evil.example.com", recipient, "100001"), ["x402_origin_not_allowed", "x402_pay_to_not_allowed", "x402_payment_limit"]);
  const input = { token: usdc, amount: "50000", swap: false, slippage: 0, spend: { [usdc]: "80000" }, used: {}, balances: { [usdc]: "100000" }, gasCost: 1n, fee: 1n, gasUnits: 1n, gasToken: usdc, gasCharge: 30000n, calls: [] };
  assert.deepEqual(policyViolations(policy, { ...input, x402: { origin: "https://api.example.com", payTo: seller } }), []);
  assert.deepEqual(policyViolations(base, { ...input, x402: { origin: "https://api.example.com", payTo: seller } }), ["x402_not_enabled"]);
  assert.throws(() => limitsSchema.parse({ ...base, x402: { ...x402Policy, origins: { mode: "allowlist", origins: ["https://api.example.com/path"] } } }));
  assert.throws(() => limitsSchema.parse({ ...base, x402: { ...x402Policy, origins: { mode: "allowlist", origins: ["http://api.example.com"] } } }));
  const intent = { intentSchemaVersion: 1, kind: "x402_payment", token: usdc, amount: "50000", gasToken: usdc, to: seller, slippageBps: 0, feeTier: 3000, x402: { url: URL_, origin: "https://api.example.com", method: "GET", request: digest("r"), maxAmount: "50000", accepted: "{}", paymentId: digest("p"), validUntil: 1 } };
  assert.equal(intentSchema.parse(intent).kind, "x402_payment");
  assert.throws(() => intentSchema.parse({ ...intent, x402: { ...intent.x402, maxAmount: "49999" } }), /Invalid x402 intent/);
  assert.throws(() => intentSchema.parse({ ...intent, x402: undefined }), /Invalid x402 intent/);
  assert.throws(() => intentSchema.parse({ ...intent, kind: "transfer" }), /Invalid x402 intent/);
});

/** The reference client's operation shape (SPEC 4.3), built offline: gas to the paymaster in USDC, then the payment. */
function prepare(_chain, o) {
  const zero = `0x${"0".repeat(64)}`;
  const transfer = (to, amount) => ({ to: o.asset, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to, amount] }) });
  const calls = o.gas === "native" ? [transfer(o.payTo, o.amount)] : [transfer(paymaster, GAS_FEE), transfer(o.payTo, o.amount)];
  const op = {
    sender: o.account, nonce: paymentNonceKey(o.paymentId, o.validUntil) << 64n,
    factory: MAINNET.identity.accountFactory.address, factoryData: encodeFunctionData({ abi: accountFactoryAbi, functionName: "createAccount", args: [o.owner, [zero, zero], 0n] }),
    callData: encodeExecuteBatch(calls), callGasLimit: 100n, verificationGasLimit: 100n, preVerificationGas: 100n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n,
    ...(o.gas === "native" ? {} : { paymaster, paymasterVerificationGasLimit: 100n, paymasterPostOpGasLimit: 100n, paymasterData: "0x" }),
    signature: "0x",
  };
  return { op, userOpHash: computeUserOpHash(op, entryPoint, MAINNET.identity.chainId), gasFee: o.gas === "native" ? 0n : GAS_FEE, calls };
}

async function x402Fixture(t, { policy = x402Policy, usdcLimits = {} } = {}) {
  const f = await fixture(t);
  const tokens = { ...limits.tokens, [usdc]: { perTransaction: "1000000", daily: "2000000", exposure: "100000000", gasPayment: "100000", ...usdcLimits } };
  await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, limits: limitsSchema.parse({ ...limits, tokens, targets: { [usdc]: ["0xa9059cbb"] }, ...(policy ? { x402: policy } : {}) }) }));
  f.chain.balances = async (_wallet, list) => Object.fromEntries(list.map(token => [token.toLowerCase(), token === "native" ? "1000000" : token.toLowerCase() === usdc ? "5000000" : "0"]));
  f.chain.laneNonce = async (_wallet, key) => key << 64n;
  f.service.x402Loader = async () => ({ ...incentiv, makeChain: () => ({}), preparePayment: async (chain, o) => prepare(chain, o) });
  const seen = { unpaid: 0, payments: [], headers: [], fail: 0, refuse: false };
  f.service.http = async req => {
    const header = req.headers?.["payment-signature"];
    if (!header) { seen.unpaid++; return { status: 402, headers: { "payment-required": encodePaymentRequiredHeader({ x402Version: 2, resource: { url: req.url, description: "Weather", mimeType: "application/json" }, accepts: [requirements] }) }, body: Buffer.from("{}"), truncated: false }; }
    seen.headers.push(header); seen.payments.push(decodePaymentSignatureHeader(header));
    if (seen.fail > 0) { seen.fail--; throw new Error("socket hang up"); }
    if (seen.refuse) return { status: 402, headers: { "payment-required": encodePaymentRequiredHeader({ x402Version: 2, error: "insufficient_funds", resource: { url: req.url }, accepts: [requirements] }) }, body: Buffer.from("{}"), truncated: false };
    return { status: 200, headers: { "content-type": "application/json", "payment-response": encodePaymentResponseHeader({ success: true, transaction: `0x${"ab".repeat(32)}`, network: X402_NETWORK, payer: seen.payments.at(-1).payload.userOperation.sender }) }, body: Buffer.from('{"tempC":21}'), truncated: false };
  };
  const owner = await f.store.session(async s => s.envelope.owner);
  const used = () => f.store.session(async s => (await Journal.open(s)).used());
  return { ...f, seen, owner, used };
}

test("pays a resource within policy: the signed payment is exactly the quoted one, journaled first, on its own nonce lane", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  const paid = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(paid.status, "submitted");
  assert.deepEqual(JSON.parse(paid.content.text), { tempC: 21 });
  assert.equal(paid.content.third_party_content, true);
  assert.equal(paid.settlement.success, true);
  assert.equal(paid.transaction_hash, `0x${"ab".repeat(32)}`);
  assert.equal(paid.intent.amount, "0.05");
  assert.equal(f.seen.payments.length, 1);
  const payment = f.seen.payments[0];
  assert.deepEqual(payment.accepted, requirements);
  assert.equal(payment.resource.url, URL_);
  const op = userOpFromJson(payment.payload.userOperation);
  assert.equal(payment.payload.userOpHash, computeUserOpHash({ ...op, signature: "0x" }, entryPoint, MAINNET.identity.chainId));
  assert.equal((await recoverMessageAddress({ message: { raw: payment.payload.userOpHash }, signature: op.signature })).toLowerCase(), f.owner.toLowerCase());
  assert.equal(op.nonce >> 64n, paymentNonceKey(payment.payload.paymentId, payment.payload.validUntil));
  incentiv.checkPaysRequirements(incentiv.decodePaymentOp(op, incentiv.MAINNET), requirements);
  assert.deepEqual(await f.used(), { [usdc]: "80000" });
  // Its own nonce lane: a transfer is not blocked while the payment settles.
  assert.equal((await f.service.send("transfer", args(randomUUID()))).status, "submitted");
  // A retry never pays twice, even before the receipt shows: it offers the same signed payment again for the
  // answer, and the request ID stays bound to this request.
  assert.equal((await f.service.operation(id)).status, "submitted");
  const again = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(again.status, "submitted"); assert.equal(again.content_delivered, true);
  assert.equal(f.seen.payments.length, 2); assert.deepEqual(f.seen.payments[1], f.seen.payments[0]);
  assert.equal((await f.used())[usdc], "80000");
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.06", request_id: id }), { code: "idempotency_conflict" });
  await assert.rejects(f.service.send("transfer", args(id)), { code: "idempotency_conflict" });
  f.setReceipt({ success: true, actualGasCost: 1n, transactionHash: `0x${"ab".repeat(32)}` });
  assert.equal((await f.service.operation(id)).status, "confirmed");
  assert.equal((await f.used())[usdc], "80000");
});

test("refuses a price above max_amount or outside policy before signing, and checks the site before any request", async t => {
  const f = await x402Fixture(t);
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.04", request_id: randomUUID() }), { code: "x402_price_above_max" });
  await assert.rejects(f.service.payX402({ url: "https://other.example.com/x", max_amount: "1", request_id: randomUUID() }), e => e.code === "policy_denied" && /x402_origin_not_allowed/.test(e.message));
  assert.equal(f.seen.unpaid, 1);
  assert.equal(f.seen.payments.length, 0);
  await f.store.session(async s => assert.equal((await Journal.open(s)).data.records.length, 0));

  const daily = await x402Fixture(t, { usdcLimits: { perTransaction: "60000", daily: "60000" } }), id = randomUUID();
  await assert.rejects(daily.service.payX402({ url: URL_, max_amount: "1", request_id: id }), e => e.code === "policy_denied" && /daily_limit/.test(e.message));
  assert.equal(daily.seen.payments.length, 0);
  assert.equal((await daily.service.operation(id)).status, "failed");
  assert.deepEqual(await daily.used(), {});

  const sellers = await x402Fixture(t, { policy: { ...x402Policy, payTo: { mode: "allowlist", addresses: [recipient] } } });
  await assert.rejects(sellers.service.payX402({ url: URL_, max_amount: "1", request_id: randomUUID() }), e => e.code === "policy_denied" && /x402_pay_to_not_allowed/.test(e.message));
  const off = await x402Fixture(t, { policy: null });
  await assert.rejects(off.service.payX402({ url: URL_, max_amount: "1", request_id: randomUUID() }), e => e.code === "policy_denied" && /x402 payments are off/.test(e.message));
  assert.equal(off.seen.unpaid, 0);
  // An unreachable resource is a request failure, never a wallet storage problem.
  const down = await x402Fixture(t);
  down.service.http = async () => { throw new Error("getaddrinfo ENOTFOUND api.example.com"); };
  await assert.rejects(down.service.payX402({ url: URL_, max_amount: "1", request_id: randomUUID() }), e => e.code === "x402_request_failed" && /nothing was paid/.test(e.message));
});

test("an unanswered or refused payment stays reserved, is resent byte for byte, and is never relayed by the wallet", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  f.seen.fail = 1;
  const lost = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(lost.status, "submission_unknown"); assert.equal(lost.content, undefined);
  assert.deepEqual(await f.used(), { [usdc]: "80000" });
  // The administrator's resolve never broadcasts an x402 payment itself.
  await f.service.resolve(id, password);
  assert.equal(f.submissions.length, 0);
  const resent = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(resent.status, "submitted");
  // The same signed payment: the journal stores the operation canonically, so only its JSON key order may differ.
  assert.equal(f.seen.headers.length, 2); assert.deepEqual(f.seen.payments[0], f.seen.payments[1]);

  const refused = await x402Fixture(t), other = randomUUID();
  refused.seen.refuse = true;
  const answer = await refused.service.payX402({ url: URL_, max_amount: "0.05", request_id: other });
  assert.equal(answer.status, "submission_unknown");
  assert.equal(answer.seller_error, "insufficient_funds");
  assert.equal(answer.content, undefined);
  assert.match(answer.next_action, /wallet operation resolve .* --replace/);
});

test("a payment that never left this computer expires at its deadline and releases its reservation", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  f.seen.fail = 1;
  await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  // Never sent, so current policy decides: a payment the user has since disallowed is not sent.
  await f.store.session(async s => { const journal = await Journal.open(s); const r = journal.data.records[0]; r.status = "signed"; await journal.save(); await s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, x402: { ...x402Policy, maxPerPayment: "1" } } }); });
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), e => e.code === "policy_denied" && /never sent/.test(e.message));
  assert.equal(f.seen.payments.length, 1);
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].deadline = 1; await journal.save(); });
  const expired = await f.service.operation(id);
  assert.equal(expired.status, "expired");
  assert.equal(expired.last_error, "x402_payment_expired");
  assert.deepEqual(await f.used(), {});
});

test("an unsettled payment is cancelled by a replacement on its own nonce lane", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  f.seen.refuse = true;
  await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  const review = await f.service.reviewReplacement(id, true);
  const lane = BigInt(review.records[0].nonce);
  assert.equal(lane >> 64n, paymentNonceKey(f.seen.payments[0].payload.paymentId, f.seen.payments[0].payload.validUntil));
  const replaced = await f.service.replace(id, password, digest(review.records[0]));
  assert.equal(replaced.status, "superseding");
  assert.equal(BigInt(f.submissions.at(-1).nonce), lane);
  // The payment can still win its lane, so a retry says to wait rather than buy again on another lane.
  const retry = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(retry.status, "superseding");
  assert.match(retry.next_action, /wait until it shows superseded.*may pay twice/);
  assert.doesNotMatch(retry.next_action, /^Use a new request ID/);
  assert.equal(f.seen.payments.length, 1);
  // The cancellation keeps its own receipt search start and progress across reconciliations.
  const signedAt = await f.store.session(async s => (await Journal.open(s)).data.records.find(r => r.requestId === id).replacement.fromBlock);
  assert.notEqual(signedAt, undefined);
  const lookups = [];
  f.chain.receipt = async r => {
    if (r.userOpHash !== review.records[0].replacement.userOpHash) return;
    lookups.push({ fromBlock: r.fromBlock, searchedBlock: r.searchedBlock, transactionHash: r.transactionHash });
    r.searchedBlock = String(BigInt(r.searchedBlock ?? r.fromBlock) + 1000n);
  };
  await f.service.operation(id); await f.service.operation(id);
  assert.deepEqual(lookups, [{ fromBlock: signedAt, searchedBlock: undefined, transactionHash: undefined }, { fromBlock: signedAt, searchedBlock: String(BigInt(signedAt) + 1000n), transactionHash: undefined }]);
  assert.equal(await f.store.session(async s => (await Journal.open(s)).data.records.find(r => r.requestId === id).replacement.searchedBlock), String(BigInt(signedAt) + 2000n));
});

test("a first purchase rechecks policy expiry after simulation, before signing and before first delivery", async t => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const expiring = async () => {
    const f = await x402Fixture(t);
    await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt: Date.now() + 150 } }));
    return f;
  };
  // Expires while the operation is simulated: nothing is signed or sent.
  const during = await expiring(), id = randomUUID();
  const simulate = during.chain.simulate.bind(during.chain);
  during.chain.simulate = async validated => { await sleep(250); return simulate(validated); };
  await assert.rejects(during.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), e => e.code === "policy_denied" && /expired.*nothing was paid/.test(e.message));
  assert.equal(during.seen.payments.length, 0);
  assert.equal((await during.service.operation(id)).status, "failed");
  assert.deepEqual(await during.used(), {});
  // Expires after signing, before the payment first leaves: it stays unsent and expires at its deadline.
  const after = await expiring(), other = randomUUID();
  const stateFor = after.chain.stateFor.bind(after.chain);
  after.chain.stateFor = async (...a) => { await sleep(250); return stateFor(...a); };
  await assert.rejects(after.service.payX402({ url: URL_, max_amount: "0.05", request_id: other }), e => e.code === "policy_denied" && /policy_expired.*never sent/.test(e.message));
  assert.equal(after.seen.payments.length, 0);
  assert.equal((await after.service.operation(other)).status, "signed");
});

test("a signed payment that never left this computer is rechecked against full wallet policy before it is first sent", async t => {
  for (const change of [
    limits => ({ ...limits, expiresAt: 1 }),
    limits => ({ ...limits, tokens: { ...limits.tokens, [usdc]: { ...limits.tokens[usdc], perTransaction: "1000", daily: "1000" } } }),
  ]) {
    const f = await x402Fixture(t), id = randomUUID();
    f.seen.fail = 1;
    await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
    await f.store.session(async s => {
      const journal = await Journal.open(s); journal.data.records[0].status = "signed"; await journal.save();
      await s.savePolicy({ ...s.envelope.policy, limits: change(s.envelope.policy.limits) });
    });
    await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), e => e.code === "policy_denied" && /never sent/.test(e.message));
    assert.equal(f.seen.payments.length, 1);
    assert.equal((await f.service.operation(id)).status, "signed");
  }
  // Its own reservation is not counted against it: within policy, the unsent payment goes out.
  const f = await x402Fixture(t, { usdcLimits: { perTransaction: "80000", daily: "80000" } }), id = randomUUID();
  f.seen.fail = 1;
  await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].status = "signed"; await journal.save(); });
  assert.equal((await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id })).status, "submitted");
});

test("the wallet can be disabled, or policy expire, while the pre-send journal write completes; the payment then never leaves", async t => {
  const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
  const atSend = (f, act) => { let done = false; f.deps.checkpoint = async point => { if (!done && /^journal_\d+_submitting$/.test(point)) { done = true; await act(); } }; };
  // Disabled during the write: the first send is refused and the payment stays signed, unsent.
  const disabled = await x402Fixture(t), id = randomUUID();
  atSend(disabled, () => disabled.store.disable());
  await assert.rejects(disabled.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), { code: "wallet_locked" });
  assert.equal(disabled.seen.payments.length, 0);
  // Policy expires during the write.
  const expiring = await x402Fixture(t), other = randomUUID();
  await expiring.store.session(async s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt: Date.now() + 1500 } }));
  atSend(expiring, () => sleep(1600));
  await assert.rejects(expiring.service.payX402({ url: URL_, max_amount: "0.05", request_id: other }), e => e.code === "policy_denied" && /expired.*never sent/.test(e.message));
  assert.equal(expiring.seen.payments.length, 0);
  // A resend the seller may already hold is also stopped by disable, and stays unknown rather than unsent.
  const resend = await x402Fixture(t), third = randomUUID();
  resend.seen.fail = 1;
  await resend.service.payX402({ url: URL_, max_amount: "0.05", request_id: third });
  atSend(resend, () => resend.store.disable());
  await assert.rejects(resend.service.payX402({ url: URL_, max_amount: "0.05", request_id: third }), { code: "wallet_locked" });
  assert.equal(resend.seen.payments.length, 1);
  for (const [f, request, status] of [[disabled, id, "signed"], [expiring, other, "signed"], [resend, third, "submission_unknown"]]) {
    const r = await f.store.session(async s => (await Journal.open(s)).data.records.find(r => r.requestId === request));
    assert.equal(r.status, status);
    assert.equal(r.attempts, status === "signed" ? 0 : 1);
  }
});

test("receipt search progress is kept in the journal between reconciliations", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  let seen;
  f.chain.receipt = async r => { seen = r.searchedBlock; r.searchedBlock = String(BigInt(r.searchedBlock ?? "0") + 10n); };
  await f.service.operation(id);
  await f.service.operation(id);
  assert.equal(seen, "10");
  assert.equal(await f.store.session(async s => (await Journal.open(s)).data.records[0].searchedBlock), "20");
});

test("a resend after an uncertain attempt needs current policy, and a POST is not resent without an Idempotency-Key", async t => {
  // The process stopped after the durable submitting record and before HTTPS started: on restart it is
  // submission_unknown, though the seller never saw it. Policy that no longer allows it keeps it unsent.
  const f = await x402Fixture(t), id = randomUUID();
  f.deps.checkpoint = async point => { if (/^journal_\d+_submitting$/.test(point)) throw new Error("process stopped"); };
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }));
  f.deps.checkpoint = undefined;
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  await f.store.session(async s => { const { x402, ...rest } = s.envelope.policy.limits; await s.savePolicy({ ...s.envelope.policy, limits: rest }); });
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), e => e.code === "policy_denied" && /x402_not_enabled.*not sent again.*stays reserved/.test(e.message));
  assert.equal(f.seen.payments.length, 0);
  assert.equal((await f.service.operation(id)).status, "submission_unknown");
  assert.deepEqual(await f.used(), { [usdc]: "80000" });

  // A POST whose outcome is unknown is not sent again; one marked with an Idempotency-Key is.
  for (const headers of [undefined, { "Idempotency-Key": "order-1" }]) {
    const p = await x402Fixture(t), other = randomUUID(), post = { url: URL_, method: "POST", body: "{}", ...(headers ? { headers } : {}), max_amount: "0.05", request_id: other };
    p.seen.fail = 1;
    assert.equal((await p.service.payX402(post)).status, "submission_unknown");
    const retry = await p.service.payX402(post);
    if (headers) { assert.equal(retry.status, "submitted"); assert.equal(p.seen.payments.length, 2); continue; }
    assert.equal(retry.status, "submission_unknown");
    assert.match(retry.next_action, /does not send it again without an Idempotency-Key/);
    assert.equal(p.seen.payments.length, 1);
  }
});

test("a send that provably never left goes back to unsent, and seller answers are recorded as they came", async t => {
  // Connection refused: nothing was written, so the payment is unsent again and can still expire on its own.
  const f = await x402Fixture(t), id = randomUUID(), http = f.service.http;
  f.service.http = async req => { if (req.headers?.["payment-signature"]) throw Object.assign(new Error("connect ECONNREFUSED"), { code: "ECONNREFUSED" }); return http(req); };
  await assert.rejects(f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id }), e => e.code === "x402_request_failed" && /sent nothing/.test(e.message));
  const unsent = await f.store.session(async s => (await Journal.open(s)).data.records[0]);
  assert.equal(unsent.status, "signed"); assert.equal(unsent.attempts, 0);
  f.service.http = http;
  assert.equal((await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id })).status, "submitted");

  // Settled upfront, then the handler failed: the seller's transaction is kept for reconciliation.
  const failed = await x402Fixture(t), other = randomUUID(), served = failed.service.http;
  failed.service.http = async req => { const response = await served(req); return req.headers?.["payment-signature"] ? { ...response, status: 500, body: Buffer.from("oops") } : response; };
  const broken = await failed.service.payX402({ url: URL_, max_amount: "0.05", request_id: other });
  assert.equal(broken.status, "submitted"); assert.equal(broken.content, undefined);
  assert.equal(broken.transaction_hash, `0x${"ab".repeat(32)}`);
  assert.match(broken.next_action, /HTTP 500 without its answer/);

  // Served without a readable settlement: the content is returned, settlement stays unconfirmed.
  const unconfirmed = await x402Fixture(t), third = randomUUID(), plain = unconfirmed.service.http;
  unconfirmed.service.http = async req => { const response = await plain(req); if (req.headers?.["payment-signature"]) delete response.headers["payment-response"]; return response; };
  const answer = await unconfirmed.service.payX402({ url: URL_, max_amount: "0.05", request_id: third });
  assert.equal(answer.status, "submission_unknown");
  assert.equal(answer.settlement_confirmed, false);
  assert.deepEqual(JSON.parse(answer.content.text), { tempC: 21 });

  // Seller terms too large to journal are the seller's error, and nothing is recorded.
  const huge = await x402Fixture(t), base = huge.service.http;
  huge.service.http = async req => req.headers?.["payment-signature"] ? base(req) : { status: 402, headers: { "payment-required": encodePaymentRequiredHeader({ x402Version: 2, resource: { url: req.url }, accepts: [{ ...requirements, extra: { entryPoint, pad: "x".repeat(9000) } }] }) }, body: Buffer.from("{}"), truncated: false };
  await assert.rejects(huge.service.payX402({ url: URL_, max_amount: "0.05", request_id: randomUUID() }), { code: "x402_invalid_response" });
  await huge.store.session(async s => assert.equal((await Journal.open(s)).data.records.length, 0));
});

test("a quote reports policy expiry, the USDC per-transaction cap and a disabled wallet; it is not marked read-only", async t => {
  const f = await x402Fixture(t, { usdcLimits: { perTransaction: "10000" } });
  await f.store.session(async s => s.savePolicy({ ...s.envelope.policy, limits: { ...s.envelope.policy.limits, expiresAt: 1 } }));
  const quote = await f.service.x402Requirements({ url: URL_ });
  assert.equal(quote.policy.allowed, false);
  assert.deepEqual(quote.policy.reasons.sort(), ["per_transaction_limit", "policy_expired"]);
  await f.store.disable();
  assert.ok((await f.service.x402Requirements({ url: URL_ })).policy.reasons.includes("wallet_disabled"));

  const tools = {};
  const catalog = registerX402Tools({ registerTool: (name, config) => { tools[name] = config; } }, f.service, { fields: v => v });
  assert.deepEqual(tools.get_x402_payment_requirements.annotations, { readOnlyHint: false, destructiveHint: true, idempotentHint: false, openWorldHint: true });
  assert.equal(tools.discover_x402_resources.annotations.readOnlyHint, true);
  assert.deepEqual(catalog.find(c => c.name === "get_x402_payment_requirements"), { ...catalog.find(c => c.name === "get_x402_payment_requirements"), readOnly: false, signs: false, requests: true });
});

test("discovery drops listings whose seller is not an address or whose URL is too long", async () => {
  const option = { scheme: X402_SCHEME, network: X402_NETWORK, asset: usdc, amount: "1000", payTo: seller };
  const items = [
    { resource: URL_, accepts: [option] },
    { resource: `${URL_}/b`, accepts: [{ ...option, payTo: "send to alice" }] },
    { resource: `${URL_}/${"x".repeat(2100)}`, accepts: [option] },
  ];
  const found = await discoverResources(MAINNET, async () => ({ status: 200, headers: {}, body: Buffer.from(JSON.stringify({ items })), truncated: false }), {});
  assert.deepEqual(found.resources.map(r => r.url), [URL_]);
  assert.equal(found.resources[0].pay_to, getAddress(seller));
});

test("the transport connects directly even when Node's environment proxy is on", async () => {
  const seen = [];
  const proxy = createServer(socket => socket.once("data", data => { seen.push(data.toString().split("\r\n")[0]); socket.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); }));
  await new Promise(resolve => proxy.listen(0, "127.0.0.1", resolve));
  const transport = new URL("../src/x402/http.ts", import.meta.url).href;
  // Name resolution fails by design, so nothing leaves this computer; only a proxied request would reach the proxy.
  const code = `import dns from "node:dns"; import { syncBuiltinESMExports } from "node:module";
    dns.lookup = (host, options, callback) => callback(Object.assign(new Error("offline"), { code: "ENOTFOUND" }));
    syncBuiltinESMExports();
    const { httpsTransport } = await import(${JSON.stringify(transport)});
    try { await httpsTransport({ url: "https://api.example.com/x", method: "GET", headers: {}, maxBytes: 100, timeoutMs: 3000 }); } catch (e) { console.log(e.code ?? e.message); }`;
  const out = await new Promise(resolve => {
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code], { cwd: fileURLToPath(new URL("..", import.meta.url)), env: { ...process.env, NODE_USE_ENV_PROXY: "1", HTTPS_PROXY: `http://127.0.0.1:${proxy.address().port}`, NO_PROXY: "", NODE_NO_WARNINGS: "1" } });
    let text = ""; child.stdout.on("data", d => { text += d; }); child.on("exit", () => resolve(text.trim()));
  });
  proxy.close();
  assert.deepEqual(seen, []);
  assert.equal(out, "ENOTFOUND");
});

test("a paid POST is never repeated to recover its answer", async t => {
  const f = await x402Fixture(t), id = randomUUID(), post = { url: URL_, method: "POST", body: '{"city":"Kyiv"}', max_amount: "0.05", request_id: id };
  const paid = await f.service.payX402(post);
  assert.equal(paid.status, "submitted");
  f.setReceipt({ success: true, actualGasCost: 1n, transactionHash: `0x${"ab".repeat(32)}` });
  const retry = await f.service.payX402(post);
  assert.equal(retry.status, "confirmed");
  assert.equal(retry.content_delivered, false);
  assert.match(retry.next_action, /cannot tell whether it reached you.*does not resend a paid POST/);
  assert.equal(f.seen.payments.length, 1);
});

test("a settled payment whose answer was lost is offered to the seller again, never paid twice", async t => {
  const f = await x402Fixture(t), id = randomUUID();
  f.seen.fail = 1;
  assert.equal((await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id })).status, "submission_unknown");
  f.setReceipt({ success: true, actualGasCost: 1n, transactionHash: `0x${"cd".repeat(32)}` });
  const served = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(served.status, "confirmed");
  assert.equal(served.content_delivered, true);
  assert.deepEqual(JSON.parse(served.content.text), { tempC: 21 });
  assert.deepEqual(f.seen.payments[1], f.seen.payments[0]);
  // The answer was handed back, but whether it reached the caller is unknown: a retry asks the seller again.
  assert.equal((await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id })).content_delivered, true);
  assert.equal(f.seen.payments.length, 3); assert.deepEqual(f.seen.payments[2], f.seen.payments[0]);
  f.seen.refuse = true;
  const unsure = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(unsure.content_delivered, false);
  assert.match(unsure.next_action, /cannot tell whether it reached you.*pays again/);

  const lost = await x402Fixture(t), other = randomUUID();
  lost.seen.fail = 1;
  await lost.service.payX402({ url: URL_, max_amount: "0.05", request_id: other });
  lost.setReceipt({ success: true, actualGasCost: 1n, transactionHash: `0x${"cd".repeat(32)}` });
  lost.seen.refuse = true;
  const unserved = await lost.service.payX402({ url: URL_, max_amount: "0.05", request_id: other });
  assert.equal(unserved.status, "confirmed");
  assert.equal(unserved.content_delivered, false);
  assert.equal(unserved.content, undefined);
  assert.match(unserved.next_action, /answer was lost.*pays again/);
  assert.deepEqual(lost.seen.payments[1], lost.seen.payments[0]);
});

test("an x402 receipt is found from the seller's transaction or the EntryPoint's events when the bundler does not know it", async () => {
  const event = parseAbiItem("event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)");
  const sender = "0x30a343d137ed0492d9d7ad25fc55590d807629b3", userOpHash = `0x${"77".repeat(32)}`, nonce = (5n << 64n) | 3n;
  const tx = `0x${"aa".repeat(32)}`, wrong = `0x${"bb".repeat(32)}`, blockHash = `0x${"cc".repeat(32)}`;
  const log = { address: entryPoint, topics: encodeEventTopics({ abi: [event], eventName: "UserOperationEvent", args: { userOpHash, sender, paymaster } }), data: encodeAbiParameters([{ type: "uint256" }, { type: "bool" }, { type: "uint256" }, { type: "uint256" }], [nonce, true, 1234n, 1n]) };
  const record = { requestId: randomUUID(), intent: { kind: "x402_payment" }, userOpHash, nonce: nonce.toString(), fromBlock: "500", operation: { sender, paymaster } };
  const make = (laneUsed, head = 1000n, at = 990n) => {
    const calls = { logs: [] };
    const client = {
      getBlockNumber: async () => head,
      getBlock: async () => ({ hash: blockHash }),
      readContract: async ({ functionName, args }) => { assert.equal(functionName, "getNonce"); assert.equal(args[1], 5n); return laneUsed ? nonce + 1n : nonce; },
      getLogs: async ({ args, fromBlock, toBlock }) => { calls.logs.push([fromBlock, toBlock]); return args.userOpHash === userOpHash && fromBlock <= at && at <= toBlock ? [{ transactionHash: tx }] : []; },
      getTransactionReceipt: async ({ hash }) => ({ status: "success", blockHash, blockNumber: at, transactionHash: hash, logs: hash === tx ? [log] : [] }),
    };
    const chain = new WalletChain(new Ctx(MAINNET));
    chain.clients = [client, client];
    chain.bundlerHint = async () => undefined;
    return { chain, calls };
  };
  const expected = { success: true, actualGasCost: 1234n, transactionHash: tx };
  let { chain, calls } = make(true);
  assert.deepEqual(await chain.receipt({ ...record, transactionHash: tx }), expected);
  assert.equal(calls.logs.length, 0);
  ({ chain, calls } = make(true));
  assert.deepEqual(await chain.receipt({ ...record, transactionHash: wrong }), expected);
  assert.deepEqual(calls.logs, [[500n, 1000n]]); // From the head back to the block it was signed at.
  ({ chain, calls } = make(true));
  assert.deepEqual(await chain.receipt(record), expected);
  // A stale bundler hash, one that fails verification or is no longer found, falls through to the other sources.
  ({ chain, calls } = make(true));
  chain.bundlerHint = async () => wrong;
  assert.deepEqual(await chain.receipt({ ...record, transactionHash: tx }), expected);
  assert.equal(calls.logs.length, 0);
  ({ chain, calls } = make(true));
  chain.bundlerHint = async () => wrong;
  for (const client of chain.clients) { const get = client.getTransactionReceipt; client.getTransactionReceipt = async a => { if (a.hash === wrong) throw new Error("not found"); return get(a); }; }
  assert.deepEqual(await chain.receipt(record), expected);
  assert.deepEqual(calls.logs, [[500n, 1000n]]);
  ({ chain, calls } = make(false));
  assert.equal(await chain.receipt(record), undefined);
  assert.equal(calls.logs.length, 0);
  // A payment settled more than one search window after it was signed is reached over several attempts: each
  // covers a bounded range forward from the signing block and records its progress, short of the head.
  ({ chain, calls } = make(true, 3_000_000n, 1_500_000n));
  const old = { ...record, fromBlock: "100" };
  assert.equal(await chain.receipt(old), undefined);
  assert.equal(old.searchedBlock, "1000099");
  assert.deepEqual(calls.logs[0], [100n, 5099n]);
  assert.deepEqual(await chain.receipt(old), expected);
  assert.ok(calls.logs.at(-1)[0] <= 1_500_000n && 1_500_000n <= calls.logs.at(-1)[1]);
  ({ chain, calls } = make(true, 1000n, 2000n));
  const fresh = { ...record };
  assert.equal(await chain.receipt(fresh), undefined);
  assert.equal(fresh.searchedBlock, "872"); // Never closer to the head than the reorg margin.
  assert.equal(await chain.receipt(fresh), undefined);
  assert.deepEqual(calls.logs.at(-1), [873n, 1000n]);
  // Other operations keep using only the wallet's bundler.
  ({ chain, calls } = make(true));
  assert.equal(await chain.receipt({ ...record, intent: { kind: "transfer" }, transactionHash: tx }), undefined);
});
