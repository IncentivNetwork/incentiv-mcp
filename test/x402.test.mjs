import assert from "node:assert/strict";
import test from "node:test";
import { randomUUID } from "node:crypto";
import { encodeFunctionData, erc20Abi, recoverMessageAddress } from "viem";
import { decodePaymentSignatureHeader, encodePaymentRequiredHeader, encodePaymentResponseHeader } from "@x402/core/http";
import * as incentiv from "@incentiv/x402";
import { args, fixture, limits, password, recipient } from "../scripts/wallet-pipeline-fixture.mjs";
import { MAINNET } from "../src/config.ts";
import { accountFactoryAbi } from "../src/abi.ts";
import { computeUserOpHash, encodeExecuteBatch, userOpFromJson } from "../src/userop.ts";
import { Journal, digest, intentSchema } from "../src/wallet/journal.ts";
import { limitsSchema, policyViolations, x402Violations } from "../src/wallet/policy.ts";
import { checkHeaders, checkResourceUrl, isPublicAddress } from "../src/x402/http.ts";
import { parsePaymentRequired, paymentNonceKey, selectRequirements, x402Config, X402_NETWORK, X402_SCHEME } from "../src/x402/protocol.ts";
import { facilitatorUrl } from "../src/x402/discovery.ts";
import { usdcAmount, x402Request } from "../src/x402/request.ts";

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
  // A retry never pays twice, even before the receipt shows, and the request ID stays bound to this request.
  assert.equal((await f.service.operation(id)).status, "submitted");
  const again = await f.service.payX402({ url: URL_, max_amount: "0.05", request_id: id });
  assert.equal(again.status, "submitted"); assert.match(again.next_action, /new request ID/);
  assert.equal(f.seen.payments.length, 1);
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
});
