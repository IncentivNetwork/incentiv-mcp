import assert from "node:assert/strict";
import test from "node:test";
import { decodeFunctionData, encodeFunctionData, HttpRequestError } from "viem";
import { MAINNET } from "../src/config.ts";
import { accountAbi, erc20Abi } from "../src/abi.ts";
import { billableGas, buildUserOpUnsigned, computeGasTokenAmount, getPaymasterConfig, requiredPaymentUsdc } from "../src/userop.ts";

const USDC = MAINNET.manifest.canonicalTokens.USDC.address, WCENT = MAINNET.manifest.contracts.wcent.address;
const OTHER = MAINNET.manifest.canonicalTokens.WETH.address, PAYMASTER = MAINNET.manifest.contracts.unifiedTokenPaymaster.address;
const token = (address, symbol, decimals) => ({ address, symbol, name: symbol, decimals });
// The live schedule shape: a 26000 floor up to baseGas, then linear to 64000 at upperGas.
const schedule = g => g <= 200_000n ? 26_000n : 26_000n + ((g - 200_000n) * 38_000n) / 600_000n;

/** A chain whose paymaster prices by its USDC schedule and whose pools quote 1 USDC unit = 10^9 WCENT wei and 1 OTHER wei = 2 WCENT wei. */
function fakeCtx({ overhead = 50_000n, pool = 2n, allowed = true, quoteError } = {}) {
  const calls = [], setOverhead = value => { overhead = value; };
  const config = structuredClone(MAINNET);
  return { calls, config, setOverhead, client: { readContract: async ({ address, functionName, args }) => {
    calls.push([functionName, args]);
    if (address === PAYMASTER) return { usdcToken: () => USDC, usdcPoolFee: () => 500, overheadGas: () => overhead, maxVerificationGas: () => 2_000_000n, requiredPaymentUsdc: () => schedule(args[0]), allowedPaymentToken: () => allowed }[functionName]();
    const q = args[0];
    if (quoteError && q.tokenIn !== USDC) throw quoteError;
    if (functionName === "quoteExactInputSingle") return [q.tokenIn === USDC ? q.amountIn * 10n ** 9n : q.amountIn * pool, 0n, 0, 0n];
    if (functionName === "quoteExactOutputSingle") return [q.amount / 2n, 0n, 0, 0n];
    throw new Error(`unexpected read ${functionName}`);
  } } };
}

test("the paymaster bills preVerificationGas + callGasLimit + overheadGas, not verification gas", async () => {
  const ctx = fakeCtx(), cfg = await getPaymasterConfig(ctx);
  assert.equal(billableGas(cfg, { callGasLimit: 250_000n, preVerificationGas: 90_000n, verificationGasLimit: 700_000n }), 390_000n);
  assert.equal(await requiredPaymentUsdc(ctx, cfg, { callGasLimit: 250_000n, preVerificationGas: 90_000n }), schedule(390_000n));
  assert.deepEqual(ctx.calls.at(-1), ["requiredPaymentUsdc", [390_000n]]);
});

test("gas paid in USDC is exactly the schedule's amount, without any pool quote", async () => {
  const ctx = fakeCtx(), cfg = await getPaymasterConfig(ctx), before = ctx.calls.length;
  assert.equal(await computeGasTokenAmount(ctx, cfg, token(USDC, "USDC", 6), 36_666n), 36_666n);
  assert.equal(ctx.calls.length, before);
});

test("gas paid in WCENT or another token covers the USDC amount's WCENT quote with a margin", async () => {
  const ctx = fakeCtx(), cfg = await getPaymasterConfig(ctx), cent = 36_666n * 10n ** 9n;
  assert.equal(await computeGasTokenAmount(ctx, cfg, token(WCENT, "WCENT", 18), 36_666n), cent * 102n / 100n);
  const other = await computeGasTokenAmount(ctx, cfg, token(OTHER, "WETH", 18), 36_666n);
  assert.ok(other * 2n >= cent * 102n / 100n, "the other token quotes to at least the required WCENT");
  // The paymaster quotes other tokens through its default 0.3% pool.
  assert.ok(ctx.calls.filter(([fn, args]) => fn.startsWith("quote") && args[0].tokenIn === OTHER).every(([, args]) => args[0].fee === 3000));
  await assert.rejects(computeGasTokenAmount(fakeCtx({ pool: 0n }), cfg, token(OTHER, "WETH", 18), 36_666n), error => error.code === "gas_token_unavailable" && /Could not price gas in WETH/.test(error.message));
});

test("a pool that cannot quote the token refuses it for good, but an RPC failure stays retryable", async () => {
  const cfg = await getPaymasterConfig(fakeCtx());
  // On mainnet, USDT is allowlisted but the quoter reverts without data: no USDT/WCENT pool at 0.3%.
  await assert.rejects(computeGasTokenAmount(fakeCtx({ quoteError: new Error("Execution reverted for an unknown reason.") }), cfg, token(OTHER, "USDT", 6), 36_666n),
    error => error.code === "gas_token_unavailable" && /Could not price gas in USDT: no USDT\/WCENT pool/.test(error.message) && /new request ID/.test(error.message));
  const outage = new HttpRequestError({ url: "https://rpc.incentiv.io", status: 503 });
  await assert.rejects(computeGasTokenAmount(fakeCtx({ quoteError: outage }), cfg, token(OTHER, "USDT", 6), 36_666n), error => error === outage);
});

test("a token off the paymaster's allowlist is refused before pricing, however its pool quotes", async () => {
  const ctx = fakeCtx({ allowed: false }), cfg = await getPaymasterConfig(ctx);
  await assert.rejects(computeGasTokenAmount(ctx, cfg, token(OTHER, "MEME", 18), 36_666n), error => error.code === "gas_token_unavailable" && /The paymaster does not accept MEME for gas/.test(error.message));
  assert.ok(ctx.calls.some(([fn, args]) => fn === "allowedPaymentToken" && args[0] === OTHER));
  // USDC and WCENT need no allowlist entry.
  assert.equal(await computeGasTokenAmount(ctx, cfg, token(USDC, "USDC", 6), 36_666n), 36_666n);
  assert.ok(await computeGasTokenAmount(ctx, cfg, token(WCENT, "WCENT", 18), 36_666n) > 0n);
});

test("a token-paid operation pays the schedule for its own limits, whatever the base fee", async t => {
  const fetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = fetch; });
  globalThis.fetch = async () => Response.json({ result: { callGasLimit: "0x30d40", verificationGasLimit: "0x7a120", preVerificationGas: "0x15f90" } });
  const paid = [];
  for (const base of [12_600n * 10n ** 9n, 37_001n * 10n ** 9n, 66_400n * 10n ** 9n]) {
    const ctx = fakeCtx();
    const fees = { maxFeePerGas: base * 2n, maxPriorityFeePerGas: 10n ** 9n, baseFeePerGas: base };
    const built = await buildUserOpUnsigned(ctx, { account: "0x214324E3412eD8864Da4EfB2c2D34c3281dbEe7A", calls: [{ to: "0x0000000000000000000000000000000000000001", value: 0n, data: "0x" }], gasToken: token(USDC, "USDC", 6), state: { deployed: true, nonce: 0n, fees } });
    const [targets, , data] = decodeFunctionData({ abi: accountAbi, data: built.op.callData }).args;
    const transfer = decodeFunctionData({ abi: erc20Abi, data: data[0] });
    assert.equal(targets[0], USDC); assert.equal(transfer.args[0], PAYMASTER);
    assert.equal(transfer.args[1], schedule(built.op.preVerificationGas + built.op.callGasLimit + 50_000n));
    assert.equal(built.gasToken.requiredUsdc, transfer.args[1]);
    paid.push(transfer.args[1]);
  }
  assert.equal(new Set(paid).size, 1, "the USDC price does not move with the base fee");
});

test("unsigned token-gas estimation can use a balance that covers price and actual fee", async t => {
  const balance = 50_000n, price = 10_000n;
  const recipient = "0x0000000000000000000000000000000000000001";
  const estimatedFees = [];
  t.mock.method(globalThis, "fetch", async (_url, { body }) => {
    const [estimate] = JSON.parse(body).params;
    assert.equal(estimate.paymaster, undefined);
    const [, , data] = decodeFunctionData({ abi: accountAbi, data: estimate.callData }).args;
    const charge = decodeFunctionData({ abi: erc20Abi, data: data[0] }).args[1];
    assert.equal(decodeFunctionData({ abi: erc20Abi, data: data[1] }).args[1], price);
    estimatedFees.push(charge);
    if (charge + price > balance) return Response.json({ error: { code: -32521, message: "ERC20: transfer amount exceeds balance" } });
    return Response.json({ result: { callGasLimit: "0x11170", verificationGasLimit: "0x493e0", preVerificationGas: "0x9c40" } });
  });
  const built = await buildUserOpUnsigned(fakeCtx(), {
    account: "0x214324E3412eD8864Da4EfB2c2D34c3281dbEe7A",
    calls: [{ to: USDC, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [recipient, price] }) }],
    gasToken: token(USDC, "USDC", 6),
    state: { deployed: true, nonce: 0n, fees: { maxFeePerGas: 2n, maxPriorityFeePerGas: 1n, baseFeePerGas: 1n } },
  });
  assert.deepEqual(estimatedFees, [26_000n, 26_000n]);
  assert.equal(built.op.signature, "0x");
  assert.equal(built.gasToken.tokenAmount + price, 36_000n);
});

test("an operation to sign prices gas with the paymaster's current overhead, not a cached one", async t => {
  const fetch = globalThis.fetch;
  t.after(() => { globalThis.fetch = fetch; });
  globalThis.fetch = async () => Response.json({ result: { callGasLimit: "0x30d40", verificationGasLimit: "0x7a120", preVerificationGas: "0x15f90" } });
  const ctx = fakeCtx();
  assert.equal((await getPaymasterConfig(ctx)).overheadGas, 50_000n);
  // The owner raises overheadGas while the earlier read is still cached.
  ctx.setOverhead(400_000n);
  const fees = { maxFeePerGas: 2n * 10n ** 9n, maxPriorityFeePerGas: 10n ** 9n, baseFeePerGas: 10n ** 9n };
  const built = await buildUserOpUnsigned(ctx, { account: "0x214324E3412eD8864Da4EfB2c2D34c3281dbEe7A", calls: [{ to: "0x0000000000000000000000000000000000000001", value: 0n, data: "0x" }], gasToken: token(USDC, "USDC", 6), state: { deployed: true, nonce: 0n, fees } });
  assert.equal(built.gasToken.requiredUsdc, schedule(built.op.preVerificationGas + built.op.callGasLimit + 400_000n));
});

test("an unlisted token is refused before any quote, so a quote outage cannot make it retryable", async () => {
  const outage = new HttpRequestError({ url: "https://rpc.incentiv.io", status: 503 });
  const ctx = fakeCtx({ allowed: false }), cfg = await getPaymasterConfig(ctx), read = ctx.client.readContract;
  ctx.client.readContract = async opts => { if (opts.functionName.startsWith("quote")) throw outage; return read(opts); };
  await assert.rejects(computeGasTokenAmount(ctx, cfg, token(OTHER, "MEME", 18), 36_666n), error => error.code === "gas_token_unavailable" && /does not accept MEME/.test(error.message));
  assert.ok(!ctx.calls.some(([fn]) => fn.startsWith("quote")));
});
