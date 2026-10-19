import assert from "node:assert/strict";
import test from "node:test";
import { decodeFunctionData, formatUnits } from "viem";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { accountAbi, erc20Abi, swapRouterAbi } from "../src/abi.ts";
import { makeServer } from "../src/server.ts";

const account = "0x0000000000000000000000000000000000000001";
const recipient = "0x0000000000000000000000000000000000000002";
const indivisible = "0x0000000000000000000000000000000000000003";
const usdc = MAINNET.manifest.canonicalTokens.USDC.address;
const max = 2n ** 256n - 1n;

function context() {
  const ctx = new Ctx(MAINNET), reads = [];
  ctx.indexer = {
    listAssets: async () => ({ items: [
      { contract: usdc, symbol: "USDC", name: "USD Coin", type: "ERC20", decimals: 18, price: 2 },
      { contract: indivisible, symbol: "WHOLE", name: "Indivisible", type: "ERC20", decimals: 6 },
    ] }),
    accountAssets: async () => ({ items: [{ assetId: usdc }] }),
  };
  ctx.client = {
    getBlock: async () => ({ baseFeePerGas: 1n }),
    getCode: async () => "0x6000",
    getBalance: async () => max,
    getTransactionCount: async () => 7,
    estimateGas: async () => 21000n,
    readContract: async ({ address, functionName }) => {
      reads.push({ address, functionName });
      if (functionName === "decimals") return address.toLowerCase() === indivisible ? 0 : 6;
      if (functionName === "balanceOf") return max;
      if (functionName === "readBalances") return [1000000n];
      if (functionName === "checkApproval") return { reject: 0 };
      if (functionName === "getNonce") return 0n;
      if (functionName === "quoteExactInputSingle") return [10n ** 18n, 0n, 0, 100000n];
      assert.fail(`Unexpected contract read: ${functionName}`);
    },
  };
  return { ctx, reads };
}

async function connect(t, ctx) {
  const bundle = makeServer(ctx, () => []);
  const client = new Client({ name: "public-builders-test", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await bundle.server.connect(b); await client.connect(a);
  t.after(async () => { await client.close(); await bundle.server.close(); });
  return client;
}

function data(response) {
  assert.ok(!response.isError, JSON.stringify(response));
  return JSON.parse(response.content[0].text);
}

test("resolved token units come from chain and survive explorer refreshes, including zero decimals", async t => {
  const { ctx, reads } = context();
  let now = Date.now(); t.mock.method(Date, "now", () => now);
  assert.equal((await ctx.resolveToken("USDC")).decimals, 6);
  assert.equal((await ctx.resolveToken(usdc)).decimals, 6);
  assert.equal((await ctx.resolveToken("WHOLE")).decimals, 0);
  assert.equal((await ctx.resolveToken(indivisible)).decimals, 0);
  now += 300001;
  assert.equal((await ctx.resolveToken("USDC")).decimals, 6);
  assert.equal((await ctx.resolveToken("WHOLE")).decimals, 0);
  assert.equal(reads.filter(r => r.functionName === "decimals").length, 2);
  assert.equal((await ctx.resolveToken("CENT")).decimals, 18);
});

test("explorer metadata cannot bypass failed or invalid on-chain decimal reads", async () => {
  for (const invalid of [undefined, -1, 256, 1.5]) {
    const { ctx } = context();
    ctx.client.readContract = async () => invalid;
    await assert.rejects(ctx.resolveToken("USDC"), /Invalid on-chain token decimals/);
  }
  const { ctx } = context();
  ctx.client.readContract = async () => { throw new Error("RPC unavailable"); };
  await assert.rejects(ctx.resolveToken(usdc), /RPC unavailable/);
});

test("public transfers, swaps and portfolio use authoritative units instead of explorer decimals", async t => {
  const { ctx } = context(), client = await connect(t, ctx);
  t.mock.method(globalThis, "fetch", async (url, options) => {
    assert.equal(url, MAINNET.endpoints.bundlerUrl);
    assert.equal(JSON.parse(options.body).method, "eth_estimateUserOperationGas");
    return Response.json({ result: { callGasLimit: "0x100", verificationGasLimit: "0x100", preVerificationGas: "0x100" } });
  });
  const transfer = data(await client.callTool({ name: "build_transfer", arguments: { account, to: recipient, token: "USDC", amount: "1" } }));
  const batch = decodeFunctionData({ abi: accountAbi, data: transfer.user_operation.callData });
  assert.equal(decodeFunctionData({ abi: erc20Abi, data: batch.args[2][0] }).args[1], 1000000n);
  assert.match(transfer.amount, /^1 USDC /);
  const swap = data(await client.callTool({ name: "build_swap", arguments: { account, token_in: "USDC", token_out: "CENT", amount_in: "1" } }));
  const swapBatch = decodeFunctionData({ abi: accountAbi, data: swap.user_operation.callData });
  assert.equal(decodeFunctionData({ abi: swapRouterAbi, data: swapBatch.args[2][1] }).args[0].amountIn, 1000000n);
  const portfolio = data(await client.callTool({ name: "get_portfolio", arguments: { address: account } }));
  assert.equal(portfolio.positions.find(p => p.address?.toLowerCase() === usdc.toLowerCase()).balance, "1");
  const largest = data(await client.callTool({ name: "build_transfer", arguments: { account, to: recipient, token: "WHOLE", amount: max.toString() } }));
  const largestBatch = decodeFunctionData({ abi: accountAbi, data: largest.user_operation.callData });
  assert.equal(decodeFunctionData({ abi: erc20Abi, data: largestBatch.args[2][0] }).args[1], max);
});

test("public amount inputs reject rounding, ambiguous decimals, zero and uint256 overflow before estimation", async t => {
  const { ctx } = context(), client = await connect(t, ctx);
  t.mock.method(globalThis, "fetch", async () => { assert.fail("Invalid amounts must not reach estimation"); });
  for (const amount of ["0", "-1", "01", "1e3", "", "1.0000001", formatUnits(max + 1n, 6)]) {
    for (const [name, input] of [
      ["build_transfer", { account, to: recipient, token: "USDC", amount }],
      ["build_swap", { account, token_in: "USDC", token_out: "CENT", amount_in: amount }],
      ["get_swap_quote", { token_in: "USDC", token_out: "CENT", amount_in: amount }],
    ]) {
      const response = await client.callTool({ name, arguments: input });
      assert.equal(response.isError, true, `${name}: ${amount}`);
      assert.match(response.content[0].text, /Amount/);
    }
  }
  const response = await client.callTool({ name: "build_transfer", arguments: { account, to: recipient, token: "WHOLE", amount: "0.5" } });
  assert.equal(response.isError, true); assert.match(response.content[0].text, /rounding/);
});

test("plain transactions preserve zero and exact values but reject rounding and failed simulation", async t => {
  const { ctx } = context(), client = await connect(t, ctx);
  let estimates = 0;
  ctx.client.estimateGas = async () => { estimates++; return 21000n; };
  for (const value of [undefined, "0", "0.000000000000000001", formatUnits(max, 18)]) {
    const result = data(await client.callTool({ name: "build_transaction", arguments: { from: account, to: recipient, ...(value === undefined ? {} : { value }) } }));
    assert.equal(BigInt(result.unsigned_transaction.value), value === undefined || value === "0" ? 0n : value === "0.000000000000000001" ? 1n : max);
    assert.equal(BigInt(result.unsigned_transaction.gas), 25200n);
  }
  assert.equal(estimates, 4);
  for (const value of ["", "-1", "01", "1e3", "0.0000000000000000001", formatUnits(max + 1n, 18)]) {
    assert.equal((await client.callTool({ name: "build_transaction", arguments: { from: account, to: recipient, value } })).isError, true);
  }
  assert.equal(estimates, 4);
  ctx.client.estimateGas = async () => { throw new Error("execution reverted at https://rpc.test/SECRET_CANARY"); };
  const rejected = await client.callTool({ name: "build_transaction", arguments: { from: account, to: recipient, value: "0" } });
  assert.equal(rejected.isError, true);
  assert.match(rejected.content[0].text, /execution reverted/);
  assert.doesNotMatch(rejected.content[0].text, /CANARY/);
});
