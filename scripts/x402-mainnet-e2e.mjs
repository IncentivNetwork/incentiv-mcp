// Deliberately outside npm test. The only operation that spends is gated in run.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, readFile, stat, unlink, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { fileURLToPath } from "node:url";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { decodePaymentRequiredHeader } from "@x402/core/http";
import { decodeEventLog, encodeEventTopics, erc20Abi, getAddress, parseAbiItem, toFunctionSelector } from "viem";
import { MAINNET } from "../dist/config.js";
import { Ctx } from "../dist/context.js";
import { WalletChain } from "../dist/wallet/chain.js";
import { nativeCredentials } from "../dist/wallet/credentials.js";
import { syncDirectory } from "../dist/wallet/files.js";
import { digest } from "../dist/wallet/journal.js";
import { WalletService } from "../dist/wallet/service.js";
import { localWalletStore } from "../dist/wallet/store.js";
import { walletProfile } from "../dist/wallet-profile.js";
import { NETWORK, PRICE, SCHEME, preflightSeller, startSeller, startTunnel } from "./x402-mainnet-seller.mjs";

const directory = resolve(process.env.X402_E2E_DIR ?? ".x402-mainnet-e2e");
const root = fileURLToPath(new URL("../", import.meta.url));
const adminKey = "x402-e2e-administration";
const price = 10_000n, gasCap = 40_000n, budget = price + gasCap;
const usdc = MAINNET.manifest.canonicalTokens.USDC.address.toLowerCase();
const paymaster = MAINNET.manifest.contracts.unifiedTokenPaymaster.address.toLowerCase();
const entryPoint = MAINNET.identity.entryPoint.address.toLowerCase();
const operationEvent = parseAbiItem("event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)");
const [operationTopic] = encodeEventTopics({ abi: [operationEvent], eventName: "UserOperationEvent" });
const [transferTopic] = encodeEventTopics({ abi: erc20Abi, eventName: "Transfer" });
const chain = new WalletChain(new Ctx(MAINNET));

function limits(seller, expiresAt) {
  return {
    tokens: { [usdc]: { perTransaction: price.toString(), daily: budget.toString(), exposure: budget.toString(), gasPayment: gasCap.toString() } },
    recipients: { mode: "allowlist", addresses: [] }, targets: { [usdc]: [toFunctionSelector("transfer(address,uint256)")] },
    swaps: false, maxSlippageBps: 0, maxQuoteDeviationBps: 0, independentRpcOrigins: [],
    // This bounds the underlying operation, including first-use account deployment.
    // The fee the buyer can pay is still limited by the USDC gasPayment and daily caps above.
    maxGasCostWei: "100000000000000000000", maxFeePerGas: "100000000000000", maxGasUnits: "1500000", maxBatchCalls: 2,
    ...(seller ? { expiresAt, x402: { origins: { mode: "allowlist", origins: [seller.origin] }, payTo: { mode: "allowlist", addresses: [seller.address] }, maxPerPayment: price.toString() } } : {}),
  };
}

async function load(name) {
  try { return JSON.parse(await readFile(join(directory, name), "utf8")); }
  catch (error) { if (error.code !== "ENOENT") throw error; return undefined; }
}

async function save(name, data) {
  await writeFile(join(directory, name), JSON.stringify(data, null, 2) + "\n", { mode: 0o600, flag: "wx", flush: true });
  await syncDirectory(directory);
}

async function withBuyer(profile, work) {
  const client = new Client({ name: "incentiv-x402-mainnet-e2e", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [join(root, "dist/index.js"), "--wallet-profile", profile], cwd: root, stderr: "inherit",
  });
  try {
    await client.connect(transport);
    return await work(async (name, args = {}, expectedError) => {
      const response = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000 });
      const result = JSON.parse(response.content[0].text);
      if (expectedError) {
        assert.equal(response.isError, true, `${name} must refuse before signing`);
        assert.equal(result.code, expectedError);
      } else if (response.isError) {
        if (name === "get_agent_operation" && result.code === "operation_not_found") return { result };
        throw new Error(`${name} failed with ${result.code}: ${result.message}`);
      }
      return { result, meta: response._meta?.["x402/payment-response"] };
    });
  } finally { await client.close(); }
}

async function withSeller(run, work) {
  const seller = await startSeller({ payTo: run.seller, runId: run.id });
  let tunnel;
  try {
    tunnel = await startTunnel(seller.internal);
    const url = tunnel.origin + seller.resource;
    const deadline = Date.now() + 65_000;
    for (;;) {
      let response;
      let failure;
      try { response = await fetch(url, { signal: AbortSignal.timeout(5_000), redirect: "error" }); }
      catch (error) { failure = error.cause?.code ?? error.message; }
      if (response?.status === 402) {
        const challenge = decodePaymentRequiredHeader(response.headers.get("payment-required"));
        await response.body?.cancel();
        assert.equal(challenge.x402Version, 2);
        assert.ok(challenge.accepts.some(o => o.scheme === SCHEME && o.network === NETWORK && o.asset.toLowerCase() === usdc
          && o.payTo.toLowerCase() === run.seller.toLowerCase() && o.amount === price.toString()
          && o.extra.entryPoint.toLowerCase() === entryPoint), "The tunnel must expose the exact test route");
        break;
      }
      await response?.body?.cancel();
      if (Date.now() >= deadline) throw new Error(`Seller HTTPS preflight did not return HTTP 402: ${failure ?? response?.status}`);
      await delay(2_000);
    }
    return await work({ ...seller, origin: tunnel.origin, url });
  } finally {
    try { await tunnel?.close(); }
    finally { await seller.close(); }
  }
}

async function prepare() {
  const existing = await load("run.json");
  if (existing) {
    console.log(JSON.stringify(existing, null, 2));
    return;
  }
  await preflightSeller();
  await mkdir(directory, { mode: 0o700, recursive: true });
  let draft = await load("draft.json");
  if (!draft) {
    draft = { id: randomBytes(6).toString("hex") };
    await save("draft.json", draft);
  }
  const { id } = draft;
  assert.match(id, /^[0-9a-f]{12}$/);
  const buyerProfile = `x402-e2e-b-${id}`, sellerProfile = `x402-e2e-s-${id}`;
  const seller = await localWalletStore(MAINNET, sellerProfile).createOrLoad();
  await withSeller({ id, seller: seller.account }, async () => {});
  const credentials = await nativeCredentials(walletProfile(buyerProfile).credentialService);
  let passphrase = await credentials.read(adminKey);
  try {
    if (!passphrase) {
      passphrase = randomBytes(32);
      await credentials.create(adminKey, passphrase);
    }
    const store = localWalletStore(MAINNET, buyerProfile);
    const initialized = await stat(join(walletProfile(buyerProfile).root, "wallet.binding.json")).then(
      () => true, error => { if (error.code === "ENOENT") return false; throw error; },
    );
    const buyer = initialized ? await store.createOrLoad() : await store.initialize(limits(), passphrase);
    assert.equal(buyer.policy.configured, true);
    assert.equal(buyer.policy.enabled, false);
    await withBuyer(buyerProfile, async call => {
      const { result } = await call("get_agent_wallet");
      assert.equal(getAddress(result.account), getAddress(buyer.account));
      assert.equal(result.reason, "wallet_disabled");
      assert.equal(result.candidate_signing_enabled, true);
    });
    const run = { id, buyerProfile, sellerProfile, buyer: buyer.account, seller: seller.account, chainId: MAINNET.identity.chainId, token: usdc, fundUsdc: "0.05" };
    assert.notEqual(run.buyer.toLowerCase(), run.seller.toLowerCase());
    await save("run.json", run);
    console.log(JSON.stringify(run, null, 2));
    console.log(`Send exactly ${run.fundUsdc} USDC on Incentiv Mainnet to the buyer smart account above. Run data is in ${directory}.`);
  } finally { passphrase?.fill(0); }
}

async function tokenBalance(address) {
  const values = await Promise.all(chain.clients.map(client => client.readContract({
    address: usdc, abi: erc20Abi, functionName: "balanceOf", args: [address],
  })));
  assert.ok(values.every(balance => balance === values[0]), "Configured RPCs disagree on the test account balance");
  return values[0];
}

async function confirm(call, requestId) {
  const stop = Date.now() + 180_000;
  do {
    const { result } = await call("get_agent_operation", { id: requestId });
    if (result.code === "operation_not_found") throw new Error("The funded request did not produce a wallet record");
    if (result.status === "confirmed") return result;
    if (["failed", "expired", "cancelled", "reverted", "superseded"].includes(result.status)) throw new Error(`Purchase reached ${result.status}`);
    await delay(5_000);
  } while (Date.now() < stop);
  throw new Error("Purchase is unresolved. Use status to reconcile the original request.");
}

function receiptEvidence(receipt, run, userOpHash) {
  assert.equal(receipt.status, "success");
  const buyer = run.buyer.toLowerCase(), seller = run.seller.toLowerCase();
  const operations = [], credits = [], payments = [];
  for (const log of receipt.logs) {
    const address = log.address.toLowerCase();
    if (address === entryPoint && log.topics[0] === operationTopic) {
      const { args } = decodeEventLog({ abi: [operationEvent], ...log });
      if (args.userOpHash.toLowerCase() === userOpHash.toLowerCase()) operations.push(args);
    }
    if (address === usdc && log.topics[0] === transferTopic) {
      const { args } = decodeEventLog({ abi: erc20Abi, eventName: "Transfer", ...log });
      if (args.from.toLowerCase() !== buyer) continue;
      if (args.to.toLowerCase() === seller) credits.push(args.value);
      if (args.to.toLowerCase() === paymaster) payments.push(args.value);
    }
  }
  assert.equal(operations.length, 1);
  assert.equal(operations[0].sender.toLowerCase(), buyer);
  assert.equal(operations[0].paymaster.toLowerCase(), paymaster);
  assert.equal(operations[0].success, true);
  assert.deepEqual(credits, [price]);
  const gas = payments.reduce((total, value) => total + value, 0n);
  assert.ok(gas > 0n && gas <= gasCap, "The paymaster transfer must fit the approved gas cap");
  return { blockHash: receipt.blockHash, blockNumber: receipt.blockNumber.toString(), paymasterTransferAtomic: gas.toString() };
}

async function clearFailedAttempt(run) {
  const attempt = await load("attempt.json");
  assert.ok(attempt, "There is no funded attempt to retry");
  assert.equal(await load("result.json"), undefined, "A completed purchase cannot be retried as failed");
  const id = attempt.purchase.request_id;
  assert.match(id, /^[0-9a-f-]{36}$/i);
  const operation = await withBuyer(run.buyerProfile, async call => (await call("get_agent_operation", { id })).result);
  assert.equal(operation.request_id, id);
  assert.equal(operation.status, "failed", "A retry requires a failed preparation");
  assert.equal(operation.archived, true, "A retry requires the terminal wallet record");
  assert.equal(operation.user_op_hash, undefined, "A recorded user operation must be reconciled without another purchase");
  assert.equal(operation.transaction_hash, undefined, "A recorded transaction must be reconciled without another purchase");
  const history = `attempt-${id}.json`;
  if (!await load(history)) await save(history, { ...attempt, operation });
  await unlink(join(directory, "attempt.json"));
  await syncDirectory(directory);
}

async function runSuite(run, retryFailed) {
  assert.equal(await tokenBalance(run.buyer), budget, "The test buyer must hold exactly 0.05 USDC for this run");
  await preflightSeller();
  // Reserve the suite before enabling the wallet. Only one runner may reach the funded case.
  const lock = join(directory, "running");
  await writeFile(lock, "", { flag: "wx", mode: 0o600 });
  const store = localWalletStore(MAINNET, run.buyerProfile);
  let enabled = false;
  try {
    if (retryFailed) await clearFailedAttempt(run);
    else assert.equal(await load("attempt.json"), undefined, "A funded attempt was already recorded. Use status.");
    await withSeller(run, async seller => {
      const credentials = await nativeCredentials(walletProfile(run.buyerProfile).credentialService);
      const passphrase = await credentials.read(adminKey);
      assert.ok(passphrase, "The isolated test wallet's administration credential is unavailable");
      try {
        const service = new WalletService(new Ctx(MAINNET), store);
        const review = await service.review();
        assert.equal(getAddress(review.wallet.account), getAddress(run.buyer));
        assert.equal(review.records.length, 0);
        enabled = true; // Disable on exit even if configuration fails after saving the enabling policy.
        await service.configure(limits({ origin: seller.origin, address: run.seller }, Date.now() + 15 * 60_000), passphrase, false, digest([]));
      } finally { passphrase.fill(0); }
      await withBuyer(run.buyerProfile, async call => {
        const wallet = async () => (await call("get_agent_wallet")).result;
        const before = await wallet();
        assert.equal(getAddress(before.account), getAddress(run.buyer));
        assert.equal(before.balances[usdc], budget.toString());
        assert.deepEqual(before.pending_reservations, {});
        const sellerBefore = await tokenBalance(run.seller);
        const { result: quote } = await call("get_x402_payment_requirements", { url: seller.url });
        assert.equal(quote.payment_required, true);
        assert.equal(quote.payable, true);
        assert.equal(quote.policy.allowed, true);
        assert.equal(quote.price.amount_atomic, price.toString());
        assert.equal(getAddress(quote.price.pay_to), getAddress(run.seller));
        assert.equal(quote.price.network, NETWORK);
        assert.equal(quote.price.scheme, SCHEME);

        await call("pay_x402_resource", { url: seller.url, request_id: randomUUID(), max_amount: "0.009999", gas_token: "USDC" }, "x402_price_above_max");
        assert.equal(seller.seen.paid.length, 0);
        assert.deepEqual((await wallet()).pending_reservations, {});
        assert.equal(await tokenBalance(run.buyer), budget);

        const purchase = { url: seller.url, request_id: randomUUID(), max_amount: PRICE, gas_token: "USDC" };
        const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
        const walletSourceDirty = Boolean(execFileSync("git", ["status", "--porcelain", "--", "src"], { cwd: root, encoding: "utf8" }).trim());
        const estimatorSha256 = createHash("sha256").update(await readFile(join(root, "dist/userop.js"))).digest("hex");
        const build = { commit, walletSourceDirty, estimatorSha256 };
        await save("attempt.json", { ...build, purchase, startedAt: new Date().toISOString() });
        console.log(`Funded request ${purchase.request_id} started.`);
        const { result: paid, meta } = await call("pay_x402_resource", purchase);
        assert.equal(paid.status, "submitted", "The seller must report a successful settlement");
        assert.equal(paid.seller_reported_settlement, true);
        assert.equal(meta?.success, true);
        assert.deepEqual(JSON.parse(paid.content.text), seller.fixture);
        assert.equal(seller.seen.paid.length, 1);

        const settled = await confirm(call, purchase.request_id);
        assert.equal(settled.user_op_hash, paid.user_op_hash);
        assert.equal(settled.transaction_hash, meta.transaction);
        const receipts = await Promise.all(chain.clients.map(client => client.getTransactionReceipt({ hash: settled.transaction_hash })));
        const ledger = receipts.map(receipt => receiptEvidence(receipt, run, settled.user_op_hash));
        assert.ok(ledger.every(evidence => JSON.stringify(evidence) === JSON.stringify(ledger[0])), "Configured RPCs disagree on the settlement evidence");
        assert.deepEqual((await wallet()).pending_reservations, {});
        const buyerAfter = await tokenBalance(run.buyer), sellerAfter = await tokenBalance(run.seller);
        assert.equal(sellerAfter - sellerBefore, price);
        const buyerDebit = budget - buyerAfter;
        const netGas = buyerDebit - price;
        assert.ok(netGas > 0n && netGas <= BigInt(ledger[0].paymasterTransferAtomic));
        const settlement = {
          ...build, ...run, requestId: purchase.request_id, userOpHash: settled.user_op_hash, transactionHash: settled.transaction_hash,
          ...ledger[0], buyerDebitAtomic: buyerDebit.toString(), netGasAtomic: netGas.toString(),
          sellerCreditAtomic: (sellerAfter - sellerBefore).toString(),
        };
        await save("settlement.json", settlement);

        const { result: replay } = await call("pay_x402_resource", purchase);
        assert.equal(replay.user_op_hash, settled.user_op_hash);
        assert.equal(seller.seen.paid.length, 2);
        assert.equal(seller.seen.paid[0], seller.seen.paid[1], "Replay must carry the identical signed payment");
        assert.equal(await tokenBalance(run.buyer), buyerAfter);
        assert.equal(await tokenBalance(run.seller), sellerAfter);

        const result = {
          ...settlement, http: { unpaid: seller.seen.unpaid, paid: seller.seen.paid.length },
          replayContentDelivered: replay.content_delivered, passed: true,
        };
        await save("result.json", result);
        console.log(JSON.stringify(result, null, 2));
      });
    });
  } finally {
    try { if (enabled) await store.disable(); }
    finally { await unlink(lock); }
  }
}

async function status(run) {
  const attempt = await load("attempt.json");
  const result = await load("result.json");
  const fundedUsdcAtomic = (await tokenBalance(run.buyer)).toString();
  if (attempt && !result) {
    await withBuyer(run.buyerProfile, async call => {
      console.log(JSON.stringify({ ...run, fundedUsdcAtomic, attempt, operation: (await call("get_agent_operation", { id: attempt.purchase.request_id })).result }, null, 2));
    });
  } else console.log(JSON.stringify({ ...run, fundedUsdcAtomic, attempt, result }, null, 2));
}

async function main(args) {
  if (args.length === 1 && args[0] === "prepare") return prepare();
  const retryFailed = args.length === 3 && args[2] === "--retry-failed";
  if (!((args.length === 1 && args[0] === "status") || (args[0] === "run" && args[1] === "--approve-mainnet-spend" && (args.length === 2 || retryFailed)))) {
    throw new Error("Use prepare, status, or run --approve-mainnet-spend [--retry-failed]. One purchase may spend up to 0.05 real USDC.");
  }
  const run = await load("run.json");
  assert.ok(run, "Prepare the isolated mainnet test wallet first");
  assert.match(run.id, /^[0-9a-f]{12}$/);
  assert.equal(run.chainId, MAINNET.identity.chainId);
  assert.equal(run.buyerProfile, `x402-e2e-b-${run.id}`);
  assert.equal(run.sellerProfile, `x402-e2e-s-${run.id}`);
  return args[0] === "status" ? status(run) : runSuite(run, retryFailed);
}

if (process.env.INCENTIV_ALLOW_FILE_KEY === "1") {
  console.error("The mainnet suite requires OS credential storage. Unset INCENTIV_ALLOW_FILE_KEY.");
  process.exitCode = 1;
} else {
  await main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode = 1; });
}
