// Deliberately outside npm test. The only operation that spends is gated in run.
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdir, mkdtemp, readdir, readFile, rm, stat, unlink, writeFile } from "node:fs/promises";
import { hostname, tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";
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
import { installTestPackage } from "./install-test-package.mjs";

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

async function withBuyer(profile, work, dist = join(root, "dist"), signal) {
  signal?.throwIfAborted();
  const client = new Client({ name: "incentiv-x402-mainnet-e2e", version: "1.0.0" });
  const transport = new StdioClientTransport({
    command: process.execPath, args: [join(dist, "index.js"), "--wallet-profile", profile], cwd: dist, stderr: "inherit",
  });
  try {
    await client.connect(transport);
    return await work(async (name, args = {}, expectedError) => {
      signal?.throwIfAborted();
      const response = await client.callTool({ name, arguments: args }, undefined, { timeout: 180_000, signal });
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

async function withSeller(run, work, dropFirstSettlement, signal) {
  const seller = await startSeller({ payTo: run.seller, runId: run.id, dropFirstSettlement, acceptPayments: false });
  let tunnel;
  try {
    signal.throwIfAborted();
    tunnel = await startTunnel(seller.internal);
    const url = tunnel.origin + seller.resource;
    const deadline = Date.now() + 65_000;
    for (;;) {
      signal.throwIfAborted();
      let response;
      let failure;
      try { response = await fetch(url, { signal: AbortSignal.any([signal, AbortSignal.timeout(5_000)]), redirect: "error" }); }
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
      await delay(2_000, undefined, { signal });
    }
    signal.throwIfAborted();
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
  assert.equal(payments.length, 1, "The operation must charge the paymaster once");
  assert.ok(gas > 0n && gas <= gasCap, "The paymaster transfer must fit the approved gas cap");
  return {
    blockHash: receipt.blockHash, blockNumber: receipt.blockNumber.toString(), paymasterTransferAtomic: gas.toString(),
    actualGasUsed: operations[0].actualGasUsed.toString(), actualGasCostWei: operations[0].actualGasCost.toString(),
  };
}

async function configureBuyer(run, policy, enabled = true) {
  const credentials = await nativeCredentials(walletProfile(run.buyerProfile).credentialService);
  const passphrase = await credentials.read(adminKey);
  assert.ok(passphrase, "The isolated test wallet's administration credential is unavailable");
  try {
    const service = new WalletService(new Ctx(MAINNET), localWalletStore(MAINNET, run.buyerProfile));
    await service.configure(policy, passphrase, false, digest([]), enabled);
  } finally { passphrase.fill(0); }
}

async function verifyFreeRefusals(run, seller, dist, signal) {
  const balance = await tokenBalance(run.buyer);
  const policy = limits({ origin: seller.origin, address: run.seller }, Date.now() + 15 * 60_000);
  const args = { url: seller.url, max_amount: PRICE, gas_token: "USDC" };
  const cases = [
    { name: "disabled wallet", policy, enabled: false, code: "wallet_locked" },
    { name: "x402 disabled", policy: limits(), message: /x402 payments are off/ },
    { name: "expired policy", policy: { ...policy, expiresAt: 1 }, message: /expired/ },
    { name: "origin allowlist", policy: { ...policy, x402: { ...policy.x402, origins: { mode: "allowlist", origins: ["https://example.com"] } } }, message: /x402_origin_not_allowed/, quoteMessage: /does not allow this site/ },
    { name: "seller allowlist", policy: { ...policy, x402: { ...policy.x402, payTo: { mode: "allowlist", addresses: [run.buyer] } } }, reason: "x402_pay_to_not_allowed" },
    { name: "spend cap", policy: { ...policy, x402: { ...policy.x402, maxPerPayment: (price - 1n).toString() } }, reason: "x402_payment_limit" },
  ];
  await withBuyer(run.buyerProfile, async call => {
    for (const check of cases) {
      signal.throwIfAborted();
      await configureBuyer(run, check.policy, check.enabled);
      const before = seller.seen.unpaid;
      const code = check.code ?? "policy_denied";
      const { result: quote } = await call("get_x402_payment_requirements", { url: seller.url }, check.reason ? undefined : code);
      const requestId = randomUUID();
      const { result: refused } = await call("pay_x402_resource", { ...args, request_id: requestId }, code);
      if (check.reason) {
        assert.equal(quote.payable, true);
        assert.deepEqual(quote.policy, { allowed: false, reasons: [check.reason] });
        assert.ok(refused.message.includes(check.reason), `${check.name} must match the quoted reason`);
      } else if (check.message) {
        assert.match(quote.message, check.quoteMessage ?? check.message);
        assert.match(refused.message, check.message);
      }
      assert.equal(seller.seen.unpaid - before, check.reason ? 2 : 0, check.name);
      assert.equal(seller.seen.paid.length, 0, check.name);
      assert.equal((await call("get_agent_operation", { id: requestId })).result.code, "operation_not_found");
      assert.deepEqual((await call("get_agent_wallet")).result.pending_reservations, {});
      console.log(`Passed: ${check.name}`);
    }
    signal.throwIfAborted();
    await configureBuyer(run, policy);
    const { result: quote } = await call("get_x402_payment_requirements", { url: seller.url });
    assert.equal(quote.payment_required, true);
    assert.equal(quote.payable, true);
    assert.deepEqual(quote.policy, { allowed: true, reasons: [] });
    assert.equal(quote.price.amount_atomic, price.toString());
    assert.equal(getAddress(quote.price.pay_to), getAddress(run.seller));
    assert.equal(quote.price.network, NETWORK);
    assert.equal(quote.price.scheme, SCHEME);
    await call("pay_x402_resource", { ...args, request_id: randomUUID(), max_amount: "0.009999" }, "x402_price_above_max");
    assert.equal(seller.seen.paid.length, 0);
    assert.deepEqual((await call("get_agent_wallet")).result.pending_reservations, {});
    assert.equal(await tokenBalance(run.buyer), balance);
    console.log("Passed: payable quote and caller price cap");
  }, dist, signal);
}

async function clearFailedAttempt(run, signal) {
  const attempt = await load("attempt.json");
  assert.ok(attempt, "There is no funded attempt to retry");
  assert.equal(await load("result.json"), undefined, "A completed purchase cannot be retried as failed");
  const id = attempt.purchase.request_id;
  assert.match(id, /^[0-9a-f-]{36}$/i);
  const operation = await withBuyer(run.buyerProfile, async call => (await call("get_agent_operation", { id })).result, undefined, signal);
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

const lock = join(directory, "running");

// The marker names its runner, so a stopped run can be told apart from an active one.
async function lockOwner() {
  let text;
  try { text = await readFile(lock, "utf8"); } catch (error) { if (error.code === "ENOENT") return undefined; throw error; }
  try {
    const owner = JSON.parse(text);
    if (Number.isSafeInteger(owner.pid) && owner.pid > 0 && typeof owner.host === "string") return owner;
  } catch { /* an empty or partial marker names no runner */ }
  return { unknown: true };
}

function running(owner) {
  if (owner.unknown || owner.host !== hostname()) return true; // Its runner cannot be checked from here.
  try { process.kill(owner.pid, 0); return true; } catch (error) { return error.code === "EPERM"; }
}

const describe = owner => owner.unknown ? "with no recorded owner" : `by process ${owner.pid} on ${owner.host} since ${owner.startedAt}`;

async function acquireLock() {
  try {
    await writeFile(lock, JSON.stringify({ pid: process.pid, host: hostname(), startedAt: new Date().toISOString() }), { mode: 0o600, flag: "wx", flush: true });
  } catch (error) {
    if (error.code !== "EEXIST") throw error;
    const owner = await lockOwner() ?? { unknown: true };
    throw new Error(running(owner)
      ? `Another run holds ${lock}, ${describe(owner)}. If no run is active, delete that file and run again.`
      : `A stopped run left ${lock} (${describe(owner)}). Run \`npm run e2e:x402 -- unlock\`, then status, before running again.`);
  }
}

// Removes only a marker whose runner has exited on this host. Funded attempts stay recorded and still gate the next run.
async function unlock() {
  const owner = await lockOwner();
  if (!owner) return console.log("No run marker is present.");
  if (running(owner)) throw new Error(`The marker was left ${describe(owner)}, and that run may still be active. Delete ${lock} yourself only once no run is active.`);
  await unlink(lock);
  await syncDirectory(directory);
  console.log(`Removed the marker left ${describe(owner)}. Run status to reconcile any funded attempt.`);
}

async function distDigest() {
  const hash = createHash("sha256");
  const files = (await readdir(join(root, "dist"), { recursive: true, withFileTypes: true })).filter(entry => entry.isFile()).map(entry => join(entry.parentPath, entry.name)).sort();
  for (const file of files) hash.update(relative(root, file)).update("\0").update(await readFile(file)).update("\0");
  return hash.digest("hex");
}

// The tarball is packed from dist/ and this runner loads it too, so both must be what the checkout's source builds.
async function freshBuild() {
  const npm = process.env.npm_execpath;
  assert.ok(npm, "Run this suite through npm");
  const before = await distDigest();
  // tsc never deletes outputs, so a file whose source was removed would survive a rebuild in place.
  await rm(join(root, "dist"), { recursive: true, force: true });
  execFileSync(process.execPath, [npm, "run", "build"], { cwd: root, stdio: ["ignore", "ignore", "inherit"] });
  if (await distDigest() !== before) throw new Error("dist/ did not match the source, so it was rebuilt. Run the same command again to test the current build.");
  return before;
}

async function runSuite(run, { retryFailed = false, freeOnly = false, dropResponse = false } = {}) {
  if (!freeOnly) assert.equal(await tokenBalance(run.buyer), budget, "The test buyer must hold exactly 0.05 USDC for this run");
  await preflightSeller();
  // Reserve the suite before enabling the wallet. Only one runner may reach the funded case.
  await acquireLock();
  const store = localWalletStore(MAINNET, run.buyerProfile);
  let enabled = false, temp;
  const controller = new AbortController(), { signal } = controller;
  const interrupted = name => {
    process.exitCode = name === "SIGTERM" ? 143 : 130;
    controller.abort(new Error(`Stopped by ${name}. Run status before running again.`));
  };
  const interrupt = () => interrupted("SIGINT"), terminate = () => interrupted("SIGTERM");
  process.on("SIGINT", interrupt);
  process.on("SIGTERM", terminate);
  try {
    const distSha256 = await freshBuild();
    if (retryFailed) await clearFailedAttempt(run, signal);
    else assert.equal(await load("attempt.json"), undefined, "A funded attempt was already recorded. Use status.");
    temp = await mkdtemp(join(tmpdir(), "incentiv-x402-package-"));
    const { dist, tarballSha256 } = await installTestPackage(root, temp);
    const service = new WalletService(new Ctx(MAINNET), store);
    const review = await service.review();
    assert.equal(getAddress(review.wallet.account), getAddress(run.buyer));
    assert.equal(review.records.length, 0);
    signal.throwIfAborted();
    await withSeller(run, async seller => {
      enabled = true; // Disable on exit even if configuration fails after writing an enabling policy.
      await verifyFreeRefusals(run, seller, dist, signal);
      if (freeOnly) return;
      const buyerBefore = await tokenBalance(run.buyer), sellerBefore = await tokenBalance(run.seller);
      assert.equal(buyerBefore, budget);
      const purchase = { url: seller.url, request_id: randomUUID(), max_amount: PRICE, gas_token: "USDC" };
      const commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: root, encoding: "utf8" }).trim();
      const walletSourceDirty = Boolean(execFileSync("git", ["status", "--porcelain", "--", "src"], { cwd: root, encoding: "utf8" }).trim());
      const estimatorSha256 = createHash("sha256").update(await readFile(join(dist, "userop.js"))).digest("hex");
      const build = { commit, walletSourceDirty, distSha256, estimatorSha256, tarballSha256 };
      seller.allowPayments();
      const firstPayment = await withBuyer(run.buyerProfile, async call => {
        await save("attempt.json", { ...build, purchase, startedAt: new Date().toISOString() });
        console.log(`Funded request ${purchase.request_id} started.`);
        const { result: first, meta } = await call("pay_x402_resource", purchase);
        assert.equal(seller.seen.paid.length, 1);
        if (dropResponse) {
          assert.equal(first.status, "submission_unknown", "The first MCP process must miss the settlement response");
          assert.equal(first.content, undefined);
          assert.equal(meta, undefined);
          assert.ok(seller.seen.droppedSettlement, "The seller must drop the response after settlement");
        } else {
          assert.equal(first.status, "submitted");
          assert.equal(first.seller_reported_settlement, true);
          assert.equal(meta?.success, true);
          assert.deepEqual(JSON.parse(first.content.text), seller.fixture);
        }
        return { userOpHash: first.user_op_hash, transactionHash: dropResponse ? seller.seen.droppedSettlement : meta.transaction };
      }, dist, signal);

      // A new MCP process must recover the original journal record and signed operation.
      await withBuyer(run.buyerProfile, async call => {
        const settled = await confirm(call, purchase.request_id);
        assert.equal(settled.user_op_hash, firstPayment.userOpHash);
        assert.equal(settled.transaction_hash, firstPayment.transactionHash);
        const receipts = await Promise.all(chain.clients.map(client => client.getTransactionReceipt({ hash: settled.transaction_hash })));
        const ledger = receipts.map(receipt => receiptEvidence(receipt, run, settled.user_op_hash));
        assert.ok(ledger.every(evidence => JSON.stringify(evidence) === JSON.stringify(ledger[0])), "Configured RPCs disagree on the settlement evidence");
        assert.deepEqual((await call("get_agent_wallet")).result.pending_reservations, {});
        const buyerAfter = await tokenBalance(run.buyer), sellerAfter = await tokenBalance(run.seller);
        assert.equal(sellerAfter - sellerBefore, price);
        const buyerDebit = buyerBefore - buyerAfter;
        const netGas = buyerDebit - price;
        assert.ok(netGas > 0n && netGas <= BigInt(ledger[0].paymasterTransferAtomic));
        const settlement = {
          ...build, ...run, requestId: purchase.request_id, userOpHash: settled.user_op_hash, transactionHash: settled.transaction_hash,
          ...ledger[0], buyerDebitAtomic: buyerDebit.toString(), netGasAtomic: netGas.toString(),
          sellerCreditAtomic: (sellerAfter - sellerBefore).toString(),
        };
        await save("settlement.json", settlement);

        const { result: replay } = await call("pay_x402_resource", purchase);
        assert.equal(replay.status, "confirmed");
        assert.equal(replay.user_op_hash, settled.user_op_hash);
        assert.equal(seller.seen.paid.length, 2);
        assert.equal(seller.seen.paid[0], seller.seen.paid[1], "Replay must carry the identical signed payment");
        if (replay.content_delivered) assert.deepEqual(JSON.parse(replay.content.text), seller.fixture);
        assert.equal(await tokenBalance(run.buyer), buyerAfter);
        assert.equal(await tokenBalance(run.seller), sellerAfter);
        assert.deepEqual((await call("get_agent_wallet")).result.pending_reservations, {});

        const result = {
          ...settlement, http: { unpaid: seller.seen.unpaid, paid: seller.seen.paid.length, droppedAfterSettlement: dropResponse },
          replayContentDelivered: replay.content_delivered, passed: true,
        };
        await save("result.json", result);
        console.log(JSON.stringify(result, null, 2));
      }, dist, signal);
    }, dropResponse, signal);
  } finally {
    // Only the suite cleans up. No more work can start from this invocation once it reaches this block.
    try {
      try { if (enabled) await store.disable(); }
      finally { if (temp) await rm(temp, { recursive: true, force: true }); }
      await unlink(lock);
    } finally {
      process.off("SIGINT", interrupt);
      process.off("SIGTERM", terminate);
    }
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
  if (args.length === 1 && args[0] === "unlock") return unlock();
  const flags = args.slice(2);
  const fundedRun = args[0] === "run" && args[1] === "--approve-mainnet-spend" &&
    flags.length === new Set(flags).size && flags.every(flag => ["--retry-failed", "--drop-response"].includes(flag));
  if (!fundedRun && !(args.length === 1 && ["status", "preflight"].includes(args[0]))) {
    throw new Error("Use prepare, preflight, status, unlock, or run --approve-mainnet-spend [--retry-failed] [--drop-response]. One purchase may spend up to 0.05 real USDC.");
  }
  const run = await load("run.json");
  assert.ok(run, "Prepare the isolated mainnet test wallet first");
  assert.match(run.id, /^[0-9a-f]{12}$/);
  assert.equal(run.chainId, MAINNET.identity.chainId);
  assert.equal(run.buyerProfile, `x402-e2e-b-${run.id}`);
  assert.equal(run.sellerProfile, `x402-e2e-s-${run.id}`);
  return args[0] === "status" ? status(run) : runSuite(run, {
    freeOnly: !fundedRun, retryFailed: flags.includes("--retry-failed"), dropResponse: flags.includes("--drop-response"),
  });
}

if (process.env.INCENTIV_ALLOW_FILE_KEY === "1") {
  console.error("The mainnet suite requires OS credential storage. Unset INCENTIV_ALLOW_FILE_KEY.");
  process.exitCode = 1;
} else {
  await main(process.argv.slice(2)).catch(error => { console.error(error.message); process.exitCode ||= 1; });
}
