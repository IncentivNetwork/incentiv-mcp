import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { encodeFunctionData } from "viem";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { assertWalletNetwork } from "../src/network.ts";
import { accountFactoryAbi } from "../src/abi.ts";
import { computeUserOpHash, encodeExecuteBatch } from "../src/userop.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { WalletService } from "../src/wallet/service.ts";
import { WalletChain } from "../src/wallet/chain.ts";
import { Journal } from "../src/wallet/journal.ts";
import { newAdministration } from "../src/wallet/policy.ts";

export const password = Buffer.from("PUBLIC_TEST_ADMIN_CANARY_2026");
export const recipient = "0x0000000000000000000000000000000000000002";
export const limits = { tokens: { native: { perTransaction: "10000", daily: "1000000", exposure: "10000000", gasPayment: "10000" } }, recipients: { mode: "allowlist", addresses: [recipient] }, targets: {}, swaps: false, maxSlippageBps: 50, maxQuoteDeviationBps: 50, independentRpcOrigins: [], maxGasCostWei: "10000", maxFeePerGas: "100", maxGasUnits: "1000000", maxBatchCalls: 2 };
let administration;
export function unsigned(wallet, intent, { deployed, nonce }) {
  const zero = `0x${"0".repeat(64)}`;
  const op = { sender: wallet.account, nonce, callData: encodeExecuteBatch([{ to: intent.to, value: BigInt(intent.amount), data: "0x" }]), callGasLimit: 100n, verificationGasLimit: 100n, preVerificationGas: 100n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n, signature: "0x" };
  if (!deployed) { op.factory = MAINNET.identity.accountFactory.address; op.factoryData = encodeFunctionData({ abi: accountFactoryAbi, functionName: "createAccount", args: [wallet.owner, [zero, zero], 0n] }); }
  return { op, userOpHash: computeUserOpHash(op, MAINNET.identity.entryPoint.address, MAINNET.identity.chainId), maxGasCostWei: 300n };
}
export async function fixture(t, options = {}) {
  const parent = options.root ? undefined : await mkdtemp(join(await realpath(tmpdir()), "wallet-pipeline-"));
  const root = options.root ?? join(parent, "state");
  if (parent) t?.after(() => rm(parent, { recursive: true, force: true }));
  const config = options.config ?? MAINNET;
  const context = new Ctx(config);
  const deps = { root, allowFileKey: true, credentials: async () => ({ read: async () => undefined }), verify: async (cfg, wallet) => { if (wallet) assertWalletNetwork(cfg, wallet); }, checkpoint: options.checkpoint, lockTimeoutMs: 500 };
  const store = new WalletStore(config, deps), chain = new WalletChain(context);
  let builds = 0, submissions = [], receipt;
  chain.token = async ref => ({ address: "native", symbol: "CENT", decimals: 18, name: "CENT" });
  chain.state = async () => ({ deployed: false, nonce: 0n, block: 1n, timestamp: Math.floor(Date.now() / 1000), fees: { baseFeePerGas: 1n, maxFeePerGas: 1n, maxPriorityFeePerGas: 1n } });
  chain.balances = async (_wallet, tokens) => Object.fromEntries(tokens.map(token => [token.toLowerCase(), token === "native" ? "1000000" : "0"]));
  chain.gasDeposit = async () => "0";
  chain.build = async (wallet, intent, state) => { builds++; return unsigned(wallet, intent, state); };
  chain.buildReplacement = async (wallet, _record, state) => {
    const built = unsigned(wallet, { to: wallet.account, amount: "0" }, state);
    built.op.maxFeePerGas = 2n; built.op.maxPriorityFeePerGas = 2n;
    built.userOpHash = computeUserOpHash(built.op, MAINNET.identity.entryPoint.address, MAINNET.identity.chainId);
    return built;
  };
  chain.simulate = async () => {};
  chain.relay = async (operation, beforeSubmit) => { await beforeSubmit?.(); submissions.push(structuredClone(operation)); return computeUserOpHash((await import("../src/userop.ts")).userOpFromJson(operation), MAINNET.identity.entryPoint.address, MAINNET.identity.chainId); };
  chain.receipt = async () => receipt;
  const service = new WalletService(context, store, chain, options.releaseApproved ?? true);
  if (!options.existing) {
    await store.createOrLoad();
    administration ??= await newAdministration(password);
    await store.session(async s => {
      const journal = await Journal.open(s, true); await journal.save();
      await s.savePolicy({ schemaVersion: 1, configured: true, enabled: true, limits: structuredClone(limits), administration });
    });
  }
  return { root, parent, store, chain, service, deps, builds: () => builds, submissions, setReceipt: value => { receipt = value; } };
}
export const args = id => ({ request_id: id, token: "CENT", to: recipient, amount: "0.000000000000001" });
