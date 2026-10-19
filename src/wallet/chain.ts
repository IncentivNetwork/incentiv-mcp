import { createPublicClient, decodeEventLog, encodeFunctionData, getAddress, http, isAddress, keccak256, parseAbiItem, parseUnits, type Address, type Hex, type PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { Ctx, type TokenInfo } from "../context.js";
import { accountAbi, accountFactoryAbi, dexFactoryAbi, dexPoolAbi, entryPointAbi, erc20Abi, quoterAbi, swapRouterAbi, transferGateAbi } from "../abi.js";
import { broadcastUserOp, buildUserOpUnsigned, bundlerRpc, userOpFromJson as userOpFromWire, userOpToJson, type UserOp } from "../userop.js";
import { buildSwapCalls, planRoute, quoteRoute } from "../swap.js";
import { WalletError, type WalletEnvelope } from "./keystore.js";
import { type Intent, type OperationRecord } from "./journal.js";
import { type Limits, type Spend } from "./policy.js";
import type { validateOperation } from "./validate.js";

const operationEvent = parseAbiItem("event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)");
const same = (values: unknown[]) => values.every(v => String(v).toLowerCase() === String(values[0]).toLowerCase());
export const SWAP_DEADLINE_SECONDS = 60;
export const MIN_SWAP_REMAINING_SECONDS = 10;
export interface ChainState { nonce: bigint; deployed: boolean; block: bigint; timestamp: number; fees: { baseFeePerGas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } }
export interface ChainReceipt { success: boolean; actualGasCost: bigint; transactionHash: Hex }

export class WalletChain {
  readonly clients: PublicClient[];
  constructor(readonly ctx: Ctx) {
    this.clients = ctx.config.endpoints.rpcUrls.map(url => createPublicClient({ transport: http(url, { timeout: 20_000, retryCount: 0 }) }));
  }
  async state(wallet: WalletEnvelope): Promise<ChainState> {
    const heads = await Promise.all(this.clients.map(c => c.getBlockNumber({ cacheTime: 0 })));
    const block = heads.reduce((a, b) => a < b ? a : b);
    if (heads.some(n => n - block > 5n)) throw new WalletError("validation_failed", "RPC chain heads disagree");
    const blocks = await Promise.all(this.clients.map(c => c.getBlock({ blockNumber: block })));
    const nonces = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.identity.entryPoint.address, abi: entryPointAbi, functionName: "getNonce", args: [wallet.account as Address, 0n], blockNumber: block })));
    const codes = await Promise.all(this.clients.map(c => c.getCode({ address: wallet.account as Address, blockNumber: block })));
    if (blocks.some(b => !b.hash) || !same(blocks.map(b => b.hash)) || !same(blocks.map(b => b.timestamp)) || !same(blocks.map(b => b.baseFeePerGas)) || !same(nonces) || !same(codes)) throw new WalletError("validation_failed", "RPC nonce, account or fee state disagrees");
    const deployed = !!codes[0] && codes[0] !== "0x";
    if (deployed) {
      const owners = await Promise.all(this.clients.map(c => c.readContract({ address: wallet.account as Address, abi: accountAbi, functionName: "owner", blockNumber: block })));
      const factoryAccounts = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.identity.accountFactory.address, abi: accountFactoryAbi, functionName: "isDeployedByFactory", args: [wallet.account as Address], blockNumber: block })));
      if (!owners.every(a => a.toLowerCase() === wallet.owner.toLowerCase()) || !factoryAccounts.every(Boolean)) throw new WalletError("validation_failed", "Deployed account ownership or factory mismatch");
    }
    const base = blocks[0].baseFeePerGas;
    if (base === null || base === undefined) throw new WalletError("validation_failed", "Missing base fee");
    return { nonce: nonces[0], deployed, block, timestamp: Number(blocks[0].timestamp), fees: { baseFeePerGas: base, maxFeePerGas: base * 2n + 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n } };
  }
  async token(ref: string): Promise<TokenInfo> {
    const cfg = this.ctx.config, name = ref.trim();
    if (name.toLowerCase() === "native" || name.toUpperCase() === cfg.identity.nativeSymbol) return this.ctx.nativeToken();
    const tokens = { ...cfg.manifest.canonicalTokens, WCENT: cfg.manifest.contracts.wcent };
    const entry = Object.entries(tokens).find(([symbol, pin]) => symbol === name.toUpperCase() || pin.address.toLowerCase() === name.toLowerCase());
    if (!entry) throw new WalletError("validation_failed", "Wallet tokens must be pinned in the approved manifest");
    const decimals = await Promise.all(this.clients.map(c => c.readContract({ address: entry[1].address, abi: erc20Abi, functionName: "decimals" })));
    if (!same(decimals)) throw new WalletError("validation_failed", "Token decimals disagree");
    return { address: entry[1].address.toLowerCase() as Address, symbol: entry[0], name: entry[0], decimals: Number(decimals[0]) };
  }
  async normalize(kind: "transfer" | "swap", args: Record<string, unknown>): Promise<Intent> {
    const token = await this.token(String(kind === "transfer" ? args.token : args.token_in));
    const gas = await this.token(String(args.gas_token ?? "native"));
    const amount = exactAmount(String(kind === "transfer" ? args.amount : args.amount_in), token.decimals);
    const base = { intentSchemaVersion: 1 as const, kind, token: token.address, amount: amount.toString(), gasToken: gas.address, slippageBps: kind === "swap" ? Number(args.slippage_bps ?? 50) : 0, feeTier: kind === "swap" ? Number(args.fee_tier ?? 3000) : 3000 };
    if (kind === "transfer") {
      if (!isAddress(String(args.to))) throw new WalletError("validation_failed", "Invalid recipient");
      return { ...base, to: getAddress(String(args.to)).toLowerCase() };
    }
    const output = await this.token(String(args.token_out));
    if (output.address === token.address) throw new WalletError("validation_failed", "Swap tokens must differ");
    return { ...base, tokenOut: output.address, minimumOut: exactAmount(String(args.minimum_out), output.decimals).toString() };
  }
  async balances(wallet: WalletEnvelope, tokens: string[]): Promise<Spend> {
    const result: Spend = {};
    await Promise.all([...new Set(tokens.map(t => t.toLowerCase()))].map(async token => {
      const values = await Promise.all(this.clients.map(c => token === "native" ? c.getBalance({ address: wallet.account as Address }) : c.readContract({ address: token as Address, abi: erc20Abi, functionName: "balanceOf", args: [wallet.account as Address] })));
      if (!same(values)) throw new WalletError("validation_failed", "RPC balances disagree");
      result[token] = values[0].toString();
    }));
    return result;
  }
  async gasDeposit(wallet: WalletEnvelope): Promise<string> {
    const values = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.identity.entryPoint.address, abi: entryPointAbi, functionName: "balanceOf", args: [wallet.account as Address] })));
    if (!same(values)) throw new WalletError("validation_failed", "RPC gas deposits disagree");
    return values[0].toString();
  }
  async quote(intent: Intent, limits: Limits, blockNumber: bigint): Promise<void> {
    const urls = this.ctx.config.endpoints.rpcUrls;
    const approved = new Set(limits.independentRpcOrigins.map(u => new URL(u).origin));
    const origins = new Set(urls.map(u => new URL(u).origin));
    const trusted = new Set(limits.trustedRpcOrigins ?? []);
    if (![...origins].every(o => trusted.has(o)) && (origins.size < 2 || [...origins].some(o => !approved.has(o)))) throw new WalletError("validation_failed", "Swaps require explicitly trusted RPC origins or two administrator-attested independent RPC operators");
    if (blockNumber <= 0n) throw new WalletError("validation_failed", "Swap quote requires a pinned block");
    const input = await this.token(intent.token), output = await this.token(intent.tokenOut!);
    const quotes = await Promise.all(urls.map(async url => {
      const context = new Ctx({ ...this.ctx.config, endpoints: { ...this.ctx.config.endpoints, rpcUrls: [url] } });
      return (await quoteRoute(context, planRoute(context, input, output, intent.feeTier), BigInt(intent.amount), blockNumber)).amountOut;
    }));
    const low = quotes.reduce((a, b) => a < b ? a : b), high = quotes.reduce((a, b) => a > b ? a : b);
    if (low <= 0n || (high - low) * 10_000n > low * BigInt(limits.maxQuoteDeviationBps)) throw new WalletError("validation_failed", "Configured swap quotes disagree");
    // Caller minimum is absolute, must also satisfy the authorized slippage bound at every source.
    if (BigInt(intent.minimumOut!) > low || BigInt(intent.minimumOut!) * 10_000n < high * BigInt(10_000 - intent.slippageBps)) throw new WalletError("validation_failed", "Absolute minimum output is incompatible with the quotes and slippage bound");
  }
  async verifySwap(wallet: WalletEnvelope, intent: Intent, limits: Limits, state: ChainState): Promise<void> {
    const now = Math.floor(Date.now() / 1000);
    if (!Number.isSafeInteger(state.timestamp) || state.timestamp < now - 60 || state.timestamp > now + 30) throw new WalletError("validation_failed", "Swap RPC block is stale or in the future");
    await this.quote(intent, limits, state.block);
    const cfg = this.ctx.config, contracts = cfg.manifest.contracts;
    const input = await this.token(intent.token), output = await this.token(intent.tokenOut!);
    const route = planRoute(this.ctx, input, output, intent.feeTier);
    const addresses = new Set([contracts.quoter.address, contracts.swapRouter.address, contracts.wcent.address, input.address, output.address].map(a => a.toLowerCase()));
    const pins = [...Object.values(contracts), ...Object.values(cfg.manifest.canonicalTokens)].filter(p => addresses.has(p.address.toLowerCase()));
    await Promise.all(this.clients.map(async client => {
      const blockNumber = state.block;
      await Promise.all(pins.map(async pin => {
        const code = await client.getCode({ address: pin.address, blockNumber });
        if (!code || keccak256(code) !== pin.codeHash) throw new WalletError("validation_failed", "Swap contract code changed");
      }));
      if (!route.hops.length) return;
      const [factory, quoteFactory] = await Promise.all([
        client.readContract({ address: contracts.swapRouter.address, abi: swapRouterAbi, functionName: "factory", blockNumber }),
        client.readContract({ address: contracts.quoter.address, abi: quoterAbi, functionName: "factory", blockNumber }),
      ]);
      if (!same([factory, quoteFactory]) || /^0x0{40}$/i.test(factory)) throw new WalletError("validation_failed", "Router and quoter factories disagree");
      await Promise.all(route.hops.map(async hop => {
        const pool = await client.readContract({ address: factory, abi: dexFactoryAbi, functionName: "getPool", args: [hop.tokenIn, hop.tokenOut, hop.fee], blockNumber });
        if (/^0x0{40}$/i.test(pool)) throw new WalletError("validation_failed", "Swap pool is missing");
        const [poolFactory, token0, token1, fee] = await Promise.all([
          client.readContract({ address: pool, abi: dexPoolAbi, functionName: "factory", blockNumber }),
          client.readContract({ address: pool, abi: dexPoolAbi, functionName: "token0", blockNumber }),
          client.readContract({ address: pool, abi: dexPoolAbi, functionName: "token1", blockNumber }),
          client.readContract({ address: pool, abi: dexPoolAbi, functionName: "fee", blockNumber }),
        ]);
        const expected = [hop.tokenIn, hop.tokenOut].map(a => a.toLowerCase()).sort();
        if (!same([poolFactory, factory]) || fee !== hop.fee || [token0, token1].map(a => a.toLowerCase()).sort().join() !== expected.join()) throw new WalletError("validation_failed", "Swap pool does not match the verified route");
      }));
      if (input.address !== "native") {
        const allowance = await client.readContract({ address: input.address, abi: erc20Abi, functionName: "allowance", args: [wallet.account as Address, contracts.swapRouter.address], blockNumber });
        if (allowance !== 0n) throw new WalletError("validation_failed", "Swap router allowance must be zero before execution");
      }
    }));
  }
  async build(wallet: WalletEnvelope, intent: Intent, state: ChainState, deadline?: number) {
    const input = await this.token(intent.token), gasToken = await this.token(intent.gasToken);
    const calls = intent.kind === "transfer" ? (input.address === "native" ? [{ to: intent.to as Address, value: BigInt(intent.amount), data: "0x" as Hex }] : [{ to: input.address, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [intent.to as Address, BigInt(intent.amount)] }) }]) : buildSwapCalls(this.ctx, input, await this.token(intent.tokenOut!), planRoute(this.ctx, input, await this.token(intent.tokenOut!), intent.feeTier), BigInt(intent.amount), BigInt(intent.minimumOut!), wallet.account as Address, true, BigInt(deadline!));
    return buildUserOpUnsigned(this.ctx, { account: wallet.account as Address, owner: wallet.owner as Address, calls, gasToken, state });
  }
  async simulate(validated: ReturnType<typeof validateOperation>): Promise<void> {
    try {
      for (const call of validated.calls) {
        const checks = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.manifest.contracts.transferGate.address, abi: transferGateAbi, functionName: "checkApproval", args: [call.to, call.value, call.data], account: validated.op.sender })));
        if (checks.some(c => c.reject !== 0)) throw new Error();
      }
      const op: UserOp = { ...validated.op };
      op.signature = await privateKeyToAccount(generatePrivateKey()).signMessage({ message: { raw: validated.hash } });
      const estimate = await bundlerRpc(this.ctx, "eth_estimateUserOperationGas", [userOpToJson(op), this.ctx.config.identity.entryPoint.address]) as Record<string, string>;
      for (const key of ["callGasLimit", "verificationGasLimit", "preVerificationGas"] as const) if (BigInt(estimate[key]) > op[key] || BigInt(estimate[key]) <= 0n) throw new Error();
    } catch { throw new WalletError("simulation_failed", "The exact validated operation failed simulation or exceeds its gas allocation"); }
  }
  async buildReplacement(wallet: WalletEnvelope, original: OperationRecord, state: ChainState) {
    const old = userOpFromWire(original.operation!);
    if (state.nonce !== old.nonce) throw new WalletError("operation_pending", "The original nonce has moved; locate its receipt before resolution");
    const bump = (n: bigint) => n * 120n / 100n + 1n;
    const fees = { ...state.fees, maxFeePerGas: state.fees.maxFeePerGas > bump(old.maxFeePerGas) ? state.fees.maxFeePerGas : bump(old.maxFeePerGas), maxPriorityFeePerGas: state.fees.maxPriorityFeePerGas > bump(old.maxPriorityFeePerGas) ? state.fees.maxPriorityFeePerGas : bump(old.maxPriorityFeePerGas) };
    return buildUserOpUnsigned(this.ctx, { account: wallet.account as Address, owner: wallet.owner as Address, state: { ...state, fees }, calls: [{ to: wallet.account as Address, value: 0n, data: "0x" }] });
  }
  async relay(operation: Record<string, string>, beforeSubmit?: () => Promise<void>): Promise<string> {
    await beforeSubmit?.();
    return broadcastUserOp(this.ctx, userOpFromWire(operation));
  }
  async receipt(record: OperationRecord): Promise<ChainReceipt | undefined> {
    if (!record.userOpHash || !record.operation) return;
    // Bundler is a discovery hint. Only matching EntryPoint events in RPC receipts settle reservations.
    const hint = await bundlerRpc(this.ctx, "eth_getUserOperationReceipt", [record.userOpHash]) as { receipt?: { transactionHash?: Hex } } | null;
    if (!hint?.receipt?.transactionHash) return;
    const receipts = await Promise.all(this.clients.map(c => c.getTransactionReceipt({ hash: hint.receipt!.transactionHash! })));
    if (!same(receipts.map(r => r.blockHash)) || !same(receipts.map(r => r.blockNumber)) || receipts.some(r => r.status !== "success")) throw new Error("Receipt disagreement");
    const blocks = await Promise.all(this.clients.map((c, i) => c.getBlock({ blockNumber: receipts[i].blockNumber })));
    if (blocks.some((b, i) => b.hash !== receipts[i].blockHash)) throw new Error("Receipt is not in the canonical chain");
    const heads = await Promise.all(this.clients.map(c => c.getBlockNumber({ cacheTime: 0 })));
    if (heads.some(h => h < receipts[0].blockNumber + 2n)) return;
    const matches = receipts.map(r => r.logs.flatMap(log => {
      if (log.address.toLowerCase() !== this.ctx.config.identity.entryPoint.address.toLowerCase()) return [];
      try {
        const { args } = decodeEventLog({ abi: [operationEvent], ...log });
        if (args.userOpHash !== record.userOpHash || args.sender.toLowerCase() !== record.operation!.sender.toLowerCase() || args.nonce !== BigInt(record.nonce!) || args.paymaster.toLowerCase() !== (record.operation!.paymaster ?? `0x${"0".repeat(40)}`).toLowerCase()) return [];
        return [{ success: args.success, actualGasCost: args.actualGasCost, transactionHash: r.transactionHash }];
      } catch { return []; }
    }));
    if (matches.some(m => m.length !== 1) || !same(matches.map(m => `${m[0].success}:${m[0].actualGasCost}`))) throw new Error("Receipt event mismatch");
    return matches[0][0];
  }
}
export function exactAmount(text: string, decimals: number): bigint {
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(text) || (text.split(".")[1]?.length ?? 0) > decimals) throw new WalletError("validation_failed", "Amount must be a positive decimal without rounding");
  const amount = parseUnits(text, decimals);
  if (amount <= 0n || amount >= 2n ** 256n) throw new WalletError("validation_failed", "Amount is out of range");
  return amount;
}
