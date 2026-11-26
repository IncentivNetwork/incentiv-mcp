import { AGENT_LINK_MIN_SECONDS, AGENT_LINK_REQUEST_SECONDS, assertAgentSignature, assertNotUnlink, assertRegistryApproved, freshBlockTime, hasRegistryEvent, linkBlocker, parentBlocker, readAgentLinkDigest, isContractRejection, isRegistryIntent, isTransportFailure, registryApprovalSchema, registryCall, registryCapability, registryRevertCode, registryStatus, verifyRegistryDeployment, verifyRegistryIntent } from "../agent-registry.js";
import { BaseError, createPublicClient, decodeEventLog, decodeFunctionData, encodeFunctionData, getAddress, http, isAddress, keccak256, parseAbiItem, parseUnits, type Address, type Hex, type PublicClient } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { Ctx, type TokenInfo } from "../context.js";
import { accountAbi, accountFactoryAbi, dexFactoryAbi, dexPoolAbi, entryPointAbi, erc20Abi, quoterAbi, swapRouterAbi, transferGateAbi } from "../abi.js";
import { BundlerUnavailableError, broadcastUserOp, buildUserOpUnsigned, bundlerRpc, userOpFromJson as userOpFromWire, userOpToJson, type UserOp } from "../userop.js";
import { buildSwapCalls, planRoute, quoteRoute } from "../swap.js";
import { WalletError, type WalletEnvelope } from "./keystore.js";
import { RpcDisagreementError } from "./errors.js";
import { type Intent, type OperationRecord } from "./journal.js";
import { type Limits, type Spend } from "./policy.js";
import type { validateOperation } from "./validate.js";

const operationEvent = parseAbiItem("event UserOperationEvent(bytes32 indexed userOpHash, address indexed sender, address indexed paymaster, uint256 nonce, bool success, uint256 actualGasCost, uint256 actualGasUsed)");
const beforeExecutionEvent = parseAbiItem("event BeforeExecution()");
const revertReasonEvent = parseAbiItem("event UserOperationRevertReason(bytes32 indexed userOpHash,address indexed sender,uint256 nonce,bytes revertReason)");

/** A node or network problem that a retry can clear, as opposed to an answer from the chain. */
export { isTransportFailure };
const same = (values: unknown[]) => values.every(v => String(v).toLowerCase() === String(values[0]).toLowerCase());
export const SWAP_DEADLINE_SECONDS = 60;
/** How far back, and in what steps, an operation is looked for in EntryPoint events. */
// One reconciliation searches at most SEARCH_PER_PASS blocks while it holds the wallet lock; saved progress continues it.
const SEARCH_CHUNK = 5_000n, SEARCH_BLOCKS = 1_000_000n, SEARCH_PER_PASS = 100_000n;
export const REORG_MARGIN_BLOCKS = 128n;
/** How many unresolved EntryPoint logs one operation's receipt search keeps for retry. */
export const MAX_RETRY_LOGS = 16;
type RetryLog = NonNullable<OperationRecord["retryLogs"]>[number];
export const MIN_SWAP_REMAINING_SECONDS = 10;
export interface ChainState { nonce: bigint; deployed: boolean; block: bigint; timestamp: number; fees: { baseFeePerGas: bigint; maxFeePerGas: bigint; maxPriorityFeePerGas: bigint } }
export interface ChainReceipt { success: boolean; actualGasCost: bigint; transactionHash: Hex; registryError?: string; blockNumber?: bigint; blockHash?: Hex }

export class WalletChain {
  readonly clients: PublicClient[];
  constructor(readonly ctx: Ctx) {
    this.clients = ctx.config.endpoints.rpcUrls.map(url => createPublicClient({ transport: http(url, { timeout: 20_000, retryCount: 0 }) }));
  }
  async state(wallet: WalletEnvelope): Promise<ChainState> {
    const heads = await Promise.all(this.clients.map(c => c.getBlockNumber({ cacheTime: 0 })));
    const block = heads.reduce((a, b) => a < b ? a : b);
    if (heads.some(n => n - block > 5n)) throw new RpcDisagreementError("RPC chain heads disagree");
    const blocks = await Promise.all(this.clients.map(c => c.getBlock({ blockNumber: block })));
    const nonces = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.identity.entryPoint.address, abi: entryPointAbi, functionName: "getNonce", args: [wallet.account as Address, 0n], blockNumber: block })));
    const codes = await Promise.all(this.clients.map(c => c.getCode({ address: wallet.account as Address, blockNumber: block })));
    if (blocks.some(b => !b.hash) || !same(blocks.map(b => b.hash)) || !same(blocks.map(b => b.timestamp)) || !same(blocks.map(b => b.baseFeePerGas)) || !same(nonces) || !same(codes)) throw new RpcDisagreementError("RPC nonce, account or fee state disagrees");
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
  async canonicalBlockHash(blockNumber: bigint): Promise<Hex> {
    const hashes = await Promise.all(this.clients.map(c => c.getBlock({ blockNumber }).then(block => block.hash)));
    const [hash] = hashes;
    if (!hash || !same(hashes)) throw new RpcDisagreementError("RPC block hashes disagree");
    return hash;
  }

  /** The account's next nonce on one EntryPoint key, agreed by every configured RPC at `block`. */
  async laneNonce(wallet: WalletEnvelope, key: bigint, block: bigint): Promise<bigint> {
    const nonces = await Promise.all(this.clients.map(c => c.readContract({ address: this.ctx.config.identity.entryPoint.address, abi: entryPointAbi, functionName: "getNonce", args: [wallet.account as Address, key], blockNumber: block })));
    if (!same(nonces)) throw new RpcDisagreementError("RPC nonces disagree");
    return nonces[0];
  }
  /**
   * The chain state an operation's nonce is checked against: its own lane for an x402 payment (whose key is the
   * nonce's upper 192 bits), the main lane otherwise.
   */
  async stateFor(wallet: WalletEnvelope, record: OperationRecord): Promise<ChainState> {
    const state = await this.state(wallet);
    return record.intent.kind === "x402_payment" ? { ...state, nonce: await this.laneNonce(wallet, BigInt(record.nonce!) >> 64n, state.block) } : state;
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
  async normalize(kind: Intent["kind"], args: Record<string, unknown>): Promise<Intent> {
    if (kind === "link_agent" || kind === "unlink_agent") {
      registryCapability(this.ctx.config);
      const gas = await this.token(String(args.gas_token ?? "native"));
      const approval = kind === "link_agent" ? registryApprovalSchema.parse(args.approval) : undefined;
      const parent = getAddress(String(approval?.parent ?? args.parent)).toLowerCase();
      return { intentSchemaVersion: 1, kind, token: gas.address, amount: "0", gasToken: gas.address, slippageBps: 0, feeTier: 3000,
        registryParent: parent, ...(approval ? { registryApproval: { ...approval, registry: approval.registry.toLowerCase(), parent, agent: approval.agent.toLowerCase(), parent_signature: approval.parent_signature.toLowerCase() } } : {}) };
    }
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
    freshBlockTime(state.timestamp, ["validation_failed", "Swap RPC block is stale or in the future"]);
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
  private async registryRead<T>(wallet: WalletEnvelope, read: () => Promise<T>): Promise<T> {
    assertRegistryApproved(this.ctx.config, wallet);
    try { return await read(); } catch (error) {
      if (error instanceof WalletError) throw error;
      if (isTransportFailure(error)) throw new WalletError("registry_rpc_unavailable", "Could not read registry state from RPC; retry this request");
      // Reverts, malformed return data and local faults repeat on retry, so they close the request.
      if (isContractRejection(error)) throw new WalletError("registry_verification_failed", "The registry refused a read, so it may have changed");
      throw new WalletError("registry_verification_failed", "Registry state could not be verified");
    }
  }
  async verifyRegistry(wallet: WalletEnvelope, intent: Intent, state?: ChainState) {
    // Before any RPC read, so a refused unlink never waits on the network.
    assertNotUnlink(intent);
    await this.registryRead(wallet, async () => {
      const current = state ?? await this.state(wallet);
      await Promise.all(this.clients.map(client => verifyRegistryIntent(client, this.ctx.config, wallet, intent, current)));
    });
  }
  async registryStatus(wallet: WalletEnvelope, parent?: Address) {
    return this.registryRead(wallet, async () => this.registryStatusAt(wallet, await this.state(wallet), parent));
  }
  /** The registry status at `state`'s block, agreed by every RPC after each verifies the deployment. */
  private async registryStatusAt(wallet: WalletEnvelope, state: ChainState, parent?: Address) {
    const results = await Promise.all(this.clients.map(async client => {
      await verifyRegistryDeployment(client, this.ctx.config, state.block);
      return registryStatus(client, this.ctx.config, wallet.account as Address, parent, state.block);
    }));
    if (!same(results.map(r => JSON.stringify(r)))) throw new WalletError("validation_failed", "Registry state disagrees across RPCs");
    return { ...results[0], deployed: state.deployed };
  }
  /**
   * The registry status for `parent` and, when this deployed agent may consent to it, the AgentLink digest,
   * both read at one block every RPC agrees on. A registry blocker is returned first, since renewing the
   * policy would not clear it. The deadline runs from that block's time and never passes `notAfter` (Unix
   * seconds), so the consent cannot outlive the local policy that allowed it; a policy ending too soon is
   * refused against the same clock.
   */
  async agentLinkConsent(wallet: WalletEnvelope, parent: Address, notAfter?: number) {
    return this.registryRead(wallet, async () => {
      const state = await this.state(wallet), status = await this.registryStatusAt(wallet, state, parent);
      const blocked = linkBlocker(status, state.deployed) ?? parentBlocker(status, parent);
      // Only a deployed agent signs, so only then do the block's time and the policy's expiry matter.
      if (blocked || !state.deployed) return { status, blocked };
      const now = freshBlockTime(state.timestamp), deadline = Math.min(now + AGENT_LINK_REQUEST_SECONDS, notAfter ?? Number.MAX_SAFE_INTEGER);
      if (deadline < now + AGENT_LINK_MIN_SECONDS) return { status, blocked: ["policy_expired", "Local wallet policy has expired or expires too soon. Renew it with incentiv-mcp setup in your local terminal"] as [string, string] };
      const results = await Promise.all(this.clients.map(client => readAgentLinkDigest(client, this.ctx.config, wallet.account as Address, parent, BigInt(deadline), state.block)));
      if (!same(results.map(r => `${r.nonce}:${r.digest}`))) throw new WalletError("validation_failed", "Registry state disagrees across RPCs");
      return { status, blocked, consent: { ...results[0], deadline: BigInt(deadline), block: state.block } };
    });
  }
  async verifyAgentLinkSignature(wallet: WalletEnvelope, digest: Hex, signature: Hex, block: bigint) {
    await this.registryRead(wallet, () => Promise.all(this.clients.map(client => assertAgentSignature(client, wallet.account as Address, digest, signature, block))));
  }
  /**
   * An x402 payment is built like a token transfer, on the nonce in `state` (its own lane), so its USDC gas fee
   * comes from the pinned paymaster's own fee schedule, as for any transfer.
   */
  async build(wallet: WalletEnvelope, intent: Intent, state: ChainState, deadline?: number) {
    const input = await this.token(intent.token), gasToken = await this.token(intent.gasToken);
    const calls = isRegistryIntent(intent) ? [registryCall(this.ctx.config, wallet.account as Address, intent)] : intent.kind === "transfer" || intent.kind === "x402_payment" ? (input.address === "native" ? [{ to: intent.to as Address, value: BigInt(intent.amount), data: "0x" as Hex }] : [{ to: input.address, value: 0n, data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [intent.to as Address, BigInt(intent.amount)] }) }]) : buildSwapCalls(this.ctx, input, await this.token(intent.tokenOut!), planRoute(this.ctx, input, await this.token(intent.tokenOut!), intent.feeTier), BigInt(intent.amount), BigInt(intent.minimumOut!), wallet.account as Address, true, BigInt(deadline!));
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
    } catch (error) {
      // An outage says nothing about the operation, so the same request stays retryable; only a rejection fails it.
      if (error instanceof BundlerUnavailableError || isTransportFailure(error)) throw new WalletError("rpc_unavailable", "Could not reach the RPC or bundler to simulate the operation; retry this request");
      throw new WalletError("simulation_failed", "The exact validated operation failed simulation or exceeds its gas allocation");
    }
  }
  async buildReplacement(wallet: WalletEnvelope, original: OperationRecord, state: ChainState, gasToken = original.intent.gasToken) {
    const old = userOpFromWire(original.operation!);
    if (state.nonce !== old.nonce) throw new WalletError("operation_pending", "The original nonce has moved; locate its receipt before resolution");
    const bump = (n: bigint) => n * 120n / 100n + 1n;
    const fees = { ...state.fees, maxFeePerGas: state.fees.maxFeePerGas > bump(old.maxFeePerGas) ? state.fees.maxFeePerGas : bump(old.maxFeePerGas), maxPriorityFeePerGas: state.fees.maxPriorityFeePerGas > bump(old.maxPriorityFeePerGas) ? state.fees.maxPriorityFeePerGas : bump(old.maxPriorityFeePerGas) };
    return buildUserOpUnsigned(this.ctx, { account: wallet.account as Address, owner: wallet.owner as Address, state: { ...state, fees }, calls: [{ to: wallet.account as Address, value: 0n, data: "0x" }], gasToken: await this.token(gasToken) });
  }
  async relay(operation: Record<string, string>, beforeSubmit?: () => Promise<void>): Promise<string> {
    await beforeSubmit?.();
    return broadcastUserOp(this.ctx, userOpFromWire(operation));
  }
  /** The bundle transaction the configured bundler reports for an operation, if it indexes it. A hint only. */
  async bundlerHint(userOpHash: string): Promise<Hex | undefined> {
    const hint = await bundlerRpc(this.ctx, "eth_getUserOperationReceipt", [userOpHash]) as { receipt?: { transactionHash?: Hex } } | null;
    return hint?.receipt?.transactionHash;
  }
  async receipt(record: OperationRecord): Promise<ChainReceipt | undefined> {
    if (!record.userOpHash || !record.operation) return;
    // Bundler is a discovery hint. Only matching EntryPoint events in RPC receipts settle reservations.
    if (record.intent.kind !== "x402_payment") {
      const hint = await this.bundlerHint(record.userOpHash);
      return hint ? this.verifiedReceipt(record, hint) : undefined;
    }
    // The seller's facilitator submits an x402 payment, possibly through another bundler, so its reported
    // transaction and, once the payment's nonce lane has moved, the EntryPoint's own events are hints too.
    // Each hint counts only once verified; a stale or unverifiable one (say after a reorg) falls through to the next.
    const tried = new Set<string>();
    const verify = async (hash: Hex | undefined) => {
      if (!hash || tried.has(hash.toLowerCase())) return;
      tried.add(hash.toLowerCase());
      return this.verifiedReceipt(record, hash).catch(() => undefined);
    };
    return await verify(await this.bundlerHint(record.userOpHash).catch(() => undefined))
      ?? await verify(record.transactionHash as Hex | undefined)
      ?? this.searchOperation(record);
  }
  /**
   * Finds an operation's bundle in the EntryPoint's events, searching forward from the block it was signed at.
   * Only runs once the operation's nonce is used, so an unspent payment costs one read. Each call covers at most
   * SEARCH_PER_PASS blocks and records how far it got in `searchedBlock`, so an old payment is still reached.
   */
  async searchOperation(record: OperationRecord): Promise<ChainReceipt | undefined> {
    const nonce = BigInt(record.nonce!), sender = record.operation!.sender as Address, entryPoint = this.ctx.config.identity.entryPoint.address;
    const heads = await Promise.all(this.clients.map(c => c.getBlockNumber({ cacheTime: 0 })));
    const head = heads.reduce((a, b) => a < b ? a : b);
    const lanes = await Promise.all(this.clients.map(c => c.readContract({ address: entryPoint, abi: entryPointAbi, functionName: "getNonce", args: [sender, nonce >> 64n], blockNumber: head })));
    if (!same(lanes)) throw new Error("RPC nonces disagree");
    if (lanes[0] <= nonce) return;
    const start = record.searchedBlock !== undefined ? BigInt(record.searchedBlock) + 1n : record.fromBlock !== undefined ? BigInt(record.fromBlock) : head > SEARCH_BLOCKS ? head - SEARCH_BLOCKS : 0n;
    // Blocks only some RPCs could search, from a pass an RPC's log queries failed: they stay to be searched again by
    // every RPC, but discovery goes on past them, so a log outage on one RPC cannot strand a later receipt.
    const discovered = record.discoveredBlock !== undefined ? BigInt(record.discoveredBlock) : undefined;
    // Progress stops short of the head, so a reorg cannot hide an event in blocks already searched.
    const settled = head > REORG_MARGIN_BLOCKS ? head - REORG_MARGIN_BLOCKS : 0n;
    // A log that could not yet be verified or ruled out, say because its block header was unavailable, is kept and
    // tried first on every pass, so neither cursor has to wait for it. One known orphaned is dropped.
    const orphaned = async ({ blockNumber, blockHash }: RetryLog) => {
      if (!blockHash || blockNumber === undefined) return false;
      const canonical = await this.canonicalBlockHash(BigInt(blockNumber)).catch(() => undefined);
      return canonical !== undefined && canonical.toLowerCase() !== blockHash;
    };
    const retry: RetryLog[] = [];
    for (const log of record.retryLogs ?? []) {
      const receipt = await this.verifiedReceipt(record, log.transactionHash as Hex).catch(() => undefined);
      if (receipt) return receipt;
      if (!await orphaned(log)) retry.push(log);
    }
    // Past MAX_RETRY_LOGS unresolved logs, the cursors wait instead, as a log that is never resolved cannot be dropped.
    let progressBlocked = false, inconclusive = false;
    let failedChunk: { reason: unknown } | undefined;
    let logClients = this.clients;
    for (let from = start, budget = SEARCH_PER_PASS; from <= head && budget > 0n;) {
      const last = from + (budget < SEARCH_CHUNK ? budget : SEARCH_CHUNK) - 1n;
      const to = last < head ? last : head;
      // A failed log query blocks the cursor, but other RPCs can still locate a receipt for all RPCs to verify.
      const results = await Promise.allSettled(logClients.map(c => logsIn(from, to, range =>
        c.getLogs({ address: entryPoint, event: operationEvent, args: { userOpHash: record.userOpHash as Hex }, ...range }))));
      logClients = logClients.filter((_, index) => results[index].status === "fulfilled");
      if (!logClients.length) {
        const failure = results.find(result => result.status === "rejected");
        failedChunk = { reason: failure?.reason ?? new Error("No RPC could search EntryPoint logs") };
        break;
      }
      if (logClients.length !== this.clients.length) progressBlocked = true;
      const found = results.flatMap(result => result.status === "fulfilled" ? result.value : []);
      // Try each distinct transaction: an unresolved log cannot hide a receipt in a later range of this pass.
      const candidates = [...new Set(found.flatMap(log => log.transactionHash ? [log.transactionHash.toLowerCase() as Hex] : []))];
      for (const hash of candidates) {
        const receipt = await this.verifiedReceipt(record, hash).catch(() => undefined);
        if (receipt) return receipt;
      }
      for (const { blockNumber, blockHash, transactionHash } of found) {
        if (!transactionHash || retry.some(log => log.transactionHash === transactionHash.toLowerCase())) continue;
        const log: RetryLog = { transactionHash: transactionHash.toLowerCase() as Hex, ...(blockNumber != null ? { blockNumber: blockNumber.toString() } : {}), ...(blockHash ? { blockHash: blockHash.toLowerCase() as Hex } : {}) };
        if (await orphaned(log)) continue;
        if (retry.length < MAX_RETRY_LOGS) retry.push(log); else inconclusive = true;
      }
      budget -= to - from + 1n;
      from = to + 1n;
      // Neither cursor passes a log that could not be kept for retry, so the next pass reaches it again.
      if (inconclusive) continue;
      const covered = to < settled ? to : settled;
      if (covered < start) continue;
      if (!progressBlocked) record.searchedBlock = covered.toString();
      else if (record.discoveredBlock === undefined || covered > BigInt(record.discoveredBlock)) record.discoveredBlock = covered.toString();
      // The RPC that failed is out of this pass, so the blocks the others already searched are skipped.
      if (progressBlocked && discovered !== undefined && discovered >= from) from = discovered + 1n;
    }
    if (record.discoveredBlock !== undefined && record.searchedBlock !== undefined && BigInt(record.searchedBlock) >= BigInt(record.discoveredBlock)) delete record.discoveredBlock;
    // The caller can save the cursors even after a failure, so keep every candidate they advanced past.
    if (retry.length) record.retryLogs = retry; else delete record.retryLogs;
    if (failedChunk) throw failedChunk.reason;
  }
  /** The operation's outcome in one bundle transaction, agreed by every configured RPC; undefined until 2 blocks deep. */
  async verifiedReceipt(record: OperationRecord, transactionHash: Hex): Promise<ChainReceipt | undefined> {
    if (!record.userOpHash || !record.operation) return;
    const receipts = await Promise.all(this.clients.map(c => c.getTransactionReceipt({ hash: transactionHash })));
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
    let registryError: string | undefined;
    if (isRegistryIntent(record.intent) && record.userOpHash !== record.replacement?.userOpHash) {
      // The event comes from the registry this operation called, which a later release may have moved.
      const registry = calledRegistry(record.operation);
      const errors: (string | undefined)[] = [];
      for (const receipt of receipts) {
        const index = receipt.logs.findIndex(log => {
          try { return log.address.toLowerCase() === this.ctx.config.identity.entryPoint.address.toLowerCase() && decodeEventLog({ abi: [operationEvent], ...log }).args.userOpHash === record.userOpHash; } catch { return false; }
        });
        let start = index - 1;
        while (start >= 0) {
          const log = receipt.logs[start];
          try { if (log.address.toLowerCase() === this.ctx.config.identity.entryPoint.address.toLowerCase()) { decodeEventLog({ abi: [operationEvent, beforeExecutionEvent], ...log }); break; } } catch { /* another event */ }
          start--;
        }
        // Exclude validation/setup logs before BeforeExecution, including for the first operation.
        // Without that boundary this operation's logs cannot be isolated, so its registry event counts as missing.
        const logs = start < 0 ? [] : receipt.logs.slice(start + 1, index);
        // The EntryPoint result settles the nonce either way, so a missing event is reported rather than blocking the wallet.
        let code = matches[0][0].success && !hasRegistryEvent(this.ctx.config, record.intent, record.operation.sender, logs, registry) ? "registry_event_missing" : undefined;
        // Revert reasons are keyed by userOpHash, so they are safe to read from the whole bundle prefix.
        for (const log of start < 0 ? receipt.logs.slice(0, index) : logs) {
          if (log.address.toLowerCase() !== this.ctx.config.identity.entryPoint.address.toLowerCase()) continue;
          try {
            const { args } = decodeEventLog({ abi: [revertReasonEvent], ...log });
            if (args.userOpHash === record.userOpHash && args.sender.toLowerCase() === record.operation.sender.toLowerCase() && args.nonce === BigInt(record.nonce!)) code = registryRevertCode(args.revertReason);
          } catch { /* unrelated log */ }
        }
        errors.push(code);
      }
      if (!same(errors)) throw new Error("Registry revert reason disagrees across RPCs");
      registryError = errors[0];
    }
    return { ...matches[0][0], ...(record.intent.kind === "x402_payment" ? { blockNumber: receipts[0].blockNumber, blockHash: receipts[0].blockHash } : {}), ...(registryError ? { registryError } : {}) };
  }
}
/** The registry a signed registry operation called: its last call, after any gas-token payment. Undefined if it cannot be decoded. */
function calledRegistry(operation: Record<string, string>): Address | undefined {
  try {
    const { functionName, args } = decodeFunctionData({ abi: accountAbi, data: operation.callData as Hex });
    return functionName === "executeBatch" ? (args as readonly [readonly Address[], ...unknown[]])[0].at(-1) : undefined;
  } catch { return undefined; }
}
export function exactAmount(text: string, decimals: number): bigint {
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(text) || (text.split(".")[1]?.length ?? 0) > decimals) throw new WalletError("validation_failed", "Amount must be a positive decimal without rounding");
  const amount = parseUnits(text, decimals);
  if (amount <= 0n || amount >= 2n ** 256n) throw new WalletError("validation_failed", "Amount is out of range");
  return amount;
}

const LOG_RANGE_LIMIT = /(?:block range|range of blocks).*(?:too (?:wide|large)|limit|maximum|exceed)|(?:limit|maximum|exceed).*block range|query returned more than|too many (?:logs|results)|(?:log response|response size).*(?:too large|exceed|limit)/i;

function logRangeTooLarge(error: unknown): boolean {
  const matchesLimit = (cause: unknown) => cause instanceof Error
    && (LOG_RANGE_LIMIT.test(cause.message) || (cause instanceof BaseError && LOG_RANGE_LIMIT.test(cause.details)));
  return error instanceof BaseError ? !!error.walk(matchesLimit) : matchesLimit(error);
}

/** Halve the range down to 64 blocks only when the RPC reports a log range or result size limit. */
export async function logsIn<L>(from: bigint, to: bigint, read: (range: { fromBlock: bigint; toBlock: bigint }) => Promise<L[]>): Promise<L[]> {
  try { return await read({ fromBlock: from, toBlock: to }); } catch (error) {
    if (to - from < 64n || !logRangeTooLarge(error)) throw error;
    const mid = from + (to - from) / 2n;
    return [...await logsIn(from, mid, read), ...await logsIn(mid + 1n, to, read)];
  }
}
