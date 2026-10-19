import { z } from "zod";
import { publicErrorMessage, publicServiceUrl } from "./public-output.js";
import { networkStatusFields, verifyNetwork } from "./network.js";
import type { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import {
  encodeFunctionData,
  formatUnits,
  isAddress,
  getAddress,
  parseUnits,
  type Address,
  type Hex,
} from "viem";
import type { Ctx, TokenInfo } from "./context.js";
import { NATIVE } from "./context.js";
import {
  bulkBalanceReaderAbi,
  erc20Abi,
  paymasterAbi,
  transferGateAbi,
  TRANSFER_GATE_REASONS,
} from "./abi.js";
import {
  broadcastUserOp,
  buildUserOpUnsigned,
  computeGasTokenAmount,
  getFees,
  getPaymasterConfig,
  requiredCentFor,
  userOpFromJson,
  userOpToJson,
  waitForUserOp,
  type Call,
} from "./userop.js";
import { buildSwapCalls, planRoute, quoteRoute, DEFAULT_FEE_TIER } from "./swap.js";
import { buildUnsignedTx, broadcastRawTx } from "./eoa.js";
import {
  getBridgeConfig,
  findRoute,
  remoteClient,
  buildInboundBridge,
  buildOutboundBridge,
  checkDelivered,
  warpAbi,
} from "./bridge.js";

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function ok(data: unknown): ToolResult {
  return {
    content: [
      {
        type: "text",
        text: typeof data === "string" ? data : JSON.stringify(data, (_k, v) => (typeof v === "bigint" ? v.toString() : v), 2),
      },
    ],
  };
}

function err(message: string): ToolResult {
  return { content: [{ type: "text", text: message }], isError: true };
}

function wrap(fn: (args: never) => Promise<ToolResult>): (args: unknown) => Promise<ToolResult> {
  return async (args: unknown) => {
    try {
      return await fn(args as never);
    } catch (e) {
      return err(publicErrorMessage(e));
    }
  };
}

function tokenLabel(t: TokenInfo): string {
  return t.address === NATIVE ? `${t.symbol} (native)` : `${t.symbol} (${t.address})`;
}

function parseAmount(amount: string, decimals: number, allowZero = false): bigint {
  if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255 ||
      !/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(amount) || (amount.split(".")[1]?.length ?? 0) > decimals) {
    throw new Error(`Amount must be a decimal with at most ${decimals} decimal places; rounding is not allowed`);
  }
  const raw = parseUnits(amount, decimals);
  if (raw < 0n || (!allowZero && raw === 0n) || raw >= 2n ** 256n) throw new Error("Amount is out of range");
  return raw;
}

async function parseTokenAmount(ctx: Ctx, tokenRef: string, amount: string): Promise<{ token: TokenInfo; raw: bigint }> {
  const token = await ctx.resolveToken(tokenRef);
  const raw = parseAmount(amount, token.decimals);
  return { token, raw };
}

async function tokenBalance(ctx: Ctx, token: TokenInfo, account: Address): Promise<bigint> {
  if (token.address === NATIVE) return ctx.client.getBalance({ address: account });
  return ctx.client.readContract({ address: token.address as Address, abi: erc20Abi, functionName: "balanceOf", args: [account] });
}

/** Check each call against TransferGate, as the account will. */
async function gateCheck(ctx: Ctx, calls: Call[]): Promise<{ target: string; result: string; ok: boolean }[]> {
  const out: { target: string; result: string; ok: boolean }[] = [];
  for (const call of calls) {
    try {
      const r = await ctx.client.readContract({
        address: ctx.config.manifest.contracts.transferGate.address,
        abi: transferGateAbi,
        functionName: "checkApproval",
        args: [call.to, call.value, call.data],
      });
      const reason = TRANSFER_GATE_REASONS[Number(r.reject)] ?? `UNKNOWN(${r.reject})`;
      out.push({ target: call.to, result: reason, ok: reason === "APPROVED" });
    } catch (e) {
      out.push({ target: call.to, result: `check failed: ${publicErrorMessage(e)}`, ok: false });
    }
  }
  return out;
}

interface TransferArgs {
  account: string;
  token: string;
  to: string;
  amount: string;
  gas_token?: string;
  owner?: string;
  salt?: string;
}

async function buildTransferCalls(ctx: Ctx, args: TransferArgs) {
  const account = ctx.resolveAccount(args.account);
  if (!isAddress(args.to)) throw new Error(`Recipient is not a valid address: ${args.to}`);
  const to = getAddress(args.to);
  const { token, raw } = await parseTokenAmount(ctx, args.token, args.amount);
  const calls: Call[] =
    token.address === NATIVE
      ? [{ to, value: raw, data: "0x" as Hex }]
      : [
          {
            to: token.address as Address,
            value: 0n,
            data: encodeFunctionData({ abi: erc20Abi, functionName: "transfer", args: [to, raw] }),
          },
        ];
  const gasToken = args.gas_token ? await ctx.resolveToken(args.gas_token) : undefined;
  return { account, token, to, raw, calls, gasToken };
}

interface SwapArgs {
  account: string;
  token_in: string;
  token_out: string;
  amount_in: string;
  slippage_bps?: number;
  fee_tier?: number;
  gas_token?: string;
  owner?: string;
  salt?: string;
}

/** Parse the optional owner and salt used to deploy an account. */
function deployArgs(ctx: Ctx, args: { owner?: string; salt?: string }): { owner?: Address; salt?: bigint } {
  return {
    owner: args.owner ? ctx.resolveAccount(args.owner) : undefined,
    salt: args.salt !== undefined ? BigInt(args.salt) : undefined,
  };
}

async function buildSwapPlan(ctx: Ctx, args: SwapArgs) {
  const account = ctx.resolveAccount(args.account);
  const { token: tokenIn, raw: amountIn } = await parseTokenAmount(ctx, args.token_in, args.amount_in);
  const tokenOut = await ctx.resolveToken(args.token_out);
  const feeTier = args.fee_tier ?? DEFAULT_FEE_TIER;
  const slippageBps = BigInt(args.slippage_bps ?? 100);
  if (slippageBps < 0n || slippageBps > 5000n) throw new Error("slippage_bps must be between 0 and 5000");
  const route = planRoute(ctx, tokenIn, tokenOut, feeTier);
  const { amountOut } = await quoteRoute(ctx, route, amountIn);
  if (amountOut === 0n) {
    throw new Error(
      `No liquidity for ${route.description} at the ${feeTier / 10_000}% fee tier. The quote is zero, so this swap cannot execute. Try another route, fee tier, or amount.`,
    );
  }
  const minOut = route.kind === "wrap" || route.kind === "unwrap" ? amountOut : (amountOut * (10_000n - slippageBps)) / 10_000n;
  const gasToken = args.gas_token ? await ctx.resolveToken(args.gas_token) : undefined;
  const calls = buildSwapCalls(ctx, tokenIn, tokenOut, route, amountIn, minOut, account, true);
  return { account, tokenIn, tokenOut, amountIn, amountOut, minOut, route, slippageBps, gasToken, calls };
}

function describeEstimationError(e: unknown): string {
  const msg = publicErrorMessage(e);
  let hint = "";
  if (msg.includes("AA21")) hint = ". The account cannot prefund gas in CENT. Fund it, or pass gas_token to pay in another token.";
  else if (msg.includes("AA23")) hint = ". Validation reverted: check the signature and the account.";
  else if (msg.includes("AA31") || msg.toLowerCase().includes("paymaster")) hint = ". The paymaster rejected the operation: check the gas token balance and minimum payment.";
  else if (msg.includes("-32521") || msg.includes("execution reverted")) hint = ". The calls revert in simulation, usually because the account lacks the funds it is sending.";
  else if (msg.includes("balance")) hint = ". Insufficient token balance.";
  return msg + hint;
}

export interface ToolDoc {
  name: string;
  title?: string;
  description?: string;
  params: { name: string; required: boolean }[];
  readOnly: boolean;
}

/** Register the keyless public tool surface and return its documentation catalog. */
export function registerPublicTools(server: McpServer, ctx: Ctx): ToolDoc[] {
  const cfg = ctx.config;
  const { routes: ROUTES, remoteChains: REMOTE_CHAINS, domain: INCENTIV_DOMAIN, note: NON_EVM_NOTE } = getBridgeConfig(cfg);
  const catalog: ToolDoc[] = [];

  // Record each registration, then delegate.
  const passthrough = server.registerTool.bind(server);
  const record = ((name: string, config: Record<string, unknown>, handler: unknown) => {
    if (!cfg.manifest.bridge.enabled && name.includes("bridge")) return;
    const shape = (config.inputSchema ?? {}) as Record<string, { isOptional?: () => boolean }>;
    catalog.push({
      name,
      title: config.title as string | undefined,
      description: config.description as string | undefined,
      params: Object.entries(shape).map(([p, schema]) => ({
        name: p,
        required: typeof schema?.isOptional === "function" ? !schema.isOptional() : true,
      })),
      readOnly: (config.annotations as { readOnlyHint?: boolean } | undefined)?.readOnlyHint === true,
    });
    const guarded = async (args: Record<string, unknown>, extra: unknown) => {
      // Local startup/custody does not depend on unrelated remote RPCs. Every
      // bridge tool and remote broadcast must verify those pins before use.
      if (name.includes("bridge") || (name === "broadcast_transaction" && String(args.chain ?? "incentiv").trim().toLowerCase() !== "incentiv")) {
        try { await verifyNetwork(cfg); }
        catch (error) { return err(publicErrorMessage(error)); }
      }
      return (handler as (args: unknown, extra: unknown) => Promise<ToolResult>)(args, extra);
    };
    return passthrough(name as never, config as never, guarded as never);
  }) as typeof server.registerTool;
  server = new Proxy(server, {
    get: (t, prop, r) => (prop === "registerTool" ? record : Reflect.get(t, prop, r)),
  });

  // Account
  server.registerTool(
    "get_account",
    {
      title: "Get account",
      description:
        "Inspect any Incentiv account by address: type (EOA vs smart account/contract), deployment status, and native CENT balance.",
      inputSchema: {
        address: z.string().describe("Account address to inspect (0x...)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address: string }) => {
      const address = ctx.resolveAccount(args.address);
      const [balance, code] = await Promise.all([
        ctx.client.getBalance({ address }),
        ctx.client.getCode({ address }).catch(() => undefined),
      ]);
      const hasCode = !!code && code !== "0x";
      return ok({
        address,
        type: hasCode ? "contract (smart account or other contract)" : "EOA or undeployed account (no code on chain)",
        deployed: hasCode,
        native_balance: `${formatUnits(balance, 18)} ${cfg.identity.nativeSymbol}`,
        network: { name: cfg.identity.name, chainId: cfg.identity.chainId },
        explorer: ctx.explorerAddress(address),
      });
    }),
  );

  server.registerTool(
    "get_smart_account",
    {
      title: "Get the smart account for an owner",
      description:
        "Derive the Incentiv smart account controlled by an owner EOA. The address is deterministic and exists before the account is deployed — it can receive funds immediately, and deploys itself with its first signed operation (pass `owner` to build_transfer/build_swap to do that). Signer is the owner EOA; passkeys are not used.",
      inputSchema: {
        owner: z.string().describe("Owner EOA address (0x...) — the key that will sign this account's operations"),
        salt: z.string().optional().describe("CREATE2 salt (default 0). Different salts give the same owner different accounts."),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { owner: string; salt?: string }) => {
      const owner = ctx.resolveAccount(args.owner);
      const salt = args.salt !== undefined ? BigInt(args.salt) : 0n;
      const account = await ctx.deriveSmartAccount(owner, salt);
      const [deployed, balance] = await Promise.all([
        ctx.isDeployed(account),
        ctx.client.getBalance({ address: account }),
      ]);
      return ok({
        owner,
        salt: salt.toString(),
        account,
        deployed,
        native_balance: `${formatUnits(balance, 18)} ${cfg.identity.nativeSymbol}`,
        status: deployed
          ? "Deployed and ready to use."
          : "Not deployed yet — it looks like a plain address on chain. It can already receive funds; the first signed operation from it will deploy it (pass `owner` to build_transfer/build_swap).",
        funding_note: deployed
          ? undefined
          : `You can fund this address before it exists. If it holds a paymaster-supported token, pass gas_token so the first operation deploys the account and pays its own gas in that token — no ${cfg.identity.nativeSymbol} needed.`,
        explorer: ctx.explorerAddress(account),
      });
    }),
  );

  server.registerTool(
    "get_portfolio",
    {
      title: "Get portfolio",
      description:
        "Get all token balances (native CENT + ERC-20s) for the agent account (or a given address), with USD prices where available.",
      inputSchema: {
        address: z.string().describe("Account address (0x...)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address?: string }) => {
      const address = await ctx.resolveAccount(args.address);
      const known = await ctx.knownTokens();

      // The explorer lists which tokens are held; balances come from chain.
      let held: string[] = [];
      try {
        const { items } = await ctx.indexer.accountAssets(address);
        held = items
          .map((i) => String((i as Record<string, unknown>).assetId ?? ""))
          .filter((a) => isAddress(a));
      } catch {
        held = known.filter(t => t.address !== NATIVE).map(t => t.address);
      }
      const tokens = [...new Set(held.map((h) => h.toLowerCase()))];
      const balances = tokens.length
        ? await ctx.client.readContract({
            address: cfg.manifest.contracts.bulkBalanceReader.address,
            abi: bulkBalanceReaderAbi,
            functionName: "readBalances",
            args: [address, tokens.map((t) => getAddress(t))],
          })
        : [];
      const native = await ctx.client.getBalance({ address });

      const positions: Record<string, unknown>[] = [];
      let totalUsd = 0;
      let pricedCount = 0;
      const nativeInfo = ctx.nativeToken();
      positions.push({
        token: cfg.identity.nativeSymbol,
        type: "native",
        balance: formatUnits(native, 18),
        raw: native.toString(),
      });
      for (let i = 0; i < tokens.length; i++) {
        const bal = balances[i] ?? 0n;
        if (bal === 0n) continue;
        let info;
        try {
          info = await ctx.resolveToken(tokens[i]);
        } catch {
          // Not ERC-20 shaped; report the raw balance.
          positions.push({ token: tokens[i], balance: bal.toString(), note: "non-ERC20 asset (raw balance)" });
          continue;
        }
        const human = Number(formatUnits(bal, info.decimals));
        const usd = info.price ? human * info.price : undefined;
        if (usd) {
          totalUsd += usd;
          pricedCount++;
        }
        positions.push({
          token: info.symbol,
          name: info.name,
          address: info.address,
          balance: formatUnits(bal, info.decimals),
          raw: bal.toString(),
          price_usd: info.price,
          value_usd: usd !== undefined ? Number(usd.toFixed(2)) : undefined,
        });
      }
      return ok({
        account: address,
        positions,
        // A zero total would read as a valuation rather than missing prices.
        total_value_usd_excl_native: pricedCount > 0 ? Number(totalUsd.toFixed(2)) : undefined,
        note:
          pricedCount > 0
            ? "USD values cover only tokens with a known price."
            : "No USD prices are available for these tokens (the explorer reports no exchange rates on this chain); balances are exact, values are not shown.",
        explorer: ctx.explorerAddress(address),
      });
    }),
  );

  server.registerTool(
    "get_account_activity",
    {
      title: "Get account activity",
      description: "Recent user operations (transactions) for the agent account or a given address, incoming and outgoing.",
      inputSchema: {
        address: z.string().describe("Account address (0x...)"),
        limit: z.number().int().min(1).max(100).optional().describe("Max results (default 10)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address?: string; limit?: number }) => {
      const address = await ctx.resolveAccount(args.address);
      const { items } = await ctx.indexer.accountUserOpActivity(address, undefined, args.limit ?? 10);
      if (items.length === 0) {
        return ok({
          account: address,
          activity: [],
          note: "No user operations for this account. If this is an EOA, that is expected — EOAs send plain transactions, not user operations; use get_transactions for its history.",
        });
      }
      return ok({ account: address, activity: items });
    }),
  );

  server.registerTool(
    "get_transactions",
    {
      title: "Get plain transactions",
      description:
        "Plain (classic EVM) transaction history for an address — the only surface where EOA activity appears. Smart-account actions show here as the bundle transactions that carried their user operations.",
      inputSchema: {
        address: z.string().describe("Address (0x...) — for an EOA this shows plain-tx history"),
        limit: z.number().int().min(1).max(100).optional().describe("Max results (default 10)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address?: string; limit?: number }) => {
      const address = await ctx.resolveAccount(args.address);
      const { items } = await ctx.indexer.accountTransactions(address, undefined, args.limit ?? 10);
      return ok({ account: address, transactions: items, explorer: ctx.explorerAddress(address) });
    }),
  );

  server.registerTool(
    "get_transfers",
    {
      title: "Get token transfers",
      description: "Token transfer history for the agent account or a given address.",
      inputSchema: {
        address: z.string().describe("Account address (0x...)"),
        limit: z.number().int().min(1).max(100).optional().describe("Max results (default 25)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address?: string; limit?: number }) => {
      const address = await ctx.resolveAccount(args.address);
      const { items } = await ctx.indexer.accountTransfers(address, args.limit ?? 25);
      return ok({ account: address, transfers: items });
    }),
  );

  // Market
  server.registerTool(
    "list_assets",
    {
      title: "List assets",
      description: "List tokens/assets on the Incentiv network with metadata and USD prices. Optionally filter by type or search by symbol/name.",
      inputSchema: {
        search: z.string().optional().describe("Filter by symbol or name substring"),
        type: z.string().optional().describe("Asset type filter, e.g. ERC20, ERC721"),
        limit: z.number().int().min(1).max(200).optional().describe("Max results (default 50)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { search?: string; type?: string; limit?: number }) => {
      const wanted = args.limit ?? 50;
      // Over-fetch and filter locally so substrings the server misses match.
      const { items } = await ctx.indexer.listAssets({
        type: args.type,
        q: args.search,
        max: args.search ? Math.max(wanted, 200) : wanted,
      });
      let out = items as Record<string, unknown>[];
      if (args.search) {
        const q = args.search.toLowerCase();
        out = out.filter(
          (a) => String(a.symbol ?? "").toLowerCase().includes(q) || String(a.name ?? "").toLowerCase().includes(q),
        );
      }
      const slim = out.slice(0, wanted).map((a) => ({
        symbol: a.symbol,
        name: a.name,
        address: a.contract ?? a.assetId,
        type: a.type,
        decimals: a.decimals,
        price_usd: typeof a.price === "number" && a.price > 0 ? a.price : undefined,
        holders: a.totalHolders,
      }));
      return ok({ count: slim.length, assets: slim });
    }),
  );

  server.registerTool(
    "get_asset",
    {
      title: "Get asset details",
      description: "Details for one token/asset (by symbol or address): supply, holders, price, volume.",
      inputSchema: { asset: z.string().describe("Token symbol (e.g. USDC) or 0x address") },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { asset: string }) => {
      // Addresses work for NFTs too, which have no ERC-20 metadata.
      if (isAddress(args.asset)) {
        const details = await ctx.indexer.getAsset(args.asset).catch(() => undefined);
        if (details && Object.keys(details as object).length > 0) return ok(details);
      }
      const token = await ctx.resolveToken(args.asset);
      if (token.address === NATIVE) {
        return ok({ symbol: token.symbol, type: "native", decimals: 18, note: "Native gas token of Incentiv. Wrapped form: WCENT " + cfg.manifest.contracts.wcent.address });
      }
      const details = await ctx.indexer.getAsset(String(token.address)).catch(() => undefined);
      return ok(details ?? token);
    }),
  );

  server.registerTool(
    "get_swap_quote",
    {
      title: "Get swap quote",
      description:
        "Quote a token swap on Incentiv's native DEX (Uniswap-V3-style). Returns expected output, route, and price impact info. Does not execute anything.",
      inputSchema: {
        token_in: z.string().describe("Token to sell: symbol, 0x address, or CENT for native"),
        token_out: z.string().describe("Token to buy: symbol, 0x address, or CENT for native"),
        amount_in: z.string().describe('Human amount of token_in to sell, e.g. "1.5"'),
        fee_tier: z.number().int().optional().describe("Pool fee tier in hundredths of a bip (default 3000 = 0.3%)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { token_in: string; token_out: string; amount_in: string; fee_tier?: number }) => {
      const { token: tokenIn, raw: amountIn } = await parseTokenAmount(ctx, args.token_in, args.amount_in);
      const tokenOut = await ctx.resolveToken(args.token_out);
      const route = planRoute(ctx, tokenIn, tokenOut, args.fee_tier ?? DEFAULT_FEE_TIER);
      const { amountOut, gasEstimate } = await quoteRoute(ctx, route, amountIn);
      const price = Number(formatUnits(amountOut, tokenOut.decimals)) / Number(formatUnits(amountIn, tokenIn.decimals));
      return ok({
        sell: `${formatUnits(amountIn, tokenIn.decimals)} ${tokenLabel(tokenIn)}`,
        receive_estimate: `${formatUnits(amountOut, tokenOut.decimals)} ${tokenLabel(tokenOut)}`,
        route: route.description,
        effective_price: `1 ${tokenIn.symbol} = ${price.toPrecision(6)} ${tokenOut.symbol}`,
        swap_gas_estimate: gasEstimate.toString(),
        note: "Use build_swap to construct the signable operation.",
      });
    }),
  );

  server.registerTool(
    "get_gas_payment_options",
    {
      title: "Get gas payment options",
      description:
        "Which tokens can pay gas via the Unified Token Paymaster (Incentiv lets you pay gas in any supported token), with estimated cost per token for a typical transfer. Pass an account address to also show that account's balance and sufficiency per token.",
      inputSchema: {
        address: z.string().optional().describe("Account address (0x...) to show balances/sufficiency for"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { address?: string }) => {
      const account = args.address ? ctx.resolveAccount(args.address) : undefined;
      const [pmCfg, fees, known] = await Promise.all([getPaymasterConfig(ctx), getFees(ctx), ctx.knownTokens()]);
      // Representative gas for a sponsored token transfer.
      const sample = { callGasLimit: 350_000n, verificationGasLimit: 400_000n, preVerificationGas: 60_000n };
      const requiredCent = requiredCentFor(pmCfg, sample, fees.maxFeePerGas);
      const options: Record<string, unknown>[] = [
        {
          token: cfg.identity.nativeSymbol,
          method: "native (no paymaster)",
          estimated_cost: `${formatUnits((sample.callGasLimit + sample.verificationGasLimit + sample.preVerificationGas) * fees.maxFeePerGas, 18)} ${cfg.identity.nativeSymbol} (max)`,
          balance: account ? formatUnits(await ctx.client.getBalance({ address: account }), 18) : undefined,
        },
      ];
      for (const listed of known) {
        if (listed.address === NATIVE || listed.address.toLowerCase() === cfg.manifest.contracts.wcent.address.toLowerCase()) continue;
        try {
          const t = await ctx.resolveToken(listed.address);
          const amount = await computeGasTokenAmount(ctx, pmCfg, t, requiredCent);
          const balance = account ? await tokenBalance(ctx, t, account) : undefined;
          options.push({
            token: t.symbol,
            address: t.address,
            method: "Unified Token Paymaster",
            estimated_cost: `${formatUnits(amount, t.decimals)} ${t.symbol}`,
            balance: balance !== undefined ? formatUnits(balance, t.decimals) : undefined,
            sufficient: balance !== undefined ? balance >= amount : undefined,
          });
        } catch {
          // No WCENT pool, so this token cannot pay gas.
        }
      }
      return ok({
        account,
        note: "Estimates assume a typical single-transfer user operation. Pass gas_token to review_transfer/place_transfer/review_swap/place_swap to use one.",
        options,
      });
    }),
  );

  server.registerTool(
    "get_network_status",
    {
      title: "Get network status",
      description: "Incentiv network status: chain ID, latest block, base fee, entry point, and service health (RPC, bundler, indexer).",
      inputSchema: {},
      annotations: { readOnlyHint: true },
    },
    wrap(async () => {
      const [block, fees] = await Promise.all([ctx.client.getBlock(), getFees(ctx)]);
      let bundlerOk = false;
      try {
        const r = await fetch(cfg.endpoints.bundlerUrl, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_supportedEntryPoints", params: [] }),
          signal: AbortSignal.timeout(8000),
        });
        const j = (await r.json()) as { result?: string[] };
        bundlerOk = Array.isArray(j.result) && j.result.some((e) => e.toLowerCase() === cfg.identity.entryPoint.address.toLowerCase());
      } catch {
        /* bundler unreachable */
      }
      let explorerOk = false;
      let latestIndexed: unknown;
      try {
        const { items } = await ctx.indexer.listBlocks({ max: 1 });
        explorerOk = items.length > 0;
        latestIndexed = (items[0] as Record<string, unknown>)?.number;
      } catch {
        /* explorer API unreachable */
      }
      return ok({
        ...networkStatusFields(cfg),
        network: cfg.identity.name,
        chain_id: cfg.identity.chainId,
        latest_block: Number(block.number),
        base_fee_per_gas: `${formatUnits(block.baseFeePerGas ?? 0n, 9)} gwei`,
        suggested_max_fee_per_gas: `${formatUnits(fees.maxFeePerGas, 9)} gwei`,
        entry_point: cfg.identity.entryPoint.address,
        services: {
          rpc: { url: publicServiceUrl(cfg.endpoints.rpcUrls[0]), ok: true },
          bundler: { url: publicServiceUrl(cfg.endpoints.bundlerUrl), ok: bundlerOk },
          explorer_api: { url: publicServiceUrl(cfg.endpoints.explorerApiUrl), ok: explorerOk, latest_indexed_block: latestIndexed },
        },
        explorer: cfg.endpoints.explorerUrl,
      });
    }),
  );

  // Explorer
  server.registerTool(
    "get_transaction",
    {
      title: "Get transaction",
      description: "Look up a transaction by hash, including its user operations and token transfers.",
      inputSchema: { hash: z.string().describe("Transaction hash (0x...)") },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { hash: string }) => {
      const [tx, userops, transfers] = await Promise.all([
        ctx.indexer.getTransaction(args.hash),
        ctx.indexer.transactionUserOperations(args.hash).catch(() => ({ items: [] as unknown[] })),
        ctx.indexer.transactionTransfers(args.hash).catch(() => ({ items: [] as unknown[] })),
      ]);
      return ok({
        transaction: tx,
        user_operations: userops.items,
        transfers: transfers.items,
        explorer: ctx.explorerTx(args.hash),
      });
    }),
  );

  server.registerTool(
    "get_user_operation",
    {
      title: "Get user operation",
      description: "Look up an Incentiv user operation (AA transaction) by its hash, including resulting token transfers.",
      inputSchema: { hash: z.string().describe("User operation hash (0x...)") },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { hash: string }) => {
      const [op, transfers] = await Promise.all([
        ctx.indexer.getUserOperation(args.hash),
        ctx.indexer.userOperationTransfers(args.hash).catch(() => ({ items: [] })),
      ]);
      return ok({ user_operation: op, transfers: (transfers as { items: unknown[] }).items, explorer: ctx.explorerOp(args.hash) });
    }),
  );

  server.registerTool(
    "get_block",
    {
      title: "Get block",
      description: "Look up a block by number or hash; optionally include its transactions.",
      inputSchema: {
        block: z.string().describe("Block number or 0x hash (or 'latest')"),
        include_transactions: z.boolean().optional(),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { block: string; include_transactions?: boolean }) => {
      let id = args.block;
      if (id === "latest") {
        const { items } = await ctx.indexer.listBlocks({ max: 1 });
        id = String((items[0] as Record<string, unknown>)?.number ?? "");
      }
      const block = await ctx.indexer.getBlock(id);
      const txs = args.include_transactions ? (await ctx.indexer.blockTransactions(id)).items : undefined;
      return ok({ block, transactions: txs });
    }),
  );

  server.registerTool(
    "search",
    {
      title: "Search Incentiv",
      description: "Search the Incentiv explorer for a block, transaction, user operation, address, or token.",
      inputSchema: {
        query: z.string().describe("Hash, address, block number, or token symbol"),
        type: z.enum(["block", "transaction", "userOperation"]).optional().describe("Restrict lookup to one kind"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { query: string; type?: string }) => {
      const q = args.query.trim();
      const want = (k: string) => !args.type || args.type === k;

      // Classify an address by its code and the token registry.
      if (isAddress(q)) {
        const [code, token] = await Promise.all([
          ctx.client.getCode({ address: getAddress(q) }).catch(() => undefined),
          ctx.resolveToken(q).catch(() => undefined),
        ]);
        return ok({
          kind: code && code !== "0x" ? "contract" : "account",
          address: getAddress(q),
          token: token && token.symbol !== "?" ? token : undefined,
          explorer: ctx.explorerAddress(q),
        });
      }

      // A 32-byte hash may be a user operation, transaction, or block hash.
      if (/^0x[0-9a-fA-F]{64}$/.test(q)) {
        if (want("userOperation")) {
          const op = await ctx.indexer.getUserOperation(q).catch(() => undefined);
          if (op?.hash) return ok({ kind: "userOperation", user_operation: op, explorer: ctx.explorerOp(q) });
        }
        if (want("transaction")) {
          const tx = await ctx.indexer.getTransaction(q).catch(() => undefined);
          if (tx?.hash) return ok({ kind: "transaction", transaction: tx, explorer: ctx.explorerTx(q) });
        }
        if (want("block")) {
          const block = await ctx.indexer.getBlock(q).catch(() => undefined);
          if (block?.hash) return ok({ kind: "block", block });
        }
        return ok({ kind: "none", note: "No user operation, transaction, or block on Incentiv matches this hash." });
      }

      // All digits: a block number.
      if (/^\d+$/.test(q) && want("block")) {
        const block = await ctx.indexer.getBlock(q).catch(() => undefined);
        if (block?.hash) return ok({ kind: "block", block });
        return ok({ kind: "none", note: `No block ${q} on Incentiv.` });
      }

      // Otherwise a token symbol.
      const token = await ctx.resolveToken(q).catch(() => undefined);
      if (token) return ok({ kind: "token", token });
      return ok({ kind: "none", results: [], note: "Nothing on Incentiv matches this query (checked user operations, transactions, blocks, tokens)." });
    }),
  );

  // Build and broadcast. Build tools return an unsigned transaction and the
  // hash to sign; the caller signs it and submits it through a broadcast tool.

  const gasTokenParam = z
    .string()
    .optional()
    .describe(`Token to pay gas with (symbol or address) via the Unified Token Paymaster. Default: native ${cfg.identity.nativeSymbol}.`);

  const ownerParam = z
    .string()
    .optional()
    .describe(
      "Owner EOA of the account. Required only if the account is not deployed yet — the operation then also creates it (deploy on first use).",
    );

  const saltParam = z
    .string()
    .optional()
    .describe("CREATE2 salt used to derive the account (default 0). Must match what get_smart_account used.");

  const userOpObject = z
    .object({
      sender: z.string(),
      nonce: z.string(),
      callData: z.string(),
      callGasLimit: z.string(),
      verificationGasLimit: z.string(),
      preVerificationGas: z.string(),
      maxFeePerGas: z.string(),
      maxPriorityFeePerGas: z.string(),
      signature: z.string().optional(),
      factory: z.string().optional(),
      factoryData: z.string().optional(),
      paymaster: z.string().optional(),
      paymasterVerificationGasLimit: z.string().optional(),
      paymasterPostOpGasLimit: z.string().optional(),
      paymasterData: z.string().optional(),
    })
    .passthrough();

  const SIGNING_NOTE =
    "Sign `sign_hash` as an EIP-191 personal message (personal_sign / eth_sign of the 32-byte hash) with the OWNER key of `user_operation.sender`, put the 65-byte signature into `user_operation.signature`, then call broadcast_user_operation.";

  const buildOpResponse = async (
    account: Address,
    calls: Call[],
    gasToken: TokenInfo | undefined,
    extra: Record<string, unknown>,
    deploy?: { owner?: Address; salt?: bigint },
  ): Promise<ToolResult> => {
    const gate = await gateCheck(ctx, calls);
    let prepared;
    try {
      prepared = await buildUserOpUnsigned(ctx, { account, calls, gasToken, ...deploy });
    } catch (e) {
      return err(`Could not build the operation: ${describeEstimationError(e)}`);
    }
    const deploysAccount = !!prepared.op.factory;
    return ok({
      ...extra,
      account,
      execution: "Incentiv smart account (ERC-4337 v0.7 user operation)",
      deploys_account: deploysAccount || undefined,
      deployment_note: deploysAccount
        ? "This account is not deployed yet — signing and broadcasting this operation creates it. Its gas is included in the quote below."
        : undefined,
      transfer_gate: gate,
      gas_payment: prepared.gasToken
        ? `${formatUnits(prepared.gasToken.tokenAmount, prepared.gasToken.token.decimals)} ${prepared.gasToken.token.symbol} (via Unified Token Paymaster)`
        : `native ${cfg.identity.nativeSymbol}`,
      max_gas_cost: `${formatUnits(prepared.maxGasCostWei, 18)} ${cfg.identity.nativeSymbol}`,
      user_operation: userOpToJson(prepared.op),
      sign_hash: prepared.userOpHash,
      signing_scheme: "EIP-191 personal_sign over sign_hash by the account owner key",
      next_step: SIGNING_NOTE,
    });
  };

  server.registerTool(
    "build_transfer",
    {
      title: "Build a transfer (unsigned)",
      description:
        "Construct an UNSIGNED Incentiv user operation that transfers a token from a smart account. Returns the operation, a compliance (TransferGate) check, the gas quote, and the hash to sign. The caller signs it client-side with their own key and submits it via broadcast_user_operation. This build tool never accesses wallet keys.",
      inputSchema: {
        account: z.string().describe("The sender smart account (0x...)"),
        token: z.string().describe(`Token to send: symbol, 0x address, or ${cfg.identity.nativeSymbol} for native`),
        to: z.string().describe("Recipient address (0x...)"),
        amount: z.string().describe('Human amount to send, e.g. "10.5"'),
        gas_token: gasTokenParam,
        owner: ownerParam,
        salt: saltParam,
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: TransferArgs) => {
      const t = await buildTransferCalls(ctx, args);
      const balance = await tokenBalance(ctx, t.token, t.account);
      const warnings: string[] = [];
      if (balance < t.raw)
        warnings.push(
          `Account ${t.token.symbol} balance is ${formatUnits(balance, t.token.decimals)}, below the ${formatUnits(t.raw, t.token.decimals)} being sent — fund it before broadcasting.`,
        );
      return buildOpResponse(
        t.account,
        t.calls,
        t.gasToken,
        {
          action: "TRANSFER",
          to: t.to,
          amount: `${formatUnits(t.raw, t.token.decimals)} ${tokenLabel(t.token)}`,
          warnings: warnings.length ? warnings : undefined,
        },
        deployArgs(ctx, args),
      );
    }),
  );

  server.registerTool(
    "build_swap",
    {
      title: "Build a swap (unsigned)",
      description:
        "Construct an UNSIGNED Incentiv user operation that swaps tokens on the native DEX from a smart account. Returns the operation, quote, minimum received for the slippage, a compliance check, the gas quote, and the hash to sign. The caller signs client-side and submits via broadcast_user_operation. This build tool never accesses wallet keys.",
      inputSchema: {
        account: z.string().describe("The sender smart account (0x...)"),
        token_in: z.string().describe("Token to sell: symbol, 0x address, or CENT for native"),
        token_out: z.string().describe("Token to buy: symbol, 0x address, or CENT for native"),
        amount_in: z.string().describe('Human amount of token_in to sell, e.g. "1.5"'),
        slippage_bps: z.number().int().min(0).max(5000).optional().describe("Max slippage in basis points (default 100 = 1%)"),
        fee_tier: z.number().int().optional().describe("Pool fee tier (default 3000 = 0.3%)"),
        gas_token: gasTokenParam,
        owner: ownerParam,
        salt: saltParam,
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: SwapArgs) => {
      const s = await buildSwapPlan(ctx, args);
      const balance = await tokenBalance(ctx, s.tokenIn, s.account);
      const warnings: string[] = [];
      if (balance < s.amountIn)
        warnings.push(
          `Account ${s.tokenIn.symbol} balance is ${formatUnits(balance, s.tokenIn.decimals)}, below the ${formatUnits(s.amountIn, s.tokenIn.decimals)} being swapped — fund it before broadcasting.`,
        );
      return buildOpResponse(
        s.account,
        s.calls,
        s.gasToken,
        {
          action: "SWAP",
          sell: `${formatUnits(s.amountIn, s.tokenIn.decimals)} ${tokenLabel(s.tokenIn)}`,
          receive_estimate: `${formatUnits(s.amountOut, s.tokenOut.decimals)} ${tokenLabel(s.tokenOut)}`,
          minimum_received: `${formatUnits(s.minOut, s.tokenOut.decimals)} ${s.tokenOut.symbol} (slippage ${Number(s.slippageBps) / 100}%)`,
          route: s.route.description,
          warnings: warnings.length ? warnings : undefined,
        },
        deployArgs(ctx, args),
      );
    }),
  );

  server.registerTool(
    "broadcast_user_operation",
    {
      title: "Broadcast a signed user operation",
      description:
        "Submit a client-signed Incentiv user operation to the bundler. Pass the `user_operation` object returned by build_transfer/build_swap with its `signature` field filled in (or pass `signature` separately). Executes on-chain.",
      inputSchema: {
        user_operation: userOpObject.describe("The user_operation object from build_transfer/build_swap, with signature filled in"),
        signature: z.string().optional().describe("The signature, if not already set inside user_operation"),
        wait: z.boolean().optional().describe("Wait for the receipt (default true)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    wrap(async (args: { user_operation: Record<string, unknown>; signature?: string; wait?: boolean }) => {
      const raw = { ...args.user_operation };
      if (args.signature) raw.signature = args.signature;
      const op = userOpFromJson(raw);
      let userOpHash;
      try {
        userOpHash = await broadcastUserOp(ctx, op);
      } catch (e) {
        return err(`Bundler rejected the operation: ${describeEstimationError(e)}`);
      }
      const receipt = args.wait === false ? undefined : await waitForUserOp(ctx, userOpHash);
      return ok({
        action: "USER OPERATION BROADCAST",
        user_op_hash: userOpHash,
        status: receipt
          ? receipt.success
            ? "confirmed"
            : `failed${receipt.reason ? `: ${receipt.reason}` : ""}`
          : "submitted (confirmation pending — check the explorer)",
        transaction_hash: receipt?.transactionHash,
        explorer: ctx.explorerOp(userOpHash),
      });
    }),
  );

  server.registerTool(
    "build_transaction",
    {
      title: "Build a plain transaction (unsigned)",
      description:
        "Construct an UNSIGNED EIP-1559 transaction for a plain EOA (nonce, gas, fees, chainId all filled). Returns it for the caller to sign with their own key and submit via broadcast_transaction. Native CENT gas only; no paymaster or batching. Use build_transfer/build_swap for smart-account (paymaster/batched) operations.",
      inputSchema: {
        from: z.string().describe("Sender EOA address (0x...)"),
        to: z.string().describe("Target address (0x...)"),
        value: z.string().optional().describe(`Native ${cfg.identity.nativeSymbol} amount to send, human units (default 0)`),
        data: z.string().optional().describe("Calldata hex (default 0x)"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { from: string; to: string; value?: string; data?: string }) => {
      const from = ctx.resolveAccount(args.from);
      if (!isAddress(args.to)) throw new Error(`Not a valid address: ${args.to}`);
      const value = parseAmount(args.value ?? "0", 18, true);
      const data = (args.data ?? "0x") as Hex;
      const tx = await buildUnsignedTx(ctx, from, { to: getAddress(args.to), value, data });
      return ok({
        action: "TRANSACTION",
        unsigned_transaction: tx,
        next_step: "Sign this EIP-1559 transaction with the `from` key, then submit the raw signed tx via broadcast_transaction.",
      });
    }),
  );

  // Bridge
  server.registerTool(
    "get_bridge_routes",
    {
      title: "List Incentiv Bridge routes",
      description:
        "Which tokens the official Incentiv Bridge (Hyperlane warp routes) moves, between which chains, and the current interchain gas cost each way. Use this before build_bridge_transfer.",
      inputSchema: {
        token: z.string().optional().describe("Filter by token symbol, e.g. USDC"),
        chain: z.string().optional().describe("Filter by remote chain, e.g. base"),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { token?: string; chain?: string }) => {
      let rows = ROUTES;
      const tokenFilter = args.token?.trim().toUpperCase();
      const chainFilter = args.chain?.trim().toLowerCase();
      if (tokenFilter) rows = rows.filter((r) => r.token === tokenFilter);
      if (chainFilter) rows = rows.filter((r) => r.chain === chainFilter);

      const routes = await Promise.all(
        rows.map(async (r) => {
          const chain = REMOTE_CHAINS[r.chain];
          let intoIncentiv: string | undefined;
          let outOfIncentiv: string | undefined;
          if (!r.inboundNote) {
            try {
              const q = await remoteClient(cfg, r.chain).readContract({
                address: r.remoteRouter, abi: warpAbi, functionName: "quoteGasPayment", args: [INCENTIV_DOMAIN],
              });
              intoIncentiv = `${formatUnits(q, 18)} ${chain.nativeSymbol}`;
            } catch { intoIncentiv = "unavailable"; }
          }
          try {
            const q = await ctx.client.readContract({
              address: r.localRouter, abi: warpAbi, functionName: "quoteGasPayment", args: [chain.domain],
            });
            outOfIncentiv = `${formatUnits(q, 18)} ${cfg.identity.nativeSymbol}`;
          } catch { outOfIncentiv = "unavailable"; }

          return {
            token: r.token,
            chain: r.chain,
            chain_id: chain.chainId,
            decimals: r.decimals,
            incentiv_token: r.incentivToken,
            remote_token: r.remoteToken,
            remote_router: r.remoteRouter,
            interchain_gas_into_incentiv: intoIncentiv,
            interchain_gas_out_of_incentiv: outOfIncentiv,
            unavailable: r.inboundNote,
          };
        }),
      );
      return ok({
        bridge: "Incentiv Bridge (Hyperlane warp routes)",
        routes,
        note: NON_EVM_NOTE,
        how: "build_bridge_transfer constructs the unsigned transaction(s); you sign them and submit with broadcast_transaction (pass the same `chain`).",
      });
    }),
  );

  server.registerTool(
    "build_bridge_transfer",
    {
      title: "Build a bridge transfer (unsigned)",
      description:
        "Construct the UNSIGNED transaction(s) to move a token across the official Incentiv Bridge. Into Incentiv: returns up to two source-chain transactions (approve, then transferRemote) to sign and broadcast in order. Out of Incentiv: returns one Incentiv transaction. You sign; this build tool never accesses wallet keys.",
      inputSchema: {
        token: z.string().describe("Token symbol to bridge, e.g. USDC"),
        from_chain: z.string().describe('Source chain: "incentiv", or a remote chain such as "base", "ethereum", "arbitrum", "optimism"'),
        amount: z.string().describe('Human amount to bridge, e.g. "25"'),
        sender: z.string().describe("The address sending on the source chain (0x...)"),
        recipient: z.string().optional().describe("Destination address (0x...). Defaults to the sender address."),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { token: string; from_chain: string; amount: string; sender: string; recipient?: string }) => {
      const sender = ctx.resolveAccount(args.sender);
      const recipient = ctx.resolveAccount(args.recipient ?? args.sender);
      const from = args.from_chain.trim().toLowerCase();
      if (from === "incentiv") {
        return err(
          "This tool bridges INTO Incentiv from a remote chain. To bridge out of Incentiv, use build_bridge_transfer_out (it builds a user operation from your smart account).",
        );
      }

      const route = findRoute(cfg, args.token, from);
      const raw = parseAmount(args.amount, route.decimals);
      const chain = REMOTE_CHAINS[route.chain];

      const { steps, gasPayment, balance, allowance } = await buildInboundBridge(cfg, route, sender, recipient, raw);
      const warnings: string[] = [];
      if (balance < raw)
        warnings.push(`Sender holds ${formatUnits(balance, route.decimals)} ${route.token} on ${chain.name}, less than the ${args.amount} being bridged.`);

      return ok({
        action: "BRIDGE INTO INCENTIV",
        token: route.token,
        amount: `${formatUnits(raw, route.decimals)} ${route.token}`,
        from: `${chain.name} (chain ${chain.chainId})`,
        to: `Incentiv (chain ${cfg.identity.chainId})`,
        sender,
        recipient,
        recipient_note:
          "The recipient may be an Incentiv smart account that is not deployed yet — its address can receive funds before it exists.",
        interchain_gas: `${formatUnits(gasPayment, 18)} ${chain.nativeSymbol} (attached to the transferRemote call)`,
        current_allowance: formatUnits(allowance, route.decimals),
        unsigned_transactions: steps,
        warnings: warnings.length ? warnings : undefined,
        next_step: `Sign each transaction in order with the ${sender} key on ${chain.name}, submitting each via broadcast_transaction with chain="${route.chain}" before signing the next (the second depends on the first). Then poll get_bridge_status.`,
      });
    }),
  );

  server.registerTool(
    "build_bridge_transfer_out",
    {
      title: "Build a bridge transfer out of Incentiv (unsigned)",
      description:
        "Construct an UNSIGNED Incentiv user operation that bridges a token from an Incentiv smart account to a remote chain over the official Incentiv Bridge. Returns the operation and the hash to sign, like build_transfer.",
      inputSchema: {
        account: z.string().describe("The sending Incentiv smart account (0x...)"),
        token: z.string().describe("Token symbol to bridge, e.g. USDC"),
        to_chain: z.string().describe('Destination chain, e.g. "base", "ethereum", "arbitrum", "optimism"'),
        amount: z.string().describe('Human amount to bridge, e.g. "25"'),
        recipient: z.string().describe("Address you control on the destination chain (0x...). An Incentiv smart-account address may not be controlled there."),
        gas_token: gasTokenParam,
        owner: ownerParam,
        salt: saltParam,
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: {
      account: string; token: string; to_chain: string; amount: string;
      recipient: string; gas_token?: string; owner?: string; salt?: string;
    }) => {
      const account = ctx.resolveAccount(args.account);
      const recipient = ctx.resolveAccount(args.recipient);
      const route = findRoute(cfg, args.token, args.to_chain);
      const raw = parseAmount(args.amount, route.decimals);
      const chain = REMOTE_CHAINS[route.chain];

      const { to, value, data, gasPayment } = await buildOutboundBridge(ctx, route, recipient, raw);
      const gasToken = args.gas_token ? await ctx.resolveToken(args.gas_token) : undefined;

      const isNative = route.incentivStandard === "native";
      const nativeBal = await ctx.client.getBalance({ address: account });
      // A native route bridges the native balance itself.
      const tokenBal = isNative
        ? nativeBal
        : await ctx.client.readContract({ address: route.incentivToken, abi: erc20Abi, functionName: "balanceOf", args: [account] });
      const warnings: string[] = [];
      if (tokenBal < raw)
        warnings.push(`Account holds ${formatUnits(tokenBal, route.decimals)} ${route.token}, less than the ${args.amount} being bridged.`);
      // The interchain gas rides as msg.value, which a paymaster cannot cover.
      if (nativeBal < value) {
        return err(
          `Bridging ${route.token} out of Incentiv attaches ${formatUnits(value, 18)} ${cfg.identity.nativeSymbol} to the call` +
            (isNative
              ? ` (${formatUnits(raw, 18)} being bridged + ${formatUnits(gasPayment, 18)} Hyperlane interchain gas)`
              : ` as Hyperlane interchain gas`) +
            `, but ${account} holds ${formatUnits(nativeBal, 18)} ${cfg.identity.nativeSymbol}. ` +
            `This ${cfg.identity.nativeSymbol} is required even when gas_token pays the transaction fee — a paymaster can sponsor the fee, not the value the call carries. Fund the account with at least ${formatUnits(value, 18)} ${cfg.identity.nativeSymbol} and retry.`,
        );
      }

      return buildOpResponse(
        account,
        [{ to, value, data }],
        gasToken,
        {
          action: "BRIDGE OUT OF INCENTIV",
          token: route.token,
          amount: `${formatUnits(raw, route.decimals)} ${route.token}`,
          to_chain: `${chain.name} (chain ${chain.chainId})`,
          recipient,
          interchain_gas: `${formatUnits(gasPayment, 18)} ${cfg.identity.nativeSymbol}`,
          warnings: warnings.length ? warnings : undefined,
        },
        deployArgs(ctx, args),
      );
    }),
  );

  server.registerTool(
    "get_bridge_status",
    {
      title: "Check bridge delivery",
      description:
        "Check whether a bridged message has been delivered on the destination chain, using the Hyperlane message id emitted by the transferRemote transaction.",
      inputSchema: {
        message_id: z.string().describe("The Hyperlane message id (0x..., 32 bytes) returned by transferRemote"),
        destination: z.string().describe('Destination chain: "incentiv", or a remote chain such as "base"'),
      },
      annotations: { readOnlyHint: true },
    },
    wrap(async (args: { message_id: string; destination: string }) => {
      const dest = args.destination.trim().toLowerCase();
      const r = await checkDelivered(args.message_id as Hex, dest, ctx);
      return ok({
        message_id: args.message_id,
        destination: r.chain,
        delivered: r.delivered,
        mailbox: r.mailbox,
        status: r.delivered
          ? "Delivered — the funds have arrived on the destination chain."
          : "Not delivered yet. Hyperlane relayers usually take a few minutes; re-check shortly.",
      });
    }),
  );

  server.registerTool(
    "broadcast_transaction",
    {
      title: "Broadcast a signed transaction",
      description: "Submit a client-signed raw transaction (0x...) to Incentiv via eth_sendRawTransaction. Executes on-chain.",
      inputSchema: {
        signed_transaction: z.string().describe("The raw signed transaction hex (0x...)"),
        chain: z.string().optional().describe('Chain to broadcast on: "incentiv" (default), or a bridge source chain such as "base"'),
        wait: z.boolean().optional().describe("Wait for the receipt (default true)"),
      },
      annotations: { readOnlyHint: false, destructiveHint: true },
    },
    wrap(async (args: { signed_transaction: string; chain?: string; wait?: boolean }) => {
      const chainName = (args.chain ?? "incentiv").trim().toLowerCase();
      const remote = chainName === "incentiv" ? undefined : REMOTE_CHAINS[chainName];
      if (chainName !== "incentiv" && !remote) {
        return err(`Unknown chain "${args.chain}". Use "incentiv" or one of: ${Object.keys(REMOTE_CHAINS).join(", ")}.`);
      }
      const client = remote ? remoteClient(cfg, chainName) : ctx.client;

      let hash: Hex;
      try {
        hash = remote
          ? ((await client.request({ method: "eth_sendRawTransaction", params: [args.signed_transaction as Hex] })) as Hex)
          : await broadcastRawTx(ctx, args.signed_transaction as Hex);
      } catch (e) {
        return err(`Broadcast rejected: ${describeEstimationError(e)}`);
      }
      const receipt =
        args.wait === false ? undefined : await client.waitForTransactionReceipt({ hash, timeout: 120_000 }).catch(() => undefined);
      return ok({
        action: "TRANSACTION BROADCAST",
        chain: remote ? remote.name : cfg.identity.name,
        transaction_hash: hash,
        status: receipt ? (receipt.status === "success" ? "confirmed" : "reverted") : "submitted (confirmation pending — check the explorer)",
        block_number: receipt ? Number(receipt.blockNumber) : undefined,
        explorer: remote ? remote.explorerTx(hash) : ctx.explorerTx(hash),
        next_step: remote
          ? "If this was a transferRemote, take the Hyperlane message id from the logs and poll get_bridge_status with destination=\"incentiv\"."
          : undefined,
      });
    }),
  );

  return catalog;
}
