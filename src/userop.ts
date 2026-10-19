import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  numberToHex,
  pad,
  toHex,
  type Address,
  type Hex,
} from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import type { Ctx, TokenInfo } from "./context.js";
import { NATIVE, ZERO32 } from "./context.js";
import {
  accountAbi,
  accountFactoryAbi,
  entryPointAbi,
  erc20Abi,
  paymasterAbi,
  quoterAbi,
} from "./abi.js";

export interface Call {
  to: Address;
  value: bigint;
  data: Hex;
}

/** ERC-4337 v0.7 user operation, unpacked bundler wire format. */
export interface UserOp {
  sender: Address;
  nonce: bigint;
  factory?: Address;
  factoryData?: Hex;
  callData: Hex;
  callGasLimit: bigint;
  verificationGasLimit: bigint;
  preVerificationGas: bigint;
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  paymaster?: Address;
  paymasterVerificationGasLimit?: bigint;
  paymasterPostOpGasLimit?: bigint;
  paymasterData?: Hex;
  signature: Hex;
}

export interface GasTokenPlan {
  token: TokenInfo;
  /** Amount transferred to the paymaster as the gas payment. */
  tokenAmount: bigint;
  /** WCENT the payment must quote to. */
  requiredCent: bigint;
}

export interface PreparedOp {
  op: UserOp;
  userOpHash: Hex;
  gasToken?: GasTokenPlan;
  /** Maximum gas cost in wei. */
  maxGasCostWei: bigint;
}

const DEFAULT_POOL_FEE = 3000;

export function encodeExecuteBatch(calls: Call[]): Hex {
  return encodeFunctionData({
    abi: accountAbi,
    functionName: "executeBatch",
    args: [calls.map((c) => c.to), calls.map((c) => c.value), calls.map((c) => c.data)],
  });
}

function packUint128Pair(high: bigint, low: bigint): Hex {
  return concatHex([pad(numberToHex(high), { size: 16 }), pad(numberToHex(low), { size: 16 })]);
}

function packInitCode(op: UserOp): Hex {
  return op.factory ? concatHex([op.factory, op.factoryData ?? "0x"]) : "0x";
}

function packPaymasterAndData(op: UserOp): Hex {
  if (!op.paymaster) return "0x";
  return concatHex([
    op.paymaster,
    pad(numberToHex(op.paymasterVerificationGasLimit ?? 0n), { size: 16 }),
    pad(numberToHex(op.paymasterPostOpGasLimit ?? 0n), { size: 16 }),
    op.paymasterData ?? "0x",
  ]);
}

/** EntryPoint v0.7 getUserOpHash. */
export function computeUserOpHash(op: UserOp, entryPoint: Address, chainId: number): Hex {
  const packedHash = keccak256(
    encodeAbiParameters(
      [
        { type: "address" }, // sender
        { type: "uint256" }, // nonce
        { type: "bytes32" }, // keccak(initCode)
        { type: "bytes32" }, // keccak(callData)
        { type: "bytes32" }, // accountGasLimits
        { type: "uint256" }, // preVerificationGas
        { type: "bytes32" }, // gasFees
        { type: "bytes32" }, // keccak(paymasterAndData)
      ],
      [
        op.sender,
        op.nonce,
        keccak256(packInitCode(op)),
        keccak256(op.callData),
        packUint128Pair(op.verificationGasLimit, op.callGasLimit),
        op.preVerificationGas,
        packUint128Pair(op.maxPriorityFeePerGas, op.maxFeePerGas),
        keccak256(packPaymasterAndData(op)),
      ],
    ),
  );
  return keccak256(
    encodeAbiParameters(
      [{ type: "bytes32" }, { type: "address" }, { type: "uint256" }],
      [packedHash, entryPoint, BigInt(chainId)],
    ),
  );
}

function opToWire(op: UserOp): Record<string, string> {
  const wire: Record<string, string> = {
    sender: op.sender,
    nonce: toHex(op.nonce),
    callData: op.callData,
    callGasLimit: toHex(op.callGasLimit),
    verificationGasLimit: toHex(op.verificationGasLimit),
    preVerificationGas: toHex(op.preVerificationGas),
    maxFeePerGas: toHex(op.maxFeePerGas),
    maxPriorityFeePerGas: toHex(op.maxPriorityFeePerGas),
    signature: op.signature,
  };
  if (op.factory) {
    wire.factory = op.factory;
    wire.factoryData = op.factoryData ?? "0x";
  }
  if (op.paymaster) {
    wire.paymaster = op.paymaster;
    wire.paymasterVerificationGasLimit = toHex(op.paymasterVerificationGasLimit ?? 0n);
    wire.paymasterPostOpGasLimit = toHex(op.paymasterPostOpGasLimit ?? 0n);
    wire.paymasterData = op.paymasterData ?? "0x";
  }
  return wire;
}

export async function bundlerRpc(ctx: Ctx, method: string, params: unknown[]): Promise<unknown> {
  const res = await fetch(ctx.config.endpoints.bundlerUrl, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }),
    signal: AbortSignal.timeout(30_000),
  });
  if (!res.ok) throw new Error(`Bundler HTTP ${res.status}`);
  const body = (await res.json()) as { result?: unknown; error?: { code: number; message: string; data?: unknown } };
  if (body.error) {
    const data = body.error.data ? ` ${JSON.stringify(body.error.data)}` : "";
    throw new Error(`Bundler error ${body.error.code}: ${body.error.message}${data}`);
  }
  return body.result;
}

function asBigInt(v: unknown): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") return BigInt(v);
  if (typeof v === "string") return BigInt(v);
  throw new Error(`Cannot parse gas value: ${String(v)}`);
}

export interface FeeData {
  maxFeePerGas: bigint;
  maxPriorityFeePerGas: bigint;
  baseFeePerGas: bigint;
}

export async function getFees(ctx: Ctx): Promise<FeeData> {
  const block = await ctx.client.getBlock();
  const base = block.baseFeePerGas ?? 12_600_000_000_000n;
  const tip = 1_000_000_000n; // 1 gwei
  return { maxFeePerGas: base * 2n + tip, maxPriorityFeePerGas: tip, baseFeePerGas: base };
}

export interface PaymasterConfig {
  gasEstimateCoefficient: bigint;
  usdcToken: Address;
  usdcPoolFee: number;
  minPaymentUsdc: bigint;
  minTransactionGas: bigint;
  maxVerificationGas: bigint;
}

const pmConfigCache = new WeakMap<Ctx["config"], { at: number; cfg: PaymasterConfig }>();

export async function getPaymasterConfig(ctx: Ctx): Promise<PaymasterConfig> {
  const cached = pmConfigCache.get(ctx.config);
  if (cached && Date.now() - cached.at < 300_000) return cached.cfg;
  const pm = ctx.config.manifest.contracts.unifiedTokenPaymaster.address;
  const read = <T,>(functionName: string) =>
    ctx.client.readContract({ address: pm, abi: paymasterAbi, functionName: functionName as never }) as Promise<T>;
  const [coeff, usdcToken, usdcPoolFee, minPaymentUsdc, minTransactionGas, maxVerificationGas] = await Promise.all([
    read<bigint>("gasEstimateCoefficient"),
    read<Address>("usdcToken"),
    read<number>("usdcPoolFee"),
    read<bigint>("minPaymentUsdc"),
    read<bigint>("minTransactionGas"),
    read<bigint>("maxVerificationGas"),
  ]);
  const cfg = {
    gasEstimateCoefficient: coeff,
    usdcToken,
    usdcPoolFee: Number(usdcPoolFee),
    minPaymentUsdc,
    minTransactionGas,
    maxVerificationGas,
  };
  pmConfigCache.set(ctx.config, { at: Date.now(), cfg });
  return cfg;
}

/** WCENT the paymaster requires for the given limits. */
export function requiredCentFor(
  cfg: PaymasterConfig,
  limits: { callGasLimit: bigint; verificationGasLimit: bigint; preVerificationGas: bigint },
  maxFeePerGas: bigint,
): bigint {
  let ver = limits.verificationGasLimit;
  if (cfg.maxVerificationGas !== 0n && ver > cfg.maxVerificationGas) ver = cfg.maxVerificationGas;
  let totalGas = limits.callGasLimit + ver + limits.preVerificationGas;
  if (totalGas < cfg.minTransactionGas) totalGas = cfg.minTransactionGas;
  return (totalGas * maxFeePerGas * cfg.gasEstimateCoefficient) / 10_000n;
}

async function quoteExactOutputToWcent(ctx: Ctx, tokenIn: Address, fee: number, wcentOut: bigint): Promise<bigint> {
  const [amountIn] = await ctx.client.readContract({
    address: ctx.config.manifest.contracts.quoter.address,
    abi: quoterAbi,
    functionName: "quoteExactOutputSingle",
    args: [{ tokenIn, tokenOut: ctx.config.manifest.contracts.wcent.address, amount: wcentOut, fee, sqrtPriceLimitX96: 0n }],
  });
  return amountIn;
}

async function quoteExactInputToWcent(ctx: Ctx, tokenIn: Address, fee: number, amountIn: bigint): Promise<bigint> {
  const [amountOut] = await ctx.client.readContract({
    address: ctx.config.manifest.contracts.quoter.address,
    abi: quoterAbi,
    functionName: "quoteExactInputSingle",
    args: [{ tokenIn, tokenOut: ctx.config.manifest.contracts.wcent.address, amountIn, fee, sqrtPriceLimitX96: 0n }],
  });
  return amountOut;
}

/** Token amount whose WCENT quote satisfies the paymaster's gas and minimum checks. */
export async function computeGasTokenAmount(
  ctx: Ctx,
  cfg: PaymasterConfig,
  token: TokenInfo,
  requiredCent: bigint,
): Promise<bigint> {
  if (token.address === NATIVE) throw new Error("native CENT does not go through the paymaster");
  const isUsdc = token.address.toLowerCase() === cfg.usdcToken.toLowerCase();
  const poolFee = isUsdc && cfg.usdcPoolFee !== 0 ? cfg.usdcPoolFee : DEFAULT_POOL_FEE;

  let target = requiredCent;
  if (!isUsdc && cfg.minPaymentUsdc !== 0n && cfg.usdcToken !== "0x0000000000000000000000000000000000000000" && cfg.usdcPoolFee !== 0) {
    const minCent = await quoteExactInputToWcent(ctx, cfg.usdcToken, cfg.usdcPoolFee, cfg.minPaymentUsdc);
    if (minCent > target) target = minCent;
  }

  let amount: bigint;
  if (target === 0n) {
    amount = 0n;
  } else {
    amount = await quoteExactOutputToWcent(ctx, token.address, poolFee, target);
    // Margin for pool movement, then confirm against the paymaster's own check.
    amount = (amount * 102n) / 100n;
    for (let i = 0; i < 5; i++) {
      const out = await quoteExactInputToWcent(ctx, token.address, poolFee, amount);
      if (out >= target) break;
      amount = (amount * 105n) / 100n;
    }
  }
  if (isUsdc && amount < cfg.minPaymentUsdc) amount = cfg.minPaymentUsdc;
  return amount;
}

export interface BuildOptions {
  /** Locally cross-checked state, supplied only by the wallet pipeline. */
  state?: { deployed: boolean; nonce: bigint; fees: FeeData };
  /** Sender smart account. */
  account: Address;
  calls: Call[];
  /** Pay gas in this token via the Unified Token Paymaster. */
  gasToken?: TokenInfo;
  /** Owner EOA. Required only when the account is not yet deployed. */
  owner?: Address;
  /** CREATE2 salt used to derive the account (default 0). */
  salt?: bigint;
}

/**
 * Build and estimate an unsigned user operation. Returns the populated
 * operation with an empty signature and the hash the caller must sign.
 */
export async function buildUserOpUnsigned(ctx: Ctx, opts: BuildOptions): Promise<PreparedOp> {
  const sender = opts.account;

  // Accounts are deployed by their first operation. Carry initCode when the
  // address has no code yet.
  const deployed = opts.state?.deployed ?? await ctx.isDeployed(sender);
  let init: { factory?: Address; factoryData?: Hex } = {};
  if (!deployed) {
    if (!opts.owner) {
      throw new Error(
        `Smart account ${sender} is not deployed yet. Pass \`owner\` (the EOA that controls it) so this first operation can deploy it, or use get_smart_account to derive the address from an owner.`,
      );
    }
    const derived = await ctx.deriveSmartAccount(opts.owner, opts.salt ?? 0n);
    if (derived.toLowerCase() !== sender.toLowerCase()) {
      throw new Error(
        `Owner ${opts.owner} controls ${derived}, not ${sender}. Pass the matching account/owner pair (salt ${opts.salt ?? 0n}).`,
      );
    }
    init = {
      factory: ctx.config.identity.accountFactory.address,
      factoryData: encodeFunctionData({
        abi: accountFactoryAbi,
        functionName: "createAccount",
        args: [opts.owner, [ZERO32, ZERO32], opts.salt ?? 0n],
      }),
    };
  }

  const [nonce, fees] = opts.state ? [opts.state.nonce, opts.state.fees] : await Promise.all([
    ctx.client.readContract({
      address: ctx.config.identity.entryPoint.address,
      abi: entryPointAbi,
      functionName: "getNonce",
      args: [sender, 0n],
    }),
    getFees(ctx),
  ]);

  const useGasToken = opts.gasToken && opts.gasToken.address !== NATIVE;
  const pmCfg = useGasToken ? await getPaymasterConfig(ctx) : undefined;

  const makeCallData = (gasPayment?: { token: Address; amount: bigint }): Hex => {
    const calls = gasPayment
      ? [
          {
            to: gasPayment.token,
            value: 0n,
            data: encodeFunctionData({
              abi: erc20Abi,
              functionName: "transfer",
              args: [ctx.config.manifest.contracts.unifiedTokenPaymaster.address, gasPayment.amount],
            }),
          },
          ...opts.calls,
        ]
      : opts.calls;
    return encodeExecuteBatch(calls);
  };

  // The paymaster quotes the payment during simulation, so seed a realistic
  // amount rather than a placeholder.
  let seedAmount: bigint | undefined;
  if (useGasToken && pmCfg) {
    const seedCent = requiredCentFor(
      pmCfg,
      { callGasLimit: 600_000n, verificationGasLimit: 100_000n, preVerificationGas: 100_000n },
      fees.maxFeePerGas,
    );
    seedAmount = await computeGasTokenAmount(ctx, pmCfg, opts.gasToken!, seedCent);
  }

  const op: UserOp = {
    sender,
    nonce,
    ...init,
    callData: makeCallData(
      useGasToken ? { token: opts.gasToken!.address as Address, amount: seedAmount! } : undefined,
    ),
    callGasLimit: 0n,
    verificationGasLimit: 0n,
    preVerificationGas: 0n,
    maxFeePerGas: fees.maxFeePerGas,
    maxPriorityFeePerGas: fees.maxPriorityFeePerGas,
    signature: "0x",
  };
  if (useGasToken) {
    op.paymaster = ctx.config.manifest.contracts.unifiedTokenPaymaster.address;
    op.paymasterVerificationGasLimit = 500_000n;
    op.paymasterPostOpGasLimit = 50_000n;
    op.paymasterData = "0x";
  }

  // Estimation needs a well-formed signature or the account's ECDSA check
  // reverts. This throwaway key never appears in the returned operation.
  const ephemeral = privateKeyToAccount(generatePrivateKey());
  let gasToken: GasTokenPlan | undefined;

  const iterations = useGasToken ? 2 : 1;
  for (let i = 0; i < iterations; i++) {
    // Estimate without the paymaster. A zero verificationGasLimit makes the
    // bundler simulate above the paymaster's cap, which reverts.
    const estOp: UserOp = {
      sender: op.sender,
      nonce: op.nonce,
      factory: op.factory,
      factoryData: op.factoryData,
      callData: op.callData,
      callGasLimit: 0n,
      verificationGasLimit: 0n,
      preVerificationGas: 0n,
      maxFeePerGas: op.maxFeePerGas,
      maxPriorityFeePerGas: op.maxPriorityFeePerGas,
      signature: "0x",
    };
    estOp.signature = await ephemeral.signMessage({
      message: { raw: computeUserOpHash(estOp, ctx.config.identity.entryPoint.address, ctx.config.identity.chainId) },
    });
    const est = (await bundlerRpc(ctx, "eth_estimateUserOperationGas", [
      opToWire(estOp),
      ctx.config.identity.entryPoint.address,
    ])) as Record<string, unknown>;
    op.callGasLimit = (asBigInt(est.callGasLimit) * 120n) / 100n;
    op.verificationGasLimit = (asBigInt(est.verificationGasLimit ?? est.verificationGas) * 110n) / 100n;
    op.preVerificationGas = (asBigInt(est.preVerificationGas) * 105n) / 100n;
    if (op.paymaster) {
      // Under the paymaster cap, and excluded from the token charge.
      op.paymasterVerificationGasLimit = 300_000n;
      if (pmCfg && op.verificationGasLimit > pmCfg.maxVerificationGas && pmCfg.maxVerificationGas !== 0n) {
        throw new Error(
          `This operation needs ${op.verificationGasLimit} verification gas, above the paymaster's cap of ${pmCfg.maxVerificationGas}. Pay gas in ${ctx.config.identity.nativeSymbol} instead (omit gas_token).`,
        );
      }
    }
    if (useGasToken && pmCfg) {
      const requiredCent = requiredCentFor(pmCfg, op, op.maxFeePerGas);
      const tokenAmount = await computeGasTokenAmount(ctx, pmCfg, opts.gasToken!, requiredCent);
      gasToken = { token: opts.gasToken!, tokenAmount, requiredCent };
      op.callData = makeCallData({ token: opts.gasToken!.address as Address, amount: tokenAmount });
    }
  }

  // Hash over the finished operation with an empty signature.
  op.signature = "0x";
  const userOpHash = computeUserOpHash(op, ctx.config.identity.entryPoint.address, ctx.config.identity.chainId);

  const maxGasCostWei =
    (op.callGasLimit + op.verificationGasLimit + op.preVerificationGas +
      (op.paymasterVerificationGasLimit ?? 0n) + (op.paymasterPostOpGasLimit ?? 0n)) *
    op.maxFeePerGas;

  return { op, userOpHash, gasToken, maxGasCostWei };
}

/** Serialize to hex strings for the tool boundary. */
export function userOpToJson(op: UserOp): Record<string, string> {
  return opToWire(op);
}

/** Parse a client-provided user operation. */
export function userOpFromJson(j: Record<string, unknown>): UserOp {
  const s = (k: string) => (j[k] === undefined || j[k] === null ? undefined : String(j[k]));
  const req = (k: string) => {
    const v = s(k);
    if (v === undefined) throw new Error(`user_operation is missing required field "${k}"`);
    return v;
  };
  const op: UserOp = {
    sender: req("sender") as Address,
    nonce: BigInt(req("nonce")),
    callData: req("callData") as Hex,
    callGasLimit: BigInt(req("callGasLimit")),
    verificationGasLimit: BigInt(req("verificationGasLimit")),
    preVerificationGas: BigInt(req("preVerificationGas")),
    maxFeePerGas: BigInt(req("maxFeePerGas")),
    maxPriorityFeePerGas: BigInt(req("maxPriorityFeePerGas")),
    signature: req("signature") as Hex,
  };
  if (s("factory")) {
    op.factory = s("factory") as Address;
    op.factoryData = (s("factoryData") ?? "0x") as Hex;
  }
  if (s("paymaster")) {
    op.paymaster = s("paymaster") as Address;
    op.paymasterVerificationGasLimit = BigInt(s("paymasterVerificationGasLimit") ?? "0");
    op.paymasterPostOpGasLimit = BigInt(s("paymasterPostOpGasLimit") ?? "0");
    op.paymasterData = (s("paymasterData") ?? "0x") as Hex;
  }
  return op;
}

/** Submit a signed user operation to the bundler. */
export async function broadcastUserOp(ctx: Ctx, op: UserOp): Promise<Hex> {
  if (!op.signature || op.signature === "0x") {
    throw new Error("user_operation has no signature — sign the userOpHash client-side first.");
  }
  const result = await bundlerRpc(ctx, "eth_sendUserOperation", [opToWire(op), ctx.config.identity.entryPoint.address]);
  return result as Hex;
}

export interface OpReceipt {
  userOpHash: Hex;
  success?: boolean;
  transactionHash?: Hex;
  blockNumber?: string;
  actualGasCost?: string;
  reason?: string;
  raw?: unknown;
}

/** Poll for the operation receipt until it lands or times out. */
export async function waitForUserOp(ctx: Ctx, userOpHash: Hex, timeoutMs = 90_000): Promise<OpReceipt | undefined> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const r = (await bundlerRpc(ctx, "eth_getUserOperationReceipt", [userOpHash])) as Record<string, unknown> | null;
      if (r) {
        const receipt = (r.receipt ?? {}) as Record<string, unknown>;
        return {
          userOpHash,
          success: r.success === true || r.success === "0x1" || r.success === "true",
          transactionHash: (receipt.transactionHash ?? r.transactionHash) as Hex | undefined,
          blockNumber: String(receipt.blockNumber ?? r.blockNumber ?? ""),
          actualGasCost: r.actualGasCost !== undefined ? String(asBigInt(r.actualGasCost)) : undefined,
          reason: typeof r.reason === "string" ? r.reason : undefined,
        };
      }
    } catch {
      // Bundler may not support receipt lookups; the explorer covers it.
    }
    try {
      const uo = (await ctx.indexer.getUserOperation(userOpHash)) as Record<string, unknown> | null;
      if (uo && (uo.hash || uo.blockNumber)) {
        return {
          userOpHash,
          success: uo.success === true || uo.status === "success",
          transactionHash: uo.transactionHash as Hex | undefined,
          blockNumber: uo.blockNumber !== undefined ? String(uo.blockNumber) : undefined,
          actualGasCost: uo.fee !== undefined ? String(uo.fee) : undefined,
          reason: typeof uo.revertReason === "string" && uo.revertReason ? uo.revertReason : undefined,
          raw: uo,
        };
      }
    } catch {
      /* not indexed yet */
    }
    await new Promise((r) => setTimeout(r, 3000));
  }
  return undefined;
}
