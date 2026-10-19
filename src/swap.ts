import { concatHex, encodeFunctionData, numberToHex, pad, type Address, type Hex } from "viem";
import type { Ctx, TokenInfo } from "./context.js";
import { NATIVE } from "./context.js";
import { erc20Abi, quoterAbi, swapRouterAbi, wcentAbi } from "./abi.js";
import type { Call } from "./userop.js";

export const DEFAULT_FEE_TIER = 3000;

/** ERC-20 leg of a swap side; native CENT trades as WCENT. */
function legToken(ctx: Ctx, t: TokenInfo): Address {
  return t.address === NATIVE ? ctx.config.manifest.contracts.wcent.address : t.address;
}

export interface SwapRoute {
  kind: "wrap" | "unwrap" | "single" | "multihop";
  /** Route description for display. */
  description: string;
  hops: { tokenIn: Address; tokenOut: Address; fee: number }[];
}

export function planRoute(ctx: Ctx, tokenIn: TokenInfo, tokenOut: TokenInfo, feeTier = DEFAULT_FEE_TIER): SwapRoute {
  const wcent = ctx.config.manifest.contracts.wcent.address.toLowerCase();
  const inLeg = legToken(ctx, tokenIn);
  const outLeg = legToken(ctx, tokenOut);

  if (inLeg.toLowerCase() === outLeg.toLowerCase()) {
    if (tokenIn.address === NATIVE && tokenOut.address !== NATIVE) {
      return { kind: "wrap", description: `wrap ${ctx.config.identity.nativeSymbol} -> WCENT`, hops: [] };
    }
    if (tokenOut.address === NATIVE && tokenIn.address !== NATIVE) {
      return { kind: "unwrap", description: `unwrap WCENT -> ${ctx.config.identity.nativeSymbol}`, hops: [] };
    }
    throw new Error("token_in and token_out are the same token");
  }

  const pct = (feeTier / 10_000).toFixed(2).replace(/0$/, "");
  if (inLeg.toLowerCase() === wcent || outLeg.toLowerCase() === wcent) {
    return {
      kind: "single",
      description: `${tokenIn.symbol} -${pct}%-> ${tokenOut.symbol}`,
      hops: [{ tokenIn: inLeg, tokenOut: outLeg, fee: feeTier }],
    };
  }
  // All pools pair against WCENT.
  return {
    kind: "multihop",
    description: `${tokenIn.symbol} -${pct}%-> WCENT -${pct}%-> ${tokenOut.symbol}`,
    hops: [
      { tokenIn: inLeg, tokenOut: ctx.config.manifest.contracts.wcent.address, fee: feeTier },
      { tokenIn: ctx.config.manifest.contracts.wcent.address, tokenOut: outLeg, fee: feeTier },
    ],
  };
}

/** Uniswap V3 path encoding: token(20) | fee(3) | token(20) [| fee(3) | token(20)]. */
function encodePath(hops: SwapRoute["hops"]): Hex {
  let path: Hex = hops[0].tokenIn;
  for (const hop of hops) {
    path = concatHex([path, pad(numberToHex(hop.fee), { size: 3 }), hop.tokenOut]);
  }
  return path;
}

export async function quoteRoute(ctx: Ctx, route: SwapRoute, amountIn: bigint, blockNumber?: bigint): Promise<{ amountOut: bigint; gasEstimate: bigint }> {
  if (route.kind === "wrap" || route.kind === "unwrap") {
    return { amountOut: amountIn, gasEstimate: 60_000n };
  }
  if (route.hops.length === 1) {
    const [amountOut, , , gasEstimate] = await ctx.client.readContract({
      address: ctx.config.manifest.contracts.quoter.address,
      abi: quoterAbi,
      functionName: "quoteExactInputSingle",
      blockNumber,
      args: [
        {
          tokenIn: route.hops[0].tokenIn,
          tokenOut: route.hops[0].tokenOut,
          amountIn,
          fee: route.hops[0].fee,
          sqrtPriceLimitX96: 0n,
        },
      ],
    });
    return { amountOut, gasEstimate };
  }
  const [amountOut, , , gasEstimate] = await ctx.client.readContract({
    address: ctx.config.manifest.contracts.quoter.address,
    abi: quoterAbi,
    functionName: "quoteExactInput",
    blockNumber,
    args: [encodePath(route.hops), amountIn],
  });
  return { amountOut, gasEstimate };
}

/**
 * Build the calls for a swap. Native input is attached as value. For native
 * output, an atomic batch lets the router hold WCENT and unwrap at the end;
 * a non-atomic sequence sends WCENT to the account for the caller to unwrap.
 */
export function buildSwapCalls(
  ctx: Ctx,
  tokenIn: TokenInfo,
  tokenOut: TokenInfo,
  route: SwapRoute,
  amountIn: bigint,
  amountOutMinimum: bigint,
  account: Address,
  atomic = true,
  deadline = BigInt(Math.floor(Date.now() / 1000) + 900),
): Call[] {
  const router = ctx.config.manifest.contracts.swapRouter.address;

  if (route.kind === "wrap") {
    return [{ to: ctx.config.manifest.contracts.wcent.address, value: amountIn, data: encodeFunctionData({ abi: wcentAbi, functionName: "deposit" }) }];
  }
  if (route.kind === "unwrap") {
    return [{ to: ctx.config.manifest.contracts.wcent.address, value: 0n, data: encodeFunctionData({ abi: wcentAbi, functionName: "withdraw", args: [amountIn] }) }];
  }

  const nativeIn = tokenIn.address === NATIVE;
  const nativeOut = tokenOut.address === NATIVE;
  const recipient = nativeOut && atomic ? router : account;
  const calls: Call[] = [];

  if (!nativeIn) {
    calls.push({
      to: tokenIn.address as Address,
      value: 0n,
      data: encodeFunctionData({ abi: erc20Abi, functionName: "approve", args: [router, amountIn] }),
    });
  }

  if (route.hops.length === 1) {
    calls.push({
      to: router,
      value: nativeIn ? amountIn : 0n,
      data: encodeFunctionData({
        abi: swapRouterAbi,
        functionName: "exactInputSingle",
        args: [
          {
            tokenIn: route.hops[0].tokenIn,
            tokenOut: route.hops[0].tokenOut,
            fee: route.hops[0].fee,
            recipient,
            deadline,
            amountIn,
            amountOutMinimum,
            sqrtPriceLimitX96: 0n,
          },
        ],
      }),
    });
  } else {
    calls.push({
      to: router,
      value: nativeIn ? amountIn : 0n,
      data: encodeFunctionData({
        abi: swapRouterAbi,
        functionName: "exactInput",
        args: [{ path: encodePath(route.hops), recipient, deadline, amountIn, amountOutMinimum }],
      }),
    });
  }

  if (nativeOut && atomic) {
    calls.push({
      to: router,
      value: 0n,
      data: encodeFunctionData({ abi: swapRouterAbi, functionName: "unwrapWETH9", args: [amountOutMinimum, account] }),
    });
  }

  return calls;
}
