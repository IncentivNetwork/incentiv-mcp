import { toHex, type Address, type Hex } from "viem";
import type { Ctx } from "./context.js";
import type { Call } from "./userop.js";

/**
 * Unsigned transaction building and raw broadcast for plain EOAs.
 * Gas is native CENT only; the paymaster applies to user operations.
 */

export interface UnsignedTx {
  from: Address;
  to?: Address;
  value: string; // hex wei
  data: Hex;
  nonce: string; // hex
  gas: string; // hex
  maxFeePerGas: string; // hex
  maxPriorityFeePerGas: string; // hex
  chainId: number;
  type: "0x2"; // EIP-1559
}

/** Build an unsigned EIP-1559 transaction. */
export async function buildUnsignedTx(ctx: Ctx, from: Address, call: Call): Promise<UnsignedTx> {
  const block = await ctx.client.getBlock();
  const base = block.baseFeePerGas ?? 12_600_000_000_000n;
  const tip = 1_000_000_000n;
  const maxFeePerGas = base * 2n + tip;

  const [nonce, gas] = await Promise.all([
    ctx.client.getTransactionCount({ address: from }),
    ctx.client.estimateGas({ account: from, to: call.to, value: call.value, data: call.data }),
  ]);

  return {
    from,
    to: call.to,
    value: toHex(call.value),
    data: call.data,
    nonce: toHex(nonce),
    gas: toHex((gas * 120n) / 100n),
    maxFeePerGas: toHex(maxFeePerGas),
    maxPriorityFeePerGas: toHex(tip),
    chainId: ctx.config.identity.chainId,
    type: "0x2",
  };
}

/** Submit a signed raw transaction. */
export async function broadcastRawTx(ctx: Ctx, rawSigned: Hex): Promise<Hex> {
  return ctx.client.request({
    method: "eth_sendRawTransaction",
    params: [rawSigned],
  }) as Promise<Hex>;
}
