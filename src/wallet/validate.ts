import { decodeFunctionData, encodeFunctionData, type Address, type Hex } from "viem";
import { z } from "zod";
import type { Config } from "../config.js";
import { accountAbi, accountFactoryAbi, erc20Abi, swapRouterAbi, wcentAbi } from "../abi.js";
import { ZERO32 } from "../context.js";
import { computeUserOpHash, userOpFromJson, type Call } from "../userop.js";
import { WalletError, type WalletEnvelope } from "./keystore.js";
import type { Intent } from "./journal.js";
import { address, addSpend, type Spend } from "./policy.js";
import { SWAP_DEADLINE_SECONDS } from "./chain.js";

const bytes = z.string().regex(/^0x(?:[0-9a-fA-F]{2})*$/);
const quantity = z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/).refine(s => BigInt(s) < 2n ** 128n);
const operationSchema = z.strictObject({
  sender: address, nonce: z.string().regex(/^0x(?:0|[1-9a-f][0-9a-f]*)$/).refine(s => BigInt(s) < 2n ** 256n),
  factory: address.optional(), factoryData: bytes.optional(), callData: bytes,
  callGasLimit: quantity, verificationGasLimit: quantity, preVerificationGas: quantity,
  maxFeePerGas: quantity, maxPriorityFeePerGas: quantity,
  paymaster: address.optional(), paymasterVerificationGasLimit: quantity.optional(), paymasterPostOpGasLimit: quantity.optional(), paymasterData: bytes.optional(), signature: bytes,
});
function requireValue(condition: unknown): asserts condition {
  if (!condition) throw new WalletError("validation_failed", "Operation does not match the locally authorized intent");
}
const equal = (a: string | undefined, b: string | undefined) => a?.toLowerCase() === b?.toLowerCase();
function decode(abi: any, data: Hex): any {
  const parsed = decodeFunctionData({ abi, data });
  // Reject noncanonical encodings, trailing bytes and arguments hidden from the decoder.
  requireValue(equal(encodeFunctionData({ abi, functionName: parsed.functionName!, args: parsed.args }), data));
  return parsed;
}
export function validateOperation(cfg: Config, wallet: WalletEnvelope, intent: Intent, wire: Record<string, string>, expected: { nonce: bigint; deployed: boolean; hash: string; deadline?: number }) {
  try {
    const parsed = operationSchema.parse(wire), op = userOpFromJson(parsed);
    requireValue(equal(op.sender, wallet.account) && op.nonce === expected.nonce && op.signature === "0x");
    requireValue(op.callGasLimit > 0n && op.verificationGasLimit > 0n && op.preVerificationGas > 0n && op.maxFeePerGas >= op.maxPriorityFeePerGas && op.maxFeePerGas > 0n);
    if (expected.deployed) requireValue(!op.factory && parsed.factoryData === undefined);
    else {
      requireValue(equal(op.factory, cfg.identity.accountFactory.address) && !!op.factoryData);
      const deployment = decode(accountFactoryAbi, op.factoryData!);
      requireValue(deployment.functionName === "createAccount" && equal(deployment.args[0], wallet.owner) && deployment.args[1].every((k: string) => k === ZERO32) && deployment.args[2] === 0n);
    }
    const batch = decode(accountAbi, op.callData);
    requireValue(batch.functionName === "executeBatch");
    const [targets, values, payloads] = batch.args as [Address[], bigint[], Hex[]];
    requireValue(targets.length > 0 && targets.length === values.length && targets.length === payloads.length);
    const calls: Call[] = targets.map((to, i) => ({ to, value: values[i], data: payloads[i] }));
    const business = [...calls];
    let gasCharge: bigint;
    const gasUnits = op.callGasLimit + op.verificationGasLimit + op.preVerificationGas + (op.paymasterVerificationGasLimit ?? 0n) + (op.paymasterPostOpGasLimit ?? 0n);
    const gasCost = gasUnits * op.maxFeePerGas;
    if (intent.gasToken !== "native") {
      requireValue(equal(op.paymaster, cfg.manifest.contracts.unifiedTokenPaymaster.address) && op.paymasterData === "0x" && (op.paymasterVerificationGasLimit ?? 0n) > 0n && (op.paymasterPostOpGasLimit ?? 0n) > 0n);
      const gas = business.shift(); requireValue(gas && equal(gas.to, intent.gasToken) && gas.value === 0n);
      const transfer = decode(erc20Abi, gas.data);
      requireValue(transfer.functionName === "transfer" && equal(transfer.args[0], op.paymaster));
      gasCharge = transfer.args[1]; requireValue(gasCharge > 0n);
    } else {
      requireValue(!op.paymaster && parsed.paymasterData === undefined && parsed.paymasterVerificationGasLimit === undefined && parsed.paymasterPostOpGasLimit === undefined);
      gasCharge = gasCost;
    }
    const amount = BigInt(intent.amount);
    if (intent.kind === "transfer") {
      requireValue(business.length === 1 && intent.to);
      const call = business[0];
      if (intent.token === "native") requireValue(equal(call.to, intent.to) && call.value === amount && call.data === "0x");
      else {
        requireValue(equal(call.to, intent.token) && call.value === 0n);
        const transfer = decode(erc20Abi, call.data);
        requireValue(transfer.functionName === "transfer" && equal(transfer.args[0], intent.to) && transfer.args[1] === amount);
      }
    } else {
      requireValue(intent.tokenOut && intent.minimumOut && expected.deadline && expected.deadline > Math.floor(Date.now() / 1000) && expected.deadline <= Math.floor(Date.now() / 1000) + SWAP_DEADLINE_SECONDS);
      const wcent = cfg.manifest.contracts.wcent.address, router = cfg.manifest.contracts.swapRouter.address;
      const input = intent.token === "native" ? wcent : intent.token;
      const output = intent.tokenOut === "native" ? wcent : intent.tokenOut;
      const minimum = BigInt(intent.minimumOut);
      if (equal(input, output)) {
        requireValue(intent.token !== intent.tokenOut && business.length === 1 && minimum <= amount);
        const call = business[0]; requireValue(equal(call.to, wcent));
        const action = decode(wcentAbi, call.data);
        if (intent.token === "native") requireValue(action.functionName === "deposit" && call.value === amount);
        else requireValue(action.functionName === "withdraw" && call.value === 0n && action.args[0] === amount);
      } else {
        if (intent.token !== "native") {
          const allowance = business.shift(); requireValue(allowance && equal(allowance.to, input) && allowance.value === 0n);
          const approval = decode(erc20Abi, allowance.data);
          requireValue(approval.functionName === "approve" && equal(approval.args[0], router) && approval.args[1] === amount);
        }
        const swap = business.shift(); requireValue(swap && equal(swap.to, router) && swap.value === (intent.token === "native" ? amount : 0n));
        const action = decode(swapRouterAbi, swap.data), params = action.args[0];
        requireValue(equal(params.recipient, intent.tokenOut === "native" ? router : wallet.account) && params.amountIn === amount && params.amountOutMinimum === minimum && params.deadline === BigInt(expected.deadline));
        if (equal(input, wcent) || equal(output, wcent)) {
          requireValue(action.functionName === "exactInputSingle" && equal(params.tokenIn, input) && equal(params.tokenOut, output) && params.fee === intent.feeTier && params.sqrtPriceLimitX96 === 0n);
        } else {
          const fee = intent.feeTier.toString(16).padStart(6, "0");
          requireValue(action.functionName === "exactInput" && equal(params.path, `${input}${fee}${wcent.slice(2)}${fee}${output.slice(2)}`));
        }
        if (intent.tokenOut === "native") {
          const unwrap = business.shift(); requireValue(unwrap && equal(unwrap.to, router) && unwrap.value === 0n);
          const action = decode(swapRouterAbi, unwrap.data);
          requireValue(action.functionName === "unwrapWETH9" && action.args[0] === minimum && equal(action.args[1], wallet.account));
        }
        requireValue(business.length === 0);
      }
    }
    const hash = computeUserOpHash(op, cfg.identity.entryPoint.address, cfg.identity.chainId);
    requireValue(hash === expected.hash);
    const spend: Spend = {}; addSpend(spend, intent.token, amount); addSpend(spend, intent.gasToken, gasCharge);
    return { op, hash, calls, spend, gasCharge, gasCost, gasUnits };
  } catch (error) {
    if (error instanceof WalletError) throw error;
    throw new WalletError("validation_failed", "Cannot decode or validate the complete operation");
  }
}
