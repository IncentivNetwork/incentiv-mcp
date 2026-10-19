import { formatUnits, getAddress, isAddress, parseUnits, toFunctionSelector } from "viem";
import type { Config } from "./config.js";
import type { TokenInfo } from "./context.js";
import { WalletError } from "./wallet/errors.js";
import { limitsSchema, type Limits } from "./wallet/policy.js";

export type Ask = (question: string) => Promise<string>;
export type Tell = (message: string) => void;
export const technicalLimits = { maxSlippageBps: 50, maxQuoteDeviationBps: 50, maxFeePerGas: "100000000000000", maxGasUnits: "1000000", maxBatchCalls: 4 };

/** Policy allowances may be zero. Never round or parse amounts through floating point. */
export function allowance(text: string, decimals: number): string {
  if (!/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/.test(text) || (text.split(".")[1]?.length ?? 0) > decimals) {
    throw new WalletError("validation_failed", `Enter a decimal amount with at most ${decimals} decimal places (no commas or rounding)`);
  }
  const value = parseUnits(text, decimals);
  if (value >= 2n ** 256n) throw new WalletError("validation_failed", "Amount is too large");
  return value.toString();
}

export async function answer<T>(ask: Ask, tell: Tell, label: string, parse: (text: string) => T): Promise<T> {
  for (;;) {
    const text = (await ask(label)).trim();
    if (text.toLowerCase() === "cancel") throw new WalletError("policy_denied", "Setup cancelled. Rerun setup to continue with the same wallet.");
    try { return parse(text); }
    catch (error) { tell(error instanceof WalletError ? error.message : "Enter one of the listed choices."); }
  }
}

export async function yesNo(ask: Ask, tell: Tell, label: string, defaultYes = false): Promise<boolean> {
  return answer(ask, tell, `${label} ${defaultYes ? "[Y/n]" : "[y/N]"}: `, value => {
    if (!value) return defaultYes;
    if (/^(y|yes)$/i.test(value)) return true;
    if (/^(n|no)$/i.test(value)) return false;
    throw new Error();
  });
}

export function setupTargets(config: Config, tokens: TokenInfo[], swaps: boolean): Limits["targets"] {
  const targets: Limits["targets"] = {};
  const add = (address: string, signatures: string[]) => {
    const key = address.toLowerCase();
    targets[key] = [...new Set([...(targets[key] ?? []), ...signatures.map(toFunctionSelector)])];
  };
  for (const token of tokens.filter(token => token.address !== "native")) {
    add(token.address, ["transfer(address,uint256)", ...(swaps ? ["approve(address,uint256)"] : [])]);
  }
  if (swaps) {
    add(config.manifest.contracts.wcent.address, ["deposit()", "withdraw(uint256)"]);
    add(config.manifest.contracts.swapRouter.address, [
      "exactInputSingle((address,address,uint24,address,uint256,uint256,uint256,uint160))",
      "exactInput((bytes,address,uint256,uint256,uint256))", "unwrapWETH9(uint256,address)",
    ]);
  }
  return targets;
}

export async function promptPolicy(config: Config, resolveToken: (ref: string) => Promise<TokenInfo>, ask: Ask, tell: Tell) {
  const available = [config.identity.nativeSymbol, ...Object.keys(config.manifest.canonicalTokens)];
  tell(`Choose assets: ${available.join(", ")}. Limits use normal token amounts; 0 blocks that use. Type cancel to stop.`);
  const defaults = [config.identity.nativeSymbol, ...(config.manifest.canonicalTokens.USDC ? ["USDC"] : [])];
  const symbols = await answer(ask, tell, `Assets, separated by commas [${defaults.join(", ")}]: `, value => {
    const selected = [...new Set((value || defaults.join(",")).split(",").map(s => s.trim().toUpperCase()))];
    if (selected.some(symbol => !available.includes(symbol))) throw new WalletError("validation_failed", "Choose only listed assets");
    // Native exposure and the underlying gas ceiling are always bounded, even with token gas.
    return [...new Set([config.identity.nativeSymbol, ...selected])];
  });
  const tokens = await Promise.all(symbols.map(resolveToken));
  const recipients = await answer(ask, tell, "Allowed recipient addresses, comma-separated (blank blocks transfers): ", value => {
    const addresses = value ? [...new Set(value.split(",").map(s => s.trim()))] : [];
    if (!addresses.every(a => isAddress(a))) throw new WalletError("validation_failed", "Enter complete valid EVM recipient addresses");
    return addresses.map(a => getAddress(a));
  });
  const swaps = await yesNo(ask, tell, "Allow swaps between the selected assets?", true);
  const origins = [...new Set(config.endpoints.rpcUrls.map(url => new URL(url).origin))];
  if (swaps) {
    tell(`Swap verification will trust these RPC operators: ${origins.join(", ")}. This is not independent-provider verification.`);
    if (!await yesNo(ask, tell, "Do you explicitly trust these sources for swaps?")) {
      throw new WalletError("policy_denied", "Swap trust was not approved. Rerun setup without swaps, or use advanced policy configuration with independent RPC sources.");
    }
  }
  const amounts: Limits["tokens"] = {};
  for (const token of tokens) {
    const amount = (label: string) => answer(ask, tell, `${token.symbol} — ${label}: `, value => allowance(value, token.decimals));
    const perTransaction = await amount("maximum input per transfer/swap");
    const daily = await answer(ask, tell, `${token.symbol} — total daily budget INCLUDING gas: `, value => {
      const cap = allowance(value, token.decimals);
      if (BigInt(cap) < BigInt(perTransaction)) throw new WalletError("validation_failed", "Daily budget must cover the per-operation input limit");
      return cap;
    });
    const exposure = await amount("maximum balance the wallet may hold");
    const gasPayment = await amount("maximum gas payment per operation (0 disables this gas token)");
    amounts[token.address] = { perTransaction, daily, exposure, gasPayment };
  }
  const maxGasCostWei = await answer(ask, tell, `${config.identity.nativeSymbol} — underlying gas cost ceiling, also checked for token-paid gas: `, value => {
    const amount = allowance(value, 18);
    if (amount === "0") throw new WalletError("validation_failed", "Set a positive underlying gas ceiling");
    return amount;
  });
  const technical = { ...technicalLimits };
  tell("Advanced defaults: 0.5% swap slippage, 0.5% quote deviation, 1,000,000 gas units, 100,000 gwei fee ceiling, 4 calls. Your total gas budget still applies.");
  if (await yesNo(ask, tell, "Edit these advanced limits?")) {
    const integer = (label: string, min: number, max: number, current: number) => answer(ask, tell, `${label} [${current}]: `, text => {
      const value = Number(text || current);
      if (!/^[0-9]+$/.test(text || String(current)) || !Number.isSafeInteger(value) || value < min || value > max) throw new WalletError("validation_failed", `Enter a whole number between ${min} and ${max}`);
      return value;
    });
    technical.maxSlippageBps = await integer("Maximum slippage in basis points (50 = 0.5%)", 0, 1000, technical.maxSlippageBps);
    technical.maxQuoteDeviationBps = await integer("Maximum quote deviation in basis points", 0, 1000, technical.maxQuoteDeviationBps);
    technical.maxGasUnits = String(await integer("Maximum gas units", 1, Number.MAX_SAFE_INTEGER, Number(technical.maxGasUnits)));
    technical.maxBatchCalls = await integer("Maximum batch calls", 1, 16, technical.maxBatchCalls);
    technical.maxFeePerGas = await answer(ask, tell, "Maximum fee per gas in gwei [100000]: ", value => allowance(value || "100000", 9));
  }
  const limits = limitsSchema.parse({ tokens: amounts, recipients: { mode: "allowlist", addresses: recipients }, targets: setupTargets(config, tokens, swaps), swaps, ...technical, independentRpcOrigins: [], ...(swaps ? { trustedRpcOrigins: origins } : {}), maxGasCostWei });
  return { limits, tokens };
}

export function policySummary(limits: Limits, tokens: TokenInfo[], nativeSymbol = "CENT"): string {
  const lines = ["Permissions to review:"];
  for (const [address, caps] of Object.entries(limits.tokens)) {
    const token = tokens.find(token => token.address.toLowerCase() === address.toLowerCase());
    if (!token) throw new WalletError("validation_failed", "Cannot display an unresolved policy asset");
    const fmt = (value: string) => `${formatUnits(BigInt(value), token.decimals)} ${token.symbol}`;
    lines.push(`  ${token.symbol}: input per operation ${fmt(caps.perTransaction)}; daily INCLUDING gas ${fmt(caps.daily)}; maximum holdings ${fmt(caps.exposure)}; gas per operation ${fmt(caps.gasPayment)}`);
  }
  lines.push(`  Recipients: ${limits.recipients.mode === "any" ? "ANY ADDRESS" : limits.recipients.addresses.join(", ") || "none (transfers blocked)"}`,
    `  Swaps: ${limits.swaps ? `enabled; ${limits.maxSlippageBps / 100}% maximum slippage, ${limits.maxQuoteDeviationBps / 100}% quote deviation` : "disabled"}`,
    `  Trusted RPCs: ${limits.trustedRpcOrigins?.join(", ") || "none"}; independent RPCs: ${limits.independentRpcOrigins.join(", ") || "none"}`,
    `  Underlying gas ceiling: ${formatUnits(BigInt(limits.maxGasCostWei), 18)} ${nativeSymbol}; ${limits.maxGasUnits} gas units; ${formatUnits(BigInt(limits.maxFeePerGas), 9)} gwei; ${limits.maxBatchCalls} calls`,
    `  Contract permissions: ${JSON.stringify(limits.targets)}`,
    `  Expiry: ${limits.expiresAt ? new Date(limits.expiresAt).toISOString() : "none"}`,
    "Permitted requests can execute automatically. Requests outside these limits remain subject to wallet policy and exact-operation approval. Holdings above the exposure limit block spending.");
  return lines.join("\n");
}
