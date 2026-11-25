import { formatUnits, getAddress, isAddress, parseUnits, toFunctionSelector } from "viem";
import type { Config } from "./config.js";
import type { TokenInfo } from "./context.js";
import { WalletError } from "./wallet/errors.js";
import { limitsSchema, type Limits } from "./wallet/policy.js";

export type Ask = (question: string) => Promise<string>;
export type Tell = (message: string) => void;
/**
 * Defaults for the advanced limits. Gas units count every limit of an operation, including the paymaster's own
 * verification and post-operation limits when gas is paid in a token: a USDC-paid first operation that deploys
 * and links an agent declared 1,114,937 units on mainnet, so the default leaves room above that.
 */
export const technicalLimits = { maxSlippageBps: 50, maxQuoteDeviationBps: 50, maxFeePerGas: "100000000000000", maxGasUnits: "1500000", maxBatchCalls: 4 };

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

/** Asks which Portal accounts this agent may connect to and returns the policy additions; nothing when declined. */
export async function promptAgentRegistry(config: Config, ask: Ask, tell: Tell): Promise<{ agentRegistry?: Limits["agentRegistry"]; targets?: Limits["targets"] }> {
  if (!config.manifest.agentRegistry || !await yesNo(ask, tell, "Allow this agent to connect to Portal accounts? Connections are permanent: Portal and this wallet offer no way to disconnect them.")) return {};
  const parents = await answer(ask, tell, "Allowed Portal smart-account addresses, comma-separated: ", value => {
    const values = [...new Set(value.split(",").map(v => v.trim()))];
    if (!values.length || !values.every(v => isAddress(v) && !/^0x0{40}$/i.test(v))) throw new WalletError("validation_failed", "Enter Portal smart-account addresses");
    return [...new Set(values.map(value => getAddress(value)))];
  });
  const registry = config.manifest.agentRegistry.proxy.address.toLowerCase();
  tell(`Registry link permission will be added for ${registry}. Gas budgets still apply.`);
  return { agentRegistry: { parents, allowUnlink: false }, targets: { [registry]: [toFunctionSelector("link(address,address,uint256,bytes,uint256,bytes)")] } };
}

/**
 * Connections are permanent: removes the unlink permission an earlier build's policy may hold (allowUnlink and the
 * registry's unlink() selector), so setup reviews and saves a policy without it. Returns `limits` itself when there is none.
 */
export function withoutUnlink(config: Config, limits: Limits): Limits {
  const registry = config.manifest.agentRegistry?.proxy.address.toLowerCase(), unlink = toFunctionSelector("unlink()");
  const key = registry && Object.keys(limits.targets).find(target => target.toLowerCase() === registry);
  const selectors = key ? limits.targets[key] : undefined;
  if (!limits.agentRegistry?.allowUnlink && !selectors?.some(selector => selector.toLowerCase() === unlink)) return limits;
  const targets = { ...limits.targets };
  if (key) targets[key] = selectors!.filter(selector => selector.toLowerCase() !== unlink);
  return limitsSchema.parse({ ...limits, ...(limits.agentRegistry ? { agentRegistry: { ...limits.agentRegistry, allowUnlink: false } } : {}), targets });
}

/**
 * Offers x402 payments when the policy covers Incentiv USDC. Payments still count against the USDC limits;
 * this adds the per-payment cap and which sellers may be paid.
 */
export async function promptX402(config: Config, limits: Pick<Limits, "tokens">, ask: Ask, tell: Tell): Promise<Limits["x402"]> {
  const usdc = config.manifest.canonicalTokens.USDC?.address;
  if (config.identity.chainId !== 24101 || !usdc || !Object.keys(limits.tokens).some(token => token.toLowerCase() === usdc.toLowerCase())) return undefined;
  tell("x402 lets this agent pay websites and APIs per request in USDC. Each payment also counts against the USDC limits above, and gas (about 0.03 USDC) is paid on top.");
  // Every payment also has to pass the USDC input limit per operation, so a higher x402 maximum would never apply.
  const cap = BigInt(Object.entries(limits.tokens).find(([token]) => token.toLowerCase() === usdc.toLowerCase())![1].perTransaction);
  if (cap === 0n) { tell("USDC input per operation is 0, which refuses every x402 payment; raise it to allow x402."); return undefined; }
  if (!await yesNo(ask, tell, "Allow paying for x402 resources?")) return undefined;
  const fallback = formatUnits(cap < 100_000n ? cap : 100_000n, 6);
  const maxPerPayment = await answer(ask, tell, `USDC — maximum price per x402 payment, at most the USDC input limit of ${formatUnits(cap, 6)} [${fallback}]: `, value => {
    const amount = allowance(value || fallback, 6);
    if (amount === "0") throw new WalletError("validation_failed", "Set a positive maximum, or answer no to x402");
    if (BigInt(amount) > cap) throw new WalletError("validation_failed", `The USDC input limit per operation (${formatUnits(cap, 6)} USDC) refuses larger payments; enter at most that`);
    return amount;
  });
  const origins = await answer(ask, tell, "Sites the agent may pay, as https origins separated by commas (blank allows any site): ", value => {
    const list = value ? [...new Set(value.split(",").map(s => s.trim()))] : [];
    return list.map(item => {
      let url: URL;
      try { url = new URL(item); } catch { throw new WalletError("validation_failed", "Enter origins such as https://api.example.com"); }
      if (url.protocol !== "https:" || url.pathname !== "/" || url.search || url.hash || url.username || url.password || item.endsWith("?") || item.endsWith("#")) throw new WalletError("validation_failed", "Enter https origins without a path, such as https://api.example.com");
      return url.origin;
    });
  });
  const payTo = await answer(ask, tell, "Seller payment addresses the agent may pay, separated by commas (blank allows any): ", value => {
    const addresses = value ? [...new Set(value.split(",").map(s => s.trim()))] : [];
    if (!addresses.every(a => isAddress(a))) throw new WalletError("validation_failed", "Enter complete valid EVM addresses");
    return addresses.map(a => getAddress(a));
  });
  return {
    origins: origins.length ? { mode: "allowlist", origins } : { mode: "any" },
    payTo: payTo.length ? { mode: "allowlist", addresses: payTo } : { mode: "any" },
    maxPerPayment,
  };
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
  tell(`Advanced defaults: ${technicalLimits.maxSlippageBps / 100}% swap slippage, ${technicalLimits.maxQuoteDeviationBps / 100}% quote deviation, ${Number(technicalLimits.maxGasUnits).toLocaleString("en-US")} gas units, ${Number(formatUnits(BigInt(technicalLimits.maxFeePerGas), 9)).toLocaleString("en-US")} gwei fee ceiling, ${technicalLimits.maxBatchCalls} calls. Your total gas budget still applies.`);
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
  const { agentRegistry, targets: registryTargets } = await promptAgentRegistry(config, ask, tell);
  const x402 = await promptX402(config, { tokens: amounts }, ask, tell);
  const targets = { ...setupTargets(config, tokens, swaps), ...registryTargets };
  const limits = limitsSchema.parse({ ...(agentRegistry ? { agentRegistry } : {}), ...(x402 ? { x402 } : {}), tokens: amounts, recipients: { mode: "allowlist", addresses: recipients }, targets, swaps, ...technical, independentRpcOrigins: [], ...(swaps ? { trustedRpcOrigins: origins } : {}), maxGasCostWei });
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
  if (limits.agentRegistry) lines.push(`  Agent Registry parents: ${limits.agentRegistry.parents.join(", ") || "none"}; connections are permanent`);
  const x402 = limits.x402;
  // The USDC input limit per operation also bounds each payment, so the effective maximum is the lower of the two.
  const usdcCap = Object.entries(limits.tokens).find(([address]) => tokens.find(t => t.address.toLowerCase() === address.toLowerCase())?.symbol === "USDC")?.[1].perTransaction;
  const x402Max = x402 && usdcCap !== undefined && BigInt(usdcCap) < BigInt(x402.maxPerPayment) ? usdcCap : x402?.maxPerPayment;
  lines.push(`  x402 payments: ${!x402 ? "disabled" : `up to ${formatUnits(BigInt(x402Max!), 6)} USDC each, within the USDC limits; sites ${x402.origins.mode === "any" ? "ANY SITE" : x402.origins.origins.join(", ")}; sellers ${x402.payTo.mode === "any" ? "ANY ADDRESS" : x402.payTo.addresses.join(", ")}`}`);
  lines.push(`  Recipients: ${limits.recipients.mode === "any" ? "ANY ADDRESS" : limits.recipients.addresses.join(", ") || "none (transfers blocked)"}`,
    `  Swaps: ${limits.swaps ? `enabled; ${limits.maxSlippageBps / 100}% maximum slippage, ${limits.maxQuoteDeviationBps / 100}% quote deviation` : "disabled"}`,
    `  Trusted RPCs: ${limits.trustedRpcOrigins?.join(", ") || "none"}; independent RPCs: ${limits.independentRpcOrigins.join(", ") || "none"}`,
    `  Underlying gas ceiling: ${formatUnits(BigInt(limits.maxGasCostWei), 18)} ${nativeSymbol}; ${limits.maxGasUnits} gas units; ${formatUnits(BigInt(limits.maxFeePerGas), 9)} gwei; ${limits.maxBatchCalls} calls`,
    `  Contract permissions: ${JSON.stringify(limits.targets)}`,
    `  Expiry: ${limits.expiresAt ? new Date(limits.expiresAt).toISOString() : "none"}`,
    "Permitted requests can execute automatically. Requests outside these limits remain subject to wallet policy and exact-operation approval. Holdings above the exposure limit block spending.");
  return lines.join("\n");
}
