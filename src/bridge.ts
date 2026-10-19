import { createPublicClient, http, encodeFunctionData, pad, parseAbi, type Address, type Hex, type PublicClient } from "viem";
import type { Ctx } from "./context.js";
import type { Config } from "./config.js";

export interface RemoteChain {
  name: string;
  chainId: number;
  domain: number;
  rpcUrl: string;
  nativeSymbol: string;
  explorerTx: (hash: string) => string;
}

export interface BridgeRoute {
  token: string;
  chain: string;
  incentivToken: Address;
  localRouter: Address;
  remoteRouter: Address;
  remoteToken: Address;
  remoteStandard: "collateral" | "synthetic";
  incentivStandard: "synthetic" | "native";
  decimals: number;
  inboundNote?: string;
}

/** Adapt the approved manifest for the existing unsigned bridge builders. */
export function getBridgeConfig(cfg: Config) {
  const bridge = cfg.manifest.bridge;
  const routes: BridgeRoute[] = bridge.enabled ? bridge.routes.map((r) => ({
    token: r.symbol, chain: r.remoteChain, incentivToken: (r.incentivToken ?? r.localRouter).address,
    localRouter: r.localRouter.address, remoteRouter: r.remoteRouter.address, remoteToken: r.remoteToken.address,
    remoteStandard: r.remoteStandard, incentivStandard: r.incentivStandard, decimals: r.decimals,
    inboundNote: r.inboundNote,
  })) : [];
  const remoteChains: Record<string, RemoteChain> = bridge.enabled ? Object.fromEntries(
    Object.entries(bridge.remoteChains).map(([name, chain]) => [name, {
      ...chain, rpcUrl: cfg.endpoints.remoteChains[name].rpcUrls[0],
      explorerTx: (hash: string) => cfg.endpoints.remoteChains[name].explorerUrl.replace(/\/$/, "") + "/tx/" + hash,
    }]),
  ) : {};
  return { routes, remoteChains, domain: bridge.incentivDomain, mailbox: bridge.mailbox?.address, note: bridge.note };
}

export const warpAbi = parseAbi([
  "function transferRemote(uint32 destination, bytes32 recipient, uint256 amountOrId) payable returns (bytes32 messageId)",
  "function quoteGasPayment(uint32 destinationDomain) view returns (uint256)",
  "function domains() view returns (uint32[])",
  "function routers(uint32 domain) view returns (bytes32)",
  "function mailbox() view returns (address)",
  "function wrappedToken() view returns (address)",
]);

export const mailboxAbi = parseAbi(["function delivered(bytes32 messageId) view returns (bool)"]);

const erc20 = parseAbi([
  "function approve(address spender, uint256 amount) returns (bool)",
  "function allowance(address owner, address spender) view returns (uint256)",
  "function balanceOf(address owner) view returns (uint256)",
]);

const clients = new Map<string, PublicClient>();
export function remoteClient(cfg: Config, chain: string): PublicClient {
  const { remoteChains } = getBridgeConfig(cfg);
  const remote = remoteChains[chain];
  if (!remote) throw new Error(`Unknown bridge chain "${chain}". Supported: ${Object.keys(remoteChains).join(", ")}.`);
  let c = clients.get(remote.rpcUrl);
  if (!c) {
    c = createPublicClient({ transport: http(remote.rpcUrl, { timeout: 20_000 }) });
    clients.set(remote.rpcUrl, c);
  }
  return c;
}

export function findRoute(cfg: Config, token: string, chain: string): BridgeRoute {
  const { routes } = getBridgeConfig(cfg);
  const t = token.trim().toUpperCase();
  const c = chain.trim().toLowerCase();
  const route = routes.find((r) => r.token === t && r.chain === c);
  if (!route) {
    const forToken = routes.filter((r) => r.token === t).map((r) => r.chain);
    throw new Error(
      forToken.length
        ? `${t} does not bridge between Incentiv and "${chain}". It bridges with: ${forToken.join(", ")}.`
        : `"${token}" is not bridged by the Incentiv Bridge. Bridged tokens: ${[...new Set(routes.map((r) => r.token))].join(", ")}.`,
    );
  }
  return route;
}

/** Left-pad an address into the bytes32 recipient Hyperlane expects. */
export function toBytes32(address: Address): Hex {
  return pad(address, { size: 32 });
}

export interface UnsignedStep {
  step: string;
  chain: string;
  chainId: number;
  to: Address;
  value: string;
  data: Hex;
  note?: string;
}

/** Bridge into Incentiv. Returns up to two transactions to send in order. */
export async function buildInboundBridge(
  cfg: Config,
  route: BridgeRoute,
  sender: Address,
  recipient: Address,
  amount: bigint,
): Promise<{ steps: UnsignedStep[]; gasPayment: bigint; balance: bigint; allowance: bigint }> {
  if (route.inboundNote) throw new Error(route.inboundNote);
  if (!route.remoteToken) throw new Error(`No token known on ${route.chain} for ${route.token}.`);
  const { remoteChains, domain } = getBridgeConfig(cfg);
  const chain = remoteChains[route.chain];
  const client = remoteClient(cfg, route.chain);
  const needsApproval = route.remoteStandard === "collateral";

  const [gasPayment, balance, allowance] = await Promise.all([
    client.readContract({ address: route.remoteRouter, abi: warpAbi, functionName: "quoteGasPayment", args: [domain] }),
    client.readContract({ address: route.remoteToken, abi: erc20, functionName: "balanceOf", args: [sender] }),
    needsApproval
      ? client.readContract({ address: route.remoteToken, abi: erc20, functionName: "allowance", args: [sender, route.remoteRouter] })
      : Promise.resolve(0n),
  ]);

  const steps: UnsignedStep[] = [];
  // Only a collateral route needs an allowance.
  if (needsApproval && allowance < amount) {
    steps.push({
      step: "approve",
      chain: route.chain,
      chainId: chain.chainId,
      to: route.remoteToken,
      value: "0x0",
      data: encodeFunctionData({ abi: erc20, functionName: "approve", args: [route.remoteRouter, amount] }),
      note: `Lets the bridge escrow ${route.token}. Current allowance is below the amount.`,
    });
  }
  steps.push({
    step: "transferRemote",
    chain: route.chain,
    chainId: chain.chainId,
    to: route.remoteRouter,
    value: `0x${gasPayment.toString(16)}`,
    data: encodeFunctionData({
      abi: warpAbi,
      functionName: "transferRemote",
      args: [domain, toBytes32(recipient), amount],
    }),
    note: `Sends ${route.token} to ${recipient} on Incentiv. The attached ${chain.nativeSymbol} pays Hyperlane's interchain gas.`,
  });

  return { steps, gasPayment, balance, allowance };
}

/** Bridge out of Incentiv. One call, with the interchain gas attached. */
export async function buildOutboundBridge(
  ctx: Ctx,
  route: BridgeRoute,
  recipient: Address,
  amount: bigint,
): Promise<{ to: Address; value: bigint; data: Hex; gasPayment: bigint }> {
  const gasPayment = await ctx.client.readContract({
    address: route.localRouter,
    abi: warpAbi,
    functionName: "quoteGasPayment",
    args: [ctx.config.manifest.bridge.remoteChains[route.chain].domain],
  });
  // A native route carries the bridged amount as msg.value; a synthetic route
  // burns the token and carries only the gas.
  const value = route.incentivStandard === "native" ? gasPayment + amount : gasPayment;
  return {
    to: route.localRouter,
    value,
    data: encodeFunctionData({
      abi: warpAbi,
      functionName: "transferRemote",
      args: [ctx.config.manifest.bridge.remoteChains[route.chain].domain, toBytes32(recipient), amount],
    }),
    gasPayment,
  };
}

/** Whether a Hyperlane message has been delivered. */
export async function checkDelivered(
  messageId: Hex,
  destination: "incentiv" | string,
  ctx: Ctx,
): Promise<{ delivered: boolean; mailbox: Address; chain: string }> {
  const { remoteChains, routes, mailbox: localMailbox } = getBridgeConfig(ctx.config);
  if (!ctx.config.manifest.bridge.enabled || !localMailbox) throw new Error("Bridge capability is disabled");
  if (destination === "incentiv") {
    const delivered = await ctx.client.readContract({
      address: localMailbox,
      abi: mailboxAbi,
      functionName: "delivered",
      args: [messageId],
    });
    return { delivered, mailbox: localMailbox, chain: "incentiv" };
  }
  const chain = remoteChains[destination];
  if (!chain) throw new Error(`Unknown chain "${destination}".`);
  const client = remoteClient(ctx.config, destination);
  // Any route on that chain exposes its mailbox.
  const route = routes.find((r) => r.chain === destination);
  if (!route) throw new Error(`No Incentiv Bridge route on "${destination}".`);
  const mailbox = await client.readContract({ address: route.remoteRouter, abi: warpAbi, functionName: "mailbox" });
  const delivered = await client.readContract({ address: mailbox, abi: mailboxAbi, functionName: "delivered", args: [messageId] });
  return { delivered, mailbox, chain: destination };
}
