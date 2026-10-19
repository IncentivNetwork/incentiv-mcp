import { readFileSync } from "node:fs";
import { isAbsolute } from "node:path";
import { z } from "zod";
import { isAddress, keccak256, stringToHex, type Address, type Hex } from "viem";
import mainnet from "./mainnet.json" with { type: "json" };

const hash = z.custom<Hex>((v) => typeof v === "string" && /^0x[0-9a-f]{64}$/.test(v));
const address = z.custom<Address>((v) => typeof v === "string" && isAddress(v) && !/^0x0{40}$/i.test(v));
const pin = z.strictObject({ address, codeHash: hash });
const text = z.string().min(1).max(200);
const symbol = z.string().regex(/^[A-Z0-9]+$/);
const chainId = z.number().int().positive().max(Number.MAX_SAFE_INTEGER);
const url = z.string().url().refine((value) => {
  const parsed = new URL(value);
  return ["https:", "http:"].includes(parsed.protocol) && !parsed.username && !parsed.password && !parsed.hash;
}, "Expected an HTTP(S) URL without credentials or a fragment").transform(value => new URL(value).href);
const rpcUrls = z.array(url).min(1).refine((values) => new Set(values).size === values.length, "Duplicate RPC URL");
const key = z.string().regex(/^[a-z0-9_-]+$/);

export const identitySchema = z.strictObject({
  schemaVersion: z.literal(1), networkId: hash, name: text, chainId, genesisHash: hash,
  nativeSymbol: symbol, userOpVersion: z.literal("0.7"), signingScheme: z.literal("eip191-userop-hash"),
  accountDerivation: z.literal("factory-create2-v1"), accountInitCodeHash: hash, accountVersion: text,
  entryPoint: pin, accountFactory: pin, accountBeacon: pin, accountImplementation: pin,
});

export const manifestSchema = z.strictObject({
  schemaVersion: z.literal(1), manifestId: hash, networkId: hash,
  contracts: z.strictObject({
    contractRegistry: pin, transferGate: pin, bulkBalanceReader: pin, unifiedTokenPaymaster: pin,
    wcent: pin, swapRouter: pin, quoter: pin,
  }),
  canonicalTokens: z.record(symbol, pin),
  bridge: z.strictObject({
    enabled: z.boolean(), incentivDomain: z.number().int().nonnegative().max(0xffffffff), mailbox: pin.optional(),
    routes: z.array(z.strictObject({
      symbol, incentivToken: pin.optional(), remoteChain: key, remoteToken: pin,
      localRouter: pin, remoteRouter: pin, decimals: z.number().int().min(0).max(255),
      remoteStandard: z.enum(["collateral", "synthetic"]), incentivStandard: z.enum(["synthetic", "native"]),
      inboundNote: text.optional(),
    })),
    remoteChains: z.record(key, z.strictObject({
      name: text, nativeSymbol: symbol, chainId, domain: z.number().int().nonnegative().max(0xffffffff),
    })),
    note: text.optional(),
  }),
});

const configSchema = z.strictObject({
  identity: identitySchema, manifest: manifestSchema,
  // Hash-pinned, unparameterized BeaconProxy creation bytecode. Owner-specific
  // constructor arguments are appended locally, never supplied by the host.
  accountCreationCode: z.custom<Hex>((v) => typeof v === "string" && /^0x(?:[0-9a-f]{2})+$/.test(v)),
  endpoints: z.strictObject({
    rpcUrls, bundlerUrl: url, explorerApiUrl: url, explorerUrl: url,
    remoteChains: z.record(key, z.strictObject({ rpcUrls, explorerUrl: url })),
  }),
});

export type WalletNetworkIdentity = z.infer<typeof identitySchema>;
export type CapabilityManifest = z.infer<typeof manifestSchema>;
export type ContractPin = z.infer<typeof pin>;
export type Config = z.infer<typeof configSchema>;
export type NetworkEndpoints = Config["endpoints"];

/** RFC 8785: ECMAScript number/string serialization and UTF-16 property order. */
export function canonicalJson(value: unknown): string {
  if (typeof value === "string") {
    if (Buffer.from(value, "utf8").toString("utf8") !== value) throw new Error("Invalid Unicode in canonical JSON");
    return JSON.stringify(value);
  }
  if (value === null || typeof value === "boolean" || (typeof value === "number" && Number.isFinite(value))) {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${Array.from(value, canonicalJson).join(",")}]`;
  if (typeof value === "object" && value !== null && Object.getPrototypeOf(value) === Object.prototype) {
    return `{${Object.keys(value).sort().map((k) => `${canonicalJson(k)}:${canonicalJson((value as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  throw new Error("Value is not canonical JSON");
}

export function configurationId(value: Record<string, unknown>, id: "networkId" | "manifestId"): Hex {
  const { [id]: _id, ...body } = value;
  return keccak256(stringToHex(canonicalJson(body)));
}

export function parseConfig(input: unknown): Config {
  const result = configSchema.safeParse(input);
  if (!result.success) {
    // Report paths, never the supplied configuration or endpoint credentials.
    throw new Error(`Invalid network configuration: ${result.error.issues.map((i) => i.path.join(".")).join(", ")}`);
  }
  const cfg = result.data;
  const { identity, manifest, endpoints } = cfg;
  if (configurationId(identity, "networkId") !== identity.networkId) throw new Error("Invalid networkId");
  if (configurationId(manifest, "manifestId") !== manifest.manifestId) throw new Error("Invalid manifestId");
  if (manifest.networkId !== identity.networkId) throw new Error("Manifest belongs to a different network identity");
  if (keccak256(cfg.accountCreationCode) !== identity.accountInitCodeHash) throw new Error("Account creation bytecode hash mismatch");
  if (manifest.bridge.enabled && (!manifest.bridge.mailbox || !manifest.bridge.routes.length)) {
    throw new Error("Enabled bridge requires a mailbox and routes");
  }
  const routeKeys = new Set<string>();
  for (const route of manifest.bridge.routes) {
    const id = `${route.symbol}:${route.remoteChain}`;
    if (routeKeys.has(id)) throw new Error("Duplicate bridge route");
    routeKeys.add(id);
    if (!manifest.bridge.remoteChains[route.remoteChain]) throw new Error("Bridge route has no remote chain");
    if (route.incentivStandard === "synthetic" && !route.incentivToken) throw new Error("Synthetic bridge route requires a token pin");
  }
  const remoteNames = Object.keys(manifest.bridge.remoteChains).sort();
  if (canonicalJson(remoteNames) !== canonicalJson(Object.keys(endpoints.remoteChains).sort())) {
    throw new Error("Remote endpoints must match the declared remote chains");
  }
  for (const pins of [localContractPins(cfg), ...remoteNames.map((name) => remoteContractPins(cfg, name))]) {
    const seen = new Map<string, Hex>();
    for (const p of pins) {
      const previous = seen.get(p.address.toLowerCase());
      if (previous && previous !== p.codeHash) throw new Error("Conflicting contract code hashes");
      seen.set(p.address.toLowerCase(), p.codeHash);
    }
  }
  return cfg;
}

export function localContractPins(cfg: Config): ContractPin[] {
  const { identity: i, manifest: m } = cfg;
  return [i.entryPoint, i.accountFactory, i.accountBeacon, i.accountImplementation,
    ...Object.values(m.contracts), ...Object.values(m.canonicalTokens),
    ...(m.bridge.enabled ? [m.bridge.mailbox!, ...m.bridge.routes.flatMap((r) => [r.localRouter, ...(r.incentivToken ? [r.incentivToken] : [])])] : [])];
}

export function remoteContractPins(cfg: Config, chain: string): ContractPin[] {
  return cfg.manifest.bridge.enabled
    ? cfg.manifest.bridge.routes.filter((r) => r.remoteChain === chain).flatMap((r) => [r.remoteToken, r.remoteRouter]) : [];
}

export const MAINNET = parseConfig(mainnet);

export function loadConfig(environment: NodeJS.ProcessEnv = process.env): Config {
  const partialOverrides = ["CHAIN_ID", "ENTRY_POINT", "ACCOUNT_FACTORY", "CONTRACT_REGISTRY", "TRANSFER_GATE",
    "BULK_BALANCE_READER", "PAYMASTER", "WCENT", "SWAP_ROUTER", "QUOTER"];
  if (partialOverrides.some((name) => environment[`INCENTIV_${name}`])) {
    throw new Error("Partial network/contract overrides are not supported; use INCENTIV_NETWORK_CONFIG");
  }
  const file = environment.INCENTIV_NETWORK_CONFIG;
  if (file && !isAbsolute(file)) throw new Error("INCENTIV_NETWORK_CONFIG must be an absolute path");
  const cfg = file ? parseConfig(JSON.parse(readFileSync(file, "utf8"))) : structuredClone(MAINNET);
  const e = cfg.endpoints;
  if (environment.INCENTIV_RPC_URL) e.rpcUrls = [environment.INCENTIV_RPC_URL];
  for (const [name, property] of [
    ["INCENTIV_BUNDLER_URL", "bundlerUrl"], ["INCENTIV_EXPLORER_API_URL", "explorerApiUrl"],
    ["INCENTIV_EXPLORER_URL", "explorerUrl"],
  ] as const) {
    if (environment[name]) e[property] = environment[name];
  }
  return parseConfig(cfg);
}
