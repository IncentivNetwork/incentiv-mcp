import { homedir } from "node:os";
import { join } from "node:path";
import { concatHex, encodeAbiParameters, encodeFunctionData, getContractAddress, keccak256, parseAbi, toHex, type Address, type Hex } from "viem";
import { canonicalJson, localContractPins, parseConfig, remoteContractPins, type Config, type ContractPin, type WalletNetworkIdentity } from "./config.js";

export class NetworkError extends Error {
  constructor(readonly code: "wallet_network_mismatch" | "capability_manifest_unapproved" | "network_verification_failed", message: string) {
    super(`${code}: ${message}`);
  }
}

// Legacy default namespace. Named profiles are explicit local startup choices;
// network configuration never selects another wallet path.
export function walletDirectory(): string {
  return join(homedir(), ".incentiv-mcp", "wallet");
}

export function assertWalletNetwork(cfg: Config, wallet: {
  networkIdentity: WalletNetworkIdentity;
  approvedCapabilityManifestId: Hex;
}): void {
  if (canonicalJson(wallet.networkIdentity) !== canonicalJson(cfg.identity)) {
    throw new NetworkError("wallet_network_mismatch", "The existing wallet belongs to a different network identity. For the supported Incentiv account upgrade, use wallet upgrade-implementation in your local terminal");
  }
  if (wallet.approvedCapabilityManifestId !== cfg.manifest.manifestId) {
    throw new NetworkError("capability_manifest_unapproved", "The wallet has not approved this capability manifest");
  }
}

const factoryAbi = parseAbi([
  "function accountBeacon() view returns (address)",
  "function getAddress(address owner, bytes32[2] publicKey, uint256 salt) view returns (address)",
]);
const beaconAbi = parseAbi(["function implementation() view returns (address)"]);
const initializeAbi = parseAbi(["function initialize(address owner, bytes32[2] publicKey)"]);
const zero32 = toHex(0n, { size: 32 });

export function deriveSmartAccount(cfg: Config, owner: Address, salt = 0n): Address {
  if (/^0x0{40}$/i.test(owner) || salt < 0n || salt >= 2n ** 256n) throw new Error("Invalid account owner or salt");
  if (keccak256(cfg.accountCreationCode) !== cfg.identity.accountInitCodeHash) throw new Error("Account creation bytecode hash mismatch");
  const initializer = encodeFunctionData({ abi: initializeAbi, functionName: "initialize", args: [owner, [zero32, zero32]] });
  const bytecode = concatHex([cfg.accountCreationCode, encodeAbiParameters(
    [{ type: "address" }, { type: "bytes" }], [cfg.identity.accountBeacon.address, initializer],
  )]);
  return getContractAddress({ opcode: "CREATE2", from: cfg.identity.accountFactory.address, salt: toHex(salt, { size: 32 }), bytecode });
}

export type RpcRequest = (url: string, method: string, params: unknown[]) => Promise<unknown>;

class RpcUnavailable extends Error {}
const rpcRequest: RpcRequest = async (url, method, params) => {
  // These are verification reads only. Retry transient transport failures, never
  // a returned identity/code mismatch, and never signing or broadcast work.
  for (let attempt = 0; ; attempt++) {
    let reason = "invalid RPC response", retry = false;
    try {
      const response = await fetch(url, {
        method: "POST", headers: { "content-type": "application/json" },
        body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params }), signal: AbortSignal.timeout(20_000),
      });
      if (!response.ok) {
        reason = `HTTP ${response.status}`;
        retry = [408, 429, 500, 502, 503, 504].includes(response.status);
        await response.body?.cancel().catch(() => {});
      } else {
        const body = await response.json() as { result?: unknown; error?: { code?: number } } | null;
        if (body && !body.error && body.result !== undefined) return body.result;
        const code = body?.error?.code;
        if (typeof code === "number" && Number.isSafeInteger(code)) {
          reason = `RPC error ${code}`;
          retry = [-32000, -32002, -32005, -32603].includes(code);
        }
      }
    } catch (error) {
      const code = (error as { cause?: { code?: string } })?.cause?.code;
      retry = (error instanceof Error && error.name === "TimeoutError") || ["ECONNRESET", "ETIMEDOUT", "EAI_AGAIN", "UND_ERR_CONNECT_TIMEOUT", "UND_ERR_HEADERS_TIMEOUT", "UND_ERR_SOCKET"].includes(code ?? "");
      reason = retry ? "connection interrupted or timed out" : "connection or response failure";
    }
    if (!retry || attempt === 2) throw new RpcUnavailable(`${method} unavailable (${reason}; ${attempt + 1} attempt(s))`);
    await new Promise(resolve => setTimeout(resolve, 500 * (attempt + 1)));
  }
};

async function verifyPins(url: string, pins: ContractPin[], block: Hex, request: RpcRequest): Promise<void> {
  const unique = new Map(pins.map((p) => [p.address.toLowerCase(), p]));
  await Promise.all([...unique.values()].map(async (pin) => {
    const code = await request(url, "eth_getCode", [pin.address, block]);
    if (typeof code !== "string" || !/^0x(?:[0-9a-fA-F]{2})+$/.test(code) || keccak256(code as Hex) !== pin.codeHash) {
      throw new Error(`Contract code mismatch at ${pin.address}`);
    }
  }));
}

/** Always verify all local pins; bridge use and capability approval also verify remotes. */
export async function verifyNetwork(cfg: Config, request: RpcRequest = rpcRequest, scope: "local" | "all" = "all"): Promise<void> {
  parseConfig(cfg);
  const verifyChain = async (url: string, expectedChain: number, pins: ContractPin[], local: boolean, label: string) => {
    try {
      const chain = await request(url, "eth_chainId", []);
      if (chain !== toHex(expectedChain)) throw new Error("Chain ID mismatch");
      if (local) {
        const genesis = await request(url, "eth_getBlockByNumber", ["0x0", false]) as { hash?: string } | null;
        if (genesis?.hash !== cfg.identity.genesisHash) throw new Error("Genesis hash mismatch");
      }
      const block = await request(url, "eth_blockNumber", []);
      if (typeof block !== "string" || !/^0x[0-9a-f]+$/i.test(block)) throw new Error("Invalid block height");
      await verifyPins(url, pins, block as Hex, request);
      if (local) {
        const call = (to: Address, data: Hex) => request(url, "eth_call", [{ to, data }, block]);
        const { accountFactory, accountBeacon, accountImplementation } = cfg.identity;
        const beacon = await call(accountFactory.address, encodeFunctionData({ abi: factoryAbi, functionName: "accountBeacon" }));
        const implementation = await call(accountBeacon.address, encodeFunctionData({ abi: beaconAbi, functionName: "implementation" }));
        const encodedAddress = (address: Address) => encodeAbiParameters([{ type: "address" }], [address]);
        if (beacon !== encodedAddress(accountBeacon.address)) throw new Error("Factory beacon mismatch");
        if (implementation !== encodedAddress(accountImplementation.address)) throw new Error("Account implementation mismatch");
        const owner = "0x0000000000000000000000000000000000000001";
        const account = await call(accountFactory.address, encodeFunctionData({ abi: factoryAbi, functionName: "getAddress", args: [owner, [zero32, zero32], 0n] }));
        if (account !== encodedAddress(deriveSmartAccount(cfg, owner))) throw new Error("Factory derivation mismatch");
      }
    } catch (error) {
      // Avoid forwarding RPC bodies, URL credentials or generic serialized objects.
      const reason = error instanceof RpcUnavailable || (error instanceof Error && /^(Chain ID|Genesis hash|Contract code|Factory beacon|Account implementation|Factory derivation|Invalid block)/.test(error.message))
        ? error.message : "RPC verification unavailable";
      throw new NetworkError("wallet_network_mismatch", `${label}: ${reason}`);
    }
  };
  await Promise.all([
    ...cfg.endpoints.rpcUrls.map((url, index) => verifyChain(url, cfg.identity.chainId, localContractPins(cfg), true, `local RPC ${index + 1}`)),
    ...(scope === "all" && cfg.manifest.bridge.enabled ? Object.entries(cfg.manifest.bridge.remoteChains).flatMap(([name, chain]) =>
      cfg.endpoints.remoteChains[name].rpcUrls.map((url, index) => verifyChain(url, chain.chainId, remoteContractPins(cfg, name), false, `${name} RPC ${index + 1}`))) : []),
  ]);
}

export function networkStatusFields(cfg: Config) {
  const i = cfg.identity;
  return {
    network_id: i.networkId, network_identity: i, manifest_id: cfg.manifest.manifestId, capability_manifest: cfg.manifest,
    genesis_hash: i.genesisHash, account_derivation: i.accountDerivation, account_init_code_hash: i.accountInitCodeHash,
    account_version: i.accountVersion, native_symbol: i.nativeSymbol, user_op_version: i.userOpVersion, signing_scheme: i.signingScheme,
  };
}

/** Phase 3 calls this before wallet creation/loading and every signing session. */
export async function verifyWalletSession(cfg: Config, wallet?: Parameters<typeof assertWalletNetwork>[1], scope: "local" | "all" = "local"): Promise<void> {
  if (wallet) assertWalletNetwork(cfg, wallet);
  await verifyNetwork(cfg, undefined, scope);
}
