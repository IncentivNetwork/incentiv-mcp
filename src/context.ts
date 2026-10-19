import {
  createPublicClient,
  http,
  formatUnits,
  getAddress,
  isAddress,
  type Address,
  type PublicClient,
} from "viem";
import type { Config } from "./config.js";
import { deriveSmartAccount } from "./network.js";
import { IndexerClient, makeIndexer } from "./indexer.js";
import { erc20Abi } from "./abi.js";

export const NATIVE = "native" as const;
/** Zero P-256 public key selects the EOA-owner path in the factory. */
export const ZERO32 = `0x${"0".repeat(64)}` as const;

export interface TokenInfo {
  /** Token contract address, or "native" for CENT. */
  address: Address | typeof NATIVE;
  symbol: string;
  name: string;
  decimals: number;
  /** USD price reported by the explorer, when available. */
  price?: number;
  /** Holder count, used to disambiguate duplicate symbols. */
  holders?: number;
}

export class Ctx {
  readonly client: PublicClient;
  readonly indexer: IndexerClient;
  private tokenCache = new Map<string, TokenInfo>(); // key: lowercase address or "native"
  private tokenDecimals = new Map<string, number>(); // on-chain units, never overwritten by the explorer
  private tokenListLoaded = 0;
  private tokenListFailedAt = 0;
  private tokenListInflight?: Promise<void>;

  constructor(readonly config: Config) {
    this.client = createPublicClient({ transport: http(config.endpoints.rpcUrls[0], { timeout: 20_000 }) });
    this.indexer = makeIndexer(config);
  }

  async isDeployed(address: Address): Promise<boolean> {
    const code = await this.client.getCode({ address });
    return !!code && code !== "0x";
  }

  /**
   * The smart account an owner EOA controls. The CREATE2 address is
   * deterministic and can receive funds before the account is deployed.
   */
  async deriveSmartAccount(owner: Address, salt = 0n): Promise<Address> {
    return deriveSmartAccount(this.config, owner, salt);
  }

  /** Validate and checksum an address argument. */
  resolveAccount(address?: string): Address {
    if (!address) throw new Error("An `address` is required.");
    if (!isAddress(address)) throw new Error(`Not a valid address: ${address}`);
    return getAddress(address);
  }

  /** Load the token list into the cache, refreshed every five minutes. */
  private async loadTokenList(): Promise<void> {
    if (Date.now() - this.tokenListLoaded < 300_000) return;
    if (Date.now() - this.tokenListFailedAt < 20_000) return; // backoff after a failure
    if (this.tokenListInflight) return this.tokenListInflight; // dedupe concurrent callers

    this.tokenListInflight = (async () => {
      try {
        const { items } = await this.indexer.listAssets({ max: 5000 });
        for (const raw of items) {
          const a = raw as Record<string, unknown>;
          const contract = (a.contract || a.assetId) as string | undefined;
          if (!contract || !isAddress(contract)) continue;
          if (a.type !== "ERC20" && a.type !== "erc20" && a.type !== "native") continue;
          this.tokenCache.set(contract.toLowerCase(), {
            address: getAddress(contract),
            symbol: String(a.symbol ?? ""),
            name: String(a.name ?? ""),
            decimals: Number(a.decimals ?? 18),
            price: typeof a.price === "number" && a.price > 0 ? a.price : undefined,
            holders: typeof a.totalHolders === "number" ? a.totalHolders : undefined,
          });
        }
        this.tokenListLoaded = Date.now();
        this.tokenListFailedAt = 0;
      } catch {
        // Explorer unavailable; addresses still resolve on-chain.
        this.tokenListFailedAt = Date.now();
      } finally {
        this.tokenListInflight = undefined;
      }
    })();
    return this.tokenListInflight;
  }

  nativeToken(): TokenInfo {
    return { address: NATIVE, symbol: this.config.identity.nativeSymbol, name: `${this.config.identity.nativeSymbol} (native)`, decimals: 18 };
  }

  /** Resolve a symbol, address, or the native symbol to a token. */
  async resolveToken(ref: string): Promise<TokenInfo> {
    const trimmed = ref.trim();
    if (trimmed.toUpperCase() === this.config.identity.nativeSymbol || trimmed.toLowerCase() === "native") {
      return this.nativeToken();
    }
    if (isAddress(trimmed)) {
      const key = trimmed.toLowerCase();
      if (!this.tokenCache.has(key)) await this.loadTokenList();
      const listed = this.tokenCache.get(key);
      const address = getAddress(trimmed);
      const [symbol, name, decimals] = await Promise.all([
        listed?.symbol ?? this.client.readContract({ address, abi: erc20Abi, functionName: "symbol" }).catch(() => "?"),
        listed?.name ?? this.client.readContract({ address, abi: erc20Abi, functionName: "name" }).catch(() => "?"),
        this.tokenDecimals.get(key) ?? this.client.readContract({ address, abi: erc20Abi, functionName: "decimals" }),
      ]);
      if (!Number.isInteger(decimals) || decimals < 0 || decimals > 255) throw new Error("Invalid on-chain token decimals");
      const info: TokenInfo = { ...listed, address, symbol, name, decimals };
      this.tokenDecimals.set(key, decimals);
      this.tokenCache.set(key, info);
      return info;
    }
    // Canonical addresses win outright; the open token list contains duplicates.
    await this.loadTokenList();
    const canonical = this.config.manifest.canonicalTokens[trimmed.toUpperCase()];
    if (canonical) return this.resolveToken(canonical.address);
    let matches = [...this.tokenCache.values()].filter(
      (t) => t.symbol.toUpperCase() === trimmed.toUpperCase(),
    );
    if (matches.length === 0) {
      // Token search covers entries beyond what the cache loaded.
      try {
        const { items } = await this.indexer.listAssets({ q: trimmed, max: 50 });
        for (const raw of items) {
          const a = raw as Record<string, unknown>;
          const contract = (a.contract || a.assetId) as string | undefined;
          if (contract && isAddress(contract) && String(a.symbol ?? "").toUpperCase() === trimmed.toUpperCase()) {
            // One bad candidate must not abort the rest.
            try {
              matches.push(await this.resolveToken(contract));
            } catch {
              /* skip this candidate */
            }
          }
        }
      } catch {
        /* fall through to the error below */
      }
    }
    if (matches.length === 0) {
      throw new Error(
        `Unknown token "${ref}". Use list_assets to see available tokens, or pass the token's 0x address.`,
      );
    }
    if (matches.length > 1) {
      // Resolve only when one candidate dominates by holder count; otherwise
      // refuse, since picking wrong means sending to the wrong token.
      const byHolders = [...matches].sort((a, b) => (b.holders ?? 0) - (a.holders ?? 0));
      const top = byHolders[0].holders ?? 0;
      const next = byHolders[1].holders ?? 0;
      if (top > 0 && top >= next * 10) return this.resolveToken(byHolders[0].address);
      throw new Error(
        `Token symbol "${ref}" is ambiguous on Incentiv: ${byHolders
          .map((m) => `${m.symbol} (${m.name}) at ${m.address}${m.holders !== undefined ? ` [${m.holders} holders]` : ""}`)
          .join("; ")}. Pass the 0x address instead.`,
      );
    }
    return this.resolveToken(matches[0].address);
  }

  /** Token discovery metadata; resolve a token before using its units. */
  async knownTokens(): Promise<TokenInfo[]> {
    await this.loadTokenList();
    return [...this.tokenCache.values()];
  }

  explorerTx(hash: string): string {
    return `${this.config.endpoints.explorerUrl}/tx/${hash}`;
  }
  explorerOp(hash: string): string {
    return `${this.config.endpoints.explorerUrl}/op/${hash}`;
  }
  explorerAddress(addr: string): string {
    return `${this.config.endpoints.explorerUrl}/address/${addr}`;
  }
}

export function fmtAmount(raw: bigint, decimals: number): string {
  return formatUnits(raw, decimals);
}
