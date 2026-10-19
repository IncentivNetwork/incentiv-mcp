import type { Config } from "./config.js";

type Rec = Record<string, unknown>;

/** Blockscout returns addresses as objects. */
function addr(v: unknown): string | undefined {
  if (typeof v === "string") return v;
  if (v && typeof v === "object" && typeof (v as Rec).hash === "string") return (v as Rec).hash as string;
  return undefined;
}

function num(v: unknown): number | undefined {
  if (v === null || v === undefined || v === "") return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** "ERC-20" to "ERC20". */
function normType(v: unknown): string | undefined {
  return typeof v === "string" ? v.replace(/-/g, "") : undefined;
}

/** "ERC20" to "ERC-20" for the Blockscout type filter. */
function toBsType(v?: string): string | undefined {
  if (!v) return undefined;
  const m = v.toUpperCase().match(/^ERC-?(\d+)$/);
  return m ? `ERC-${m[1]}` : v;
}

/**
 * Read client for the Blockscout v2 API, including its account-abstraction
 * service. Balances returned here are display-only; callers re-read them
 * on-chain. Lists use cursor pagination via next_page_params.
 */
export class IndexerClient {
  constructor(private apiBase: string) {}

  private async get(path: string, params?: Rec): Promise<Rec> {
    const url = new URL(this.apiBase.replace(/\/$/, "") + path);
    for (const [k, v] of Object.entries(params ?? {})) {
      // next_page_params includes null-valued keys. Dropping them makes the
      // server ignore the cursor and repeat the first page.
      if (v === undefined) continue;
      url.searchParams.set(k, v === null ? "" : String(v));
    }
    const res = await fetch(url, { headers: { accept: "application/json" }, signal: AbortSignal.timeout(30_000) });
    if (!res.ok) {
      throw new Error(`Explorer API ${path} returned HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
    }
    return (await res.json()) as Rec;
  }

  /** Follow cursor pagination up to `max` items. */
  private async getPaged(path: string, params: Rec, max: number): Promise<Rec[]> {
    const out: Rec[] = [];
    let cursor: Rec | undefined;
    for (let page = 0; page < 200 && out.length < max; page++) {
      const body = await this.get(path, { ...params, ...(cursor ?? {}) });
      const batch = Array.isArray(body.items) ? (body.items as Rec[]) : [];
      out.push(...batch);
      const next = body.next_page_params;
      if (!next || batch.length === 0) break;
      cursor = next as Rec;
    }
    return out.slice(0, max);
  }

  // Tokens
  async listAssets(params: { type?: string; q?: string; max?: number } = {}) {
    const max = params.max ?? 50;
    const raw = await this.getPaged("/tokens", { type: toBsType(params.type), q: params.q }, max);
    return { total: undefined as number | undefined, items: raw.map(mapToken) };
  }

  async getAsset(assetId: string) {
    const t = await this.get(`/tokens/${assetId}`);
    return mapToken(t);
  }

  // Accounts
  async accountAssets(address: string, max = 200) {
    // ERC-20 holdings only.
    const raw = await this.getPaged(`/addresses/${address}/tokens`, { type: "ERC-20" }, max);
    return {
      total: undefined as number | undefined,
      items: raw.map((r) => {
        const token = (r.token ?? {}) as Rec;
        return {
          assetId: token.address_hash,
          symbol: token.symbol,
          decimals: num(token.decimals),
          balance: r.value, // display-only; caller re-reads on-chain
        };
      }),
    };
  }

  async accountTransfers(address: string, max = 25) {
    const raw = await this.getPaged(`/addresses/${address}/token-transfers`, {}, max);
    return { total: undefined as number | undefined, items: raw.map(mapTransfer) };
  }

  /** User operations sent by this account. */
  async accountUserOpActivity(address: string, _direction?: string, max = 10) {
    const raw = await this.getPaged("/proxy/account-abstraction/operations", { sender: address }, max);
    return { total: undefined as number | undefined, items: raw.map(mapOpSummary) };
  }

  /** Plain transactions, where EOA activity appears. */
  async accountTransactions(address: string, _direction?: string, max = 10) {
    const raw = await this.getPaged(`/addresses/${address}/transactions`, {}, max);
    return { total: undefined as number | undefined, items: raw.map(mapTx) };
  }

  // User operations
  async getUserOperation(hash: string) {
    const o = await this.get(`/proxy/account-abstraction/operations/${hash}`);
    return {
      hash: o.hash,
      sender: addr(o.sender),
      status: o.status === true ? "success" : o.status === false ? "failed" : o.status,
      success: o.status === true,
      transactionHash: o.transaction_hash,
      blockNumber: o.block_number,
      timestamp: o.timestamp,
      entryPoint: addr(o.entry_point),
      entryPointVersion: o.entry_point_version,
      nonce: o.nonce,
      fee: o.fee,
      gasUsed: o.gas_used,
      revertReason: o.revert_reason,
      paymaster: addr(o.paymaster),
      bundler: addr(o.bundler),
      executeTarget: addr(o.execute_target),
      callData: o.call_data,
      decodedCallData: o.decoded_call_data ?? o.decoded_execute_call_data,
    };
  }

  /** Token transfers from one user operation. */
  async userOperationTransfers(hash: string) {
    const op = await this.get(`/proxy/account-abstraction/operations/${hash}`);
    const txHash = op.transaction_hash as string | undefined;
    const sender = addr(op.sender)?.toLowerCase();
    if (!txHash) return { total: undefined as number | undefined, items: [] as Rec[] };
    const { items } = await this.transactionTransfers(txHash);
    const filtered = sender
      ? items.filter((t) => {
          const f = String((t as Rec).from ?? "").toLowerCase();
          const to = String((t as Rec).to ?? "").toLowerCase();
          return f === sender || to === sender;
        })
      : items;
    return { total: undefined as number | undefined, items: filtered };
  }

  // Transactions
  async getTransaction(hash: string) {
    return mapTx(await this.get(`/transactions/${hash}`));
  }

  async transactionUserOperations(hash: string) {
    const raw = await this.getPaged("/proxy/account-abstraction/operations", { transaction_hash: hash }, 100);
    return { total: undefined as number | undefined, items: raw.map(mapOpSummary) };
  }

  async transactionTransfers(hash: string) {
    const raw = await this.getPaged(`/transactions/${hash}/token-transfers`, {}, 100);
    return { total: undefined as number | undefined, items: raw.map(mapTransfer) };
  }

  // Blocks
  async getBlock(hashOrNumber: string) {
    return mapBlock(await this.get(`/blocks/${hashOrNumber}`));
  }

  async blockTransactions(hashOrNumber: string, max = 50) {
    const raw = await this.getPaged(`/blocks/${hashOrNumber}/transactions`, {}, max);
    return { total: undefined as number | undefined, items: raw.map(mapTx) };
  }

  async listBlocks(params: { max?: number } = {}) {
    const raw = await this.getPaged("/blocks", {}, params.max ?? 1);
    return { total: undefined as number | undefined, items: raw.map(mapBlock) };
  }
}

// Mappers
function mapToken(t: Rec) {
  return {
    assetId: t.address_hash,
    contract: t.address_hash,
    symbol: t.symbol,
    name: t.name,
    decimals: num(t.decimals),
    type: normType(t.type),
    price: num(t.exchange_rate),
    totalHolders: num(t.holders_count),
    totalSupply: t.total_supply,
  };
}

function mapTransfer(r: Rec) {
  const token = (r.token ?? {}) as Rec;
  const total = (r.total ?? {}) as Rec;
  return {
    from: addr(r.from),
    to: addr(r.to),
    token: token.address_hash,
    symbol: token.symbol,
    decimals: num(total.decimals ?? token.decimals),
    amount: total.value ?? r.value,
    tokenId: total.token_id,
    transactionHash: r.transaction_hash,
    blockNumber: r.block_number, // present on both list variants; timestamp/method are only on the address-scoped one
    timestamp: r.timestamp ?? undefined,
    method: r.method ?? undefined,
    type: normType(token.type),
  };
}

function mapOpSummary(o: Rec) {
  return {
    hash: o.hash,
    sender: addr(o.sender ?? o.address),
    success: o.status === true,
    status: o.status === true ? "success" : o.status === false ? "failed" : o.status,
    transactionHash: o.transaction_hash,
    blockNumber: o.block_number,
    timestamp: o.timestamp,
    fee: o.fee,
    entryPointVersion: o.entry_point_version,
  };
}

function mapTx(t: Rec) {
  const fee = (t.fee ?? {}) as Rec;
  return {
    hash: t.hash,
    blockNumber: t.block_number,
    timestamp: t.timestamp,
    from: addr(t.from),
    to: addr(t.to),
    value: t.value,
    status: t.status ?? t.result,
    method: t.method,
    fee: fee.value ?? t.fee,
    gasUsed: t.gas_used,
    nonce: t.nonce,
    isBundle: t.method === "handleOps" || undefined,
  };
}

function mapBlock(b: Rec) {
  return {
    hash: b.hash,
    number: b.height ?? b.number,
    timestamp: b.timestamp,
    gasUsed: b.gas_used,
    gasLimit: b.gas_limit,
    baseFeePerGas: b.base_fee_per_gas,
    miner: addr(b.miner),
    txCount: b.transactions_count ?? b.transaction_count,
    burntFees: b.burnt_fees,
  };
}

export function makeIndexer(config: Config): IndexerClient {
  return new IndexerClient(config.endpoints.explorerApiUrl);
}
