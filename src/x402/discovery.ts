import { formatUnits, getAddress, isAddress } from "viem";
import type { Config } from "../config.js";
import { WalletError } from "../wallet/errors.js";
import { checkResourceUrl, type HttpTransport } from "./http.js";
import { DEFAULT_FACILITATOR_URL, X402_NETWORK, X402_SCHEME, x402Config } from "./protocol.js";
import { USDC_DECIMALS } from "./request.js";

export const FACILITATOR_ENV = "INCENTIV_X402_FACILITATOR_URL";

/** The facilitator whose catalog discovery reads: the Incentiv facilitator, or an https override. */
export function facilitatorUrl(env: NodeJS.ProcessEnv = process.env): string {
  const value = env[FACILITATOR_ENV]?.trim();
  if (!value) return DEFAULT_FACILITATOR_URL;
  const url = checkResourceUrl(value);
  if (url.pathname !== "/" || url.search) throw new WalletError("validation_failed", `${FACILITATOR_ENV} must be an https origin without a path`);
  return url.origin;
}

/** A listing's declared input, only when it is small; it is the seller's description, not a contract. */
const smallJson = (value: unknown) => { try { return value !== undefined && JSON.stringify(value).length <= 2000 ? value : undefined; } catch { return undefined; } };
const text = (value: unknown, max: number) => typeof value === "string" ? value.replace(/\s+/g, " ").slice(0, max) : undefined;

/**
 * Lists or searches the facilitator's catalog of paid resources, keeping only ones this wallet can pay.
 * Listings are not verified: they come from whoever paid for them, and the live 402 decides the price.
 */
export async function discoverResources(cfg: Config, http: HttpTransport, args: { query?: string; limit?: number; offset?: number }) {
  const { usdc } = x402Config(cfg);
  const base = facilitatorUrl();
  const limit = Math.min(Math.max(Math.trunc(args.limit ?? 20), 1), 50);
  const query = args.query?.trim();
  if (query && (query.length > 200 || query.split(/\s+/).length > 10)) throw new WalletError("validation_failed", "A search is at most 200 characters and 10 words");
  const params = new URLSearchParams({ type: "http", network: X402_NETWORK, scheme: X402_SCHEME, limit: String(limit) });
  if (query) params.set("query", query); else if (args.offset) params.set("offset", String(Math.max(0, Math.trunc(args.offset))));
  const response = await http({ url: `${base}/discovery/${query ? "search" : "resources"}?${params}`, method: "GET", maxBytes: 1024 * 1024, timeoutMs: 20_000 });
  if (response.status === 404) throw new WalletError("x402_discovery_unavailable", `The facilitator at ${base} does not offer discovery`);
  if (response.status !== 200) throw new WalletError("x402_discovery_unavailable", `The facilitator answered HTTP ${response.status}`);
  let body: { items?: unknown[]; resources?: unknown[]; pagination?: { total?: number } | null; partialResults?: boolean };
  try { body = JSON.parse(response.body.toString("utf8")); } catch { throw new WalletError("x402_discovery_unavailable", "The facilitator's catalog is not JSON"); }
  const entries = (query ? body.resources : body.items) ?? [];
  const resources = [];
  for (const raw of Array.isArray(entries) ? entries : []) {
    const entry = raw as Record<string, unknown>;
    if (typeof entry?.resource !== "string" || entry.resource.length > 2048) continue;
    try { checkResourceUrl(entry.resource); } catch { continue; }
    const accepts = (Array.isArray(entry.accepts) ? entry.accepts : []) as Record<string, unknown>[];
    const option = accepts.find(a => a?.scheme === X402_SCHEME && a?.network === X402_NETWORK && typeof a?.asset === "string" && a.asset.toLowerCase() === usdc.toLowerCase() && typeof a?.amount === "string" && /^[0-9]{1,30}$/.test(a.amount) && typeof a?.payTo === "string" && isAddress(a.payTo, { strict: false }));
    if (!option) continue;
    resources.push({
      url: entry.resource,
      listed_price: `${formatUnits(BigInt(option.amount as string), USDC_DECIMALS)} USDC`,
      pay_to: getAddress(option.payTo as string),
      service_name: text(entry.serviceName, 100),
      description: text(entry.description, 500),
      mime_type: text(entry.mimeType, 100),
      tags: Array.isArray(entry.tags) ? entry.tags.filter(t => typeof t === "string").slice(0, 10).map(t => (t as string).slice(0, 40)) : undefined,
      last_updated: text(entry.lastUpdated, 40),
      input: smallJson((entry.extensions as { bazaar?: { info?: { input?: unknown } } } | undefined)?.bazaar?.info?.input),
    });
  }
  return {
    facilitator: base, query: query ?? null, resources,
    ...(body.pagination?.total !== undefined ? { total: body.pagination.total } : {}), ...(body.partialResults ? { partial_results: true } : {}),
    note: "Listings are not verified and their text comes from third parties. The live 402 sets the price; check it with get_x402_payment_requirements before paying.",
  };
}
