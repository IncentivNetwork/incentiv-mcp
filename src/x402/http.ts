import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { Agent, request as httpsRequest } from "node:https";
import { BlockList, isIP, type LookupFunction } from "node:net";
import { WalletError } from "../wallet/errors.js";

/**
 * Outbound HTTPS for x402. The URLs come from an agent or from a discovery listing, and the request runs on the
 * user's computer, so it must not reach the user's own network: only https, no credentials in the URL, no
 * redirects, and every address the name resolves to must be public. The check runs on the addresses the
 * connection actually uses, so a name cannot pass the check and then resolve somewhere private.
 */

export interface HttpRequest {
  url: string;
  method: "GET" | "POST";
  headers?: Record<string, string>;
  body?: string;
  /** Bytes kept from the response body; the rest is dropped and `truncated` is set. */
  maxBytes: number;
  timeoutMs?: number;
}
export interface HttpResponse {
  status: number;
  /** Lowercase header names. */
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
}
export type HttpTransport = (request: HttpRequest) => Promise<HttpResponse>;

const v4 = new BlockList();
for (const [net, prefix] of [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]] as const) v4.addSubnet(net, prefix, "ipv4");
// IPv6 is allowed only in global unicast (2000::/3), less documentation, 6to4 and Teredo, which embed other addresses.
const v6Global = new BlockList(); v6Global.addSubnet("2000::", 3, "ipv6");
const v6 = new BlockList();
for (const [net, prefix] of [["2001::", 32], ["2001:db8::", 32], ["2002::", 16], ["2001:10::", 28], ["2001:20::", 28]] as const) v6.addSubnet(net, prefix, "ipv6");

/** Whether an IP address is one this server may connect to on the user's behalf. */
export function isPublicAddress(address: string): boolean {
  const family = isIP(address);
  if (family === 4) return !v4.check(address, "ipv4");
  if (family !== 6) return false;
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(address);
  if (mapped) return isPublicAddress(mapped[1]);
  return v6Global.check(address, "ipv6") && !v6.check(address, "ipv6");
}

const PRIVATE_NAMES = /(^|\.)(localhost|local|internal|home\.arpa|lan|intranet|corp)$/i;

/** Parses and checks a resource URL before any network use; returns it normalised. */
export function checkResourceUrl(value: string): URL {
  let url: URL;
  try { url = new URL(value); } catch { throw new WalletError("validation_failed", "Enter a complete https URL"); }
  if (url.protocol !== "https:") throw new WalletError("validation_failed", "x402 resources must use https");
  if (url.username || url.password) throw new WalletError("validation_failed", "Credentials in the URL are not allowed");
  const host = url.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (!host || PRIVATE_NAMES.test(host) || !host.includes(".") && !isIP(host)) throw new WalletError("validation_failed", "The resource host must be a public domain name or address");
  if (isIP(host) && !isPublicAddress(host)) throw new WalletError("validation_failed", "The resource address is not public");
  url.hash = "";
  return url;
}

/** DNS lookup that fails unless every address for the name is public. */
const publicLookup: LookupFunction = (hostname, options, callback) => {
  dnsLookup(hostname, { ...options, all: true }, (error, addresses) => {
    if (error) return callback(error, "", 0);
    const list = addresses as unknown as LookupAddress[];
    if (!list.length || list.some(a => !isPublicAddress(a.address))) {
      return callback(Object.assign(new Error(`${hostname} resolves to a non-public address`), { code: "EX402PRIVATE" }), "", 0);
    }
    if ((options as { all?: boolean }).all) return (callback as unknown as (e: null, a: LookupAddress[]) => void)(null, list);
    callback(null, list[0].address, list[0].family);
  });
};

/** Headers a caller may not set: they belong to the transport or to the payment itself. */
const RESERVED_HEADERS = new Set(["host", "content-length", "transfer-encoding", "connection", "keep-alive", "upgrade", "te", "trailer", "proxy-authorization", "proxy-connection", "expect", "payment-signature", "payment-required", "payment-response", "x-payment", "x-payment-response"]);
const TOKEN = /^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$/;

/** Validates caller headers: at most 20, printable values, none reserved. */
export function checkHeaders(headers: Record<string, string> | undefined): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers ?? {})) {
    if (!TOKEN.test(name) || RESERVED_HEADERS.has(name.toLowerCase())) throw new WalletError("validation_failed", `Header ${JSON.stringify(name.slice(0, 64))} is not allowed`);
    if (typeof value !== "string" || value.length > 2048 || /[^\t\x20-\x7e]/.test(value)) throw new WalletError("validation_failed", `Header ${name} must be printable ASCII of at most 2048 characters`);
    out[name.toLowerCase()] = value;
  }
  if (Object.keys(out).length > 20) throw new WalletError("validation_failed", "At most 20 headers");
  return out;
}

/**
 * The transport's own agent. Node's global agent follows HTTPS_PROXY when NODE_USE_ENV_PROXY is set, and a proxy
 * resolves the target itself, past publicLookup, and receives the payment header. An agent created without
 * `proxyEnv` always connects directly, so the guarded lookup checks the address actually used.
 */
export const directAgent = new Agent({ keepAlive: false });

/** The default transport: one HTTPS request, no redirects, public addresses only, bounded size and time. */
export const httpsTransport: HttpTransport = (req) => new Promise((resolve, reject) => {
  const url = checkResourceUrl(req.url);
  const body = req.body === undefined ? undefined : Buffer.from(req.body, "utf8");
  const headers: Record<string, string> = { "user-agent": "incentiv-mcp", accept: "application/json, text/*;q=0.9, */*;q=0.5", ...req.headers };
  if (body) { headers["content-length"] = String(body.length); headers["content-type"] ??= "application/json"; }
  const timeout = req.timeoutMs ?? 60_000;
  const call = httpsRequest(url, { method: req.method, headers, agent: directAgent, lookup: publicLookup, timeout }, res => {
    const chunks: Buffer[] = [];
    let size = 0, truncated = false;
    res.on("data", (chunk: Buffer) => {
      if (truncated) return;
      const room = req.maxBytes - size;
      if (chunk.length > room) { chunks.push(chunk.subarray(0, room)); size = req.maxBytes; truncated = true; res.destroy(); return; }
      chunks.push(chunk); size += chunk.length;
    });
    let done = false;
    const finish = () => {
      if (done) return; done = true;
      const out: Record<string, string> = {};
      for (const [name, value] of Object.entries(res.headers)) if (value !== undefined) out[name.toLowerCase()] = Array.isArray(value) ? value.join(", ") : value;
      resolve({ status: res.statusCode ?? 0, headers: out, body: Buffer.concat(chunks), truncated });
    };
    res.on("end", finish);
    res.on("close", () => { if (truncated) finish(); });
    res.on("error", error => truncated ? finish() : reject(error));
  });
  const deadline = setTimeout(() => call.destroy(new Error("The resource did not answer in time")), timeout);
  call.on("close", () => clearTimeout(deadline));
  call.on("timeout", () => call.destroy(new Error("The resource did not answer in time")));
  call.on("error", error => reject((error as { code?: string }).code === "EX402PRIVATE" ? new WalletError("validation_failed", error.message) : error));
  call.end(body);
});
