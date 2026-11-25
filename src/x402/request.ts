import { createHash } from "node:crypto";
import { parseUnits } from "viem";
import { WalletError } from "../wallet/errors.js";
import { checkHeaders, checkResourceUrl, type HttpResponse } from "./http.js";

/** USDC has 6 decimals on Incentiv (`@incentiv/x402` SPEC section 1). */
export const USDC_DECIMALS = 6;
/** Response bytes kept from a paid or probed resource. */
export const MAX_RESPONSE_BYTES = 256 * 1024;
/** Text returned to the agent; longer text is cut and marked truncated. */
const MAX_TEXT_CHARS = 100_000;
const MAX_BODY_CHARS = 64 * 1024;

export interface X402Request {
  url: string;
  origin: string;
  method: "GET" | "POST";
  headers: Record<string, string>;
  body?: string;
}

/** Validates the caller's request without touching the network. */
export function x402Request(args: Record<string, unknown>): X402Request {
  const url = checkResourceUrl(String(args.url ?? ""));
  const method = String(args.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "POST") throw new WalletError("validation_failed", "Method must be GET or POST");
  if (args.body !== undefined && method !== "POST") throw new WalletError("validation_failed", "Only a POST request has a body");
  const body = args.body === undefined ? undefined : typeof args.body === "string" ? args.body : JSON.stringify(args.body);
  if (body !== undefined && body.length > MAX_BODY_CHARS) throw new WalletError("validation_failed", `The request body is limited to ${MAX_BODY_CHARS} characters`);
  return { url: url.href, origin: url.origin, method, headers: checkHeaders(args.headers as Record<string, string> | undefined), ...(body !== undefined ? { body } : {}) };
}

/** A positive USDC amount in atomic units, from a decimal string, never rounded. */
export function usdcAmount(text: unknown): bigint {
  const value = String(text ?? "");
  if (!/^(?:0|[1-9][0-9]{0,20})(?:\.[0-9]{1,6})?$/.test(value)) throw new WalletError("validation_failed", "max_amount must be a USDC amount with at most 6 decimal places, such as 0.05");
  const amount = parseUnits(value, USDC_DECIMALS);
  if (amount <= 0n) throw new WalletError("validation_failed", "max_amount must be positive");
  return amount;
}

const TEXTUAL = /^(text\/|application\/(json|ld\+json|problem\+json|xml|javascript|x-ndjson|csv|yaml|x-yaml)|[^;]*\+(json|xml))/i;

/**
 * The resource's answer, for the agent. It is third-party content: the agent should treat it as data, never as
 * instructions. Text is returned as text; other content as base64 when small, otherwise only described.
 */
export function responseContent(response: HttpResponse) {
  const type = response.headers["content-type"]?.slice(0, 200) ?? "application/octet-stream";
  const sha256 = createHash("sha256").update(response.body).digest("hex");
  const base = { http_status: response.status, content_type: type, bytes: response.body.length, sha256, truncated: response.truncated, third_party_content: true };
  // Without a declared type, the body is text only if it is valid UTF-8 (a cut may end inside a character).
  const untyped = response.headers["content-type"] ? undefined : utf8(response.body, response.truncated);
  if (TEXTUAL.test(type) || untyped !== undefined) {
    const text = untyped ?? response.body.toString("utf8");
    return { ...base, text: text.length > MAX_TEXT_CHARS ? text.slice(0, MAX_TEXT_CHARS) : text, truncated: response.truncated || text.length > MAX_TEXT_CHARS };
  }
  return response.body.length <= 64 * 1024 ? { ...base, base64: response.body.toString("base64") } : base;
}

function utf8(body: Buffer, truncated: boolean): string | undefined {
  for (let cut = 0; cut <= (truncated ? 3 : 0) && cut <= body.length; cut++) {
    try { return new TextDecoder("utf-8", { fatal: true }).decode(body.subarray(0, body.length - cut)); } catch { /* not UTF-8 at this length */ }
  }
}
