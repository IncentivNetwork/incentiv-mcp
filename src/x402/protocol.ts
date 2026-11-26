import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from "@x402/core/http";
import { PaymentRequiredV2Schema } from "@x402/core/schemas";
import type { PaymentPayload, PaymentRequired, PaymentRequirements, SettleResponse } from "@x402/core/types";
import { encodeAbiParameters, keccak256, type Address, type Hex } from "viem";
import type { Config } from "../config.js";
import { WalletError } from "../wallet/errors.js";
import type { HttpResponse } from "./http.js";

/** The Incentiv x402 network and the scheme an Incentiv smart account pays with (`@incentiv/x402` SPEC sections 1 and 4). */
export const X402_NETWORK = "eip155:24101";
export const X402_SCHEME = "incentiv-userop";
export const X402_CHAIN_ID = 24101;
/** The facilitator caps `maxTimeoutSeconds` at 300 (SPEC 2.1). */
export const X402_MAX_TIMEOUT_SECONDS = 300;
/** A shorter payment window could close while the payment is built, simulated and sent, after it was journaled. */
export const X402_MIN_TIMEOUT_SECONDS = 30;
export const DEFAULT_FACILITATOR_URL = "https://x402.incentiv.io";

/** The `@incentiv/x402` contract set for this network, built from the verified local configuration. */
export function x402Config(cfg: Config) {
  const usdc = cfg.manifest.canonicalTokens.USDC?.address;
  if (cfg.identity.chainId !== X402_CHAIN_ID || !usdc) throw new WalletError("validation_failed", "x402 payments are available only on Incentiv mainnet");
  const c = cfg.manifest.contracts;
  return {
    chainId: cfg.identity.chainId, rpcUrl: cfg.endpoints.rpcUrls[0], bundlerUrl: cfg.endpoints.bundlerUrl,
    entryPoint: cfg.identity.entryPoint.address, accountFactory: cfg.identity.accountFactory.address,
    paymaster: c.unifiedTokenPaymaster.address, transferGate: c.transferGate.address, quoter: c.quoter.address, wcent: c.wcent.address, usdc,
  };
}

/** The nonce lane of one payment: the top 192 bits of keccak256(abi.encode(paymentId, validUntil)) (SPEC 4.3 item 2). */
export function paymentNonceKey(paymentId: Hex, validUntil: number): bigint {
  return BigInt(keccak256(encodeAbiParameters([{ type: "bytes32" }, { type: "uint64" }], [paymentId, BigInt(validUntil)]))) >> 64n;
}

/**
 * Reads the 402: the v2 `PAYMENT-REQUIRED` header, or a v2 body that passes `@x402/core`'s v2 schema. Anything
 * else is not an x402 v2 answer. A valid one shows the resource asked for payment, whether or not this wallet can pay it.
 */
export function parsePaymentRequired(response: HttpResponse): PaymentRequired {
  const header = response.headers["payment-required"];
  if (!header && response.incomplete) throw new WalletError("x402_invalid_response", "The payment requirements response was interrupted");
  let parsed: unknown;
  try {
    if (header) parsed = decodePaymentRequiredHeader(header);
    else parsed = JSON.parse(response.body.toString("utf8"));
  } catch { throw new WalletError("x402_invalid_response", "The 402 answer has no readable x402 payment requirements"); }
  const required = parsed as PaymentRequired;
  if (!required || typeof required !== "object" || required.x402Version !== 2 || !Array.isArray(required.accepts) || !required.accepts.length || !PaymentRequiredV2Schema.safeParse(required).success) {
    throw new WalletError("x402_invalid_response", "The 402 answer is not an x402 v2 payment request");
  }
  return required;
}

/** The cheapest option this wallet can pay, shared by catalog discovery and live quotes. */
export function findUsableRequirements(accepts: unknown[], { usdc, entryPoint }: Pick<ReturnType<typeof x402Config>, "usdc" | "entryPoint">) {
  const usable = accepts.filter((candidate): candidate is PaymentRequirements => {
    const r = candidate as Partial<PaymentRequirements> | null | undefined;
    return !!r && r.scheme === X402_SCHEME && r.network === X402_NETWORK
      && typeof r.asset === "string" && r.asset.toLowerCase() === usdc.toLowerCase()
      && typeof r.amount === "string" && /^[1-9][0-9]{0,30}$/.test(r.amount)
      && typeof r.payTo === "string" && /^0x[0-9a-fA-F]{40}$/.test(r.payTo)
      && typeof r.maxTimeoutSeconds === "number" && Number.isInteger(r.maxTimeoutSeconds)
      && r.maxTimeoutSeconds >= X402_MIN_TIMEOUT_SECONDS && r.maxTimeoutSeconds <= X402_MAX_TIMEOUT_SECONDS
      && typeof r.extra?.entryPoint === "string" && r.extra.entryPoint.toLowerCase() === entryPoint.toLowerCase();
  });
  // Every usable option is USDC on this network, so they differ only in price; the first listed wins a tie.
  return usable.reduce<PaymentRequirements | undefined>((best, r) => !best || BigInt(r.amount) < BigInt(best.amount) ? r : best, undefined);
}

/** A payable live option, or a reason why the requested payment is unsupported. */
export function selectRequirements(required: PaymentRequired, cfg: Config): PaymentRequirements {
  const usable = findUsableRequirements(required.accepts, x402Config(cfg));
  if (!usable) {
    const short = required.accepts.find(r => r && r.scheme === X402_SCHEME && r.network === X402_NETWORK && Number.isInteger(r.maxTimeoutSeconds) && r.maxTimeoutSeconds < X402_MIN_TIMEOUT_SECONDS);
    if (short) throw new WalletError("x402_unsupported", `The resource allows only ${short.maxTimeoutSeconds} seconds to pay, too short to prepare and send a payment (this wallet needs at least ${X402_MIN_TIMEOUT_SECONDS}); nothing was paid`);
    const offered = [...new Set(required.accepts.map(r => `${String(r?.scheme).slice(0, 40)} on ${String(r?.network).slice(0, 40)}`))].slice(0, 8).join(", ");
    throw new WalletError("x402_unsupported", `The resource accepts no payment this wallet can make (it needs ${X402_SCHEME} in USDC on ${X402_NETWORK}; offered: ${offered})`);
  }
  return usable;
}

/** The `PAYMENT-SIGNATURE` header for a signed `incentiv-userop` payment (SPEC 4.2). */
export function paymentHeader(accepted: PaymentRequirements, resource: PaymentRequired["resource"] | undefined, userOperation: Record<string, string>, userOpHash: Hex, paymentId: Hex, validUntil: number): string {
  const payload: PaymentPayload = { x402Version: 2, ...(resource ? { resource } : {}), accepted, payload: { userOperation, userOpHash, paymentId, validUntil } };
  return encodePaymentSignatureHeader(payload);
}

/** The settlement the seller reports in `PAYMENT-RESPONSE`, or undefined when it sent none or it is unreadable. */
export function settlement(response: HttpResponse): SettleResponse | undefined {
  const header = response.headers["payment-response"];
  if (!header) return;
  try { return decodePaymentResponseHeader(header); } catch { return; }
}

/** Lazily loads `@incentiv/x402`: its root module also carries the facilitator, so it is not loaded at startup. */
export async function incentivX402() {
  return import("@incentiv/x402");
}

export type { PaymentRequired, PaymentRequirements, SettleResponse };
export type X402Address = Address;
