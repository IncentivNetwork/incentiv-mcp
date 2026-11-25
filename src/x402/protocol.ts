import { decodePaymentRequiredHeader, decodePaymentResponseHeader, encodePaymentSignatureHeader } from "@x402/core/http";
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

/** Reads the 402: the v2 `PAYMENT-REQUIRED` header, or a v2 body. Anything else is not an x402 v2 answer. */
export function parsePaymentRequired(response: HttpResponse): PaymentRequired {
  const header = response.headers["payment-required"];
  let parsed: unknown;
  try {
    if (header) parsed = decodePaymentRequiredHeader(header);
    else parsed = JSON.parse(response.body.toString("utf8"));
  } catch { throw new WalletError("x402_invalid_response", "The 402 answer has no readable x402 payment requirements"); }
  const required = parsed as PaymentRequired;
  if (!required || typeof required !== "object" || required.x402Version !== 2 || !Array.isArray(required.accepts) || !required.accepts.length) {
    throw new WalletError("x402_invalid_response", "The 402 answer is not an x402 v2 payment request");
  }
  return required;
}

/** The first payment option this wallet can pay: Incentiv USDC through the pinned EntryPoint. */
export function selectRequirements(required: PaymentRequired, cfg: Config): PaymentRequirements {
  const { usdc, entryPoint } = x402Config(cfg);
  const usable = required.accepts.find(r => r && r.scheme === X402_SCHEME && r.network === X402_NETWORK
    && typeof r.asset === "string" && r.asset.toLowerCase() === usdc.toLowerCase()
    && typeof r.amount === "string" && /^[1-9][0-9]{0,30}$/.test(r.amount)
    && typeof r.payTo === "string" && /^0x[0-9a-fA-F]{40}$/.test(r.payTo)
    && Number.isInteger(r.maxTimeoutSeconds) && r.maxTimeoutSeconds > 0 && r.maxTimeoutSeconds <= X402_MAX_TIMEOUT_SECONDS
    && typeof r.extra?.entryPoint === "string" && r.extra.entryPoint.toLowerCase() === entryPoint.toLowerCase());
  if (!usable) {
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
