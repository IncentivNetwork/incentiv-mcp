import { randomBytes, scrypt as derive, timingSafeEqual } from "node:crypto";
import { z } from "zod";
import { WalletError } from "./errors.js";

export const uint = z.string().regex(/^(0|[1-9][0-9]*)$/).refine(s => BigInt(s) < 2n ** 256n);
export const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
export const tokenId = z.union([z.literal("native"), address]);
const limits = z.strictObject({ perTransaction: uint, daily: uint, exposure: uint, gasPayment: uint });
export const limitsSchema = z.strictObject({
  tokens: z.record(tokenId, limits),
  recipients: z.discriminatedUnion("mode", [z.strictObject({ mode: z.literal("any") }), z.strictObject({ mode: z.literal("allowlist"), addresses: z.array(address) })]),
  targets: z.record(address, z.array(z.string().regex(/^0x(?:[0-9a-f]{8})?$/))),
  swaps: z.boolean(), maxSlippageBps: z.number().int().min(0).max(1000),
  maxQuoteDeviationBps: z.number().int().min(0).max(1000),
  // The administrator attests that these exact endpoint origins have independent operators.
  independentRpcOrigins: z.array(z.url()).max(16),
  // Explicit local trust, without claiming independent operators. No default:
  // adding fields while parsing would change old envelopes' authenticated data.
  trustedRpcOrigins: z.array(z.url().refine(value => {
    const url = new URL(value);
    return ["https:", "http:"].includes(url.protocol) && value === url.origin;
  }, "Use an exact HTTP(S) origin without a path, credentials or trailing slash")).max(16).optional(),
  maxGasCostWei: uint, maxFeePerGas: uint, maxGasUnits: uint,
  maxBatchCalls: z.number().int().min(1).max(16),
  expiresAt: z.number().int().positive().optional(),
}).superRefine((p, ctx) => {
  const keys = Object.keys(p.tokens).map(k => k.toLowerCase());
  if (!keys.length || new Set(keys).size !== keys.length) ctx.addIssue({ code: "custom", message: "Token entries must be unique and nonempty" });
  for (const l of Object.values(p.tokens)) if (BigInt(l.perTransaction) > BigInt(l.daily)) ctx.addIssue({ code: "custom", message: "Transaction limit exceeds daily limit" });
});
const b64 = (size: number) => z.string().refine(s => Buffer.from(s, "base64").length === size && Buffer.from(s, "base64").toString("base64") === s);
export const adminSchema = z.strictObject({ name: z.literal("scrypt"), N: z.literal(131072), r: z.literal(8), p: z.literal(1), salt: b64(16), verifier: b64(32) });
export const policySchema = z.discriminatedUnion("configured", [
  z.strictObject({ schemaVersion: z.literal(1), enabled: z.literal(false), configured: z.literal(false) }),
  z.strictObject({ schemaVersion: z.literal(1), enabled: z.boolean(), configured: z.literal(true), limits: limitsSchema, administration: adminSchema, restored: z.boolean().optional() }),
]);
export type Policy = z.infer<typeof policySchema>;
export type Limits = z.infer<typeof limitsSchema>;
export type Spend = Record<string, string>;

export function scrypt(passphrase: Buffer, salt: Buffer): Promise<Buffer> {
  return new Promise((resolve, reject) => derive(passphrase, salt, 32, { N: 131072, r: 8, p: 1, maxmem: 256 * 1024 * 1024 }, (error, key) => error ? reject(new WalletError("wallet_locked", "Passphrase derivation failed")) : resolve(key)));
}
export async function newAdministration(passphrase: Buffer) {
  if (passphrase.length < 12) throw new WalletError("policy_denied", "Use an administration passphrase of at least 12 bytes");
  const salt = randomBytes(16), key = await scrypt(passphrase, salt);
  try { return adminSchema.parse({ name: "scrypt", N: 131072, r: 8, p: 1, salt: salt.toString("base64"), verifier: key.toString("base64") }); }
  finally { key.fill(0); }
}
export async function authorize(policy: Policy, passphrase: Buffer): Promise<void> {
  if (!policy.configured) throw new WalletError("policy_not_configured", "Configure a local administration factor first");
  return authorizeAdministration(policy.administration, passphrase);
}
export async function authorizeAdministration(administration: z.infer<typeof adminSchema>, passphrase: Buffer): Promise<void> {
  const key = await scrypt(passphrase, Buffer.from(administration.salt, "base64"));
  try { if (!timingSafeEqual(key, Buffer.from(administration.verifier, "base64"))) throw new WalletError("policy_denied", "Administration authentication failed"); }
  finally { key.fill(0); }
}
export function tokenLimits(limits: Limits, token: string) {
  return Object.entries(limits.tokens).find(([id]) => id.toLowerCase() === token.toLowerCase())?.[1];
}
export function addSpend(spend: Spend, token: string, amount: bigint): void {
  const key = token.toLowerCase(); spend[key] = (BigInt(spend[key] ?? "0") + amount).toString();
}
export function policyViolations(limits: Limits, input: {
  token: string; tokenOut?: string; amount: string; to?: string; swap: boolean; slippage: number;
  spend: Spend; used: Spend; balances: Spend; gasCost: bigint; fee: bigint; gasUnits: bigint;
  gasToken: string; gasCharge: bigint; calls: { to: string; data: string }[];
}, now = Date.now()): string[] {
  const reasons: string[] = [];
  const token = tokenLimits(limits, input.token);
  if (!token || BigInt(input.amount) > BigInt(token.perTransaction)) reasons.push("per_transaction_limit");
  if (input.to && limits.recipients.mode === "allowlist" && !limits.recipients.addresses.some(a => a.toLowerCase() === input.to!.toLowerCase())) reasons.push("recipient_not_allowed");
  if (input.swap && (!limits.swaps || !input.tokenOut || !tokenLimits(limits, input.tokenOut) || input.slippage > limits.maxSlippageBps)) reasons.push("swap_not_allowed");
  if (limits.expiresAt && now >= limits.expiresAt) reasons.push("policy_expired");
  for (const [id, amount] of Object.entries(input.spend)) {
    const cap = tokenLimits(limits, id);
    if (!cap || BigInt(amount) + BigInt(input.used[id] ?? "0") > BigInt(cap.daily)) reasons.push("daily_limit");
  }
  for (const [id, amount] of Object.entries(input.balances)) {
    const cap = tokenLimits(limits, id);
    if (BigInt(amount) > 0n && (!cap || BigInt(amount) > BigInt(cap.exposure))) reasons.push("exposure_limit");
  }
  if (input.gasCost > BigInt(limits.maxGasCostWei) || input.fee > BigInt(limits.maxFeePerGas) || input.gasUnits > BigInt(limits.maxGasUnits)) reasons.push("gas_limit");
  const gas = tokenLimits(limits, input.gasToken);
  if (!gas || input.gasCharge > BigInt(gas.gasPayment)) reasons.push("gas_payment_limit");
  if (input.calls.length > limits.maxBatchCalls) reasons.push("batch_limit");
  for (const call of input.calls) {
    // A native transfer is governed by the recipient rule. Contract calls need selectors too.
    if (call.data === "0x") continue;
    const allowed = Object.entries(limits.targets).find(([a]) => a.toLowerCase() === call.to.toLowerCase())?.[1];
    if (!allowed?.includes(call.data.slice(0, 10).toLowerCase())) reasons.push("target_or_selector_not_allowed");
  }
  return [...new Set(reasons)];
}
