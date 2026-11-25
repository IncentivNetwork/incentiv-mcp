import { registryApprovalSchema } from "../agent-registry.js";
import { createHmac, hkdfSync, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import { keccak256, toHex } from "viem";
import { canonicalJson } from "../config.js";
import { CURRENT_ACCOUNT_NETWORK_ID, PREVIOUS_ACCOUNT_NETWORK_ID } from "../account-upgrade.js";
import { WalletError } from "./keystore.js";
import { exists, readPrivate, replacePrivate } from "./files.js";
import { address, tokenId, uint, addSpend, type Spend } from "./policy.js";
import type { WalletSession } from "./store.js";

const hash = z.string().regex(/^0x[0-9a-f]{64}$/);
/**
 * What an x402 payment pays for and how it was signed. `accepted` and `resource` are the seller's JSON, kept
 * exactly so the payment payload repeats them; `request` binds the request UUID to the caller's request.
 */
export const x402IntentSchema = z.strictObject({
  url: z.string().max(2048), origin: z.string().max(256), method: z.enum(["GET", "POST"]), request: hash, maxAmount: uint,
  accepted: z.string().max(8192), resource: z.string().max(8192).optional(),
  paymentId: hash, validUntil: z.number().int().positive(),
});
export const intentSchema = z.strictObject({
  intentSchemaVersion: z.literal(1), kind: z.enum(["transfer", "swap", "link_agent", "unlink_agent", "x402_payment"]),
  token: tokenId, amount: uint, gasToken: tokenId, to: address.optional(),
  tokenOut: tokenId.optional(), minimumOut: uint.optional(), slippageBps: z.number().int().min(0).max(1000),
  feeTier: z.number().int().min(1).max(1_000_000),
  registryParent: address.optional(), registryApproval: registryApprovalSchema.optional(),
  x402: x402IntentSchema.optional(),
}).superRefine((intent, ctx) => {
  if (intent.kind === "x402_payment" ? (!intent.x402 || !intent.to || intent.token === "native" || intent.tokenOut !== undefined || intent.minimumOut !== undefined || BigInt(intent.amount) > BigInt(intent.x402.maxAmount)) : intent.x402 !== undefined) {
    ctx.addIssue({ code: "custom", message: "Invalid x402 intent" });
  }
  const registry = intent.kind === "link_agent" || intent.kind === "unlink_agent";
  if (registry ? (!intent.registryParent || intent.amount !== "0" || intent.token !== intent.gasToken || intent.to !== undefined || intent.tokenOut !== undefined || intent.minimumOut !== undefined || (intent.kind === "link_agent" ? !intent.registryApproval : !!intent.registryApproval)) : (intent.registryParent !== undefined || intent.registryApproval !== undefined)) {
    ctx.addIssue({ code: "custom", message: "Invalid registry intent" });
  }
});
export type Intent = z.infer<typeof intentSchema>;
export const statuses = ["preparing", "approval_required", "signed", "submitting", "submitted", "submission_unknown", "superseding", "superseded", "confirmed", "reverted", "failed", "cancelled", "expired"] as const;
export const ownsNonce = (status: string) => ["signed", "submitting", "submitted", "submission_unknown", "superseding"].includes(status);
/** x402 payments use their own nonce lane, so only other operations hold the account's main nonce. */
export const holdsMainNonce = (r: { status: string; intent: { kind: string } }) => ownsNonce(r.status) && r.intent.kind !== "x402_payment";
export const terminal = (status: string) => ["confirmed", "reverted", "failed", "cancelled", "expired", "superseded"].includes(status);
const recordSchema = z.strictObject({
  requestId: z.string().uuid(), intent: intentSchema, intentHash: hash,
  status: z.enum(statuses), createdAt: z.number().int(), updatedAt: z.number().int(),
  sequence: z.number().int().nonnegative(), attempts: z.number().int().nonnegative(),
  manifestId: hash.optional(),
  operation: z.record(z.string(), z.string()).optional(), userOpHash: hash.optional(), nonce: uint.optional(),
  deadline: z.number().int().positive().optional(),
  reservation: z.record(tokenId, uint), consumed: z.record(tokenId, uint).optional(), consumedAt: z.number().int().optional(),
  reasons: z.array(z.string()).optional(), lastError: z.string().optional(),
  approval: z.strictObject({
    intentHash: hash, userOpHash: hash, expiresAt: z.number().int(), operationDigest: hash,
    policyDigest: hash.optional(),
    liveTest: z.strictObject({ requestId: z.string().uuid(), policyDigest: hash }).optional(),
  }).optional(),
  transactionHash: hash.optional(),
  // x402 only: the block the payment was signed at, which bounds an on-chain search for it, the last block that
  // search has covered without finding it, and whether the seller's answer for it was handed back.
  fromBlock: uint.optional(), searchedBlock: uint.optional(), delivered: z.boolean().optional(),
  // fromBlock and searchedBlock are the replacement's own receipt search start and progress, as for the original.
  replacement: z.strictObject({ operation: z.record(z.string(), z.string()), userOpHash: hash, maxGasCost: uint, gasToken: tokenId.optional(), gasCharge: uint.optional(), signed: z.boolean(), expiresAt: z.number().int(), fromBlock: uint.optional(), searchedBlock: uint.optional() }).superRefine((replacement, ctx) => {
    if ((replacement.gasToken === undefined) !== (replacement.gasCharge === undefined)) ctx.addIssue({ code: "custom", message: "Incomplete replacement gas payment" });
  }).optional(),
});
export type OperationRecord = z.infer<typeof recordSchema>;
/**
 * x402 only: an unpaid request that cannot safely be sent twice (a POST without an Idempotency-Key), journaled
 * under its request ID before it is sent, so a retry with that ID never sends it again unless it was refused
 * with a 402, which means the resource did not act on it.
 */
export const probeSchema = z.strictObject({ requestId: z.string().uuid(), request: hash, outcome: z.enum(["sending", "payment_required", "not_required"]), at: z.number().int() });
export type Probe = z.infer<typeof probeSchema>;
export const journalSchema = z.strictObject({
  schemaVersion: z.literal(1), walletId: z.string().uuid(), networkId: hash, manifestId: hash,
  approvedManifestIds: z.array(hash).optional(),
  approvedNetworkIds: z.array(hash).optional(),
  implementationUpgrade: z.strictObject({ previousManifestId: hash, manifestId: hash }).optional(),
  sequence: z.number().int().nonnegative(), records: z.array(recordSchema),
  probes: z.array(probeSchema).optional(),
});
export type JournalData = z.infer<typeof journalSchema>;
export const journalApprovesManifest = (data: JournalData, id: string) => data.manifestId === id || !!data.approvedManifestIds?.includes(id);
export const journalApprovesNetwork = (data: JournalData, id: string) => data.networkId === id ||
  (data.networkId === PREVIOUS_ACCOUNT_NETWORK_ID && id === CURRENT_ACCOUNT_NETWORK_ID && !!data.implementationUpgrade && !!data.approvedNetworkIds?.includes(id));
const signedSchema = z.strictObject({ data: journalSchema, mac: z.string().regex(/^[0-9a-f]{64}$/) });
export const digest = (value: unknown) => keccak256(toHex(canonicalJson(value)));
const transitions: Record<OperationRecord["status"], string[]> = {
  preparing: ["approval_required", "signed", "failed", "cancelled"],
  approval_required: ["preparing", "expired", "cancelled"],
  // Only an x402 payment that never left this computer expires from signed: nobody else holds its signature.
  signed: ["submitting", "superseding", "expired"],
  // Back to its earlier status only when the last check before the outbound request refused it, so it never left.
  submitting: ["submitted", "submission_unknown", "signed"],
  submitted: ["confirmed", "reverted", "submission_unknown", "superseding"],
  submission_unknown: ["submitting", "submitted", "confirmed", "reverted", "superseding"],
  superseding: ["confirmed", "reverted", "superseded"],
  confirmed: [], reverted: [], failed: [], cancelled: [], expired: [], superseded: [],
};

/** One atomic authenticated snapshot retains every request for the wallet lifetime.
 * ponytail: linear journal reads; segment with authenticated tombstones when history exceeds 16 MiB.
 */
export class Journal {
  private constructor(readonly session: WalletSession, readonly data: JournalData) {}
  static async open(session: WalletSession, initialize = false): Promise<Journal> {
    const path = join(session.directory, "operations", "journal.json");
    let data: JournalData;
    if (await exists(path)) {
      const bytes = await readPrivate(path, 16 * 1024 * 1024);
      try {
        const parsed = signedSchema.parse(JSON.parse(bytes.toString("utf8")));
        const expected = Buffer.from(Journal.mac(session, parsed.data), "hex");
        if (!timingSafeEqual(expected, Buffer.from(parsed.mac, "hex"))) throw new Error();
        data = parsed.data;
      } catch { throw new WalletError("wallet_recovery_required", "Journal authentication or schema validation failed; history preserved"); }
      finally { bytes.fill(0); }
    } else {
      if (!initialize || session.envelope.policy.configured) throw new WalletError("wallet_recovery_required", "Authenticated operation history is missing");
      data = { schemaVersion: 1, walletId: session.envelope.walletId, networkId: session.envelope.networkIdentity.networkId, manifestId: session.envelope.approvedCapabilityManifestId, sequence: 0, records: [] };
    }
    const wallet = session.envelope;
    if (data.walletId !== wallet.walletId || !journalApprovesNetwork(data, wallet.networkIdentity.networkId) || !journalApprovesManifest(data, wallet.approvedCapabilityManifestId)) throw new WalletError("wallet_recovery_required", "Journal identity mismatch");
    const upgrade = data.implementationUpgrade;
    if (upgrade && (data.networkId !== PREVIOUS_ACCOUNT_NETWORK_ID || !data.approvedNetworkIds?.includes(CURRENT_ACCOUNT_NETWORK_ID) || !journalApprovesManifest(data, upgrade.previousManifestId) || !journalApprovesManifest(data, upgrade.manifestId))) throw new WalletError("wallet_recovery_required", "Invalid implementation upgrade history");
    const ids = new Set();
    for (const record of data.records) {
      const manifest = record.manifestId ?? data.manifestId;
      const compatiblePending = wallet.networkIdentity.networkId === CURRENT_ACCOUNT_NETWORK_ID && upgrade?.manifestId === wallet.approvedCapabilityManifestId && upgrade.previousManifestId === manifest;
      if (ids.has(record.requestId) || record.intentHash !== digest(record.intent) || record.sequence > data.sequence || !journalApprovesManifest(data, manifest) || (ownsNonce(record.status) && (!record.operation || !record.userOpHash || record.nonce === undefined || (manifest !== wallet.approvedCapabilityManifestId && !compatiblePending)))) throw new WalletError("wallet_recovery_required", "Invalid journal record");
      ids.add(record.requestId);
    }
    if (new Set(data.probes?.map(p => p.requestId)).size !== (data.probes?.length ?? 0)) throw new WalletError("wallet_recovery_required", "Invalid journal record");
    return new Journal(session, data);
  }
  static mac(session: WalletSession, data: JournalData): string {
    const key = Buffer.from(hkdfSync("sha256", session.wrappingKey, Buffer.from(session.envelope.walletId), "incentiv-mcp/journal/v1", 32));
    try { return createHmac("sha256", key).update(canonicalJson(data)).digest("hex"); }
    finally { key.fill(0); }
  }
  async save(): Promise<void> {
    await this.session.assertOwned();
    journalSchema.parse(this.data);
    const content = canonicalJson({ data: this.data, mac: Journal.mac(this.session, this.data) });
    if (Buffer.byteLength(content) > 16 * 1024 * 1024) throw new WalletError("wallet_recovery_required", "Journal capacity reached; authenticated migration required");
    await replacePrivate(join(this.session.directory, "operations", "journal.json"), content, point => this.session.checkpoint?.(`journal_${this.data.records.at(-1)?.status ?? "empty"}:${point}`) ?? Promise.resolve());
    await this.session.checkpoint?.(`journal_${this.data.sequence}_${this.data.records.at(-1)?.status ?? "empty"}`);
  }
  async transition(record: OperationRecord, status: OperationRecord["status"]): Promise<void> {
    if (!transitions[record.status].includes(status)) throw new WalletError("wallet_recovery_required", "Invalid operation transition");
    record.status = status; record.updatedAt = Date.now(); record.sequence = ++this.data.sequence;
    await this.save();
  }
  async create(requestId: string, intent: Intent): Promise<OperationRecord> {
    const record: OperationRecord = { requestId, intent, intentHash: digest(intent), manifestId: this.session.envelope.approvedCapabilityManifestId, status: "preparing", createdAt: Date.now(), updatedAt: Date.now(), sequence: ++this.data.sequence, attempts: 0, reservation: {} };
    recordSchema.parse(record); this.data.records.push(record); await this.save(); return record;
  }
  used(now = Date.now()): Spend {
    const used: Spend = {};
    for (const r of this.data.records) {
      const spend = ownsNonce(r.status) ? r.reservation : r.consumedAt !== undefined && r.consumedAt > now - 86_400_000 ? r.consumed : undefined;
      for (const [token, amount] of Object.entries(spend ?? {})) addSpend(used, token, BigInt(amount));
    }
    return used;
  }
}
