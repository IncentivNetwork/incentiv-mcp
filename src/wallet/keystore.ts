import { WalletError } from "./errors.js";
import { createCipheriv, createDecipheriv, createECDH, hkdfSync, randomBytes } from "node:crypto";
import { getAddress, keccak256, type Address } from "viem";
import { z } from "zod";
import { canonicalJson, identitySchema, type Config } from "../config.js";
import { assertWalletNetwork, deriveSmartAccount } from "../network.js";
import { adminSchema, policySchema, type Policy } from "./policy.js";

export { WalletError } from "./errors.js";

const uuid = z.string().uuid();
const base64 = (bytes: number) => z.string().refine((s) => {
  const b = Buffer.from(s, "base64");
  return b.length === bytes && b.toString("base64") === s;
});
const address = z.string().regex(/^0x[0-9a-fA-F]{40}$/);
export const bindingSchema = z.strictObject({
  schemaVersion: z.literal(1), walletId: uuid, creationToken: uuid,
  storage: z.enum(["credential-store", "file"]),
  recovery: z.strictObject({ protocol: z.literal(1), administration: adminSchema }).optional(),
});
export type WalletBinding = z.infer<typeof bindingSchema>;
const metadataSchema = z.strictObject({
  schemaVersion: z.literal(1), walletId: uuid,
  networkIdentity: identitySchema,
  approvedCapabilityManifestId: z.custom<`0x${string}`>((s) => typeof s === "string" && /^0x[0-9a-f]{64}$/.test(s)),
  owner: address, account: address, salt: z.literal("0"),
  policy: policySchema,
  keyStorage: z.strictObject({ kind: bindingSchema.shape.storage, creationToken: uuid }),
  keyDerivation: z.strictObject({ name: z.literal("HKDF-SHA256"), salt: base64(16), info: z.literal("incentiv-mcp/wallet/v1") }),
});
const envelopeSchema = metadataSchema.extend({
  cipher: z.strictObject({ name: z.literal("AES-256-GCM"), nonce: base64(12), ciphertext: base64(32), tag: base64(16) }),
});
export type WalletEnvelope = z.infer<typeof envelopeSchema>;

export function parseEnvelope(value: unknown): WalletEnvelope {
  if (value && typeof value === "object" && "schemaVersion" in value && value.schemaVersion !== 1) {
    throw new WalletError("unsupported_wallet_version", "Unsupported wallet version; explicit migration is required");
  }
  const parsed = envelopeSchema.safeParse(value);
  if (!parsed.success) throw new WalletError("wallet_recovery_required", "Invalid or incomplete wallet envelope");
  return parsed.data;
}

export function ownerAddress(privateKey: Buffer): Address {
  const ecdh = createECDH("secp256k1");
  try {
    ecdh.setPrivateKey(privateKey);
    return getAddress(`0x${keccak256(ecdh.getPublicKey(undefined, "uncompressed").subarray(1)).slice(-40)}`);
  } catch {
    throw new WalletError("keystore_authentication_failed", "Invalid wallet key material");
  } finally {
    // Best effort only: V8 and OpenSSL do not promise complete zeroization.
    const replacement = Buffer.alloc(32); replacement[31] = 1;
    ecdh.setPrivateKey(replacement); replacement.fill(0);
  }
}

export function generateOwnerKey(): Buffer {
  for (;;) {
    const key = randomBytes(32);
    try { ownerAddress(key); return key; } catch { key.fill(0); }
  }
}

function aesKey(wrappingKey: Buffer, metadata: WalletEnvelope["keyDerivation"]): Buffer {
  if (wrappingKey.length !== 32) throw new WalletError("wrapping_key_invalid", "Wrapping key must be exactly 32 bytes");
  return Buffer.from(hkdfSync("sha256", wrappingKey, Buffer.from(metadata.salt, "base64"), metadata.info, 32));
}

/** Canonical AAD includes all identity/policy/storage/KDF metadata and the cipher algorithm. */
export function walletAad(envelope: WalletEnvelope): Buffer {
  const { cipher, ...metadata } = envelope;
  return Buffer.from(canonicalJson({ ...metadata, cipher: { name: cipher.name } }), "utf8");
}

export function sealWallet(cfg: Config, binding: WalletBinding, privateKey: Buffer, wrappingKey: Buffer, policy: Policy = { schemaVersion: 1, enabled: false, configured: false }): WalletEnvelope {
  const owner = ownerAddress(privateKey);
  const envelope: WalletEnvelope = {
    schemaVersion: 1, walletId: binding.walletId, networkIdentity: structuredClone(cfg.identity),
    approvedCapabilityManifestId: cfg.manifest.manifestId, owner, account: deriveSmartAccount(cfg, owner), salt: "0",
    policy,
    keyStorage: { kind: binding.storage, creationToken: binding.creationToken },
    keyDerivation: { name: "HKDF-SHA256", salt: randomBytes(16).toString("base64"), info: "incentiv-mcp/wallet/v1" },
    cipher: { name: "AES-256-GCM", nonce: randomBytes(12).toString("base64"), ciphertext: "", tag: "" },
  };
  const key = aesKey(wrappingKey, envelope.keyDerivation);
  try {
    const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(envelope.cipher.nonce, "base64"));
    cipher.setAAD(walletAad(envelope));
    envelope.cipher.ciphertext = Buffer.concat([cipher.update(privateKey), cipher.final()]).toString("base64");
    envelope.cipher.tag = cipher.getAuthTag().toString("base64");
    return parseEnvelope(envelope);
  } finally { key.fill(0); }
}

/** Authenticate and rederive; no private key is returned to the storage caller. */
export function authenticateWallet(cfg: Config, envelope: WalletEnvelope, wrappingKey: Buffer): void {
  const key = unlockWallet(cfg, envelope, wrappingKey); key.fill(0);
}

/** Internal custody boundary. Callers must clear this buffer in a finally block. */
export function unlockWallet(cfg: Config, envelope: WalletEnvelope, wrappingKey: Buffer): Buffer {
  assertWalletNetwork(cfg, envelope);
  const key = aesKey(wrappingKey, envelope.keyDerivation);
  let plaintext: Buffer | undefined;
  try {
    const cipher = createDecipheriv("aes-256-gcm", key, Buffer.from(envelope.cipher.nonce, "base64"));
    cipher.setAAD(walletAad(envelope));
    cipher.setAuthTag(Buffer.from(envelope.cipher.tag, "base64"));
    plaintext = cipher.update(Buffer.from(envelope.cipher.ciphertext, "base64"));
    cipher.final();
    const owner = ownerAddress(plaintext);
    if (owner !== envelope.owner || deriveSmartAccount(cfg, owner) !== envelope.account) throw new Error("Address mismatch");
    return Buffer.from(plaintext);
  } catch {
    throw new WalletError("keystore_authentication_failed", "Wallet authentication or address verification failed");
  } finally { key.fill(0); plaintext?.fill(0); }
}

export function publicWallet(envelope: WalletEnvelope) {
  return {
    wallet_id: envelope.walletId, owner: envelope.owner, account: envelope.account, salt: envelope.salt,
    network_id: envelope.networkIdentity.networkId, manifest_id: envelope.approvedCapabilityManifestId,
    status: "locked" as const, reason: envelope.policy.configured ? (envelope.policy.enabled ? "readiness_check_required" : "wallet_disabled") : "policy_not_configured",
    policy: envelope.policy.configured ? { schemaVersion: 1, configured: true, enabled: envelope.policy.enabled, limits: envelope.policy.limits } : envelope.policy,
    storage: envelope.keyStorage.kind,
    ...(envelope.keyStorage.kind === "file" ? {
      warning: "File-key mode: copying the wallet directory copies everything needed to unlock it. It does not protect against a shell-capable agent running as this OS user.",
    } : {}),
  };
}
