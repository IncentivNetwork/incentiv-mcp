import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { join } from "node:path";
import { z } from "zod";
import { canonicalJson, type Config } from "../config.js";
import { previousImplementationConfig } from "../account-upgrade.js";
import { authenticateWallet, parseEnvelope, sealWallet, unlockWallet, WalletError } from "./keystore.js";
import { authorize, scrypt } from "./policy.js";
import { digest, Journal, journalApprovesManifest, journalApprovesNetwork, journalSchema, ownsNonce, type JournalData } from "./journal.js";
import { implementationReview, prepareImplementationUpgrade } from "./implementation.js";
import { readPrivate, writeNew } from "./files.js";
import type { WalletStore, WalletSession } from "./store.js";

const b64 = (size: number) => z.string().refine(s => Buffer.from(s, "base64").length === size && Buffer.from(s, "base64").toString("base64") === s);
const headerSchema = z.strictObject({ schemaVersion: z.literal(1), kdf: z.strictObject({ name: z.literal("scrypt"), N: z.literal(131072), r: z.literal(8), p: z.literal(1), dkLen: z.literal(32), salt: b64(16) }), cipher: z.strictObject({ name: z.literal("AES-256-GCM"), nonce: b64(12) }) });
const bundleSchema = z.strictObject({ header: headerSchema, ciphertext: z.string().max(24 * 1024 * 1024).regex(/^[A-Za-z0-9+/]+={0,2}$/), tag: b64(16) });

async function decrypt(config: Config, bundle: unknown, passphrase: Buffer) {
  let key: Buffer | undefined, plaintext: Buffer | undefined, wrappingKey: Buffer | undefined;
  try {
    const parsed = bundleSchema.parse(bundle);
    key = await scrypt(passphrase, Buffer.from(parsed.header.kdf.salt, "base64"));
    const cipher = createDecipheriv("aes-256-gcm", key, Buffer.from(parsed.header.cipher.nonce, "base64"));
    cipher.setAAD(Buffer.from(canonicalJson(parsed.header))); cipher.setAuthTag(Buffer.from(parsed.tag, "base64"));
    plaintext = Buffer.concat([cipher.update(Buffer.from(parsed.ciphertext, "base64")), cipher.final()]);
    const data = z.strictObject({ envelope: z.unknown(), wrappingKey: b64(32), journal: journalSchema }).parse(JSON.parse(plaintext.toString("utf8")));
    const envelope = parseEnvelope(data.envelope);
    wrappingKey = Buffer.from(data.wrappingKey, "base64");
    authenticateWallet(config, envelope, wrappingKey);
    if (data.journal.walletId !== envelope.walletId || !journalApprovesNetwork(data.journal, envelope.networkIdentity.networkId) || !journalApprovesManifest(data.journal, envelope.approvedCapabilityManifestId) || data.journal.records.some(r => ownsNonce(r.status))) throw new Error();
    return { envelope, wrappingKey: Buffer.from(wrappingKey), journal: data.journal };
  } catch { throw new WalletError("backup_authentication_failed", "Backup, recovery passphrase, network identity or history is invalid"); }
  finally { key?.fill(0); plaintext?.fill(0); wrappingKey?.fill(0); }
}

export async function backupWallet(config: Config, store: WalletStore, out: string, administration: Buffer, recovery: Buffer): Promise<void> {
  if (recovery.length < 12) throw new WalletError("policy_denied", "Use a recovery passphrase of at least 12 bytes");
  await store.session(async s => {
    await authorize(s.envelope.policy, administration);
    const journal = await Journal.open(s);
    if (journal.data.records.some(r => ownsNonce(r.status))) throw new WalletError("operation_pending", "Reconcile all nonce-owning operations before backup");
    const header = headerSchema.parse({ schemaVersion: 1, kdf: { name: "scrypt", N: 131072, r: 8, p: 1, dkLen: 32, salt: randomBytes(16).toString("base64") }, cipher: { name: "AES-256-GCM", nonce: randomBytes(12).toString("base64") } });
    const key = await scrypt(recovery, Buffer.from(header.kdf.salt, "base64"));
    const plaintext = Buffer.from(canonicalJson({ envelope: s.envelope, wrappingKey: s.wrappingKey.toString("base64"), journal: journal.data }));
    try {
      const cipher = createCipheriv("aes-256-gcm", key, Buffer.from(header.cipher.nonce, "base64"));
      cipher.setAAD(Buffer.from(canonicalJson(header)));
      const bundle = { header, ciphertext: Buffer.concat([cipher.update(plaintext), cipher.final()]).toString("base64"), tag: cipher.getAuthTag().toString("base64") };
      const verified = await decrypt(config, bundle, recovery); verified.wrappingKey.fill(0);
      await s.assertOwned(); await writeNew(out, canonicalJson(bundle));
      // Verify the committed bytes, not merely the in-memory bundle.
      const written = await readPrivate(out, 24 * 1024 * 1024);
      try { const reloaded = await decrypt(config, JSON.parse(written.toString("utf8")), recovery); reloaded.wrappingKey.fill(0); }
      finally { written.fill(0); }
    } finally { key.fill(0); plaintext.fill(0); }
  });
}

async function readBackup(config: Config, input: string, recovery: Buffer) {
  const bytes = await readPrivate(input, 24 * 1024 * 1024);
  try {
    let bundle: unknown;
    try { bundle = JSON.parse(bytes.toString("utf8")); } catch { throw new WalletError("backup_authentication_failed", "Invalid encrypted backup"); }
    return await decrypt(config, bundle, recovery);
  } finally { bytes.fill(0); }
}

export async function reviewImplementationBackup(config: Config, input: string, recovery: Buffer) {
  const snapshot = await readBackup(previousImplementationConfig(config), input, recovery);
  try { return implementationReview(config, snapshot.envelope, snapshot.journal); }
  finally { snapshot.wrappingKey.fill(0); }
}

export async function restoreWallet(config: Config, store: WalletStore, input: string, recovery: Buffer, upgrade?: { administration: Buffer; reviewedDigest: string }) {
  const previous = upgrade ? previousImplementationConfig(config) : config;
  const snapshot = await readBackup(previous, input, recovery);
  try {
    if (upgrade) {
      if (digest(implementationReview(config, snapshot.envelope, snapshot.journal)) !== upgrade.reviewedDigest) throw new WalletError("policy_denied", "Backup implementation review changed; review again");
      const prepared = await prepareImplementationUpgrade(config, snapshot.envelope, snapshot.journal, upgrade.administration);
      const ownerKey = unlockWallet(previous, snapshot.envelope, snapshot.wrappingKey);
      try {
        const old = snapshot.envelope;
        const envelope = sealWallet(config, { schemaVersion: 1, walletId: old.walletId, creationToken: old.keyStorage.creationToken, storage: old.keyStorage.kind }, ownerKey, snapshot.wrappingKey, prepared.policy);
        if (envelope.owner !== old.owner || envelope.account !== old.account) throw new WalletError("wallet_network_mismatch", "Implementation upgrade must preserve the wallet owner and address");
        snapshot.envelope = envelope;
        snapshot.journal = prepared.journal;
      } finally { ownerKey.fill(0); }
    }
    return await store.restore({ ...snapshot, initialize: async (directory, wrappingKey, envelope) => {
      const data: JournalData = structuredClone(snapshot.journal);
      // Unsigned approvals are not portable authorizations. Retain their request IDs as cancelled history.
      for (const r of data.records) if (r.status === "preparing" || r.status === "approval_required") {
        r.status = "cancelled"; delete r.approval; r.sequence = ++data.sequence; r.updatedAt = Date.now();
      }
      const session = { directory, wrappingKey, envelope } as WalletSession;
      await writeNew(join(directory, "operations", "journal.json"), canonicalJson({ data, mac: Journal.mac(session, data) }));
      await Journal.open(session);
    } });
  } finally { snapshot.wrappingKey.fill(0); }
}

export async function migrateWallet(store: WalletStore, target: number) {
  // There is no invented v2 transformation. Unsupported targets do not touch storage.
  if (target !== 1) throw new WalletError("unsupported_wallet_version", "Only format v1 is supported; no files were migrated");
  return store.session(async s => {
    const journal = await Journal.open(s, !s.envelope.policy.configured);
    if (journal.data.records.some(r => ownsNonce(r.status))) throw new WalletError("operation_pending", "Cannot migrate while an operation owns a nonce");
    return { schema_version: 1, status: "already_current", owner: s.envelope.owner, account: s.envelope.account };
  });
}
