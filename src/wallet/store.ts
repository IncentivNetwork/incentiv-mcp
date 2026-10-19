import { randomBytes, randomUUID, timingSafeEqual } from "node:crypto";
import { readdir, rename } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson, parseConfig, type Config } from "../config.js";
import { assertWalletNetwork, NetworkError, verifyWalletSession } from "../network.js";
import { walletProfile } from "../wallet-profile.js";
import { assertImplementationUpgrade } from "../account-upgrade.js";
import { nativeCredentials, type CredentialStore } from "./credentials.js";
import { exists, isMissing, prepareRoot, privateDirectory, readJson, readPrivate, replacePublic, syncDirectory, verifyTree, writeNew } from "./files.js";
import { creationLock } from "./lock.js";
import { authenticateWallet, bindingSchema, generateOwnerKey, parseEnvelope, publicWallet, sealWallet, unlockWallet, WalletError, type WalletBinding, type WalletEnvelope } from "./keystore.js";
import { replacePrivate, removeOwned } from "./files.js";
import { limitsSchema, newAdministration, type Limits, type Policy } from "./policy.js";
import { Journal, type JournalData } from "./journal.js";
import { orphanRecovery } from "./recovery.js";

export interface WalletSession {
  directory: string;
  envelope: WalletEnvelope;
  wrappingKey: Buffer;
  assertOwned: () => Promise<void>;
  disabled: () => Promise<boolean>;
  savePolicy: (policy: Policy) => Promise<void>;
  clearDisabled: () => Promise<void>;
  checkpoint?: (point: string) => Promise<void>;
}
export interface RestoreSnapshot { envelope: WalletEnvelope; wrappingKey: Buffer; initialize: (directory: string, key: Buffer, envelope: WalletEnvelope) => Promise<void> }

const ANCHOR = "wallet-binding-v1";
export const credentialNames = (binding: WalletBinding) => ({
  pending: `pending:${binding.walletId}:${binding.creationToken}`,
  committed: `wallet:${binding.walletId}:${binding.creationToken}`,
});

export interface StorageDependencies {
  // Internal dependency injection for isolated tests; not an environment/MCP option.
  root: string;
  credentials: () => Promise<CredentialStore>;
  verify: typeof verifyWalletSession;
  allowFileKey: boolean;
  lockTimeoutMs?: number;
  checkpoint?: (point: string) => Promise<void>;
}

export function localWalletStore(config: Config, profile = "default"): WalletStore {
  const location = walletProfile(profile);
  return new WalletStore(config, {
    root: location.root, credentials: () => nativeCredentials(location.credentialService),
    verify: verifyWalletSession, allowFileKey: process.env.INCENTIV_ALLOW_FILE_KEY === "1",
  });
}

function equalKeys(a: Buffer, b: Buffer): boolean { return a.length === b.length && timingSafeEqual(a, b); }

/** No filesystem/credential access until explicitly called; never returns secret material. */
export class WalletStore {
  private readonly config: Config;
  constructor(config: Config, private readonly deps: StorageDependencies) { this.config = parseConfig(config); }

  async createOrLoad() {
    try { return await this.run(); } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Wallet storage operation failed; existing evidence was preserved");
    }
  }

  async initialize(limits: Limits, passphrase: Buffer) {
    const policy: Policy = { schemaVersion: 1, configured: true, enabled: false, limits: limitsSchema.parse(limits), administration: await newAdministration(passphrase) };
    try { return await this.run(undefined, undefined, undefined, policy); } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Initialization failed; creation evidence was preserved");
    }
  }

  reviewOrphan() { return orphanRecovery(this.deps); }
  recoverOrphan(passphrase: Buffer, reviewedDigest: string) { return orphanRecovery(this.deps, { passphrase, reviewedDigest }); }

  async session<T>(work: (session: WalletSession) => Promise<T>): Promise<T> {
    if (!await exists(join(this.deps.root, "wallet"))) throw new WalletError("keystore_missing", "Create or restore the wallet first");
    try { return await this.run(work) as T; } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Wallet operation failed; existing evidence was preserved");
    }
  }

  /** CLI-only transition: verify the proposed network before unlocking under the old approved manifest. */
  async capabilitySession<T>(previous: Config, proposed: Config, work: (session: WalletSession) => Promise<T>): Promise<T> {
    const prior = parseConfig(previous);
    if (canonicalJson(parseConfig(proposed)) !== canonicalJson(this.config)) throw new WalletError("policy_denied", "Proposed configuration does not match the active configuration");
    if (canonicalJson(prior.identity) !== canonicalJson(this.config.identity)) throw new NetworkError("wallet_network_mismatch", "Capability approval cannot change the wallet network identity");
    if (!await exists(join(this.deps.root, "wallet"))) throw new WalletError("keystore_missing", "Create or restore the wallet first");
    try { return await this.run(work, undefined, prior) as T; } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Capability approval failed; existing evidence was preserved");
    }
  }

  /** CLI-only, exact reviewed implementation transition; ordinary sessions remain strict. */
  async implementationSession<T>(previous: Config, proposed: Config, work: (session: WalletSession) => Promise<T>): Promise<T> {
    assertImplementationUpgrade(previous, proposed);
    if (canonicalJson(parseConfig(proposed)) !== canonicalJson(this.config)) throw new WalletError("policy_denied", "Proposed configuration does not match the active configuration");
    if (!await exists(join(this.deps.root, "wallet.binding.json"))) throw new WalletError("keystore_missing", "Create or restore the wallet first");
    try { return await this.run(work, undefined, parseConfig(previous), undefined, "local") as T; } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Implementation upgrade failed; existing evidence was preserved");
    }
  }

  async disable(): Promise<void> {
    const directory = join(this.deps.root, "wallet");
    if (!await exists(directory)) throw new WalletError("keystore_missing", "No wallet exists");
    await verifyTree(this.deps.root);
    // Independent of the transaction lock: an in-flight builder sees this before signing/submitting.
    if (!await exists(join(directory, "disabled"))) {
      try { await writeNew(join(directory, "disabled"), "disabled\n"); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== "EEXIST") throw error; }
    }
  }

  async restore(snapshot: RestoreSnapshot) {
    authenticateWallet(this.config, snapshot.envelope, snapshot.wrappingKey);
    try { return await this.run(undefined, snapshot); } catch (error) {
      if (error instanceof WalletError || error instanceof NetworkError) throw error;
      throw new WalletError("wallet_recovery_required", "Restore failed; recovery evidence was preserved");
    }
  }

  private async run<T>(work?: (session: WalletSession) => Promise<T>, restoring?: RestoreSnapshot, previous?: Config, initialPolicy?: Extract<Policy, { configured: true }>, transitionScope: "local" | "all" = "all"): Promise<T | ReturnType<typeof publicWallet>> {
    const { root } = this.deps;
    await prepareRoot(root);
    const lock = await creationLock(root, this.deps.lockTimeoutMs);
    let credentials: CredentialStore | undefined;
    const getCredentials = async () => credentials ??= await this.deps.credentials();
    const checkpoint = async (point: string) => {
      await this.deps.checkpoint?.(point);
      await lock.assertOwned();
    };
    const target = join(root, "wallet");
    const bindingFile = join(root, "wallet.binding.json");
    try {
      await verifyTree(root);
      const names = await readdir(root);
      if ((restoring || initialPolicy) && names.some(name => name !== "wallet.create.lock")) throw new WalletError("wallet_recovery_required", "Initialization/restore refuses to overwrite existing wallet evidence");
      if (names.some((name) => !["wallet", "wallet.binding.json", "wallet.commit.json", "wallet.create.lock"].includes(name) && !/^wallet\.tmp-[0-9a-f-]{36}$/.test(name))) {
        throw new WalletError("wallet_recovery_required", "Unexpected wallet-root artifacts; refusing to create or overwrite a wallet");
      }
      let binding: WalletBinding;
      if (await exists(bindingFile)) {
        const parsed = bindingSchema.safeParse(await readJson(bindingFile, true));
        if (!parsed.success) throw new WalletError("wallet_recovery_required", "Wallet binding is incomplete or unsupported");
        binding = parsed.data;
      } else {
        if (previous) throw new WalletError("keystore_missing", "Configuration transitions require an existing wallet binding");
        if (names.some((name) => name !== "wallet.create.lock")) throw new WalletError("wallet_recovery_required", "Wallet artifacts exist without a creation binding");
        // An OS anchor survives loss of the entire filesystem tree. It is never
        // automatically deleted, so a missing keystore cannot become a new key.
        let anchor: Buffer | undefined;
        try { anchor = await (await getCredentials()).read(ANCHOR); }
        catch (error) {
          // Explicit file mode can run without an available credential service.
          // It must still honor an OS binding whenever that service is readable.
          if (!this.deps.allowFileKey || !(error instanceof WalletError) || error.code !== "wallet_locked") throw error;
        }
        if (anchor) { anchor.fill(0); throw new WalletError("wallet_recovery_required", "OS wallet binding exists without its filesystem artifacts"); }
        await this.deps.verify(this.config);
        await checkpoint("network_verified");
        binding = { schemaVersion: 1, walletId: restoring?.envelope.walletId ?? randomUUID(), creationToken: lock.token, storage: this.deps.allowFileKey ? "file" : "credential-store" };
        if (initialPolicy) binding.recovery = { protocol: 1, administration: initialPolicy.administration };
        await writeNew(bindingFile, canonicalJson(binding));
        await checkpoint("binding_written");
        if (binding.storage === "credential-store") {
          const bytes = Buffer.from(canonicalJson(binding));
          try { await (await getCredentials()).create(ANCHOR, bytes); } finally { bytes.fill(0); }
          await checkpoint("credential_anchor_written");
        }
        const wrappingKey = randomBytes(32);
        let ownerKey: Buffer | undefined;
        try {
          ownerKey = restoring ? unlockWallet(this.config, restoring.envelope, restoring.wrappingKey) : generateOwnerKey();
          const policy: Policy | undefined = restoring?.envelope.policy.configured ? { ...restoring.envelope.policy, enabled: false, restored: true } : initialPolicy;
          const envelope = sealWallet(this.config, binding, ownerKey, wrappingKey, policy);
          const staging = join(root, `wallet.tmp-${binding.walletId}`);
          if (binding.storage === "credential-store") {
            await (await getCredentials()).create(credentialNames(binding).pending, wrappingKey);
            await checkpoint("pending_credential_written");
          }
          await privateDirectory(staging); await syncDirectory(root);
          await checkpoint("staging_created");
          if (binding.storage === "file") {
            await writeNew(join(staging, "master.key"), wrappingKey);
            await checkpoint("file_key_written");
          }
          await writeNew(join(staging, "wallet.json"), canonicalJson(envelope));
          await checkpoint("keystore_written");
          await privateDirectory(join(staging, "operations")); await syncDirectory(staging);
          if (restoring) {
            await writeNew(join(staging, "disabled"), "Restored wallet: single-active-instance acknowledgement required\n");
            await restoring.initialize(staging, wrappingKey, envelope);
          }
          await checkpoint("operations_created");
        } finally { wrappingKey.fill(0); ownerKey?.fill(0); }
      }
      if (binding.storage === "file" && !this.deps.allowFileKey) throw new WalletError("file_key_not_allowed", "File-key storage requires INCENTIV_ALLOW_FILE_KEY=1 on every load");
      if (!binding.recovery && await exists(join(root, "wallet.commit.json"))) throw new WalletError("wallet_recovery_required", "Unexpected creation commit evidence");
      const staging = join(root, `wallet.tmp-${binding.walletId}`);
      if ((await readdir(root)).some((name) => name.startsWith("wallet.tmp-") && name !== `wallet.tmp-${binding.walletId}`)) {
        throw new WalletError("wallet_recovery_required", "Multiple creation artifacts require explicit recovery");
      }
      const committed = await exists(target);
      if (committed && await exists(staging)) throw new WalletError("wallet_recovery_required", "Both staged and committed wallets exist");
      const directory = committed ? target : staging;
      if (!await exists(directory) || !await exists(join(directory, "wallet.json"))) {
        throw new WalletError("keystore_missing", "Wallet binding exists but its keystore is missing; refusing to regenerate it");
      }
      await verifyTree(directory);
      if (committed && !await exists(join(directory, "operations"))) throw new WalletError("wallet_recovery_required", "Committed wallet is incomplete");
      if (committed) await privateDirectory(join(directory, "operations"));
      const envelope = parseEnvelope(await readJson(join(directory, "wallet.json"), true));
      if (envelope.walletId !== binding.walletId || envelope.keyStorage.creationToken !== binding.creationToken || envelope.keyStorage.kind !== binding.storage) {
        throw new WalletError("wallet_recovery_required", "Wallet and creation binding do not match");
      }
      // Never obtain a wrapping key before network/manifest verification.
      let authenticationConfig = previous && envelope.approvedCapabilityManifestId === previous.manifest.manifestId ? previous : this.config;
      if (previous) {
        assertWalletNetwork(authenticationConfig, envelope);
        await this.deps.verify(this.config, undefined, transitionScope);
      } else await this.deps.verify(this.config, envelope);
      const key = await this.wrappingKey(binding, directory, committed, binding.storage === "credential-store" ? await getCredentials() : undefined);
      try {
        authenticateWallet(authenticationConfig, envelope, key);
        await checkpoint("wallet_authenticated");
        if (binding.recovery) {
          const commitFile = join(root, "wallet.commit.json"), content = canonicalJson(binding);
          // This immutable barrier is durable BEFORE the account can be committed or displayed.
          if (await exists(commitFile)) {
            if (canonicalJson(await readJson(commitFile)) !== content) throw new WalletError("wallet_recovery_required", "Creation commit barrier disagrees with binding");
          } else {
            if (committed) throw new WalletError("wallet_recovery_required", "Creation commit barrier is missing");
            await writeNew(commitFile, content);
          }
          if (binding.storage === "credential-store") {
            const store = await getCredentials(), name = `commit:${binding.walletId}:${binding.creationToken}`;
            const marker = await store.read(name);
            try {
              if (marker && marker.toString("utf8") !== content) throw new WalletError("wallet_recovery_required", "OS creation commit barrier disagrees with binding");
              if (!marker) {
                if (committed) throw new WalletError("wallet_recovery_required", "OS creation commit barrier is missing");
                await store.create(name, Buffer.from(content));
              }
            } finally { marker?.fill(0); }
          }
          await checkpoint("creation_commit_barrier_written");
          if (!committed && envelope.policy.configured) {
            await privateDirectory(join(directory, "operations"));
            const path = join(directory, "operations", "journal.json");
            if (!await exists(path)) {
              const data: JournalData = { schemaVersion: 1, walletId: envelope.walletId, networkId: envelope.networkIdentity.networkId, manifestId: envelope.approvedCapabilityManifestId, sequence: 0, records: [] };
              await writeNew(path, canonicalJson({ data, mac: Journal.mac({ envelope, wrappingKey: key } as WalletSession, data) }));
            }
          }
        }
        if (!committed) {
          await privateDirectory(join(directory, "operations")); await syncDirectory(directory);
          await lock.assertOwned();
          if (await exists(target)) throw new WalletError("wallet_recovery_required", "Refusing to overwrite an existing wallet");
          await rename(staging, target); await syncDirectory(root);
          await checkpoint("wallet_committed");
        }
        if (binding.storage === "credential-store") {
          const store = await getCredentials();
          const name = credentialNames(binding);
          const existing = await store.read(name.committed);
          try {
            if (existing && !equalKeys(existing, key)) throw new WalletError("wallet_recovery_required", "Pending and committed credentials disagree");
            if (!existing) await store.create(name.committed, key);
          } finally { existing?.fill(0); }
          await checkpoint("credential_promoted");
          const reloaded = await store.read(name.committed);
          try {
            if (!reloaded || !equalKeys(reloaded, key)) throw new WalletError("wrapping_key_missing", "Committed credential could not be verified");
            authenticateWallet(authenticationConfig, parseEnvelope(await readJson(join(target, "wallet.json"), true)), reloaded);
          } finally { reloaded?.fill(0); }
          await checkpoint("committed_wallet_verified");
          await store.remove(name.pending);
          await checkpoint("pending_credential_removed");
        } else {
          const reloaded = await readPrivate(join(target, "master.key"), 32, true);
          try { authenticateWallet(authenticationConfig, parseEnvelope(await readJson(join(target, "wallet.json"), true)), reloaded); }
          finally { reloaded.fill(0); }
          await checkpoint("committed_wallet_verified");
        }
        const result = publicWallet(envelope);
        await replacePublic(join(target, "public.json"), canonicalJson(result));
        await checkpoint("public_cache_written");
        if (work) {
          const disabledPath = join(target, "disabled");
          const session: WalletSession = {
            directory: target, envelope, wrappingKey: key, assertOwned: lock.assertOwned, checkpoint,
            disabled: () => exists(disabledPath),
            savePolicy: async (policy) => {
              await lock.assertOwned();
              const owner = unlockWallet(authenticationConfig, session.envelope, key);
              try {
                const updated = sealWallet(this.config, binding, owner, key, policy);
                if (updated.account !== session.envelope.account || updated.owner !== session.envelope.owner || updated.walletId !== session.envelope.walletId) throw new WalletError("wallet_recovery_required", "Wallet update would change its owner or account");
                await replacePrivate(join(target, "wallet.json"), canonicalJson(updated));
                authenticateWallet(this.config, parseEnvelope(await readJson(join(target, "wallet.json"))), key);
                session.envelope = updated;
                authenticationConfig = this.config;
              } finally { owner.fill(0); }
            },
            clearDisabled: async () => { await lock.assertOwned(); if (await exists(disabledPath)) await removeOwned(disabledPath); },
          };
          return await work(session);
        }
        return result;
      } finally { key.fill(0); }
    } finally { await lock.release(); }
  }

  private async wrappingKey(binding: WalletBinding, directory: string, committed: boolean, store?: CredentialStore): Promise<Buffer> {
    if (binding.storage === "file") {
      try {
        const bytes = await readPrivate(join(directory, "master.key"), 32, true);
        if (bytes.length !== 32) { bytes.fill(0); throw new WalletError("wrapping_key_invalid", "Invalid file wrapping key length"); }
        return bytes;
      } catch (error) {
        if (isMissing(error)) throw new WalletError("wrapping_key_missing", "File wrapping key is missing; refusing to replace it");
        throw error;
      }
    }
    if (await exists(join(directory, "master.key"))) throw new WalletError("wallet_recovery_required", "Unexpected file key in an OS-backed wallet");
    const anchor = await store!.read(ANCHOR);
    try {
      if (!anchor || anchor.toString("utf8") !== canonicalJson(binding)) throw new WalletError("wallet_recovery_required", "OS and filesystem wallet bindings disagree");
    } finally { anchor?.fill(0); }
    const names = credentialNames(binding);
    const pending = await store!.read(names.pending);
    let key: Buffer | undefined;
    try {
      key = await store!.read(names.committed);
      if (!committed && key) throw new WalletError("wallet_recovery_required", "Committed credential exists without its committed wallet");
      if (key && pending && !equalKeys(key, pending)) throw new WalletError("wallet_recovery_required", "Pending and committed credentials disagree");
      const selected = key ?? pending;
      if (!selected) throw new WalletError("wrapping_key_missing", "Wallet has no matching wrapping credential");
      if (selected.length !== 32) throw new WalletError("wrapping_key_invalid", "Invalid OS wrapping key length");
      return Buffer.from(selected);
    } finally { key?.fill(0); pending?.fill(0); }
  }
}
