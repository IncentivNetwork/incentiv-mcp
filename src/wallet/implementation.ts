import type { Config } from "../config.js";
import { previousImplementationConfig } from "../account-upgrade.js";
import { assertWalletNetwork, deriveSmartAccount } from "../network.js";
import { publicWallet, WalletError, type WalletEnvelope } from "./keystore.js";
import { digest, Journal, type JournalData } from "./journal.js";
import { authorize, limitsSchema, newAdministration, type Limits, type Policy } from "./policy.js";
import type { WalletStore } from "./store.js";

export function implementationReview(config: Config, envelope: WalletEnvelope, journal: JournalData) {
  const previous = previousImplementationConfig(config);
  return {
    wallet: publicWallet(envelope), envelope_digest: digest(envelope),
    previous_identity: previous.identity, proposed_identity: config.identity,
    previous_manifest: previous.manifest, proposed_manifest: config.manifest,
    journal_digest: digest(journal), records: journal.records, journal_sequence: journal.sequence,
  };
}

export async function prepareImplementationUpgrade(config: Config, envelope: WalletEnvelope, data: JournalData, administration: Buffer, initialLimits?: Limits) {
  const previous = previousImplementationConfig(config);
  assertWalletNetwork(previous, envelope);
  if (deriveSmartAccount(config, envelope.owner as `0x${string}`) !== envelope.account) throw new WalletError("wallet_recovery_required", "Implementation upgrade would change the account address");
  let policy: Policy;
  if (envelope.policy.configured) {
    await authorize(envelope.policy, administration);
    if (initialLimits) throw new WalletError("policy_denied", "Implementation upgrade preserves existing policy limits");
    policy = { ...envelope.policy, enabled: false };
  } else {
    if (!initialLimits) throw new WalletError("policy_not_configured", "Establish administration and policy limits during this upgrade");
    policy = { schemaVersion: 1, configured: true, enabled: false, limits: limitsSchema.parse(initialLimits), administration: await newAdministration(administration) };
  }
  const journal = structuredClone(data);
  // Signed bytes and reservations survive; old exception approvals must never revive.
  for (const record of journal.records) {
    const cancelling = record.status === "preparing" || record.status === "approval_required";
    if (cancelling) record.status = "cancelled";
    if (record.approval || cancelling) {
      delete record.approval; record.updatedAt = Date.now(); record.sequence = ++journal.sequence;
    }
  }
  journal.approvedNetworkIds = [...new Set([...(journal.approvedNetworkIds ?? []), config.identity.networkId])];
  journal.approvedManifestIds = [...new Set([...(journal.approvedManifestIds ?? []), config.manifest.manifestId])];
  journal.implementationUpgrade = { previousManifestId: previous.manifest.manifestId, manifestId: config.manifest.manifestId };
  journal.sequence++;
  return { policy, journal };
}

export function reviewImplementation(store: WalletStore, config: Config) {
  return store.implementationSession(previousImplementationConfig(config), config, async session =>
    implementationReview(config, session.envelope, (await Journal.open(session, !session.envelope.policy.configured)).data));
}

export function approveImplementation(store: WalletStore, config: Config, administration: Buffer, reviewedDigest: string, initialLimits?: Limits) {
  return store.implementationSession(previousImplementationConfig(config), config, async session => {
    const journal = await Journal.open(session, !session.envelope.policy.configured);
    if (digest(implementationReview(config, session.envelope, journal.data)) !== reviewedDigest) throw new WalletError("policy_denied", "Wallet or implementation review changed; review again");
    if (session.envelope.networkIdentity.networkId === config.identity.networkId) {
      await authorize(session.envelope.policy, administration);
      return { ...publicWallet(session.envelope), approval: "already_current" };
    }
    const prepared = await prepareImplementationUpgrade(config, session.envelope, journal.data, administration, initialLimits);
    // The old envelope accepts this authenticated lineage after an interrupted write.
    Object.assign(journal.data, prepared.journal);
    await journal.save();
    await session.checkpoint?.("implementation_journal_committed");
    await session.savePolicy(prepared.policy);
    await session.checkpoint?.("implementation_envelope_committed");
    await Journal.open(session);
    return { ...publicWallet(session.envelope), approval: "updated_policy_review_required" };
  });
}
