import type { Config } from "../config.js";
import { publicWallet, WalletError } from "./keystore.js";
import { digest, Journal, ownsNonce } from "./journal.js";
import { authorize } from "./policy.js";
import type { WalletSession, WalletStore } from "./store.js";

async function review(session: WalletSession, previous: Config, proposed: Config) {
  const journal = await Journal.open(session, !session.envelope.policy.configured);
  return { wallet: publicWallet(session.envelope), previous_manifest: previous.manifest, proposed_manifest: proposed.manifest, records: journal.data.records, journal_sequence: journal.data.sequence };
}

export function reviewCapabilities(store: WalletStore, previous: Config, proposed: Config) {
  return store.capabilitySession(previous, proposed, session => review(session, previous, proposed));
}

export function approveCapabilities(store: WalletStore, previous: Config, proposed: Config, administration: Buffer, reviewedDigest: string) {
  return store.capabilitySession(previous, proposed, async session => {
    const current = await review(session, previous, proposed);
    if (digest(current) !== reviewedDigest) throw new WalletError("policy_denied", "Wallet or capability review changed; review again");
    const policy = session.envelope.policy;
    await authorize(policy, administration);
    if (!policy.configured) throw new WalletError("policy_not_configured", "Configure administration before changing capabilities");
    if (session.envelope.approvedCapabilityManifestId === proposed.manifest.manifestId) return { ...publicWallet(session.envelope), approval: "already_current" };
    const journal = await Journal.open(session);
    if (journal.data.records.some(r => ownsNonce(r.status))) throw new WalletError("operation_pending", "Resolve every nonce-owning operation under the previous configuration before approving capabilities");
    // The journal records approval first; the envelope activates it last. A crash
    // between these writes keeps the old envelope usable and the update retryable.
    for (const record of journal.data.records) if (record.status === "preparing" || record.status === "approval_required") {
      record.status = "cancelled"; delete record.approval; record.updatedAt = Date.now(); record.sequence = ++journal.data.sequence;
    }
    journal.data.approvedManifestIds = [...new Set([...(journal.data.approvedManifestIds ?? []), proposed.manifest.manifestId])];
    journal.data.sequence++;
    await journal.save();
    await session.checkpoint?.("capability_journal_committed");
    await session.savePolicy({ ...policy, enabled: false });
    await session.checkpoint?.("capability_envelope_committed");
    await Journal.open(session);
    return { ...publicWallet(session.envelope), approval: "updated_policy_review_required" };
  });
}
