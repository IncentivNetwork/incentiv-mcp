import { isRegistryIntent } from "../agent-registry.js";
import type { Config } from "../config.js";
import { publicWallet, WalletError } from "./keystore.js";
import { digest, Journal, ownsNonce } from "./journal.js";
import { authorize } from "./policy.js";
import type { WalletSession, WalletStore } from "./store.js";

async function review(session: WalletSession, previous: Config, proposed: Config) {
  const journal = await Journal.open(session, !session.envelope.policy.configured);
  const approved = session.envelope.approvedCapabilityManifestId;
  // The envelope keeps only manifest IDs, so a registry pin update is diffed against the registry-free manifest.
  const pinUpdate = approved !== previous.manifest.manifestId && approved !== proposed.manifest.manifestId;
  return { wallet: publicWallet(session.envelope), ...(pinUpdate ? { note: "This wallet previously approved different Agent Registry pins. They are stored only as an ID and cannot be shown, so the registry block below replaces them even though it appears as newly added." } : {}), previous_manifest: previous.manifest, proposed_manifest: proposed.manifest, records: journal.data.records, journal_sequence: journal.data.sequence };
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
    const owning = journal.data.records.filter(r => ownsNonce(r.status));
    if (owning.length) {
      // A registry request signed under earlier pins cannot be resent before this approval, so only a replacement clears it.
      const stuck = owning.find(r => isRegistryIntent(r.intent) && (r.status === "signed" || r.status === "submission_unknown"));
      throw new WalletError("operation_pending", `Resolve every nonce-owning operation under the previous configuration before approving capabilities: ${owning.map(r => r.requestId).join(", ")}${stuck ? `. Registry request ${stuck.requestId} cannot be resent until then; if it does not confirm, clear it with wallet operation resolve ${stuck.requestId} --replace` : ""}`);
    }
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
