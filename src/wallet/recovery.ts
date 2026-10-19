import { readdir, rmdir } from "node:fs/promises";
import { join } from "node:path";
import { canonicalJson } from "../config.js";
import { bindingSchema, WalletError } from "./keystore.js";
import { exists, readJson, removeOwned, syncDirectory, verifyTree } from "./files.js";
import { creationLock } from "./lock.js";
import { authorizeAdministration } from "./policy.js";
import { digest } from "./journal.js";
import { credentialNames, type StorageDependencies } from "./store.js";

/** Never accepts a missing keystore as proof that a committed account did not exist. */
export async function orphanRecovery(deps: StorageDependencies, authorization?: { passphrase: Buffer; reviewedDigest: string }) {
  if (!await exists(deps.root)) throw new WalletError("keystore_missing", "No creation evidence exists");
  const lock = await creationLock(deps.root, deps.lockTimeoutMs);
  try {
    await verifyTree(deps.root);
    const bindingFile = join(deps.root, "wallet.binding.json");
    const binding = bindingSchema.parse(await readJson(bindingFile));
    if (!binding.recovery) throw new WalletError("wallet_recovery_required", "This creation has no authenticated recovery protocol; preserve its evidence");
    const stagingName = `wallet.tmp-${binding.walletId}`, staging = join(deps.root, stagingName);
    const rootEntries = await readdir(deps.root);
    if (rootEntries.some(name => !["wallet.binding.json", "wallet.create.lock", stagingName].includes(name))) throw new WalletError("wallet_recovery_required", "Committed or unknown evidence prevents orphan removal");
    const files = await exists(staging) ? await readdir(staging) : [];
    if (files.some(name => name !== "master.key" || binding.storage !== "file")) throw new WalletError("wallet_recovery_required", "A keystore or unknown staged evidence exists; resume creation instead of discarding it");
    if (binding.storage === "file" && !deps.allowFileKey) throw new WalletError("file_key_not_allowed", "File recovery requires explicit file-key opt-in");
    const credentials = binding.storage === "credential-store" ? await deps.credentials() : undefined;
    const names = credentialNames(binding);
    let pendingPresent = false;
    if (credentials) {
      for (const name of [names.committed, `commit:${binding.walletId}:${binding.creationToken}`]) {
        const marker = await credentials.read(name);
        if (marker) { marker.fill(0); throw new WalletError("wallet_recovery_required", "OS evidence shows a commit may have occurred; orphan removal is forbidden"); }
      }
      const anchor = await credentials.read("wallet-binding-v1");
      try { if (anchor && anchor.toString("utf8") !== canonicalJson(binding)) throw new WalletError("wallet_recovery_required", "OS creation binding disagrees"); }
      finally { anchor?.fill(0); }
      const pending = await credentials.read(names.pending);
      pendingPresent = !!pending; pending?.fill(0);
    }
    const review = { wallet_id: binding.walletId, storage: binding.storage, staged_files: files.sort(), pending_credential: pendingPresent, review_digest: digest({ binding, rootEntries: rootEntries.sort(), files: files.sort(), pendingPresent }), status: "uncommitted_orphan" };
    if (!authorization) return review;
    if (authorization.reviewedDigest !== review.review_digest) throw new WalletError("policy_denied", "Creation evidence changed; review again");
    await authorizeAdministration(binding.recovery.administration, authorization.passphrase);
    await lock.assertOwned();
    // Only named private files and an empty directory are removed. No recursive deletion.
    if (credentials && pendingPresent) await credentials.remove(names.pending);
    await deps.checkpoint?.("orphan_pending_removed"); await lock.assertOwned();
    for (const file of files) await removeOwned(join(staging, file));
    if (await exists(staging)) { await rmdir(staging); await syncDirectory(deps.root); }
    if (credentials) await credentials.remove("wallet-binding-v1");
    await deps.checkpoint?.("orphan_anchor_removed"); await lock.assertOwned();
    await removeOwned(bindingFile);
    return { ...review, status: "orphan_discarded" };
  } catch (error) {
    if (error instanceof WalletError) throw error;
    throw new WalletError("wallet_recovery_required", "Orphan recovery could not prove safe removal; remaining evidence was preserved");
  } finally { await lock.release(); }
}
