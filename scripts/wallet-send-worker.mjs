// Isolated process-death test; no real RPC, credentials, wallet or network access.
import { appendFile } from "node:fs/promises";
import { join, dirname } from "node:path";
import { fixture, args, password } from "./wallet-pipeline-fixture.mjs";
import { MAINNET, configurationId } from "../src/config.ts";
import { WalletStore } from "../src/wallet/store.ts";
import { approveCapabilities, reviewCapabilities } from "../src/wallet/capabilities.ts";
import { digest, Journal } from "../src/wallet/journal.ts";
const [root, id, crashAt] = process.argv.slice(2);
if (!root || !id || !crashAt) throw new Error("Explicit test root, request and crash boundary required");
const f = await fixture(undefined, { root, existing: true, checkpoint: async point => { if (point === crashAt || point.endsWith(`_${crashAt}`)) process.exit(73); } });
if (crashAt.includes("failed")) f.chain.simulate = async () => { throw new Error("PUBLIC_FAILURE_CANARY"); };
if (crashAt.includes("confirmed") || crashAt.includes("reverted")) f.setReceipt({ success: !crashAt.includes("reverted"), actualGasCost: 200n, transactionHash: `0x${"55".repeat(32)}` });
const relay = f.chain.relay;
let relays = 0;
f.chain.relay = async op => {
  await appendFile(join(dirname(root), "relay.jsonl"), JSON.stringify(op) + "\n", { mode: 0o600 });
  if (++relays === 2 && crashAt === "replacement_relay_accepted") process.exit(73);
  if (crashAt === "relay_accepted") process.exit(73);
  if (crashAt.includes("submission_unknown")) throw new Error("PUBLIC_LOST_RESPONSE_CANARY");
  return relay(op);
};
const input = args(id);
if (["approval_required", "expired", "cancelled"].some(state => crashAt.includes(state))) input.amount = "0.00000000000002";
if (crashAt.includes("confirmed") || crashAt.includes("reverted")) input.wait_for_confirmation = true;
await f.service.send("transfer", input);
if (crashAt.includes("expired")) {
  const review = await f.service.review(id);
  await f.service.approve(id, password, digest(review.records[0]));
  await f.store.session(async s => { const journal = await Journal.open(s); journal.data.records[0].approval.expiresAt = 1; await journal.save(); });
  await f.service.send("transfer", input);
}
if (crashAt.includes("cancelled")) {
  const config = structuredClone(MAINNET);
  config.manifest.contracts.swapRouter.codeHash = `0x${"12".repeat(32)}`;
  config.manifest.manifestId = configurationId(config.manifest, "manifestId");
  const store = new WalletStore(config, f.deps), review = await reviewCapabilities(store, MAINNET, config);
  await approveCapabilities(store, MAINNET, config, password, digest(review));
}
if (["superseding", "superseded", "replacement_relay_accepted"].some(state => crashAt.includes(state))) {
  const review = await f.service.reviewReplacement(id), record = review.records[0];
  await f.service.replace(id, password, digest(record));
  if (crashAt.includes("superseded")) {
    f.chain.receipt = async r => r.userOpHash === record.replacement.userOpHash ? { success: true, actualGasCost: 400n, transactionHash: `0x${"66".repeat(32)}` } : undefined;
    await f.service.operation(id);
  }
}
