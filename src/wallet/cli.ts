import { readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { createInterface } from "node:readline/promises";
import { timingSafeEqual } from "node:crypto";
import { formatUnits } from "viem";
import { z } from "zod";
import { loadConfig, parseConfig } from "../config.js";
import { Ctx } from "../context.js";
import { WalletError } from "./keystore.js";
import { WALLET_CANDIDATE_SIGNING_ENABLED, WalletService } from "./service.js";
import { NetworkError, verifyNetwork } from "../network.js";
import { bundlerRpc } from "../userop.js";
import { address, authorize, limitsSchema } from "./policy.js";
import { digest, terminal } from "./journal.js";
import { backupWallet, migrateWallet, restoreWallet, reviewImplementationBackup } from "./backup.js";
import { approveCapabilities, reviewCapabilities } from "./capabilities.js";
import { approveImplementation, reviewImplementation, type implementationReview } from "./implementation.js";
import { localWalletStore } from "./store.js";
import { walletProfile } from "../wallet-profile.js";

export function requireTerminal() {
  if (!process.stdin.isTTY || !process.stderr.isTTY) throw new WalletError("policy_denied", "Administration requires a local TTY; passphrases are never accepted through arguments, environment or piped stdin");
}
export async function secretPrompt(label: string): Promise<Buffer> {
  requireTerminal(); process.stderr.write(label);
  return new Promise((resolve, reject) => {
    const value = Buffer.alloc(1024); let length = 0;
    const wasRaw = process.stdin.isRaw;
    const cleanup = () => { process.stdin.off("data", onData); process.stdin.off("end", onEnd); process.stdin.setRawMode(wasRaw); process.stdin.pause(); process.stderr.write("\n"); value.fill(0); };
    const onEnd = () => { cleanup(); reject(new WalletError("policy_denied", "Passphrase prompt was interrupted")); };
    const onData = (bytes: Buffer) => {
      for (const byte of bytes) {
        if (byte === 3 || byte === 4) { onEnd(); return; }
        if (byte === 13 || byte === 10) { const result = Buffer.from(value.subarray(0, length)); cleanup(); resolve(result); return; }
        if (byte === 127 || byte === 8) { if (length) value[--length] = 0; continue; }
        if (byte < 32 || length >= value.length) { onEnd(); return; }
        value[length++] = byte;
      }
    };
    process.stdin.setRawMode(true); process.stdin.resume(); process.stdin.on("data", onData); process.stdin.once("end", onEnd);
  });
}
export async function textPrompt(question: string): Promise<string> {
  requireTerminal(); const input = createInterface({ input: process.stdin, output: process.stderr });
  try { return (await input.question(question)).trim(); } finally { input.close(); }
}
export async function confirmedSecret(label: string): Promise<Buffer> {
  const first = await secretPrompt(label);
  try {
    const second = await secretPrompt("Confirm passphrase: ");
    try { if (first.length !== second.length || !timingSafeEqual(first, second)) throw new WalletError("policy_denied", "Passphrases do not match"); }
    finally { second.fill(0); }
    if (first.length < 12) throw new WalletError("policy_denied", "Use a passphrase of at least 12 bytes");
    return first;
  } catch (error) { first.fill(0); throw error; }
}
async function policyPrompt() {
  const path = await textPrompt("Policy JSON path (see docs/wallet-policy.example.json; amounts are raw token units): ");
  try { return limitsSchema.parse(JSON.parse(await readFile(resolve(path), "utf8"))); }
  catch { throw new WalletError("policy_denied", "Invalid policy JSON; no policy changed"); }
}

function displayImplementationReview(review: ReturnType<typeof implementationReview>) {
  console.error(JSON.stringify({ wallet: review.wallet, previous_implementation: review.previous_identity.accountImplementation,
    proposed_implementation: review.proposed_identity.accountImplementation, history_records: review.records.length }, null, 2));
  console.error("This local upgrade preserves the wallet address, keys, history and pending signed operations. It cancels unsigned approvals and disables sending until policy review. It sends no transaction.");
}

async function testTransfer(service: WalletService, path: string) {
  const request = z.strictObject({
    account: address, network_id: z.string().regex(/^0x[0-9a-f]{64}$/), request_id: z.string().uuid(),
    token: z.string().max(64), to: address, amount: z.string().max(100).regex(/^(?:0|[1-9][0-9]*)(?:\.[0-9]+)?$/),
    policy: limitsSchema,
  }).parse(JSON.parse(await readFile(resolve(path), "utf8")));
  request.request_id = request.request_id.toLowerCase();
  const initial = await service.review();
  if (request.account.toLowerCase() !== initial.wallet.account.toLowerCase() || request.network_id !== initial.wallet.network_id) throw new WalletError("validation_failed", "Test request does not match this wallet and network");
  console.error("One-transfer prerelease test. General sending remains gated by release review. No swaps or replacements are authorized.");
  console.error(JSON.stringify(initial.wallet, null, 2));
  let administration: Buffer | undefined;
  try {
    if (!initial.wallet.policy.configured) {
      console.error("Initial policy (raw token units):\n" + JSON.stringify(request.policy, null, 2));
      if (await textPrompt("Type SETUP to establish this policy; the transfer requires a separate gas review below: ") !== "SETUP") throw new WalletError("policy_denied", "Action cancelled");
      administration = await confirmedSecret("Choose administration passphrase (at least 12 bytes): ");
      await service.configure(request.policy, administration, false, digest(initial.records));
    }
    // Preparation never signs or rebroadcasts, even if a previous approval is still valid.
    const input = { request_id: request.request_id, token: request.token, to: request.to, amount: request.amount, gas_token: "native" };
    const prepared = await service.send("transfer", input, true);
    if (terminal(prepared.status)) { console.error(JSON.stringify(prepared, null, 2)); return; }
    const review = await service.review(request.request_id), record = review.records[0];
    if (!record?.operation) throw new WalletError("approval_required", "No current operation is ready for review");
    const token = await service.chain.token(record.intent.token);
    const gas = BigInt(record.reservation.native ?? "0") - (record.intent.token === "native" ? BigInt(record.intent.amount) : 0n);
    console.error(JSON.stringify({
      network_id: review.wallet.network_id, from: review.wallet.account, to: record.intent.to,
      amount: formatUnits(BigInt(record.intent.amount), token.decimals), token: token.symbol, token_address: record.intent.token,
      maximum_gas_cent: formatUnits(gas, 18), deploys_account: !!record.operation.factory,
      request_id: record.requestId, user_op_hash: record.userOpHash, status: record.status, reasons: record.reasons,
    }, null, 2));
    console.error("The maximum includes deployment when needed. Actual gas may be lower. Approval expires in five minutes and cannot change the amount, recipient or gas fields.");
    if (await textPrompt("Type SEND TEST to authorize this exact transfer and maximum gas: ") !== "SEND TEST") throw new WalletError("policy_denied", "Action cancelled");
    administration ??= await secretPrompt("Administration passphrase: ");
    await service.approve(record.requestId, administration, digest(record), true);
    console.error(JSON.stringify(await service.send("transfer", { ...input, wait_for_confirmation: true }), null, 2));
    console.error("Retain this request file and UUID. For pending/unknown results, reconcile with get_agent_operation; rerunning this command can only retry this same intent.");
  } finally { administration?.fill(0); }
}

export async function runWalletCli(args: string[], profile = "default"): Promise<void> {
  const config = loadConfig(), service = new WalletService(new Ctx(config), localWalletStore(config, profile));
  if (args.length === 1 && args[0] === "doctor") {
    const bundler = async () => { const entryPoints = await bundlerRpc(new Ctx(config), "eth_supportedEntryPoints", []) as string[]; if (!entryPoints.some(a => a.toLowerCase() === config.identity.entryPoint.address.toLowerCase())) throw new NetworkError("wallet_network_mismatch", "Bundler does not support the pinned EntryPoint"); };
    const checks = await Promise.allSettled([verifyNetwork(config, undefined, "local"), bundler()]);
    const result = (check: PromiseSettledResult<void>) => check.status === "fulfilled" ? { ok: true } : { ok: false, code: check.reason?.code ?? "verification_failed", message: check.reason instanceof NetworkError ? check.reason.message : "Verification failed" };
    console.error(JSON.stringify({ network: result(checks[0]), bundler: result(checks[1]), rpc_scope: "local", remote_bridge_checks: "on_bridge_use", candidate_signing_enabled: WALLET_CANDIDATE_SIGNING_ENABLED, signing_release_approved: WALLET_CANDIDATE_SIGNING_ENABLED, wallet_storage_accessed: false }, null, 2));
    if (checks.some(check => check.status === "rejected")) process.exitCode = 1;
    return;
  }
  if (args.length === 1 && args[0] === "disable") { await service.store.disable(); console.error("Wallet disabled. Already-submitted signatures cannot be revoked."); return; }
  if (args.length === 3 && args[0] === "test-transfer" && args[1] === "--request") { requireTerminal(); await testTransfer(service, args[2]); return; }
  if (args[0] === "migrate" && args.length <= 2) { console.error(JSON.stringify(await migrateWallet(service.store, Number(args[1] ?? 1)))); return; }
  const configure = args.join(" ") === "policy configure";
  const approve = args[0] === "approve" && args.length === 2;
  const replacing = args[3] === "--replace";
  const resolveOperation = args[0] === "operation" && args[1] === "resolve" && (args.length === 3 || (args.length === 4 && replacing));
  const backup = args[0] === "backup" && args[1] === "--out" && args.length === 3;
  const restoreUpgrade = args.length === 4 && args[3] === "--upgrade-implementation";
  const restore = args[0] === "restore" && args[1] === "--in" && (args.length === 3 || restoreUpgrade);
  const initialize = args.length === 1 && args[0] === "init";
  const recover = args.length === 1 && args[0] === "recover";
  const capabilities = args.length === 4 && args[0] === "capabilities" && args[1] === "approve" && args[2] === "--previous";
  const implementation = args.length === 1 && args[0] === "upgrade-implementation";
  if (!configure && !approve && !resolveOperation && !backup && !restore && !initialize && !recover && !capabilities && !implementation) throw new WalletError("validation_failed", "Commands: wallet doctor | init | policy configure | test-transfer --request <file> | capabilities approve --previous <config.json> | upgrade-implementation | recover | approve <uuid> | disable | operation resolve <uuid> [--replace] | backup --out <file> | restore --in <file> [--upgrade-implementation] | migrate [1]");
  requireTerminal();
  if (initialize) {
    console.error(`Wallet profile: ${profile}; directory: ${walletProfile(profile).root}`);
    console.error("Choose and save an ADMINISTRATION password for policy changes and backups. The separate BACKUP RECOVERY password encrypts the backup; restore retains the administration password. Keep both outside chat.");
    const limits = await policyPrompt(); console.error(JSON.stringify(limits, null, 2));
    if (await textPrompt("Type CREATE to create this disabled wallet and set its ADMINISTRATION password: ") !== "CREATE") throw new WalletError("policy_denied", "Action cancelled");
    const administration = await confirmedSecret("Choose administration passphrase (at least 12 bytes): ");
    try { console.error(JSON.stringify(await service.store.initialize(limits, administration), null, 2)); }
    finally { administration.fill(0); }
    return;
  }
  if (recover) {
    const review = await service.store.reviewOrphan(); console.error(JSON.stringify(review, null, 2));
    if (await textPrompt("Type DISCARD UNCOMMITTED to discard this incomplete creation attempt: ") !== "DISCARD UNCOMMITTED") throw new WalletError("policy_denied", "Action cancelled");
    const administration = await secretPrompt("Creation administration passphrase: ");
    try { console.error(JSON.stringify(await service.store.recoverOrphan(administration, review.review_digest), null, 2)); }
    finally { administration.fill(0); }
    return;
  }
  if (capabilities) {
    let previous;
    try { previous = parseConfig(JSON.parse(await readFile(resolve(args[3]), "utf8"))); }
    catch { throw new WalletError("validation_failed", "Previous configuration must be a complete valid configuration file"); }
    const review = await reviewCapabilities(service.store, previous, config); console.error(JSON.stringify(review, null, 2));
    if (await textPrompt("Type APPROVE CAPABILITIES to preserve this account, approve the displayed manifest and disable signing until policy review: ") !== "APPROVE CAPABILITIES") throw new WalletError("policy_denied", "Action cancelled");
    const administration = await secretPrompt("Administration passphrase: ");
    try { console.error(JSON.stringify(await approveCapabilities(service.store, previous, config, administration, digest(review)), null, 2)); }
    finally { administration.fill(0); }
    return;
  }
  if (implementation) {
    const review = await reviewImplementation(service.store, config);
    if (review.wallet.network_id === config.identity.networkId) { console.error("This wallet already uses the current implementation. Use setup to review its policy."); return; }
    displayImplementationReview(review);
    const initialLimits = review.wallet.policy.configured ? undefined : await policyPrompt();
    if (initialLimits) console.error(JSON.stringify(initialLimits, null, 2));
    if (await textPrompt("Type UPGRADE IMPLEMENTATION to approve this local wallet update: ") !== "UPGRADE IMPLEMENTATION") throw new WalletError("policy_denied", "Action cancelled");
    const administration = review.wallet.policy.configured ? await secretPrompt("Existing administration passphrase: ") : await confirmedSecret("Choose administration passphrase (at least 12 bytes): ");
    try { console.error(JSON.stringify(await approveImplementation(service.store, config, administration, digest(review), initialLimits), null, 2)); }
    finally { administration.fill(0); }
    console.error("Review wallet policy before enabling sending. Pending operations can be checked without enabling sending.");
    return;
  }
  if (restore) {
    console.error("Restore starts disabled. Running source and restored wallets concurrently can split spending limits and race nonces. Disable or destroy the source instance before re-enabling.");
    const recovery = await secretPrompt("Recovery passphrase: ");
    try {
      if (restoreUpgrade) {
        const review = await reviewImplementationBackup(config, resolve(args[2]), recovery); displayImplementationReview(review);
        if (await textPrompt("Type RESTORE AND UPGRADE to restore this old backup with the reviewed implementation: ") !== "RESTORE AND UPGRADE") throw new WalletError("policy_denied", "Action cancelled");
        const administration = await secretPrompt("Existing wallet administration passphrase: ");
        try { console.error(JSON.stringify(await restoreWallet(config, service.store, resolve(args[2]), recovery, { administration, reviewedDigest: digest(review) }), null, 2)); }
        finally { administration.fill(0); }
      } else console.error(JSON.stringify(await restoreWallet(config, service.store, resolve(args[2]), recovery), null, 2));
    }
    finally { recovery.fill(0); }
    return;
  }
  const id = approve ? args[1].toLowerCase() : resolveOperation ? args[2].toLowerCase() : undefined;
  const review = resolveOperation && replacing ? await service.reviewReplacement(id!) : await service.review(id);
  if (replacing) console.error("The displayed replacement sends zero value to this account at the SAME nonce and pays native gas up to maxGasCost. Either the original or replacement can win; no reservation is released until a receipt is verified.");
  console.error(JSON.stringify(review, null, 2));
  if (review.wallet.storage === "file") console.error("File-key mode does not protect against a shell-capable agent running as this OS user.");
  let limits;
  if (configure) {
    limits = await policyPrompt();
    console.error(JSON.stringify(limits, null, 2));
  }
  if (await textPrompt("Type APPROVE to authorize the displayed policy/operation or encrypted backup: ") !== "APPROVE") throw new WalletError("policy_denied", "Action cancelled");
  const administration = review.wallet.policy.configured ? await secretPrompt("Existing wallet administration passphrase: ") : await confirmedSecret("Choose administration passphrase (at least 12 bytes): ");
  try {
    if (configure) {
      const acknowledged = await textPrompt("Type SINGLE ACTIVE INSTANCE to confirm every source/restored copy is disabled or destroyed: ") === "SINGLE ACTIVE INSTANCE";
      await service.configure(limits!, administration, acknowledged, digest(review.records));
      console.error(WALLET_CANDIDATE_SIGNING_ENABLED ? "Policy saved. Permitted MCP transfers and swaps execute automatically within these limits. Public release approval is separate." : "Policy saved. Candidate signing is disabled in this build.");
    } else if (approve) { if (review.records.length !== 1) throw new WalletError("operation_not_found", "Unknown request ID"); await service.approve(id!, administration, digest(review.records[0])); console.error("Exact operation approved for at most five minutes. Retry the same request ID."); }
    else if (resolveOperation) console.error(JSON.stringify(replacing ? await service.replace(id!, administration, digest(review.records[0])) : await service.resolve(id!, administration), null, 2));
    else if (backup) {
      // Fail before asking for a new recovery secret when administration does not
      // match. backupWallet repeats authorization under its own lock before writing.
      await service.store.session(s => authorize(s.envelope.policy, administration));
      const recovery = await confirmedSecret("Choose recovery passphrase (at least 12 bytes): ");
      try { await backupWallet(config, service.store, resolve(args[2]), administration, recovery); console.error("Encrypted backup written, reloaded and verified."); }
      finally { recovery.fill(0); }
    }
  } finally { administration.fill(0); }
}
