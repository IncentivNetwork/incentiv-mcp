import { randomBytes, randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { isAbsolute, join, resolve } from "node:path";
import { loadConfig } from "./config.js";
import { Ctx } from "./context.js";
import { verifyNetwork } from "./network.js";
import { walletProfile } from "./wallet-profile.js";
import { WalletService, WALLET_CANDIDATE_SIGNING_ENABLED } from "./wallet/service.js";
import { localWalletStore } from "./wallet/store.js";
import { nativeCredentials } from "./wallet/credentials.js";
import { exists } from "./wallet/files.js";
import { WalletError } from "./wallet/errors.js";
import { authorize } from "./wallet/policy.js";
import { digest } from "./wallet/journal.js";
import { backupWallet } from "./wallet/backup.js";
import { confirmedSecret, requireTerminal, secretPrompt, textPrompt } from "./wallet/cli.js";
import { answer, policySummary, promptPolicy, yesNo, type Ask, type Tell } from "./setup-policy.js";
import { connectClient, connectionFor, type SetupClient } from "./setup-client.js";

export interface SetupIO {
  ask: Ask;
  tell: Tell;
  secret: (label: string) => Promise<Buffer>;
  newSecret: (label: string) => Promise<Buffer>;
}

export function checkRuntime(version = process.versions.node): void {
  const [major, minor] = version.split(".").map(Number);
  if (major < 22 || (major === 22 && minor < 18)) throw new WalletError("validation_failed", "Install Node.js 22.18 or newer, reopen your terminal, and rerun setup");
}

async function checkCredentials() {
  const credentials = await nativeCredentials("io.incentiv.mcp.setup-check");
  const name = `probe-${randomUUID()}`, value = randomBytes(32);
  let created = false;
  try {
    await credentials.create(name, value); created = true;
  } finally {
    value.fill(0);
    if (created) await credentials.remove(name);
  }
}

/** Separated from preflight/client installation so real custody transitions can be tested offline. */
export async function setupWallet(service: WalletService, root: string, io: SetupIO, profile = "default") {
  const { ask, tell } = io, config = service.ctx.config;
  const existing = await exists(join(root, "wallet"));
  let review = existing ? await service.review() : undefined;
  if (review) {
    tell(`Existing wallet: ${review.wallet.account}. Setup will keep this account and its history.`);
    if (review.wallet.policy.configured) {
      const disabled = !review.wallet.policy.enabled || await service.store.session(s => s.disabled());
      tell(disabled ? "Signing is disabled. Choose 2 to finish setup." : "The existing wallet policy is active.");
      const action = await answer(ask, tell, `1: reconnect app only; 2: review permissions, back up and enable [${disabled ? "2" : "1"}]: `, value => {
        const choice = value || (disabled ? "2" : "1");
        if (choice === "1") return "connect";
        if (choice === "2") return "policy";
        throw new Error();
      });
      if (action === "connect") return { account: review.wallet.account, configured: true, activated: false };
    }
  }
  let limits, tokens;
  if (review?.wallet.policy.configured && await yesNo(ask, tell, "Keep the current permissions?", true)) {
    limits = review.wallet.policy.limits!;
    tokens = await Promise.all(Object.keys(limits.tokens).map(token => service.chain.token(token)));
  } else {
    ({ limits, tokens } = await promptPolicy(config, ref => service.chain.token(ref), ask, tell));
  }
  tell(policySummary(limits, tokens, config.identity.nativeSymbol));
  if (!await yesNo(ask, tell, review ? "Continue with these permissions and create an encrypted backup?" : "Create this wallet DISABLED and make an encrypted backup?")) {
    throw new WalletError("policy_denied", "Setup cancelled; no permissions changed.");
  }
  tell("Save two passwords: ADMINISTRATION authorizes changes; BACKUP RECOVERY decrypts your backup. There is no administration-password reset. Never enter either in chat.");
  const administration = review?.wallet.policy.configured
    ? await io.secret("Existing administration password: ")
    : await io.newSecret("Choose administration password (at least 12 bytes): ");
  try {
    if (!review) {
      await service.store.initialize(limits, administration);
      review = await service.review();
    } else if (!review.wallet.policy.configured) {
      await service.configure(limits, administration, false, digest(review.records), false);
      review = await service.review();
    } else {
      await service.store.session(s => authorize(s.envelope.policy, administration));
    }
    tell(`Wallet address on ${config.identity.name}: ${review.wallet.account}`);
    const defaultPath = join(homedir(), `incentiv-${profile}-backup-${new Date().toISOString().replace(/[:.]/g, "-")}.json`);
    const out = await answer(ask, tell, `Encrypted backup path [${defaultPath}]: `, value => {
      const chosen = value || defaultPath;
      if (!isAbsolute(chosen)) throw new WalletError("validation_failed", "Use an absolute backup path in an existing directory");
      return resolve(chosen);
    });
    if (await exists(out)) throw new WalletError("validation_failed", "Backup file already exists. Rerun setup with a new filename; existing backups are never overwritten.");
    const recovery = await io.newSecret("Choose a separate backup recovery password (at least 12 bytes): ");
    try {
      if (administration.equals(recovery)) throw new WalletError("policy_denied", "Choose a backup recovery password different from the administration password");
      await backupWallet(config, service.store, out, administration, recovery);
    } finally { recovery.fill(0); }
    tell(`Encrypted backup written, reloaded and verified: ${out}. Store a copy somewhere separate from this computer; keep both passwords separately.`);
    // Review again after backup. configure compares this journal digest under the wallet lock.
    review = await service.review();
    tell(policySummary(limits, tokens, config.identity.nativeSymbol));
    const single = await yesNo(ask, tell, "Is this the only active copy of this wallet? Disable any source/restored copies before continuing.");
    if (!single || (await ask("Type ENABLE to permit automatic requests within these limits (anything else leaves current permissions unchanged): ")).trim() !== "ENABLE") {
      tell("Activation skipped. New wallets remain disabled. Rerun setup to continue.");
      return { account: review.wallet.account, configured: true, activated: false };
    }
    await service.configure(limits, administration, true, digest(review.records));
    tell(WALLET_CANDIDATE_SIGNING_ENABLED ? "Wallet enabled under the displayed policy. Your AI app may also request approval. No transaction was sent." : "Policy saved; this build's signing gate remains disabled.");
    return { account: review.wallet.account, configured: true, activated: true };
  } finally { administration.fill(0); }
}

export async function runSetup(args: string[], profile = "default") {
  if (args.length) throw new WalletError("validation_failed", "Use incentiv-mcp [--wallet-profile NAME] setup without additional arguments");
  requireTerminal(); checkRuntime();
  const io: SetupIO = { ask: textPrompt, tell: message => console.error(message), secret: secretPrompt, newSecret: confirmedSecret };
  const { ask, tell } = io;
  tell("Incentiv setup — connect your AI app and keep wallet keys on this computer.\nType cancel at a choice or press Ctrl+C to stop. Setup never sends funds.\nThis build is a release candidate until its public release is approved.");
  const client = await answer(ask, tell, "Choose app: 1 Codex, 2 Claude Desktop, 3 Cursor, 4 manual [1]: ", value => {
    const clients: Record<string, SetupClient> = { "1": "codex", "2": "claude", "3": "cursor", "4": "manual" };
    if (!clients[value || "1"]) throw new Error();
    return clients[value || "1"];
  });
  const config = loadConfig(), location = walletProfile(profile);
  if (process.env.INCENTIV_ALLOW_FILE_KEY === "1") throw new WalletError("policy_denied", "Guided setup requires OS credential storage. Remove INCENTIV_ALLOW_FILE_KEY and rerun setup; existing wallets are preserved.");
  tell("Checking network identity and OS credential storage…");
  try { await verifyNetwork(config, undefined, "local"); }
  catch (error) { tell("Network check failed. Run incentiv-mcp wallet doctor; fix connectivity before retrying. Never bypass an identity mismatch."); throw error; }
  try { await checkCredentials(); }
  catch { throw new WalletError("wallet_locked", "Unlock your OS credential session and rerun setup. Linux requires an unlocked Secret Service session; see the troubleshooting guide."); }
  tell(`Checks passed. Profile: ${profile}; wallet directory: ${location.root}`);
  const service = new WalletService(new Ctx(config), localWalletStore(config, profile));
  const result = await setupWallet(service, location.root, io, profile);
  await connectClient(client, profile, connectionFor(profile), ask, tell);
  const command = `incentiv-mcp${profile === "default" ? "" : ` --wallet-profile ${profile}`}`;
  tell(`\nNext steps\n1. Restart your AI app and ask: "Show the Incentiv network status, then my wallet balance."\n2. Verify your wallet address: ${result.account}\n3. After securing the backup, fund this address on ${config.identity.name}. Keep funding within your maximum-holdings limits. Ask for a fresh transfer/swap estimate; the first operation includes account deployment.\n4. Ask: "Send AMOUNT TOKEN to RECIPIENT using a new request ID and check its status." Or: "Quote a swap, show minimum output and gas, then swap AMOUNT TOKEN_IN to TOKEN_OUT within my policy." Add "pay gas in USDC" if your policy permits it.\n5. For a pending result, check the same request ID; never create a new ID to retry an uncertain send.\nStop signing: ${command} wallet disable\nNetwork and bundler checks passed; the connection inside your AI app still needs the first prompt above.\nGuide: https://github.com/IncentivNetwork/incentiv-mcp#readme`);
}
