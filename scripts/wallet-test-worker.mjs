// Child process for offline creation/concurrency/crash tests. Never uses the user wallet.
import { WalletStore } from "../src/wallet/store.ts";
import { MAINNET } from "../src/config.ts";
import { assertWalletNetwork } from "../src/network.ts";

const [root, crashAt] = process.argv.slice(2);
if (!root) throw new Error("An isolated test root is required");
const store = new WalletStore(MAINNET, {
  root, allowFileKey: true, lockTimeoutMs: 60_000,
  credentials: async () => ({ read: async () => undefined }),
  verify: async (cfg, wallet) => { if (wallet) assertWalletNetwork(cfg, wallet); },
  checkpoint: async (point) => { if (point === crashAt) process.exit(73); },
});
console.log(JSON.stringify(await store.createOrLoad()));
