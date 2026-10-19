import { timingSafeEqual } from "node:crypto";
import { WalletError } from "./keystore.js";

export interface CredentialStore {
  read(name: string): Promise<Buffer | undefined>;
  create(name: string, value: Buffer): Promise<void>;
  remove(name: string): Promise<void>;
}

/** Loaded only by local wallet storage; no import-time native-store access. */
export async function nativeCredentials(service = "io.incentiv.mcp.wallet.v1"): Promise<CredentialStore> {
  try {
    if (!["win32", "darwin", "linux"].includes(process.platform)) throw new Error("Unsupported platform");
    const { AsyncEntry } = await import("@napi-rs/keyring");
    const entry = (name: string) => new AsyncEntry(service, name, { linux: { store: "secret-service" } });
    const protect = async <T>(fn: () => Promise<T>): Promise<T> => {
      try { return await fn(); } catch (error) {
        if (error instanceof WalletError) throw error;
        throw new WalletError("wallet_locked", "OS credential storage is unavailable or locked");
      }
    };
    const read = (name: string) => protect(async () => {
      const bytes = await entry(name).getSecret();
      if (!bytes) return undefined;
      const buffer = Buffer.from(bytes); bytes.fill(0);
      return buffer;
    });
    return {
      read,
      create: (name, value) => protect(async () => {
        const existing = await read(name);
        if (existing) { existing.fill(0); throw new WalletError("wallet_recovery_required", "Credential already exists; refusing to overwrite it"); }
        await entry(name).setSecret(value);
        const committed = await read(name);
        try {
          if (!committed || committed.length !== value.length || !timingSafeEqual(committed, value)) throw new Error("Credential write verification failed");
        } finally { committed?.fill(0); }
      }),
      remove: (name) => protect(async () => { await entry(name).deleteCredential(); }),
    };
  } catch {
    throw new WalletError("wallet_locked", "OS credential storage could not be initialized");
  }
}
