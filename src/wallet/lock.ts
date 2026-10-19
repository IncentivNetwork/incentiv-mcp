import { randomUUID } from "node:crypto";
import { lstat, utimes } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout as delay } from "node:timers/promises";
import { z } from "zod";
import { exists, hostIdentity, isExists, isMissing, readJson, removeOwned, writeNew } from "./files.js";
import { WalletError } from "./keystore.js";

const lockSchema = z.strictObject({ token: z.string().uuid(), pid: z.number().int().positive(), host: z.string().min(1), startedAt: z.number().positive() });
const gone = (pid: number) => {
  try { process.kill(pid, 0); return false; } catch (error) { return (error as NodeJS.ErrnoException).code === "ESRCH"; }
};

/** The one per-user lock serializes creation and every authenticated wallet session. */
export async function creationLock(root: string, timeoutMs = 10_000) {
  const path = join(root, "wallet.create.lock");
  const recovery = join(root, "wallet.create.recover.lock");
  const record = { token: randomUUID(), pid: process.pid, host: await hostIdentity(), startedAt: Date.now() - process.uptime() * 1000 };
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (!await exists(recovery)) {
      try { await writeNew(path, JSON.stringify(record)); break; } catch (error) { if (!isExists(error)) throw error; }
      // Never infer death merely from an expired heartbeat. PID reuse/live owners
      // remain locked; an unverifiable/foreign host requires explicit recovery.
      const stat = await lstat(path).catch((error) => { if (isMissing(error)) return undefined; throw error; });
      if (stat && Date.now() - stat.mtimeMs > 60_000) {
        const old = lockSchema.safeParse(await readJson(path));
        if (!old.success || old.data.host !== record.host) throw new WalletError("wallet_recovery_required", "Creation lock owner cannot be verified on this host");
        if (gone(old.data.pid)) {
          let acquired = false;
          try {
            await writeNew(recovery, JSON.stringify(record)); acquired = true;
            if (await exists(path)) {
              const current = lockSchema.parse(await readJson(path));
              const latest = await lstat(path);
              if (current.token === old.data.token && Date.now() - latest.mtimeMs > 60_000 && gone(current.pid)) await removeOwned(path);
            }
          } catch (error) { if (!isExists(error)) throw error; }
          finally { if (acquired) await removeOwned(recovery); }
          if (acquired) continue;
        }
      }
    }
    if (Date.now() >= deadline) throw new WalletError("wallet_locked", "Another creator or a recovery lock owns the wallet; retry or inspect recovery evidence");
    await delay(100);
  }
  let failure = false;
  let heartbeat = Promise.resolve();
  const assertOwned = async () => {
    if (failure || !await exists(path)) throw new WalletError("wallet_recovery_required", "Creation lock ownership was lost");
    const current = lockSchema.safeParse(await readJson(path, true));
    if (!current.success || current.data.token !== record.token) throw new WalletError("wallet_recovery_required", "Creation lock ownership was lost");
  };
  const timer = setInterval(() => {
    heartbeat = heartbeat.then(async () => {
      await assertOwned(); const now = new Date(); await utimes(path, now, now);
    }).catch(() => { failure = true; });
  }, 10_000);
  timer.unref();
  return {
    token: record.token,
    assertOwned,
    release: async () => {
      clearInterval(timer); await heartbeat;
      await assertOwned(); await removeOwned(path);
    },
  };
}
