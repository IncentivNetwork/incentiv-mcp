import { constants } from "node:fs";
import { lstat, mkdir, open, readdir, realpath, rename, unlink } from "node:fs/promises";
import { spawn, execFile } from "node:child_process";
import { promisify } from "node:util";
import { dirname, join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import { fileURLToPath } from "node:url";
import { WalletError } from "./keystore.js";
import type { Socket } from "node:net";

let windowsWorker: ReturnType<typeof startWindowsWorker> | undefined;

function startWindowsWorker() {
  // Reuse the process, never an ACL result. The script checks each request afresh.
  // Keep normal execution policy and antivirus checks; only public paths cross stdin.
  const child = spawn(join(process.env.SystemRoot ?? "C:\\Windows", "System32", "WindowsPowerShell", "v1.0", "powershell.exe"),
    ["-NoProfile", "-NonInteractive", "-File", fileURLToPath(new URL("./windows-permissions.ps1", import.meta.url))],
    { windowsHide: true, stdio: ["pipe", "pipe", "ignore"] });
  const pending: { resolve: (value: string) => void; reject: (error: Error) => void; timer: NodeJS.Timeout }[] = [];
  const failure = () => new WalletError("wallet_permissions_invalid", "Windows owner-only ACL or reparse-point verification failed");
  let buffer = "", closed = false, idle: NodeJS.Timeout | undefined;
  function stop() {
    if (closed) return;
    closed = true;
    if (windowsWorker === worker) windowsWorker = undefined;
    clearTimeout(idle);
    process.off("exit", stop);
    child.stdin.destroy(); child.stdout.destroy(); child.kill();
    for (const request of pending.splice(0)) { clearTimeout(request.timer); request.reject(failure()); }
  }
  const worker = {
    request(action: string, paths: string[]): Promise<string> {
      return new Promise((resolve, reject) => {
        if (closed) { reject(failure()); return; }
        clearTimeout(idle);
        // This referenced timer also keeps Node alive while a response is outstanding.
        pending.push({ resolve, reject, timer: setTimeout(stop, 20_000) });
        child.stdin.write(JSON.stringify({ action, paths }) + "\n");
      });
    },
  };
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk: string) => {
    buffer += chunk;
    let end: number;
    while ((end = buffer.indexOf("\n")) >= 0) {
      if (end > 4096 || !pending.length) { stop(); return; }
      const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
      let response;
      try { response = JSON.parse(line); } catch { stop(); return; }
      if (!response || !(response.ok === false || (response.ok === true && typeof response.value === "string"))) { stop(); return; }
      const request = pending.shift()!;
      clearTimeout(request.timer);
      if (response.ok) request.resolve(response.value); else request.reject(failure());
      if (!pending.length) { idle = setTimeout(stop, 30_000); idle.unref(); }
    }
    if (buffer.length > 4096) stop();
  });
  child.on("error", stop); child.on("close", stop); child.stdin.on("error", stop);
  // Idle helpers must not keep a CLI/test process alive, or survive its normal exit.
  process.once("exit", stop);
  child.unref(); (child.stdin as Socket).unref(); (child.stdout as Socket).unref();
  return worker;
}

function windows(action: string, paths: string[] = []): Promise<string> {
  return (windowsWorker ??= startWindowsWorker()).request(action, paths);
}

export function isMissing(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === "ENOENT"; }
export function isExists(error: unknown): boolean { return (error as NodeJS.ErrnoException)?.code === "EEXIST"; }

export async function exists(path: string): Promise<boolean> {
  try { await lstat(path); return true; } catch (error) { if (isMissing(error)) return false; throw error; }
}

async function inspect(path: string): Promise<boolean> {
  const stat = await lstat(path);
  if (stat.isSymbolicLink() || (!stat.isDirectory() && !stat.isFile()) || (stat.isFile() && stat.nlink !== 1)) {
    throw new WalletError("wallet_path_unsafe", "Wallet paths must be ordinary directories and unlinked regular files");
  }
  if (process.platform !== "win32" && (stat.uid !== process.getuid?.() || (stat.mode & 0o777) !== (stat.isDirectory() ? 0o700 : 0o600))) {
    throw new WalletError("wallet_permissions_invalid", "Wallet paths must be owner-only (0700 directories, 0600 files)");
  }
  return stat.isDirectory();
}

export async function verifyPaths(paths: string[]): Promise<void> {
  for (const path of paths) await inspect(path);
  if (process.platform === "win32" && paths.length) await windows("verify", paths);
}

export async function verifyTree(root: string): Promise<void> {
  const paths: string[] = [];
  async function visit(path: string): Promise<void> {
    paths.push(path);
    if (await inspect(path)) for (const name of await readdir(path)) await visit(join(path, name));
  }
  await visit(root);
  if (process.platform === "win32") await windows("verify", paths);
}

export async function privateDirectory(path: string): Promise<void> {
  if (await exists(path)) {
    await verifyPaths([path]);
    if (!await inspect(path)) throw new WalletError("wallet_path_unsafe", "Expected an ordinary wallet directory");
    return;
  }
  if (process.platform === "win32") await windows("mkdir", [path]);
  else {
    try { await mkdir(path, { mode: 0o700 }); } catch (error) { if (!isExists(error)) throw error; }
    await verifyPaths([path]);
  }
}

export async function prepareRoot(root: string): Promise<void> {
  const parent = dirname(resolve(root));
  const actual = await realpath(parent);
  const normalize = (p: string) => process.platform === "win32" ? p.toLowerCase() : p;
  if (normalize(actual) !== normalize(parent)) throw new WalletError("wallet_path_unsafe", "Wallet parent must not traverse a symbolic link or junction");
  await privateDirectory(root);
}

export async function syncDirectory(path: string): Promise<void> {
  // Windows does not expose directory fsync through Node. File handles are still flushed.
  if (process.platform === "win32") return;
  const handle = await open(path, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
  try { await handle.sync(); } catch (error) {
    if (!["EINVAL", "ENOTSUP"].includes((error as NodeJS.ErrnoException).code ?? "")) throw error;
  } finally { await handle.close(); }
}

export async function writeNew(path: string, bytes: Buffer | string): Promise<void> {
  const handle = await open(path, constants.O_WRONLY | constants.O_CREAT | constants.O_EXCL | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW), 0o600);
  try {
    if (process.platform === "win32") await windows("protect", [path]);
    await handle.writeFile(bytes); await handle.sync();
  } finally { await handle.close(); }
  await syncDirectory(dirname(path));
}

export async function readPrivate(path: string, maxBytes = 65_536, permissionsChecked = false): Promise<Buffer> {
  if (permissionsChecked) await inspect(path);
  else await verifyPaths([path]);
  const handle = await open(path, constants.O_RDONLY | (process.platform === "win32" ? 0 : constants.O_NOFOLLOW));
  try {
    const stat = await handle.stat();
    if (!stat.isFile() || stat.nlink !== 1 || stat.size > maxBytes) throw new WalletError("wallet_recovery_required", "Invalid wallet file type or size");
    return await handle.readFile();
  } finally { await handle.close(); }
}

export async function readJson(path: string, permissionsChecked = false): Promise<unknown> {
  const bytes = await readPrivate(path, 65_536, permissionsChecked);
  try { return JSON.parse(bytes.toString("utf8")); } catch {
    throw new WalletError("wallet_recovery_required", "Invalid wallet JSON; original file preserved");
  } finally { bytes.fill(0); }
}

export async function replacePrivate(path: string, content: string | Buffer, checkpoint?: (point: string) => Promise<void>): Promise<void> {
  if (await exists(path)) await verifyPaths([path]);
  const temporary = join(dirname(path), `.commit-${randomUUID()}.tmp`);
  await writeNew(temporary, content);
  await checkpoint?.("temporary_flushed");
  await rename(temporary, path); await checkpoint?.("renamed");
  await syncDirectory(dirname(path)); await checkpoint?.("directory_flushed");
}

export const replacePublic = replacePrivate;

export async function removeOwned(path: string): Promise<void> {
  await verifyPaths([path]); await unlink(path); await syncDirectory(dirname(path));
}

let hostPromise: Promise<string> | undefined;
export function hostIdentity(): Promise<string> {
  return hostPromise ??= (async () => {
    if (process.platform === "win32") return windows("host");
    if (process.platform === "linux") {
      const { readFile } = await import("node:fs/promises");
      return (await readFile("/etc/machine-id", "utf8")).trim();
    }
    if (process.platform === "darwin") {
      const { stdout } = await promisify(execFile)("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], { timeout: 10_000 });
      const id = stdout.match(/"IOPlatformUUID"\s*=\s*"([^"]+)"/)?.[1];
      if (id) return id;
    }
    throw new WalletError("wallet_recovery_required", "Cannot establish the local host identity");
  })().then((id) => {
    if (!id || id.length > 256) throw new WalletError("wallet_recovery_required", "Invalid local host identity");
    return `${process.platform}:${id}`;
  });
}
