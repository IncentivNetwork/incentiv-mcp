import { execFile } from "node:child_process";
import { lstat, mkdir, readFile, realpath, rename, unlink } from "node:fs/promises";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import { randomUUID } from "node:crypto";
import { canonicalJson } from "./config.js";
import { writeNew, isMissing } from "./wallet/files.js";
import { WalletError } from "./wallet/errors.js";
import { walletProfile } from "./wallet-profile.js";
import { yesNo, type Ask, type Tell } from "./setup-policy.js";

export type SetupClient = "codex" | "claude" | "cursor" | "manual";
export interface Connection { command: string; args: string[]; env: Record<string, string> }
const execute = promisify(execFile);
const serverName = (profile: string) => profile === "default" ? "incentiv-wallet" : `incentiv-wallet-${profile}`;

export function connectionFor(profile: string, env = process.env, executable = process.execPath, entry = fileURLToPath(new URL("./index.js", import.meta.url))): Connection {
  walletProfile(profile);
  const environment: Record<string, string> = {};
  for (const key of ["INCENTIV_NETWORK_CONFIG", "INCENTIV_RPC_URL", "INCENTIV_BUNDLER_URL", "INCENTIV_EXPLORER_API_URL", "INCENTIV_EXPLORER_URL"]) {
    if (env[key]) environment[key] = key === "INCENTIV_NETWORK_CONFIG" ? resolve(env[key]!) : env[key]!;
  }
  return { command: resolve(executable), args: ["--use-system-ca", resolve(entry), ...(profile === "default" ? [] : ["--wallet-profile", profile])], env: environment };
}

export function clientConfigPath(client: SetupClient, platform = process.platform, home = homedir(), env = process.env): string | undefined {
  if (client === "cursor") return join(home, ".cursor", "mcp.json");
  if (client === "codex") return join(env.CODEX_HOME || join(home, ".codex"), "config.toml");
  if (client === "claude" && platform === "darwin") return join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json");
  if (client === "claude" && platform === "win32" && env.APPDATA) return join(env.APPDATA, "Claude", "claude_desktop_config.json");
  return undefined;
}

export function mergeConnection(raw: string | undefined, name: string, connection: Connection, client: SetupClient) {
  let config;
  try { config = raw === undefined ? {} : JSON.parse(raw); }
  catch { throw new WalletError("validation_failed", "Existing app configuration is not valid JSON. Original file preserved; repair it or use manual setup."); }
  const object = (value: unknown): value is Record<string, unknown> => value !== null && typeof value === "object" && !Array.isArray(value);
  if (!object(config) || (config.mcpServers !== undefined && !object(config.mcpServers))) throw new WalletError("validation_failed", "App configuration must contain an object of MCP servers. Original file preserved.");
  const servers = (config.mcpServers ?? {}) as Record<string, unknown>;
  const entry = client === "cursor" ? { type: "stdio", ...connection } : connection;
  // Earlier/manual installations may use another name for this exact profile.
  if (!Object.hasOwn(servers, name)) name = Object.keys(servers).find(key => canonicalJson(servers[key]) === canonicalJson(entry)) ?? name;
  const existing = servers[name];
  const same = existing !== undefined && canonicalJson(existing) === canonicalJson(entry);
  return { name, conflict: existing !== undefined && !same, same, content: JSON.stringify({ ...config, mcpServers: { ...servers, [name]: entry } }, null, 2) + "\n" };
}

async function readConfig(path: string): Promise<string | undefined> {
  try {
    const stat = await lstat(path);
    if (!stat.isFile() || stat.isSymbolicLink() || stat.nlink !== 1 || stat.size > 4 * 1024 * 1024) throw new WalletError("wallet_path_unsafe", "App configuration must be an ordinary file; use manual setup for linked or unusually large files");
    return await readFile(path, "utf8");
  } catch (error) { if (isMissing(error)) return undefined; throw error; }
}

export async function saveClientConfig(path: string, before: string | undefined, content: string): Promise<string | undefined> {
  await mkdir(dirname(path), { recursive: true, mode: 0o700 });
  const actual = await realpath(dirname(path));
  const normalize = (value: string) => process.platform === "win32" ? value.toLowerCase() : value;
  if (normalize(actual) !== normalize(resolve(dirname(path)))) throw new WalletError("wallet_path_unsafe", "App configuration parent is linked; use manual setup");
  if (await readConfig(path) !== before) throw new WalletError("validation_failed", "App configuration changed during setup. Rerun setup to review it again.");
  const backup = before === undefined ? undefined : `${path}.incentiv-${randomUUID()}.bak`;
  if (backup) await writeNew(backup, before!);
  const temporary = `${path}.incentiv-${randomUUID()}.tmp`;
  await writeNew(temporary, content);
  try {
    if (await readConfig(path) !== before) throw new WalletError("validation_failed", "App configuration changed during setup. Original file preserved.");
    await rename(temporary, path);
  } finally { await unlink(temporary).catch(() => {}); }
  return backup;
}

export async function connectClient(client: SetupClient, profile: string, connection: Connection, ask: Ask, tell: Tell): Promise<boolean> {
  let name = serverName(profile);
  const path = clientConfigPath(client);
  const manual = () => {
    tell("Manual connection: add this server in your app's MCP settings. Keep existing entries.");
    if (client === "codex") {
      const key = /^[A-Za-z0-9_-]+$/.test(name) ? name : JSON.stringify(name);
      tell(`[mcp_servers.${key}]\ncommand = ${JSON.stringify(connection.command)}\nargs = ${JSON.stringify(connection.args)}\n\n[mcp_servers.${key}.env]\n${Object.entries(connection.env).map(([key, value]) => `${key} = ${JSON.stringify(value)}`).join("\n")}`);
      tell("Paste the tables into Codex config.toml, replacing only this server's existing tables. Guide: https://learn.chatgpt.com/docs/extend/mcp?surface=cli");
    } else tell(JSON.stringify({ mcpServers: { [name]: client === "cursor" ? { type: "stdio", ...connection } : connection } }, null, 2));
    return false;
  };
  if (!path) {
    if (client === "claude") tell("Automatic Claude Desktop setup is available on Windows and macOS. Use a supported local MCP client on this platform.");
    return manual();
  }
  tell(`App: ${client}; server: ${name}; configuration: ${path}`);
  tell(`Command: ${connection.command}\nArguments: ${JSON.stringify(connection.args)}\nEnvironment keys: ${Object.keys(connection.env).join(", ")}`);
  try {
    const before = await readConfig(path);
    if (client === "codex") {
      const { stdout } = await execute("codex", ["mcp", "list", "--json"], { timeout: 15_000, windowsHide: true });
      const servers = JSON.parse(stdout);
      if (!Array.isArray(servers)) throw new Error("Unexpected client response");
      const sameLaunch = (server: any) => server.transport?.type === "stdio" && server.transport.command === connection.command && canonicalJson(server.transport.args ?? []) === canonicalJson(connection.args);
      const existing = servers.find(s => s.name === name) ?? servers.find(sameLaunch);
      if (existing && existing.name !== name) { name = existing.name; tell(`Reusing existing connection: ${name}`); }
      if (existing?.enabled !== false && existing?.transport?.type === "stdio" && existing.transport.command === connection.command && canonicalJson(existing.transport.args ?? []) === canonicalJson(connection.args) && canonicalJson(existing.transport.env ?? {}) === canonicalJson(connection.env)) {
        tell("This connection is already configured."); return true;
      }
      if (!await yesNo(ask, tell, existing ? "Replace the existing Incentiv connection? Other servers will be preserved." : "Add this connection to Codex?")) return manual();
      if (await readConfig(path) !== before) throw new WalletError("validation_failed", "Codex configuration changed. Rerun setup to review it again.");
      if (before !== undefined) {
        const backup = `${path}.incentiv-${randomUUID()}.bak`;
        await writeNew(backup, before); tell(`Protected configuration backup: ${backup}`);
      }
      await execute("codex", ["mcp", "add", name, ...Object.entries(connection.env).flatMap(([key, value]) => ["--env", `${key}=${value}`]), "--", connection.command, ...connection.args], { timeout: 15_000, windowsHide: true });
    } else {
      const merged = mergeConnection(before, name, connection, client);
      if (merged.name !== name) { name = merged.name; tell(`Reusing existing connection: ${name}`); }
      if (merged.same) { tell("This connection is already configured."); return true; }
      if (!await yesNo(ask, tell, merged.conflict ? "Replace the existing Incentiv connection? Other settings will be preserved." : "Add this connection? Other settings will be preserved.")) return manual();
      const backup = await saveClientConfig(path, before, merged.content);
      if (backup) tell(`Protected configuration backup: ${backup}`);
    }
    tell("App configuration saved. Restart the app or reconnect MCP, then ask it to show the Incentiv network status.");
    return true;
  } catch (error) {
    if (error instanceof WalletError && error.code === "policy_denied") throw error;
    tell(error instanceof WalletError ? error.message : "Automatic app configuration could not finish. Check the installed client and configuration permissions; use the manual configuration below.");
    return manual();
  }
}
