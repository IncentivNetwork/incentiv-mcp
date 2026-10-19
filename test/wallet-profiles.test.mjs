import assert from "node:assert/strict";
import test from "node:test";
import { homedir } from "node:os";
import { join } from "node:path";
import { MAINNET } from "../src/config.ts";
import { Ctx } from "../src/context.ts";
import { createLocalStdioMcpServer } from "../src/server.ts";
import { walletDirectory } from "../src/network.ts";
import { localWalletStore } from "../src/wallet/store.ts";
import { parseWalletProfileArgs, walletProfile } from "../src/wallet-profile.ts";

test("default wallet profile preserves the existing directory and credential namespace", () => {
  assert.deepEqual(walletProfile(), { name: "default", root: join(homedir(), ".incentiv-mcp"), credentialService: "io.incentiv.mcp.wallet.v1" });
  assert.equal(join(walletProfile().root, "wallet"), walletDirectory());
  assert.deepEqual(parseWalletProfileArgs([]), { profile: "default", args: [] });
  assert.deepEqual(parseWalletProfileArgs(["wallet", "backup", "--out", "backup.json"]), { profile: "default", args: ["wallet", "backup", "--out", "backup.json"] });
});

test("named profiles isolate both paths and native credentials without path or case aliases", () => {
  const names = ["default", "fresh", "fresh-2", "backups", "con"];
  const locations = names.map(walletProfile);
  assert.equal(new Set(locations.map(p => p.root.toLowerCase())).size, names.length);
  assert.equal(new Set(locations.map(p => p.credentialService.toLowerCase())).size, names.length);
  assert.ok(locations.every(p => p.root !== join(homedir(), ".incentiv-mcp-backups")));
  for (const name of ["", "../default", "a/b", "a\\b", "Default", "FRESH", "fresh.", "fresh ", "-fresh", "fresh-", "a:b", "é", "x".repeat(33)]) {
    assert.throws(() => walletProfile(name));
    assert.throws(() => localWalletStore(MAINNET, name));
  }
});

test("profiles require an explicit startup argument and reject misplaced, duplicate or HTTP selection", () => {
  assert.deepEqual(parseWalletProfileArgs(["--wallet-profile", "fresh", "wallet", "init"]), { profile: "fresh", args: ["wallet", "init"] });
  assert.deepEqual(parseWalletProfileArgs(["--wallet-profile", "fresh"]), { profile: "fresh", args: [] });
  for (const args of [
    ["--wallet-profile"], ["--wallet-profile=fresh"], ["wallet", "init", "--wallet-profile", "fresh"],
    ["--wallet-profile", "fresh", "--wallet-profile", "other"], ["--wallet-profile", "fresh", "--http", "3012"],
    ["--wallet-profiel", "fresh"], ["--wallet-profile", "fresh", "unknown"],
  ]) assert.throws(() => parseWalletProfileArgs(args));
});

test("named-profile MCP retains all 29 tools without creating or loading a wallet", async () => {
  const bundle = await createLocalStdioMcpServer(new Ctx(MAINNET), "profile-catalog-test");
  try {
    assert.equal(bundle.catalog.length, 29);
    assert.deepEqual(bundle.catalog.filter(t => ["create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation"].includes(t.name)).map(t => t.name), ["create_agent_wallet", "get_agent_wallet", "send_transfer", "send_swap", "get_agent_operation"]);
  } finally { await bundle.server.close(); }
});
